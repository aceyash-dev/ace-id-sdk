import Foundation
import Security
import AppAuth
import UIKit

public enum AceIDError: Error, LocalizedError {
    case invalidConfiguration(String)
    case missingAuthorizationFlow
    case missingSession
    case secureStorageFailure(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let message): return message
        case .missingAuthorizationFlow: return "No authorization flow is pending."
        case .missingSession: return "No authenticated session is available."
        case .secureStorageFailure(let status): return "Secure storage operation failed (OSStatus \(status))."
        }
    }
}

public struct AceIDConfiguration: Sendable {
    public let issuer: URL
    public let clientID: String
    public let redirectURI: URL
    public let scopes: [String]

    public init(issuer: URL, clientID: String, redirectURI: URL, scopes: [String] = ["openid", "profile", "email"]) throws {
        guard !clientID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AceIDError.invalidConfiguration("clientID must not be empty.")
        }
        guard let scheme = issuer.scheme?.lowercased(), issuer.host != nil,
              issuer.user == nil, issuer.password == nil, issuer.query == nil, issuer.fragment == nil else {
            throw AceIDError.invalidConfiguration("issuer must be an absolute URL without credentials, query, or fragment.")
        }
        let loopback = ["localhost", "127.0.0.1", "::1"].contains(issuer.host?.lowercased() ?? "")
        guard scheme == "https" || (scheme == "http" && loopback) else {
            throw AceIDError.invalidConfiguration("issuer must use HTTPS (HTTP loopback is allowed for development).")
        }
        guard let redirectScheme = redirectURI.scheme, !redirectScheme.isEmpty,
              redirectURI.user == nil, redirectURI.password == nil, redirectURI.fragment == nil else {
            throw AceIDError.invalidConfiguration("redirectURI must have a scheme and no credentials or fragment.")
        }
        if redirectScheme.lowercased() == "http" {
            let redirectLoopback = ["localhost", "127.0.0.1", "::1"].contains(redirectURI.host?.lowercased() ?? "")
            guard redirectLoopback else {
                throw AceIDError.invalidConfiguration("HTTP redirectURIs are allowed only for localhost development.")
            }
        }
        self.issuer = issuer
        self.clientID = clientID
        self.redirectURI = redirectURI
        var uniqueScopes: [String] = []
        for scope in scopes where !scope.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            if !uniqueScopes.contains(scope) { uniqueScopes.append(scope) }
        }
        self.scopes = uniqueScopes.contains("openid") ? uniqueScopes : ["openid"] + uniqueScopes
    }
}

public protocol AceIDStateStore: Sendable {
    func read() throws -> Data?
    func write(_ data: Data) throws
    func clear() throws
}

public struct AceIDKeychainStore: AceIDStateStore {
    private let service: String
    private let account: String

    public init(service: String = Bundle.main.bundleIdentifier ?? "tab.aceid.sdk", account: String = "session") {
        self.service = service
        self.account = account
    }

    public func read() throws -> Data? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = value as? Data else { throw AceIDError.secureStorageFailure(status) }
        return data
    }

    public func write(_ data: Data) throws {
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let status = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var query = baseQuery
            attributes.forEach { query[$0.key] = $0.value }
            let addStatus = SecItemAdd(query as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw AceIDError.secureStorageFailure(addStatus) }
        } else if status != errSecSuccess {
            throw AceIDError.secureStorageFailure(status)
        }
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw AceIDError.secureStorageFailure(status) }
    }

    private var baseQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }
}

public struct AceIDSession: Codable, Sendable {
    public let accessToken: String
    public let refreshToken: String?
    public let idToken: String?
    public let tokenType: String
    public let expirationDate: Date
    public let claims: [String: String]

    public init(accessToken: String, refreshToken: String?, idToken: String?, tokenType: String, expirationDate: Date, claims: [String: String]) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.tokenType = tokenType
        self.expirationDate = expirationDate
        self.claims = claims
    }
}

@MainActor
public final class AceIDClient {
    public let configuration: AceIDConfiguration
    private let storage: AceIDStateStore
    private var authorizationFlow: OIDExternalUserAgentSession?

    public init(configuration: AceIDConfiguration, storage: AceIDStateStore = AceIDKeychainStore()) {
        self.configuration = configuration
        self.storage = storage
    }

    @discardableResult
    public func signIn(presenting viewController: UIViewController, additionalParameters: [String: String] = [:], completion: @escaping (Result<AceIDSession, Error>) -> Void) -> OIDExternalUserAgentSession? {
        OIDAuthorizationService.discoverConfiguration(forIssuer: configuration.issuer) { [weak self] service, error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error { completion(.failure(error)); return }
                guard let service else {
                    completion(.failure(AceIDError.invalidConfiguration("OIDC discovery returned no configuration.")))
                    return
                }
                let request = OIDAuthorizationRequest(
                    configuration: service,
                    clientId: self.configuration.clientID,
                    scopes: self.configuration.scopes,
                    redirectURL: self.configuration.redirectURI,
                    responseType: OIDResponseTypeCode,
                    additionalParameters: additionalParameters.isEmpty ? nil : additionalParameters
                )
                self.authorizationFlow = OIDAuthState.authState(byPresenting: request, presenting: viewController) { [weak self] state, authError in
                    guard let self else { return }
                    DispatchQueue.main.async {
                        defer { self.authorizationFlow = nil }
                        if let authError { completion(.failure(authError)); return }
                        guard let state, let response = state.lastTokenResponse,
                              let accessToken = response.accessToken,
                              let expiry = response.accessTokenExpirationDate else {
                            completion(.failure(AceIDError.missingSession))
                            return
                        }
                        let session = AceIDSession(
                            accessToken: accessToken,
                            refreshToken: response.refreshToken,
                            idToken: response.idToken,
                            tokenType: response.tokenType ?? "Bearer",
                            expirationDate: expiry,
                            claims: Self.decodeClaims(response.idToken) ?? [:]
                        )
                        do { try self.persist(session); completion(.success(session)) }
                        catch { completion(.failure(error)) }
                    }
                }
            }
        }
        return authorizationFlow
    }

    @discardableResult
    public func resumeAuthorizationFlow(with url: URL) -> Bool {
        guard let flow = authorizationFlow else { return false }
        let resumed = flow.resumeExternalUserAgentFlow(with: url)
        if resumed { authorizationFlow = nil }
        return resumed
    }

    public func currentSession() throws -> AceIDSession? {
        guard let data = try storage.read() else { return nil }
        do { return try JSONDecoder().decode(AceIDSession.self, from: data) }
        catch { try? storage.clear(); return nil }
    }

    /// Returns a non-expired stored access token. Refresh requires retaining AppAuth's
    /// OIDAuthState; raw serialized token snapshots are intentionally not refreshed.
    public func validAccessToken(leeway: TimeInterval = 60) throws -> String {
        guard leeway.isFinite, leeway >= 0, leeway <= 600 else {
            throw AceIDError.invalidConfiguration("Token leeway must be between 0 and 600 seconds.")
        }
        guard let session = try currentSession() else { throw AceIDError.missingSession }
        guard session.expirationDate.timeIntervalSinceNow > leeway else {
            try storage.clear()
            throw AceIDError.missingSession
        }
        return session.accessToken
    }

    public func signOut() throws { try storage.clear() }

    private func persist(_ session: AceIDSession) throws {
        try storage.write(JSONEncoder().encode(session))
    }

    private static func decodeClaims(_ jwt: String?) -> [String: String]? {
        guard let jwt else { return nil }
        let parts = jwt.split(separator: ".")
        guard parts.count == 3 else { return nil }
        var payload = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        payload += String(repeating: "=", count: (4 - payload.count % 4) % 4)
        guard let data = Data(base64Encoded: payload),
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return raw.compactMapValues { value in
            if let string = value as? String { return string }
            if let number = value as? NSNumber { return number.stringValue }
            return nil
        }
    }
}
