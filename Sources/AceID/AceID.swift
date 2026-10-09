import Foundation
import Security
import AppAuth
#if canImport(UIKit)
import UIKit
#endif

public enum AceIDError: Error, LocalizedError {
    case invalidConfiguration(String)
    case missingAuthorizationFlow
    case missingSession
    case revocationEndpointUnavailable
    case invalidDiscoveryResponse
    case invalidIDToken(String)
    case httpFailure(Int)
    case secureStorageFailure(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let message): return message
        case .missingAuthorizationFlow: return "No authorization flow is pending."
        case .missingSession: return "No authenticated session is available."
        case .revocationEndpointUnavailable: return "The identity provider does not advertise a token revocation endpoint."
        case .invalidDiscoveryResponse: return "The identity provider returned invalid discovery metadata."
        case .invalidIDToken(let message): return message
        case .httpFailure(let status): return "The identity provider returned HTTP status \(status)."
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
        guard Self.isSafeRedirectURI(redirectURI) else {
            throw AceIDError.invalidConfiguration("redirectURI must use HTTPS or a registered custom scheme; HTTP is allowed only for loopback development.")
        }
        let normalizedClientID = clientID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedClientID.contains(where: { $0.isWhitespace }) else {
            throw AceIDError.invalidConfiguration("clientID must not contain whitespace.")
        }
        self.issuer = issuer
        self.clientID = normalizedClientID
        self.redirectURI = redirectURI
        var uniqueScopes: [String] = []
        for rawScope in scopes {
            let scope = rawScope.trimmingCharacters(in: .whitespacesAndNewlines)
            if scope.isEmpty { continue }
            guard !scope.contains(where: { $0.isWhitespace }) else {
                throw AceIDError.invalidConfiguration("Each scope must be a single non-empty scope token.")
            }
            if !uniqueScopes.contains(scope) { uniqueScopes.append(scope) }
        }
        self.scopes = uniqueScopes.contains("openid") ? uniqueScopes : ["openid"] + uniqueScopes
    }

    static func isSafeRedirectURI(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(),
              !scheme.isEmpty,
              url.user == nil,
              url.password == nil,
              url.fragment == nil,
              !["javascript", "data", "file", "ftp", "blob", "about"].contains(scheme) else {
            return false
        }
        if scheme == "https" { return url.host != nil }
        if scheme == "http" {
            return ["localhost", "127.0.0.1", "::1"].contains(url.host?.lowercased() ?? "")
        }
        return true
    }

    static func isAllowedLogoutRedirect(_ url: URL, configuredRedirectURI: URL) -> Bool {
        isSafeRedirectURI(url) && url == configuredRedirectURI
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
        guard status == errSecSuccess, let data = value as? Data else {
            throw AceIDError.secureStorageFailure(status)
        }
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
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AceIDError.secureStorageFailure(status)
        }
    }

    private var baseQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }
}

public struct AceIDSession: Sendable {
    public let accessToken: String
    public let refreshToken: String?
    public let idToken: String?
    public let tokenType: String
    public let expirationDate: Date
    /// Claims from a cryptographically verified ID token. Restored synchronous sessions
    /// leave this empty rather than exposing claims decoded from an unverified token. 
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
    #if canImport(UIKit)
    private var authorizationFlow: OIDExternalUserAgentSession?
    #endif

    public init(configuration: AceIDConfiguration, storage: AceIDStateStore = AceIDKeychainStore()) {
        self.configuration = configuration
        self.storage = storage
    }

    #if canImport(UIKit)
    public func signIn(
        presenting viewController: UIViewController,
        additionalParameters: [String: String] = [:],
        prefersEphemeralSession: Bool = false,
        completion: @escaping (Result<AceIDSession, Error>) -> Void
    ) {
        guard !additionalParameters.keys.contains(where: {
            ["client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "code_verifier"].contains($0.lowercased())
        }) else {
            completion(.failure(AceIDError.invalidConfiguration("Additional authorization parameters cannot override OAuth security parameters.")))
            return
        }
        OIDAuthorizationService.discoverConfiguration(forIssuer: configuration.issuer) { [weak self] service, error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error { completion(.failure(error)); return }
                guard let service else {
                    completion(.failure(AceIDError.invalidDiscoveryResponse))
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
                self.authorizationFlow = OIDAuthState.authState(
                    byPresenting: request,
                    presenting: viewController,
                    prefersEphemeralSession: prefersEphemeralSession
                ) { [weak self] state, authError in
                    guard let self else { return }
                    DispatchQueue.main.async {
                        defer { self.authorizationFlow = nil }
                        if let authError { completion(.failure(authError)); return }
                        guard let state else {
                            completion(.failure(AceIDError.missingSession))
                            return
                        }
                        guard let idToken = state.lastTokenResponse?.idToken else {
                            try? self.storage.clear()
                            completion(.failure(AceIDError.invalidIDToken("The token response did not contain an ID token.")))
                            return
                        }
                        guard let expectedNonce = state.lastAuthorizationResponse.request.nonce else {
                            try? self.storage.clear()
                            completion(.failure(AceIDError.invalidIDToken("Authorization response is missing the OIDC nonce.")))
                            return
                        }
                        AceIDIDTokenVerifier.validate(
                            token: idToken,
                            issuer: self.configuration.issuer,
                            clientID: self.configuration.clientID,
                            expectedNonce: expectedNonce
                        ) { validation in
                            DispatchQueue.main.async {
                                switch validation {
                                case .failure(let error):
                                    try? self.storage.clear()
                                    completion(.failure(error))
                                case .success(let claims):
                                    do {
                                        try self.persist(state)
                                        guard let session = Self.makeSession(from: state, claims: claims) else {
                                            try? self.storage.clear()
                                            completion(.failure(AceIDError.missingSession))
                                            return
                                        }
                                        completion(.success(session))
                                    } catch {
                                        completion(.failure(error))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @discardableResult
    public func resumeAuthorizationFlow(with url: URL) -> Bool {
        guard let flow = authorizationFlow else { return false }
        let resumed = flow.resumeExternalUserAgentFlow(with: url)
        if resumed { authorizationFlow = nil }
        return resumed
    }

    /// Performs provider logout in the external user agent when an end-session endpoint exists.
    /// Local credentials are cleared whether the provider redirects successfully or returns an error.
    public func signOut(
        presenting viewController: UIViewController,
        postLogoutRedirectURI: URL? = nil,
        additionalParameters: [String: String] = [:],
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard additionalParameters.keys.allSatisfy({
            !["id_token_hint", "post_logout_redirect_uri", "state"].contains($0.lowercased())
        }) else {
            completion(.failure(AceIDError.invalidConfiguration("Additional logout parameters cannot override OIDC logout security parameters.")))
            return
        }
        if let postLogoutRedirectURI {
            guard AceIDConfiguration.isAllowedLogoutRedirect(
                    postLogoutRedirectURI,
                    configuredRedirectURI: configuration.redirectURI
                  ) else {
                completion(.failure(AceIDError.invalidConfiguration("postLogoutRedirectURI must exactly match the configured, registered redirect URI.")))
                return
            }
        }
        do {
            guard let state = try loadAuthState() else {
                try storage.clear()
                completion(.success(()))
                return
            }
            guard let idToken = state.lastTokenResponse?.idToken else {
                try storage.clear()
                completion(.success(()))
                return
            }
            // Clear the local session before opening the browser so process termination
            // cannot leave the user locally authenticated after they requested logout.
            try storage.clear()
            // AppAuth requires a non-null registered post-logout redirect URI for its
            // external-user-agent callback. Without one, complete a local-only logout.
            guard let postLogoutRedirectURI else {
                completion(.success(()))
                return
            }
            OIDAuthorizationService.discoverConfiguration(forIssuer: configuration.issuer) { [weak self] service, discoveryError in
                DispatchQueue.main.async {
                    guard let self else { return }
                    if let discoveryError {
                        try? self.storage.clear()
                        completion(.failure(discoveryError))
                        return
                    }
                    guard let service, service.endSessionEndpoint != nil else {
                        do { try self.storage.clear(); completion(.success(())) }
                        catch { completion(.failure(error)) }
                        return
                    }
                    let request = OIDEndSessionRequest(
                        configuration: service,
                        idTokenHint: idToken,
                        postLogoutRedirectURL: postLogoutRedirectURI,
                        additionalParameters: additionalParameters.isEmpty ? nil : additionalParameters
                    )
                    guard let externalUserAgent = OIDExternalUserAgentIOS(presenting: viewController) else {
                        try? self.storage.clear()
                        completion(.failure(AceIDError.invalidConfiguration("Unable to create a secure external user agent.")))
                        return
                    }
                    self.authorizationFlow = OIDAuthorizationService.present(
                        request,
                        externalUserAgent: externalUserAgent
                    ) { [weak self] _, logoutError in
                        guard let self else { return }
                        DispatchQueue.main.async {
                            self.authorizationFlow = nil
                            do { try self.storage.clear() }
                            catch { completion(.failure(error)); return }
                            if let logoutError { completion(.failure(logoutError)) }
                            else { completion(.success(())) }
                        }
                    }
                }
            }
        } catch {
            try? storage.clear()
            completion(.failure(error))
            return
        }
    }
    #endif

    public func currentSession() throws -> AceIDSession? {
        guard let state = try loadAuthState() else { return nil }
        guard state.isAuthorized else {
            try storage.clear()
            return nil
        }
        return Self.makeSession(from: state)
    }

    /// Returns a valid access token, refreshing through AppAuth when necessary.
    /// The updated OIDAuthState (including rotated refresh tokens) is persisted before success.
    public func validAccessToken(
        leeway: TimeInterval = 60,
        completion: @escaping (Result<String, Error>) -> Void
    ) {
        guard leeway.isFinite, leeway >= 0, leeway <= 600 else {
            completion(.failure(AceIDError.invalidConfiguration("Token leeway must be between 0 and 600 seconds.")))
            return
        }
        do {
            guard let state = try loadAuthState() else {
                completion(.failure(AceIDError.missingSession))
                return
            }
            let previousIDToken = state.lastTokenResponse?.idToken
            if let expiry = state.lastTokenResponse?.accessTokenExpirationDate,
               expiry.timeIntervalSinceNow <= leeway {
                state.setNeedsTokenRefresh()
            }
            state.performAction() { [weak self] accessToken, freshIDToken, error in
                guard let self else { return }
                if let error {
                    if !state.isAuthorized { try? self.storage.clear() }
                    completion(.failure(error))
                    return
                }
                guard let accessToken else {
                    completion(.failure(AceIDError.missingSession))
                    return
                }
                let persistAndComplete: () -> Void = {
                    do {
                        try self.persist(state)
                        completion(.success(accessToken))
                    } catch {
                        completion(.failure(error))
                    }
                }
                if let freshIDToken, freshIDToken != previousIDToken {
                    AceIDIDTokenVerifier.validate(
                        token: freshIDToken,
                        issuer: self.configuration.issuer,
                        clientID: self.configuration.clientID,
                        expectedNonce: nil
                    ) { validation in
                        DispatchQueue.main.async {
                            switch validation {
                            case .failure(let error):
                                try? self.storage.clear()
                                completion(.failure(error))
                            case .success:
                                persistAndComplete()
                            }
                        }
                    }
                } else {
                    persistAndComplete()
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    /// Synchronous cache-only accessor. Use the completion-based overload for automatic refresh.
    public func cachedAccessToken(leeway: TimeInterval = 60) throws -> String {
        guard leeway.isFinite, leeway >= 0, leeway <= 600 else {
            throw AceIDError.invalidConfiguration("Token leeway must be between 0 and 600 seconds.")
        }
        guard let session = try currentSession(),
              session.expirationDate.timeIntervalSinceNow > leeway else {
            throw AceIDError.missingSession
        }
        return session.accessToken
    }

    /// Revokes refresh and access tokens through the provider's advertised RFC 7009 endpoint.
    /// Local state is cleared before network revocation so a failed request cannot restore a local session.
    public func revokeTokens(completion: @escaping (Result<Void, Error>) -> Void) {
        do {
            guard let state = try loadAuthState(),
                  let response = state.lastTokenResponse,
                  response.accessToken != nil else {
                completion(.failure(AceIDError.missingSession))
                return
            }
            let tokens = [
                response.refreshToken.map { ($0, "refresh_token") },
                response.accessToken.map { ($0, "access_token") }
            ].compactMap { $0 }
            discoverRevocationEndpoint { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error):
                    completion(.failure(error))
                case .success(let endpoint):
                    do {
                        // Clear locally before network calls so a killed process cannot retain
                        // tokens after the caller has requested revocation.
                        try self.storage.clear()
                    } catch {
                        completion(.failure(error))
                        return
                    }
                    self.revoke(tokens, at: endpoint, index: 0, completion: completion)
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    /// Clears local session state without contacting the provider.
    public func clearSession() throws {
        try storage.clear()
    }

    private func loadAuthState() throws -> OIDAuthState? {
        guard let data = try storage.read() else { return nil }
        do {
            return try NSKeyedUnarchiver.unarchivedObject(ofClass: OIDAuthState.self, from: data)
        } catch {
            try? storage.clear()
            throw AceIDError.invalidConfiguration("Stored authorization state could not be decoded securely.")
        }
    }

    private func persist(_ state: OIDAuthState) throws {
        let data = try NSKeyedArchiver.archivedData(withRootObject: state, requiringSecureCoding: true)
        try storage.write(data)
    }

    private static func makeSession(from state: OIDAuthState, claims: [String: String]? = nil) -> AceIDSession? {
        guard let response = state.lastTokenResponse,
              let accessToken = response.accessToken,
              let expiry = response.accessTokenExpirationDate else { return nil }
        return AceIDSession(
            accessToken: accessToken,
            refreshToken: response.refreshToken,
            idToken: response.idToken,
            tokenType: response.tokenType ?? "Bearer",
            expirationDate: expiry,
            claims: claims ?? [:]
        )
    }

    private func discoverRevocationEndpoint(completion: @escaping (Result<URL, Error>) -> Void) {
        let issuer = configuration.issuer
        var discoveryURL = issuer
        discoveryURL.appendPathComponent(".well-known")
        discoveryURL.appendPathComponent("openid-configuration")
        var request = URLRequest(
            url: discoveryURL,
            cachePolicy: .reloadIgnoringLocalCacheData,
            timeoutInterval: 10
        )
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        URLSession.shared.dataTask(with: request) { data, response, error in
            let result: Result<URL, Error>
            if let error {
                result = .failure(error)
            } else if let response = response as? HTTPURLResponse,
                      (200...299).contains(response.statusCode),
                      let data, data.count <= 1_000_000,
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let issuerString = json["issuer"] as? String,
                      issuerString == issuer.absoluteString,
                      let endpointString = json["revocation_endpoint"] as? String,
                      let endpoint = URL(string: endpointString),
                      endpoint.host != nil,
                      endpoint.user == nil, endpoint.password == nil, endpoint.fragment == nil,
                      (endpoint.scheme?.lowercased() == "https" || Self.isLoopbackHTTP(endpoint)) {
                result = .success(endpoint)
            } else {
                result = .failure(AceIDError.revocationEndpointUnavailable)
            }
            DispatchQueue.main.async { completion(result) }
        }.resume()
    }

    private func revoke(
        _ tokens: [(String, String)],
        at endpoint: URL,
        index: Int,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard index < tokens.count else { completion(.success(())); return }
        var request = URLRequest(url: endpoint, timeoutInterval: 10)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (token, hint) = tokens[index]
        let fields = [
            "token": token,
            "token_type_hint": hint,
            "client_id": configuration.clientID
        ]
        request.httpBody = fields.map { "\(Self.formEscape($0.key))=\(Self.formEscape($0.value))" }
            .sorted().joined(separator: "&").data(using: .utf8)
        URLSession.shared.dataTask(with: request) { [weak self] _, response, error in
            let result: Result<Void, Error>
            if let error {
                result = .failure(error)
            } else if let response = response as? HTTPURLResponse {
                result = (200...299).contains(response.statusCode)
                    ? .success(())
                    : .failure(AceIDError.httpFailure(response.statusCode))
            } else {
                result = .failure(AceIDError.invalidDiscoveryResponse)
            }
            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case .failure(let error): completion(.failure(error))
                case .success:
                    self.revoke(tokens, at: endpoint, index: index + 1, completion: completion)
                }
            }
        }.resume()
    }

    nonisolated private static func formEscape(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._*")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }

    nonisolated private static func isLoopbackIssuer(_ issuer: URL) -> Bool {
        issuer.scheme?.lowercased() == "http" &&
        ["localhost", "127.0.0.1", "::1"].contains(issuer.host?.lowercased() ?? "")
    }

    nonisolated private static func isLoopbackHTTP(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "http" &&
        ["localhost", "127.0.0.1", "::1"].contains(url.host?.lowercased() ?? "")
    }

}
