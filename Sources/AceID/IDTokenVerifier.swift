import Foundation
import Security

/// Verifies OIDC ID-token signatures and required claims using the issuer's JWKS.
enum AceIDIDTokenVerifier {
    static func validate(
        token: String,
        issuer: URL,
        clientID: String,
        expectedNonce: String?,
        session: URLSession = .shared,
        completion: @escaping (Result<[String: String], Error>) -> Void
    ) {
        // Bound untrusted JWT input before splitting or decoding to avoid excessive allocation.
        guard token.utf8.count <= 131_072 else {
            completion(.failure(AceIDError.invalidIDToken("ID token exceeds the supported size limit.")))
            return
        }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let headerData = decodeBase64URL(String(parts[0])),
              let claimsData = decodeBase64URL(String(parts[1])),
              let signature = decodeBase64URL(String(parts[2])),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              let claims = try? JSONSerialization.jsonObject(with: claimsData) as? [String: Any],
              let algorithm = header["alg"] as? String,
              header["crit"] == nil,
              (header["kid"] as? String).map({ !$0.isEmpty }) ?? true,
              ["RS256", "ES256"].contains(algorithm) else {
            completion(.failure(AceIDError.invalidIDToken("Malformed or unsupported ID token.")))
            return
        }

        guard validateClaims(
            claims,
            issuer: issuer,
            clientID: clientID,
            expectedNonce: expectedNonce
        ) else {
            completion(.failure(AceIDError.invalidIDToken("ID token claims did not match the expected issuer, audience, time, or nonce.")))
            return
        }

        var discoveryURL = issuer
        discoveryURL.appendPathComponent(".well-known")
        discoveryURL.appendPathComponent("openid-configuration")
        var discoveryRequest = URLRequest(
            url: discoveryURL,
            cachePolicy: .reloadIgnoringLocalCacheData,
            timeoutInterval: 10
        )
        discoveryRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        session.dataTask(with: discoveryRequest) { data, response, error in
            if let error {
                completion(.failure(error))
                return
            }
            guard let response = response as? HTTPURLResponse,
                  (200...299).contains(response.statusCode),
                  let data, data.count <= 1_000_000,
                  let metadata = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let metadataIssuer = metadata["issuer"] as? String,
                  metadataIssuer == issuer.absoluteString,
                  let jwksString = metadata["jwks_uri"] as? String,
                  let jwksURL = URL(string: jwksString),
                  jwksURL.user == nil, jwksURL.password == nil, jwksURL.fragment == nil,
                  jwksURL.scheme?.lowercased() == "https" ||
                    (isLoopbackIssuer(issuer) && isLoopbackHTTP(jwksURL)) else {
                completion(.failure(AceIDError.invalidDiscoveryResponse))
                return
            }

            var jwksRequest = URLRequest(
                url: jwksURL,
                cachePolicy: .reloadIgnoringLocalCacheData,
                timeoutInterval: 10
            )
            jwksRequest.setValue("application/json", forHTTPHeaderField: "Accept")
            session.dataTask(with: jwksRequest) { keyData, keyResponse, keyError in
                if let keyError {
                    completion(.failure(keyError))
                    return
                }
                guard let keyResponse = keyResponse as? HTTPURLResponse,
                      (200...299).contains(keyResponse.statusCode),
                      let keyData, keyData.count <= 1_000_000,
                      let jwks = try? JSONSerialization.jsonObject(with: keyData) as? [String: Any],
                      let keys = jwks["keys"] as? [[String: Any]] else {
                    completion(.failure(AceIDError.invalidDiscoveryResponse))
                    return
                }
                let keyID = header["kid"] as? String
                let matchingKeys = keys.filter { key in
                    (keyID == nil || (key["kid"] as? String) == keyID) &&
                    ((key["use"] as? String).map { $0 == "sig" } ?? true) &&
                    ((key["alg"] as? String).map { $0 == algorithm } ?? true) &&
                    ((key["key_ops"] as? [String]).map { $0.contains("verify") } ?? true)
                }
                guard matchingKeys.count == 1, let jwk = matchingKeys.first else {
                    completion(.failure(AceIDError.invalidIDToken("No unique matching signing key was found in the issuer JWKS.")))
                    return
                }

                let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
                guard verify(
                    signingInput: signingInput,
                    signature: signature,
                    algorithm: algorithm,
                    jwk: jwk
                ) else {
                    completion(.failure(AceIDError.invalidIDToken("ID token signature verification failed.")))
                    return
                }
                completion(.success(stringClaims(claims)))
            }.resume()
        }.resume()
    }

    private static func validateClaims(
        _ claims: [String: Any],
        issuer: URL,
        clientID: String,
        expectedNonce: String?
    ) -> Bool {
        guard let tokenIssuer = claims["iss"] as? String,
              let subject = claims["sub"] as? String, !subject.isEmpty,
              tokenIssuer == issuer.absoluteString,
              let expiration = (claims["exp"] as? NSNumber)?.doubleValue,
              expiration > Date().timeIntervalSince1970 - 60,
              let issuedAt = (claims["iat"] as? NSNumber)?.doubleValue,
              issuedAt <= Date().timeIntervalSince1970 + 300 else {
            return false
        }

        let audiences: [String]
        if let audience = claims["aud"] as? String {
            audiences = [audience]
        } else if let values = claims["aud"] as? [String] {
            audiences = values
        } else {
            return false
        }
        guard audiences.contains(clientID) else { return false }
        if audiences.count > 1, (claims["azp"] as? String) != clientID { return false }
        if let authorizedParty = claims["azp"] as? String, authorizedParty != clientID { return false }
        if let notBefore = (claims["nbf"] as? NSNumber)?.doubleValue,
           notBefore > Date().timeIntervalSince1970 + 60 { return false }
        if let expectedNonce, (claims["nonce"] as? String) != expectedNonce { return false }
        return true
    }

    private static func verify(
        signingInput: Data,
        signature: Data,
        algorithm: String,
        jwk: [String: Any]
    ) -> Bool {
        var error: Unmanaged<CFError>?
        let keyData: Data
        let attributes: [String: Any]
        let secAlgorithm: SecKeyAlgorithm
        let signatureData: Data

        switch algorithm {
        case "RS256":
            guard (jwk["kty"] as? String) == "RSA",
                  let modulus = jwk["n"] as? String,
                  let exponent = jwk["e"] as? String,
                  let n = decodeBase64URL(modulus),
                  let e = decodeBase64URL(exponent),
                  n.count >= 256, e.count <= 8 else { return false }
            keyData = rsaPublicKeyDER(modulus: n, exponent: e)
            attributes = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: n.count * 8
            ]
            secAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
            signatureData = signature
        case "ES256":
            guard (jwk["kty"] as? String) == "EC",
                  (jwk["crv"] as? String) == "P-256",
                  let x = jwk["x"] as? String,
                  let y = jwk["y"] as? String,
                  let xData = decodeBase64URL(x),
                  let yData = decodeBase64URL(y),
                  xData.count == 32, yData.count == 32,
                  let der = ecdsaDERSignature(signature) else { return false }
            keyData = Data([0x04]) + xData + yData
            attributes = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: 256
            ]
            secAlgorithm = .ecdsaSignatureMessageX962SHA256
            signatureData = der
        default:
            return false
        }

        guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error),
              SecKeyIsAlgorithmSupported(key, .verify, secAlgorithm) else {
            return false
        }
        return SecKeyVerifySignature(key, secAlgorithm, signingInput as CFData, signatureData as CFData, &error)
    }

    /// Security.framework expects the PKCS#1 RSAPublicKey DER representation for RSA keys.
    private static func rsaPublicKeyDER(modulus: Data, exponent: Data) -> Data {
        Data(derSequence(derInteger(modulus) + derInteger(exponent)))
    }

    private static func ecdsaDERSignature(_ signature: Data) -> Data? {
        let bytes = Array(signature)
        guard bytes.count == 64 else { return nil }
        func integer(_ part: ArraySlice<UInt8>) -> [UInt8] {
            var value = Array(part)
            while value.count > 1 && value.first == 0 { value.removeFirst() }
            if let first = value.first, first & 0x80 != 0 { value.insert(0, at: 0) }
            return [0x02] + derLength(value.count) + value
        }
        let body = integer(bytes[0..<32]) + integer(bytes[32..<64])
        return Data([0x30] + derLength(body.count) + body)
    }

    private static func derSequence(_ body: [UInt8]) -> [UInt8] {
        [0x30] + derLength(body.count) + body
    }

    private static func derInteger(_ data: Data) -> [UInt8] {
        var value = Array(data)
        while value.count > 1 && value.first == 0 { value.removeFirst() }
        if let first = value.first, first & 0x80 != 0 { value.insert(0, at: 0) }
        return [0x02] + derLength(value.count) + value
    }

    private static func derLength(_ length: Int) -> [UInt8] {
        if length < 128 { return [UInt8(length)] }
        var value = length
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)
    }

    private static func isLoopbackIssuer(_ issuer: URL) -> Bool {
        issuer.scheme?.lowercased() == "http" &&
        ["localhost", "127.0.0.1", "::1"].contains(issuer.host?.lowercased() ?? "")
    }

    private static func isLoopbackHTTP(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "http" &&
        ["localhost", "127.0.0.1", "::1"].contains(url.host?.lowercased() ?? "")
    }

    private static func stringClaims(_ claims: [String: Any]) -> [String: String] {
        claims.compactMapValues { value in
            if let string = value as? String { return string }
            if let number = value as? NSNumber { return number.stringValue }
            return nil
        }
    }
}
