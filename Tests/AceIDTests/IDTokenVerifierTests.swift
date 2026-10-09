import Foundation
import XCTest
@testable import AceID

final class IDTokenVerifierTests: XCTestCase {
    func testRejectsMalformedTokenWithoutNetworkRequest() {
        let finished = expectation(description: "malformed token rejected")
        AceIDIDTokenVerifier.validate(
            token: "not.a.valid-token",
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "aceid-test-client",
            expectedNonce: "aceid-test-nonce"
        ) { result in
            if case .success = result {
                XCTFail("Malformed token must never be accepted")
            }
            finished.fulfill()
        }
        wait(for: [finished], timeout: 1)
    }

    func testRejectsUnsignedToken() {
        let finished = expectation(description: "unsigned token rejected")
        let header = base64URL(#"{"alg":"none","kid":"none"}"#)
        let payload = base64URL(#"{"iss":"https://identity.example.com","aud":"aceid-test-client","exp":4102444800,"iat":1760000000,"nonce":"aceid-test-nonce"}"#)
        AceIDIDTokenVerifier.validate(
            token: "\(header).\(payload).",
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "aceid-test-client",
            expectedNonce: "aceid-test-nonce"
        ) { result in
            if case .success = result {
                XCTFail("Unsigned token must never be accepted")
            }
            finished.fulfill()
        }
        wait(for: [finished], timeout: 1)
    }

    func testAcceptsValidRS256TokenAndRejectsTampering() {
        let validToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFjZWlkLXRlc3Qta2V5IiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2lkZW50aXR5LmV4YW1wbGUuY29tIiwiYXVkIjoiYWNlaWQtdGVzdC1jbGllbnQiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTc2MDAwMDAwMCwibm9uY2UiOiJhY2VpZC10ZXN0LW5vbmNlIiwic3ViIjoidXNlci0xMjMifQ.MDSGWdEpJ7ZWPlavJJrB081LrzY2YNaPIEG793cwbGUlaPAVLYaQ7jvjuXtYaTj7_trdrjAWf000lVAV9kEXRO8Pwtc5DKvhfj4HBI_5BaaFDnIfxnDtXC6QASVkFrMdzzKdTImEUyGsKrmelkZArxHzuUa0KuhHEr260JhEJTKANZ9CmUfSwBTj_uWOW5OItZ6VjfxIBaOWZ7AiGn8RG9hxOkXL57Fejr9S1Ety2HFKKndAj8WWvEIbMEbH4juPHhn-sAWi0QV6xqj8lpyQUjd3f8LKAHt3tLzGqnf4SW-y5wOGm546wVgFpKvYZ7mNEpPWlNl5ZQysbRmhbf4CGQ"
        let jwks = #"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"aceid-test-key","n":"qmgnEUV8wMfHmIY4wozELZKj4rPnmV_bSd8r_ozg5EqJYpmnTmu2xOFQ1GZgYTyUJn5PGdRm7rNnPFdaf6kyD-HLJGJVjZOJDiq-Zpy87FDEwAIQQD-sfjGPCZNodMkMV8XoS3svM3HosSvT0wQx8k9uv0E3VxAQwMB4lYfDLEfXt1uU5MiwdeYeUN6zyyg7O2Y-twjucCVsx-90Pj5drwkq-Nz1R-e_UXyJh3ldS6ZnEdmq38VA9nJzxvoVO9oeiomq4NrMvZOcmdkmRQXMjw0406vqWsWLMI2f9PeJ8BlyZRSRZKJUGYVGdUs8LvZ9amITp1YL_vlJwgxXIg0mQw","e":"AQAB"}]}"#
        let metadata = #"{"issuer":"https://identity.example.com","jwks_uri":"https://identity.example.com/keys"}"#
        let session = makeSession(metadata: metadata, jwks: jwks)
        let success = expectation(description: "valid token accepted")
        AceIDIDTokenVerifier.validate(
            token: validToken,
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "aceid-test-client",
            expectedNonce: "aceid-test-nonce",
            session: session
        ) { result in
            switch result {
            case .success(let claims):
                XCTAssertEqual(claims["sub"], "user-123")
            case .failure(let error):
                XCTFail("Valid signed token was rejected: \(error)")
            }
            success.fulfill()
        }
        wait(for: [success], timeout: 2)

        let signatureStart = validToken.lastIndex(of: ".")!
        let signatureCharacter = validToken.index(after: signatureStart)
        var tampered = validToken
        tampered.replaceSubrange(
            signatureCharacter...signatureCharacter,
            with: validToken[signatureCharacter] == "A" ? "B" : "A"
        )
        let failure = expectation(description: "tampered token rejected")
        AceIDIDTokenVerifier.validate(
            token: tampered,
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "aceid-test-client",
            expectedNonce: "aceid-test-nonce",
            session: makeSession(metadata: metadata, jwks: jwks)
        ) { result in
            if case .success = result {
                XCTFail("Tampered token signature must not be accepted")
            }
            failure.fulfill()
        }
        wait(for: [failure], timeout: 2)
    }

    private func makeSession(metadata: String, jwks: String) -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        MockURLProtocol.handler = { request in
            let body = request.url?.path == "/keys" ? jwks : metadata
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, Data(body.utf8))
        }
        return URLSession(configuration: configuration)
    }

    private func base64URL(_ value: String) -> String {
        Data(value.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private final class MockURLProtocol: URLProtocol {
    static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        let (response, data) = handler(request)
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
