import XCTest
@testable import AceID

final class IDTokenVerifierTests: XCTestCase {
    func testRejectsMalformedTokenWithoutNetworkRequest() {
        let finished = expectation(description: "malformed token rejected")
        AceIDIDTokenVerifier.validate(
            token: "not.a.valid-token",
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "client",
            expectedNonce: "nonce"
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
        let header = Data("{\"alg\":\"none\",\"kid\":\"none\"}".utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let payload = Data("{\"iss\":\"https://identity.example.com\",\"aud\":\"client\",\"exp\":4102444800,\"iat\":1,\"nonce\":\"nonce\"}".utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        AceIDIDTokenVerifier.validate(
            token: "\(header).\(payload).",
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "client",
            expectedNonce: "nonce"
        ) { result in
            if case .success = result {
                XCTFail("Unsigned token must never be accepted")
            }
            finished.fulfill()
        }
        wait(for: [finished], timeout: 1)
    }
}
