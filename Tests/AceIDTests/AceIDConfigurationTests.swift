import XCTest
@testable import AceID

final class AceIDConfigurationTests: XCTestCase {
    func testAddsOpenIDScopeAndDeduplicatesScopes() throws {
        let config = try AceIDConfiguration(
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "client",
            redirectURI: URL(string: "com.example.app:/oauth/callback")!,
            scopes: ["email", "profile", "email"]
        )
        XCTAssertEqual(config.scopes, ["openid", "email", "profile"])
    }

    func testRejectsRemoteHTTPIssuer() {
        XCTAssertThrowsError(try AceIDConfiguration(
            issuer: URL(string: "http://identity.example.com")!,
            clientID: "client",
            redirectURI: URL(string: "com.example.app:/oauth/callback")!
        ))
    }

    func testRejectsIssuerCredentialsAndQuery() {
        XCTAssertThrowsError(try AceIDConfiguration(
            issuer: URL(string: "https://user@identity.example.com?x=1")!,
            clientID: "client",
            redirectURI: URL(string: "com.example.app:/oauth/callback")!
        ))
    }

    func testAllowsLocalDevelopmentIssuer() throws {
        _ = try AceIDConfiguration(
            issuer: URL(string: "http://127.0.0.1:8080")!,
            clientID: "client",
            redirectURI: URL(string: "com.example.app:/oauth/callback")!
        )
    }

    func testRejectsRemoteHTTPRedirect() {
        XCTAssertThrowsError(try AceIDConfiguration(
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "client",
            redirectURI: URL(string: "http://app.example.com/callback")!
        ))
    }


    func testRejectsDangerousRedirectSchemes() {
        XCTAssertThrowsError(try AceIDConfiguration(
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "client",
            redirectURI: URL(string: "javascript:alert(1)")!
        ))
        XCTAssertThrowsError(try AceIDConfiguration(
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "client",
            redirectURI: URL(string: "http://attacker.example/callback")!
        ))
    }

    func testRejectsWhitespaceInsideScopeTokens() {
        XCTAssertThrowsError(try AceIDConfiguration(
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "client",
            redirectURI: URL(string: "com.example.app:/oauth/callback")!,
            scopes: ["openid", "email profile"]
        ))
    }


    func testLogoutRedirectMustMatchConfiguredRedirectPolicy() throws {
        let configured = try AceIDConfiguration(
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "client",
            redirectURI: URL(string: "com.example.app:/oauth/callback")!
        )
        XCTAssertTrue(AceIDConfiguration.isAllowedLogoutRedirect(
            configured.redirectURI,
            configuredRedirectURI: configured.redirectURI
        ))
        XCTAssertFalse(AceIDConfiguration.isAllowedLogoutRedirect(
            URL(string: "https://attacker.example/callback")!,
            configuredRedirectURI: configured.redirectURI
        ))
        XCTAssertFalse(AceIDConfiguration.isAllowedLogoutRedirect(
            URL(string: "com.example.app:/oauth/callback#fragment")!,
            configuredRedirectURI: configured.redirectURI
        ))
    }

    func testEmptyClientIDFails() {
        XCTAssertThrowsError(try AceIDConfiguration(
            issuer: URL(string: "https://identity.example.com")!,
            clientID: "  ",
            redirectURI: URL(string: "com.example.app:/oauth/callback")!
        ))
    }
}
