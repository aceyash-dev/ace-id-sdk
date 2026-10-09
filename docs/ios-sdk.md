# Ace ID iOS SDK

The native Swift Package uses [AppAuth-iOS](https://github.com/openid/AppAuth-iOS) for OIDC discovery and Authorization Code + PKCE. It targets iOS 15 and newer.

## Add the package

In Xcode, choose **File → Add Package Dependencies** and enter this repository URL. Select the `AceID` product. The package uses Keychain storage by default.

## Configure a client

```swift
import AceID

let configuration = try AceIDConfiguration(
    issuer: URL(string: "https://identity.example.com")!,
    clientID: "your-public-client-id",
    redirectURI: URL(string: "com.example.app:/oauth/callback")!,
    scopes: ["openid", "profile", "email", "offline_access"]
)
let client = AceIDClient(configuration: configuration)
```

Register the exact redirect URI with the identity provider and configure its URL scheme in your application target's URL Types.

## Sign in and refresh

Call `signIn(presenting:completion:)` on the main actor. Forward the incoming redirect URL from the app or scene delegate to `resumeAuthorizationFlow(with:)`. AppAuth generates and validates state and PKCE values.

```swift
client.signIn(presenting: viewController) { result in
    switch result {
    case .success(let session):
        print("Signed in. Token expires at \(session.expirationDate)")
    case .failure(let error):
        print("Sign-in failed: \(error.localizedDescription)")
    }
}

// In the app/scene URL callback:
_ = client.resumeAuthorizationFlow(with: url)

// Get a fresh token. AppAuth refreshes when needed and rotates persisted state.
client.validAccessToken { result in
    // Use the token or handle the authentication error.
}
```

## Logout and revocation

- `signOut(presenting:postLogoutRedirectURI:completion:)` uses the provider's discovered end-session endpoint when available and a registered post-logout redirect URI is supplied. Without that URI, it performs local-only logout. Local state is cleared before the browser flow begins.
- `revokeTokens(completion:)` posts refresh and access tokens to the provider's advertised RFC 7009 revocation endpoint. It fails closed when the endpoint is absent; once revocation is attempted, local state is cleared even if the provider/network reports an error.
- `clearSession()` clears only local state; use it when offline logout is intended.
- The Keychain store uses `WhenUnlockedThisDeviceOnly` and AppAuth's `OIDAuthState` is archived using secure coding, so refresh-token rotation and authorization state survive app restarts.

## Security notes

- Use HTTPS issuers and exact registered callback URIs in production.
- Treat access and refresh tokens as secrets; never log them or store them in `UserDefaults`.
- The SDK verifies RS256 and ES256 ID-token signatures against the issuer's HTTPS JWKS, and checks issuer, audience, authorized party, expiry, issued-at, and the authorization nonce. Unsupported signing algorithms fail closed. Your API must still validate access tokens server-side.
