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

## Sign in and handle callbacks

Call `signIn(presenting:completion:)` from the main actor with a view controller. Forward the incoming redirect URL from the app or scene delegate to `resumeAuthorizationFlow(with:)`. Only AppAuth's active external user-agent session may consume the callback.

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
```

## Session handling

The default Keychain store keeps serialized session data in a generic-password item marked `WhenUnlockedThisDeviceOnly`. `validAccessToken()` returns only a token that remains valid beyond the configured leeway. This starter intentionally fails closed when an access token expires: safe refresh requires retaining AppAuth's `OIDAuthState` rather than reconstructing it from raw strings. `signOut()` clears local session state; provider end-session and remote revocation are not yet implemented.

## Security notes

- Use HTTPS issuers and exact registered callback URIs in production.
- Authorization uses AppAuth's OIDC discovery and PKCE implementation.
- Treat access and refresh tokens as secrets; never log tokens or store them in `UserDefaults`.
- Protect callbacks with a custom URL scheme or verified Universal Link.
