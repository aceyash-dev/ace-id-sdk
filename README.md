# ace-id-sdk

Official JavaScript/TypeScript SDK for Ace ID, an OpenID Connect identity provider.

## Install

```sh
npm install ace-id-sdk
```

## Browser

```ts
import { AID } from "ace-id-sdk";

const aid = new AID({
  issuer: "https://identity.ace-base.cc",
  clientId: "my-public-client",
  redirectUri: "https://example.com/callback",
});

// Step 1: redirect the user
await aid.signIn();

// Step 2: handle the redirect
const session = await aid.handleCallback();

console.log(session.user);
```

Available methods include:

- `signIn()`
- `handleCallback()`
- `getSession()`
- `isAuthenticated()`
- `getUser()`
- `getAccessToken()`
- `getValidAccessToken()`
- `signOut()`

Storage defaults to `sessionStorage`. Use `MemoryStorage` only in tests or fully controlled environments.

## Server

```ts
import { AIDServer } from "ace-id-sdk/server";

const aid = new AIDServer({
  issuer: "https://identity.ace-base.cc",
  clientId: process.env.ACE_ID_CLIENT_ID!,
  clientSecret: process.env.ACE_ID_CLIENT_SECRET!,
});

const tokens = await aid.exchangeCode(code, redirectUri);
const user = await aid.userInfo(tokens.accessToken);
```

## Vanilla JavaScript

`ace-id-sdk` can also be loaded directly in a browser without npm or a bundler.

```html
<script src="https://unpkg.com/ace-id-sdk@0.2.0/dist/ace-id-sdk.global.js"></script>
<script>
  const auth = new AceID.AID({
    issuer: "https://your-issuer.example.com",
    clientId: "your-client-id",
    redirectUri: "https://your-app.example.com/callback"
  });

  console.log(auth);
</script>
```

The browser bundle exposes the SDK through the global `AceID` object.

Available exports include:

- `AceID.AID`
- `AceID.MemoryStorage`
- `AceID.SessionStorage`
- `AceID.LocalStorage`
- `AceID.createCodeVerifier`
- `AceID.createCodeChallenge`
- `AceID.AIDError`
- `AceID.AIDDiscoveryError`
- `AceID.AIDCallbackError`
- `AceID.AIDTokenError`
- `AceID.AIDAuthenticationError`

## Android

The repository also contains a native Kotlin Android SDK under `android/`.

- Namespace: `tab.aid.sdk`
- Minimum Android version: API 23
- Compile SDK: API 36
- Authentication: Authorization Code + PKCE (S256)
- Distribution: Android Archive (AAR)

The Android workflow is manually triggered from the GitHub Actions tab.

## Security notes

- PKCE S256 only. No plain fallback.
- ID tokens are verified against the provider JWKS (`iss`, `aud`, `exp`, `sub`, and `nonce` where applicable).
- Never import `ace-id-sdk/server` in browser bundles.
- Endpoints are discovered from `{issuer}/.well-known/openid-configuration`.
- The discovered issuer is validated against the configured issuer.

## License

MIT
