# ace-id-sdk

**Current release: 0.2.2**

Official JavaScript/TypeScript SDK for Ace ID, an OpenID Connect (OIDC) identity provider.

## Install

```bash
npm install ace-id-sdk
```

## Browser usage

```typescript
import { AID } from "ace-id-sdk";

const aid = new AID({
  issuer: "https://identity.ace-base.cc",
  clientId: "my-public-client",
  redirectUri: "https://example.com/callback",
  // Optional. Defaults to 10 seconds for network requests.
  requestTimeoutMs: 10_000,
});

await aid.signIn();

const session = await aid.handleCallback();
console.log(session.user);
```

### Authentication methods

Available methods include `signIn()`, `handleCallback()`, `getSession()`, `isAuthenticated()`, `getUser()`, `getAccessToken()`, `getValidAccessToken()`, `signOut()`, and `refresh()`.

Browser storage defaults to `sessionStorage` through `SessionStorage`. For Node.js or test environments, provide an explicit storage implementation such as `MemoryStorage`.

`requestTimeoutMs` sets the timeout for discovery, token exchange/refresh/revocation, and UserInfo requests. It must be a positive finite number. The default is 10 seconds. The SDK validates OIDC endpoint URLs and does not accept insecure HTTP endpoints except localhost during local development.

Logout `redirectTo` URLs must be absolute HTTPS URLs (HTTP localhost is allowed for development) and share the origin of the configured `redirectUri`. Configure the identity provider's allowed post-logout redirect URIs to match.

## AIDC project configuration

Projects created with AIDC can store their Ace ID configuration in `.aid.json`:

```json
{
  "issuer": "https://identity.ace-base.cc",
  "app_id": "your-app-id",
  "client_id": "your-client-id",
  "redirect_uri": "https://example.com/callback",
  "scopes": ["openid", "profile", "email", "offline_access"],
  "project_type": "web",
  "framework": "Vite",
  "sdk": "ace-id-sdk"
}
```

Use `createAIDFromProjectConfig()` to convert the configuration into an `AID` instance:

```typescript
import { createAIDFromProjectConfig } from "ace-id-sdk";

const aid = createAIDFromProjectConfig(projectConfig);
```

| AIDC configuration | AID configuration |
| --- | --- |
| `issuer` | `AIDConfig.issuer` |
| `client_id` | `AIDConfig.clientId` |
| `redirect_uri` | `AIDConfig.redirectUri` |
| `scopes` | `AIDConfig.scope` |

`app_id` is AIDC project metadata and is not passed to the constructor. The SDK does not read `.aid.json` directly from the filesystem; AIDC owns project configuration and tooling, while the SDK consumes the configuration supplied by the application.

## Server

```typescript
import { AIDServer } from "ace-id-sdk/server";

const aid = new AIDServer({
  issuer: "https://identity.ace-base.cc",
  clientId: process.env.ACE_ID_CLIENT_ID!,
  clientSecret: process.env.ACE_ID_CLIENT_SECRET!,
  requestTimeoutMs: 10_000,
});

const tokens = await aid.exchangeCode(code, redirectUri);
const user = await aid.userInfo(tokens.accessToken);
```

The server entry point is intended for server-side environments only. Do not import `ace-id-sdk/server` into browser bundles, and never expose client secrets in browser applications.

## Vanilla JavaScript

The SDK can be loaded directly in a browser without npm or a bundler:

```html
<script src="https://unpkg.com/ace-id-sdk@0.2.2/dist/ace-id-sdk.global.js"></script>
<script>
  const auth = new AceID.AID({
    issuer: "https://identity.ace-base.cc",
    clientId: "your-client-id",
    redirectUri: "https://your-app.example.com/callback"
  });
</script>
```

The browser bundle exposes the SDK through the global `AceID` object. Available exports include `AID`, storage adapters, PKCE helpers, and SDK error classes.

## React integration

Install React 18 or newer in your application, then import the optional adapter from `ace-id-sdk/react`:

```tsx
import { AID } from 'ace-id-sdk';
import { AuthProvider, useAuth, ProtectedRoute } from 'ace-id-sdk/react';

const client = new AID({ issuer: 'https://identity.ace-base.cc', clientId: 'your-client-id', redirectUri: 'https://app.example.com/callback' });

function Account() {
  const { session, status, signIn } = useAuth();
  if (status === 'loading') return <p>Loading session…</p>;
  if (status !== 'authenticated') return <button onClick={() => void signIn()}>Sign in</button>;
  return <p>Signed in as {session?.user.email}</p>;
}

export function App() {
  return <AuthProvider client={client}><ProtectedRoute fallback={<p>Please sign in.</p>}><Account /></ProtectedRoute></AuthProvider>;
}
```

The React adapter is optional and does not add React to the core SDK runtime. For SSR and cookie-session security guidance, see [framework adapters](docs/framework-adapters.md). The test issuer helper is exported from `ace-id-sdk/testing`; redacted runtime diagnostics are exported from `ace-id-sdk/diagnostics`.

## Android

The repository also contains a native Kotlin Android SDK:

- **Namespace:** `tab.aid.sdk`
- **Minimum Android version:** API 23
- **Compile SDK:** API 36
- **Authentication:** Authorization Code + PKCE (S256)
- **Distribution:** Android Archive (AAR)
- **Core dependency:** Kotlin Coroutines

The Android SDK is authentication/account focused. It does not create clients, applications, programs, or provisioning resources.

### Basic Kotlin

```kotlin
val ace = AceID(
    issuer = "https://id.example.com",
    clientId = BuildConfig.ACE_CLIENT_ID,
    redirectUri = "com.example.app:/oauth/callback"
)

lifecycleScope.launch {
    val session = ace.login(this@MainActivity)
    println(session.user.email)
}
```

### Account and access token

```kotlin
lifecycleScope.launch {
    val account = ace.getAccount(this@MainActivity)
    val token = ace.getValidAccessTokenAsync(this@MainActivity)
}
```

For HTTPS redirect URIs, Android App Links are preferred when the application owns the domain. They require a verified website association through Digital Asset Links. See [the Android SDK guide](docs/android-sdk.md).

### Build the Android AAR

The Android AAR workflow is manually triggered from the repository's GitHub Actions tab. It runs Android tests, builds the AAR, and uploads it as a workflow artifact. GitHub Release creation is a separate opt-in step and requires the repository workflow token to have release-write permission.

## Security

- Authorization Code flow with PKCE using S256; no plain PKCE fallback.
- State validation during authorization callback.
- ID-token verification against provider JWKS.
- ID-token validation of issuer, audience, expiration, subject, and nonce where applicable.
- OIDC discovery issuer and endpoint validation.
- Bounded network requests with configurable timeouts.
- Logout redirect validation to reduce open-redirect risks.
- Never expose client secrets in browser applications.
- Never import `ace-id-sdk/server` into browser bundles.

## Package exports

```typescript
import { AID } from "ace-id-sdk";
import { AIDServer } from "ace-id-sdk/server";
```

The vanilla browser build is available at `dist/ace-id-sdk.global.js`.

## License

MIT
