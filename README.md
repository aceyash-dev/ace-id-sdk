# ace-id-sdk
**Current release: 0.2.2**
Official JavaScript/TypeScript SDK for Ace ID, an OpenID Connect (OIDC) identity provider.
## Install
```bash
npm install ace-id-sdk

```
## Browser Usage
```typescript
import { AID } from "ace-id-sdk";

const aid = new AID({
  issuer: "https://identity.ace-base.cc",
  clientId: "my-public-client",
  redirectUri: "https://example.com/callback",
});

await aid.signIn();

const session = await aid.handleCallback();
console.log(session.user);

```
### Authentication Methods
Available methods include:
 * signIn()
 * handleCallback()
 * getSession()
 * isAuthenticated()
 * getUser()
 * getAccessToken()
 * getValidAccessToken()
 * signOut()
 * refresh()
Browser storage defaults to sessionStorage through SessionStorage.
For Node.js or test environments, provide an explicit storage implementation such as MemoryStorage:
```typescript
import { AID, MemoryStorage } from "ace-id-sdk";

const aid = new AID({
  issuer: "https://identity.ace-base.cc",
  clientId: "test-client",
  redirectUri: "http://localhost:3000/callback",
  storage: new MemoryStorage(),
});

```
## AIDC Project Configuration
Projects created with AIDC can store their Ace ID configuration in .aid.json:
```json
{
  "issuer": "https://identity.ace-base.cc",
  "app_id": "your-app-id",
  "client_id": "your-client-id",
  "redirect_uri": "https://example.com/callback",
  "scopes": [
    "openid",
    "profile",
    "email",
    "offline_access"
  ],
  "project_type": "web",
  "framework": "Vite",
  "sdk": "ace-id-sdk"
}

```
The SDK provides createAIDFromProjectConfig() to convert an AIDC project configuration into an AID instance:
```typescript
import { createAIDFromProjectConfig } from "ace-id-sdk";

const aid = createAIDFromProjectConfig(projectConfig);

```
### Configuration Mapping
| AIDC Configuration | AID Configuration |
|---|---|
| issuer | AIDConfig.issuer |
| client_id | AIDConfig.clientId |
| redirect_uri | AIDConfig.redirectUri |
| scopes | AIDConfig.scope |
app_id is AIDC project metadata and is not passed to the AID constructor. The SDK does not read .aid.json directly from the filesystem; AIDC owns project configuration and tooling, while the SDK consumes the configuration supplied by the application.
## Server
```typescript
import { AIDServer } from "ace-id-sdk/server";

const aid = new AIDServer({
  issuer: "https://identity.ace-base.cc",
  clientId: process.env.ACE_ID_CLIENT_ID!,
  clientSecret: process.env.ACE_ID_CLIENT_SECRET!,
});

const tokens = await aid.exchangeCode(code, redirectUri);
const user = await aid.userInfo(tokens.accessToken);

```
The server entry point is intended for server-side environments only. Do not import ace-id-sdk/server into browser bundles.
## Vanilla JavaScript
ace-id-sdk can also be loaded directly in a browser without npm or a bundler:
```html
<script src="https://unpkg.com/ace-id-sdk@0.2.2/dist/ace-id-sdk.global.js"></script>

<script>
  const auth = new AceID.AID({
    issuer: "https://identity.ace-base.cc",
    clientId: "your-client-id",
    redirectUri: "https://your-app.example.com/callback"
  });

  console.log(auth);
</script>

```
The browser bundle exposes the SDK through the global AceID object.
### Available Exports
 * AceID.AID
 * AceID.MemoryStorage
 * AceID.SessionStorage
 * AceID.LocalStorage
 * AceID.createCodeVerifier
 * AceID.createCodeChallenge
 * AceID.AIDError
 * AceID.AIDDiscoveryError
 * AceID.AIDCallbackError
 * AceID.AIDTokenError
 * AceID.AIDAuthenticationError
## Android
The repository contains a native Kotlin Android SDK under android/.
The Android SDK is part of the 0.2.2 release line:
 * **Namespace:** tab.aid.sdk
 * **Minimum Android version:** API 23
 * **Compile SDK:** API 36
 * **Authentication:** Authorization Code + PKCE (S256)
 * **Distribution:** Android Archive (AAR)
 * **Core dependency:** Kotlin Coroutines
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
### Callback-Based Integration
```kotlin
ace.login(this) { session ->
    
}

```
### Account and Access Token
```kotlin
lifecycleScope.launch {
    val account = ace.getAccount(this@MainActivity)
    val token = ace.getValidAccessTokenAsync(this@MainActivity)
}

```
### API Calls
```kotlin
lifecycleScope.launch {
    ace.withAccessToken(this@MainActivity) { token ->
        
    }
}

```
### Compose / State Integration
State integration is headless and requires no Compose dependency:
```kotlin
val account by ace.account.collectAsState()
val sessionState by ace.sessionState.collectAsState()

```
### Smart Defaults
 * Memory and encrypted-disk discovery caching scoped by issuer and client ID.
 * Short-lived encrypted account caching.
 * Automatic token refresh with refresh-token rotation support.
 * Single-flight refresh for concurrent coroutine callers.
 * Normalized account fields: subject, email, name, picture, and username.
 * Raw OIDC claims through the account model.
 * Configuration diagnostics through validateConfiguration().
 * Existing synchronous APIs for compatibility.
For HTTPS redirect URIs, Android App Links are preferred when the application owns the domain. They require a verified website association through Digital Asset Links.
### Build the Android AAR
The Android AAR workflow is manually triggered from the repository's GitHub Actions tab:
 * Use the release_tag input (defaults to v0.2.2) to name the artifact.
 * The Android release workflow does not require a Git tag to trigger an AAR build; it is intentionally manual-only.
 * A successful build uploads the AAR as a workflow artifact. GitHub Release creation is an explicit opt-in input because repository token permissions may restrict release writes.
## Security
 * Authorization Code flow with PKCE using S256.
 * No plain PKCE fallback.
 * state validation during the authorization callback.
 * ID-token verification against the provider JWKS.
 * ID-token validation covering issuer, audience, expiration, subject, and nonce where applicable.
 * OIDC discovery through /.well-known/openid-configuration.
 * Validation of the discovered issuer against the configured issuer.
 * Never expose client secrets in browser applications.
 * Never import ace-id-sdk/server into browser bundles.
## Package Exports
```typescript
import { AID } from "ace-id-sdk";
import { AIDServer } from "ace-id-sdk/server";

```
The vanilla browser build is available at:
```text
dist/ace-id-sdk.global.js

```
## License
MIT
