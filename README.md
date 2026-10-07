# ace-id-sdk

**Current release: 0.2.1**

Official JavaScript/TypeScript SDK for Ace ID, an OpenID Connect (OIDC) identity provider.

Install

npm install ace-id-sdk

Browser

import { AID } from "ace-id-sdk";

const aid = new AID({
  issuer: "https://identity.ace-base.cc",
  clientId: "my-public-client",
  redirectUri: "https://example.com/callback",
});

// Start authentication
await aid.signIn();

// Handle the authorization callback
const session = await aid.handleCallback();

console.log(session.user);

Authentication methods

Available methods include:

- "signIn()"
- "handleCallback()"
- "getSession()"
- "isAuthenticated()"
- "getUser()"
- "getAccessToken()"
- "getValidAccessToken()"
- "signOut()"
- "refresh()"

Browser storage defaults to "sessionStorage" through "SessionStorage".

For Node.js or test environments, provide an explicit storage implementation such as "MemoryStorage".

import { AID, MemoryStorage } from "ace-id-sdk";

const aid = new AID({
  issuer: "https://identity.ace-base.cc",
  clientId: "test-client",
  redirectUri: "http://localhost:3000/callback",
  storage: new MemoryStorage(),
});

AIDC Project Configuration

Projects created with AIDC can store their Ace ID configuration in ".aid.json".

Example:

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

The SDK provides "createAIDFromProjectConfig()" to convert an AIDC project configuration into an "AID" instance.

import {
  createAIDFromProjectConfig,
} from "ace-id-sdk";

const aid = createAIDFromProjectConfig(projectConfig);

The adapter maps:

- "issuer" → "AIDConfig.issuer"
- "client_id" → "AIDConfig.clientId"
- "redirect_uri" → "AIDConfig.redirectUri"
- "scopes" → "AIDConfig.scope"

"app_id" is AIDC project metadata and is not passed to the "AID" constructor.

The SDK does not read ".aid.json" from the filesystem. AIDC owns project configuration and tooling, while the SDK consumes the configuration supplied by the application.

Server

import { AIDServer } from "ace-id-sdk/server";

const aid = new AIDServer({
  issuer: "https://identity.ace-base.cc",
  clientId: process.env.ACE_ID_CLIENT_ID!,
  clientSecret: process.env.ACE_ID_CLIENT_SECRET!,
});

const tokens = await aid.exchangeCode(code, redirectUri);
const user = await aid.userInfo(tokens.accessToken);

The server entry point is intended for server-side environments only.

Do not import "ace-id-sdk/server" into browser bundles.

Vanilla JavaScript

"ace-id-sdk" can also be loaded directly in a browser without npm or a bundler.

<script src="https://unpkg.com/ace-id-sdk@0.2.1/dist/ace-id-sdk.global.js"></script>

<script>
  const auth = new AceID.AID({
    issuer: "https://identity.ace-base.cc",
    clientId: "your-client-id",
    redirectUri: "https://your-app.example.com/callback"
  });

  console.log(auth);
</script>

The browser bundle exposes the SDK through the global "AceID" object.

Available exports include:

- "AceID.AID"
- "AceID.MemoryStorage"
- "AceID.SessionStorage"
- "AceID.LocalStorage"
- "AceID.createCodeVerifier"
- "AceID.createCodeChallenge"
- "AceID.AIDError"
- "AceID.AIDDiscoveryError"
- "AceID.AIDCallbackError"
- "AceID.AIDTokenError"
- "AceID.AIDAuthenticationError"

Android

The repository also contains a native Kotlin Android SDK under "android/". The Android SDK is part of the 0.2.1 release line.

- Namespace: "tab.aid.sdk"
- Minimum Android version: API 23
- Compile SDK: API 36
- Authentication: Authorization Code + PKCE (S256)
- Distribution: Android Archive (AAR)
- Core dependency: Kotlin coroutines

The Android SDK is authentication/account focused. It does not create clients, applications, programs, or provisioning resources.

Basic Kotlin:

val ace = AceID(
    issuer = "https://id.example.com",
    clientId = BuildConfig.ACE_CLIENT_ID,
    redirectUri = "com.example.app:/oauth/callback"
)

lifecycleScope.launch {
    val session = ace.login(this@MainActivity)
    println(session.user.email)
}

For callback-based integrations:

ace.login(this) { session ->
    // Authentication has started; route the callback URI to
    // ace.handleCallbackAsync(...) when your redirect Activity receives it.
}

lifecycleScope.launch {
    val account = ace.getAccount(this@MainActivity)
    val token = ace.getValidAccessTokenAsync(this@MainActivity)
}

For API calls:

lifecycleScope.launch {
    ace.withAccessToken(this@MainActivity) { token ->
        // call your API with the valid token
    }
}

Compose/state integration is headless and requires no Compose dependency:

val account by ace.account.collectAsState()
val sessionState by ace.sessionState.collectAsState()

Smart defaults include:

- Memory + encrypted disk discovery caching, scoped by issuer and client ID.
- Short-lived encrypted account caching.
- Automatic token refresh with refresh-token rotation support.
- Single-flight refresh for concurrent coroutine callers.
- Normalized account fields: subject, email, name, picture, username, plus raw claims.
- Configuration diagnostics through validateConfiguration().
- Existing synchronous APIs remain available for compatibility.

For HTTPS redirect URIs, Android App Links are preferred when the app owns the domain. They require a verified website association through Digital Asset Links.

Build the Android AAR

The Android AAR workflow is manually triggered from the repository's GitHub Actions tab. Use the `release_tag` input (default `v0.2.1`) to name the artifact.

The Android release workflow does not require a Git tag to trigger an AAR build. The workflow is intentionally manual-only. A successful build uploads the AAR as a workflow artifact; GitHub Release creation is an explicit opt-in input because repository token permissions may restrict release writes.

Security

- Authorization Code flow with PKCE S256.
- No plain PKCE fallback.
- "state" is validated during the authorization callback.
- ID tokens are verified against the provider JWKS.
- ID-token validation covers the configured issuer, audience, expiration, subject, and nonce where applicable.
- OIDC endpoints are discovered from:
  "/.well-known/openid-configuration"
- The discovered issuer is validated against the configured issuer.
- Never expose client secrets in browser applications.
- Never import "ace-id-sdk/server" into browser bundles.

Package exports

The package provides separate browser/server entry points:

import { AID } from "ace-id-sdk";

import { AIDServer } from "ace-id-sdk/server";

The vanilla browser build is available as:

dist/ace-id-sdk.global.js

License

MIT