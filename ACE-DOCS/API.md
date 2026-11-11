# JavaScript / TypeScript API

`ace-id-sdk` implements OpenID Connect Authorization Code with PKCE for browsers
and Node. Everything below is exported from the package root unless a subpath is
named.

```ts
import { AID } from 'ace-id-sdk';

const aid = new AID({
  issuer: 'https://id.ace-base.cc',
  clientId: 'your-public-client-id',
  redirectUri: 'https://app.example.com/auth/callback',
});
```

## Contents

- [Configuration](#configuration)
- [Signing in](#signing-in)
- [Session and tokens](#session-and-tokens)
- [Session state](#session-state)
- [Profile](#profile)
- [Signing out](#signing-out)
- [Errors](#errors)
- [Configuration diagnostics](#configuration-diagnostics)
- [Logging](#logging)
- [Low-level helpers](#low-level-helpers)

## Configuration

| Option | Default | Purpose |
| --- | --- | --- |
| `issuer` | required | OIDC issuer URL. HTTPS, no query or fragment. |
| `clientId` | required | Public client identifier. |
| `redirectUri` | required | Registered callback. HTTPS, or HTTP on localhost. |
| `scope` | `openid profile email` | Space-delimited scopes. |
| `storage` | `SessionStorage` | `get`/`set`/`remove` store. Use `LocalStorage` for persistence across tabs. |
| `transactionTtlMs` | 10 minutes | Lifetime of an in-flight authorization transaction. |
| `requestTimeoutMs` | 10 s | Per-attempt network timeout. |
| `discoveryCacheTtlMs` | 5 minutes | Reuse window for the discovery document; `0` disables caching. |
| `autoRefresh` | `false` | Refresh shortly before expiry. |
| `leewaySeconds` | `60` | "Expiring soon" window for refresh and state. |
| `clockSkewSeconds` | `60` | Tolerance applied to `exp`/`iat`/`auth_time`/`nbf`. |
| `maxRetries` | `2` | Extra attempts for retry-safe requests; `0` disables. |
| `unknownExpiryRefreshIntervalMs` | 60 s | Throttle for providers that omit `expires_in`. |
| `debug` / `logger` | off | See [Logging](#logging). |
| `additionalRedirectOrigins` | `[]` | Extra origins a `returnTo` may use. |
| `allowedSigningAlgorithms` | asymmetric allowlist | Narrow the accepted ID token algorithms. |
| `storageKeyPrefix` | `aid` | Keys become `aid:session` and `aid:transaction`. |

An invalid configuration throws one `AIDError` listing **every** failing check.

## Signing in

```ts
await aid.signIn({ returnTo: '/dashboard', prompt: 'login', maxAge: 0 });
```

`signIn` stores the PKCE verifier, `state` and `nonce`, then navigates to the
authorization endpoint. `returnTo` must share the redirect URI's origin; anything
else throws before navigation, so a tampered link cannot become an open redirect.

On the callback page:

```ts
const result = await aid.handleCallback();          // reads window.location
const result = await aid.handleCallback(url);       // or an explicit URL

if (result.returnTo) router.replace(result.returnTo);
```

`handleCallback` refuses, in order: a URL on another origin, a URL on another
path, credentials in the URL, duplicate `code`/`state`/`error` parameters, an
embedded `redirect_uri`, a missing or expired transaction, a `state` mismatch, a
transaction whose `redirectUri` no longer matches this client, and an ID token
that fails verification (signature, issuer, audience, algorithm, `exp`, `iat`,
`auth_time`, `azp`, `nonce`).

## Session and tokens

```ts
aid.getSession();          // AIDSession | null
aid.currentSession();      // alias
aid.isAuthenticated();     // true while the access token is unexpired
aid.getUser();             // AIDUser | null
aid.getAccessToken();      // string | null, never triggers a request
await aid.getValidAccessToken(); // refreshes when needed, then returns the token
await aid.refreshSession();      // forces a refresh; concurrent calls share one request
```

`getValidAccessToken()` refreshes inside the leeway window and returns `null` when
there is no session or no refresh token. Concurrent callers share a single
in-flight refresh, which matters with rotating refresh tokens: a second
concurrent refresh would invalidate the first result.

### Automatic refresh

```ts
const aid = new AID({ ...config, autoRefresh: true });
// or
aid.startAutoRefresh();
aid.stopAutoRefresh();
```

The timer fires `leewaySeconds` before expiry. A failed automatic refresh emits
`refresh-failed` and stops the timer rather than looping against a provider that
is refusing the token.

## Session state

```ts
type AIDSessionState =
  | { status: 'authenticated'; session: AIDSession; expiryUnknown: boolean }
  | { status: 'unauthenticated' }
  | { status: 'expired'; session: AIDSession }
  | { status: 'refresh-failed'; error: Error; session?: AIDSession };

const unsubscribe = aid.onAuthStateChange((state) => {
  // called once immediately, then on every real change
});
```

`expired` means "a session exists but the access token is expired or about to
be". `refresh-failed` keeps the stored session unless the provider rejected the
refresh token with `invalid_grant`.

## Profile

```ts
const user = await aid.fetchUserProfile();                       // UserInfo request
const cached = await aid.fetchUserProfile({ useCachedSession: true });
```

The response `sub` must equal the session subject; a mismatch is an
`AIDAuthenticationError`, not a profile update. The refreshed claims are written
back to the session, so `getUser()` reflects them.

## Signing out

```ts
await aid.signOut();                              // local state, then provider logout if advertised
await aid.signOut({ redirectTo: '/goodbye' });    // same-origin only
await aid.logout();                               // alias
```

The local session and transaction are cleared first, so logout never depends on
the network. A refresh in flight cannot resurrect the session afterwards.
Revocation is attempted for the refresh token when the provider advertises a
`revocation_endpoint`.

## Errors

```ts
import { AIDError, aidErrorCode, isRetryableError } from 'ace-id-sdk';

try {
  await aid.handleCallback();
} catch (error) {
  console.log(aidErrorCode(error));   // 'CALLBACK_ERROR' | 'TOKEN_ERROR' | ...
  if (isRetryableError(error)) retry();
}
```

See [ERRORS.md](./ERRORS.md) for the full table. Every error carries `code`,
`retryable` and optional non-secret `details`.

## Configuration diagnostics

```ts
import { validateAIDConfig } from 'ace-id-sdk';

const offline = validateAIDConfig(config);          // no network
const live = await aid.validateConfiguration();     // adds issuer capability checks

for (const check of live.checks) {
  console.log(check.status, check.name, check.message);
}
```

`validateConfiguration()` never throws: a failing check is a `fail` entry, so it
can be rendered in a setup screen.

## Logging

```ts
const aid = new AID({
  ...config,
  logger: (entry) => myTelemetry.debug(entry.event, entry.message, entry.context),
});
```

Entries are `{ level, event, message, context, timestamp }`. `context` is
redacted: keys matching `token`, `secret`, `code`, `nonce`, `authorization`,
`password`, `cookie`, `state` and JWT-shaped strings are replaced with
`[redacted]`. `debug: true` also prints to the console. Without either, the SDK
logs nothing.

## Low-level helpers

```ts
import {
  deriveSessionState, createLogger, redact, redactUrl,
  DiscoveryCache, clearJwksCache, jwksCacheSize,
  isRetryableStatus, retryAfterMs, DEFAULT_RETRY_POLICY,
  shouldRefreshToken, isTokenExpired, hasKnownExpiry,
  createCodeVerifier, createCodeChallenge,
  MemoryStorage, SessionStorage, LocalStorage,
} from 'ace-id-sdk';
```

Subpaths: `ace-id-sdk/server`, `ace-id-sdk/react`, `ace-id-sdk/diagnostics`,
`ace-id-sdk/testing`. Each is independently tree-shakeable and has its own size
budget enforced in CI.
