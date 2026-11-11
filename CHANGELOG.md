# Changelog

All notable changes to the Ace ID SDK are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.4] — Reliability, session lifecycle and Android integration

This release is about making existing authentication flows dependable: correct
OIDC validation, an explicit session lifecycle, safe network behaviour and a
developer-facing API that is the same on every platform. No existing method was
removed and no default behaviour was made stricter in a way that breaks a
correctly configured client.

### Added — JavaScript / TypeScript

- **Explicit session states.** `getAuthState()` returns one of `authenticated`,
  `unauthenticated`, `expired` or `refresh-failed`, and `onAuthStateChange()`
  streams changes. `deriveSessionState()` is exported for hosts that keep their
  own store.
- **Session API parity.** `currentSession()`, `refreshSession()`, `logout()` and
  `getAccessToken()` join the existing `getSession()`/`refresh()`/`signOut()`.
- **Automatic token refresh.** `autoRefresh: true` (or `startAutoRefresh()`)
  refreshes shortly before expiry; `stopAutoRefresh()` cancels the timer. Off by
  default, because a timer is a side effect a server or test process should opt
  into.
- **Profile API.** `fetchUserProfile()` calls UserInfo, verifies that `sub`
  matches the session, and persists the refreshed claims. `fetchUserProfile({ useCachedSession: true })`
  returns the claims already held.
- **Configuration diagnostics.** `validateAIDConfig()` checks a configuration
  offline; `AID#validateConfiguration()` adds live capability checks against the
  issuer (PKCE, JWKS, signing algorithms, refresh grant, UserInfo, logout).
- **Redacting logger.** `debug: true` or a `logger` sink receives structured
  entries with tokens, codes, secrets, nonces and JWT-shaped strings masked.
- **Discovery caching.** Fetched discovery documents are cached per client for
  `discoveryCacheTtlMs` (default 5 minutes) with issuer isolation and
  single-flight misses. `clearDiscoveryCache()` forces a refetch.
- **Network resilience.** Retries with exponential backoff and jitter for
  retry-safe requests only, `Retry-After` support, and cancellation through
  `AbortSignal`.
- **Stricter callback validation.** The authorization response must arrive on the
  registered origin *and* path; duplicated `code`/`state`/`error` parameters, an
  embedded `redirect_uri`, and a transaction whose `redirectUri` was rewritten
  are all refused before any code is exchanged.
- **Signing-algorithm allowlist.** Only asymmetric algorithms are accepted, and
  provider metadata can narrow the allowlist but never widen it.
- **New error codes.** `NETWORK_ERROR`, `SESSION_ERROR`, `PROFILE_ERROR` and
  `STORAGE_ERROR` join the existing codes, each with a `retryable` flag and
  `aidErrorCode()`/`isRetryableError()` helpers.
- **Server helpers.** `createAuthHandlers()` provides Web-Fetch-compatible
  `signIn`/`callback`/`session`/`refresh`/`signOut` handlers that work in Next.js
  route handlers, Remix, Hono and Workers, with AES-GCM sealed session cookies.
  `getServerSession()` reads a session without rendering a response.
- **React.** `AceIDProvider`, `useAceID()`, `useAceIDSession()` and
  `useAceIDActions()`; the provider subscribes to the client's state stream so a
  sign-out anywhere is reflected everywhere.
- **Testing utilities.** `createMockOIDCIssuer()` gains `setUser()` and a
  `userInfo` failure switch.
- **Build gates.** `npm run check:bundle` enforces gzipped size budgets per entry
  point and `npm run verify:package` imports every export subpath, checks
  declarations exist and refuses a tarball containing sources.

### Added — Android

- `AidNetworkPolicy` — configurable connect/read timeouts and a retry budget,
  applied to discovery, JWKS, UserInfo and token calls. Retries are limited to
  idempotent requests; code exchanges and refreshes are never retried.
- `AidHttp` — one HTTP path for every call, so timeouts, redirect policy and
  response-size limits cannot drift between endpoints.
- `AidSessionState.RefreshFailed` — distinguishes a failed refresh from an
  expired or absent session.
- `currentSession()`, `refreshSession()`, `logout()`, `getProfile()` and
  `hasPendingAuthorization()` for cross-platform API parity.
- `unlockSession()` and `AidBiometricUnlock` — an optional biometric gate for a
  locally stored session, using the platform `BiometricPrompt` (API 28+) with no
  new dependency. It never replaces provider-side authentication or MFA.

### Changed

- Discovery documents are cached per client instance by default (5 minutes
  instead of one fetch per flow).
- ID token verification applies a signing-algorithm allowlist and the configured
  clock-skew tolerance everywhere, including refresh responses.
- The SDK is silent unless a logger is supplied or `debug` is enabled.

### Fixed

- A rewritten authorization transaction can no longer send the code to a
  different `redirect_uri`.
- A callback on a different path of the same origin is rejected instead of being
  exchanged.
- Duplicate authorization parameters in a callback are refused.

### Notes

- `react`, `react-dom` and `react-test-renderer` are development dependencies
  only; `react` remains an optional peer dependency of the `./react` entry point.

## [0.2.3] — Security hardening

- PKCE S256 only, strict redirect and issuer validation, ID token verification
  with nonce/`auth_time`/`azp` checks, bounded response reads, JWKS caching with
  refetch-on-rotation, unknown-`expiry` refresh throttling.

## [0.2.2] and earlier

- Initial Android OIDC lifecycle, read-only account fetch, native async APIs,
  step-up authorization options.
