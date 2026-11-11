# Migrating to 0.2.4

0.2.4 is additive. No public method was removed, no default scope changed, and a
correctly configured client keeps working without edits. This page lists what to
adopt, in order of value.

## 1. Replace nullable-session checks with session state

Before:

```ts
const session = aid.getSession();
if (session && aid.isAuthenticated()) { /* signed in */ }
```

After:

```ts
const unsubscribe = aid.onAuthStateChange((state) => {
  switch (state.status) {
    case 'authenticated': return renderDashboard(state.session.user);
    case 'expired': return refreshOrPrompt();
    case 'refresh-failed': return showRetry(state.error);
    case 'unauthenticated': return renderSignIn();
  }
});
```

`expired` and `refresh-failed` previously arrived as `null` from `getSession()`
or as a thrown error; both are now observable states.

## 2. Let the SDK refresh

Before: a timer per app, or a manual `refresh()` before every request.

```ts
const aid = new AID({ ...config, autoRefresh: true });
const token = await aid.getValidAccessToken();
```

`getValidAccessToken()` already refreshed on demand; `autoRefresh` adds a timer
that fires `leewaySeconds` before expiry.

## 3. Use the profile API

```ts
const user = await aid.fetchUserProfile();
```

Instead of a bespoke UserInfo request, which had to verify `sub` itself.

## 4. Check the callback path

`handleCallback()` now requires the callback to arrive on the registered origin
**and** path. If your app serves the callback on several paths, register each one
as its own client, or pass `additionalRedirectOrigins` for extra origins. A path
mismatch that previously "worked" was a misconfiguration the SDK could not see.

## 5. Rename nothing, but know the aliases

| Before | Also available |
| --- | --- |
| `getSession()` | `currentSession()` |
| `refresh()` | `refreshSession()` |
| `signOut()` | `logout()` |
| `AuthProvider` | `AceIDProvider` |
| `useAuth()` | `useAceID()` |

## 6. Adopt the error codes

```ts
import { aidErrorCode, isRetryableError } from 'ace-id-sdk';

if (isRetryableError(error)) return retryLater();
if (aidErrorCode(error) === 'AUTHENTICATION_ERROR') return showSignIn();
```

`NETWORK_ERROR`, `SESSION_ERROR`, `PROFILE_ERROR` and `STORAGE_ERROR` are new;
previously these surfaced as `TOKEN_ERROR` or a generic `AIDError`.

## 7. Turn on diagnostics in staging

```ts
const report = await aid.validateConfiguration();
if (!report.ok) console.table(report.checks.filter((c) => c.status !== 'pass'));
```

This catches the classic setup mistakes — HTTP issuer, wrong redirect URI, a
provider without S256 PKCE, a missing JWKS endpoint — before a user hits them.

## Android

- The constructor gained a trailing `networkPolicy` parameter with a default, so
  existing call sites and `@JvmOverloads` Java calls are unaffected.
- `AidSessionState` gained `RefreshFailed`. A `when` over the sealed interface
  that is exhaustive will need that branch; one with an `else` keeps compiling.
- Token and refresh calls are never retried, even when `maxRetries` is set. If
  you were retrying them yourself, stop: a retried code or refresh can fail the
  whole flow.

## Behaviour changes to be aware of

1. Discovery is cached for 5 minutes per client. Call `clearDiscoveryCache()`
   after rotating issuer endpoints in development.
2. ID token verification applies an asymmetric algorithm allowlist. A provider
   that only offers HS* will now be refused, which is the intended behaviour.
3. The SDK logs nothing unless you pass `logger` or `debug`.
4. A callback with duplicated authorization parameters is refused.
