# Error codes

Every failure the SDK raises is an `AIDError` (Android: `AidException`) with a
stable code. The codes are identical across JavaScript, Android and Swift, so one
piece of UI logic can map them everywhere.

| Code | Meaning | Usually retryable |
| --- | --- | --- |
| `CONFIGURATION_ERROR` | The client was constructed or called with unusable input. | no |
| `DISCOVERY_ERROR` | The issuer's discovery document was missing, invalid or unreachable. | yes (transport / 5xx) |
| `CALLBACK_ERROR` | The authorization response was malformed, replayed, expired or rejected. | no |
| `TOKEN_ERROR` | The token endpoint failed or returned an unusable response. | no |
| `AUTHENTICATION_ERROR` | No usable session, or the provider rejected the credentials. | no |
| `SESSION_ERROR` | The stored session was corrupt or ended mid-operation. | no |
| `PROFILE_ERROR` | The UserInfo request failed or returned the wrong subject. | yes (transport / 5xx) |
| `NETWORK_ERROR` | The request never completed: offline, DNS, timeout, abort. | yes |
| `STORAGE_ERROR` | The configured storage rejected a read or write. | no |

## Reading an error

```ts
import { aidErrorCode, isRetryableError, AIDError } from 'ace-id-sdk';

try {
  await aid.getValidAccessToken();
} catch (error) {
  if (isRetryableError(error)) return scheduleRetry();
  if (aidErrorCode(error) === 'AUTHENTICATION_ERROR') return showSignIn();
  throw error;
}
```

`AIDError` fields:

- `code` — one of the codes above.
- `message` — human-readable, safe to log. Never contains a token or code.
- `retryable` — whether repeating the same call could succeed.
- `details` — optional structured, non-secret context (for example `{ status: 503 }`).
- `cause` — the underlying error, when there is one.

## Why some failures are never retried

An authorization code is single-use. If the token request succeeds but the
response is lost, a retry sends a code that has already been redeemed and fails
with `invalid_grant`. With rotating refresh tokens the same is true of a refresh:
a retried request can invalidate the token family and sign the user out. The SDK
therefore retries only idempotent requests (discovery, JWKS, UserInfo) and never
the token endpoint.

## Android

```kotlin
try {
    client.refreshSession(context)
} catch (error: AidTokenEndpointException) {
    if (error.errorCode == "invalid_grant") showSignIn() else showRetry()
}
```

Android reports the same situations through `AidException` subclasses
(`AidDiscoveryException`, `AidConfigurationException`, `AidTokenEndpointException`)
and the provider's machine-readable `errorCode` where one exists.
