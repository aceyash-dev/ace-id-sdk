# Android

The Android module implements OIDC Authorization Code with PKCE natively: a
Custom Tab for the browser handoff, encrypted storage backed by the Android
Keystore, JWT verification with RS256/384/512, and coroutine-first APIs.

```kotlin
val aceID = AceID(
    issuer = "https://id.ace-base.cc",
    clientId = "your-public-client-id",
    redirectUri = "com.example.app:/oauth/callback",
)
```

## Signing in

```kotlin
// In an Activity or Compose effect scope
lifecycleScope.launch {
    val session = aceID.login(activity)          // suspends until the callback returns
    render(session.user)
}
```

`login()` launches a Custom Tab and suspends. The transaction (state, nonce,
PKCE verifier) is written to encrypted storage *before* the browser opens, so it
survives configuration changes and process death. Forward the callback from the
Activity that declares the redirect intent filter:

```kotlin
override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    intent.data?.let { uri ->
        lifecycleScope.launch { aceID.handleCallbackAsync(this@LoginActivity, uri) }
    }
}
```

After a process restart, ask whether a flow is still waiting instead of starting a
new one:

```kotlin
if (aceID.hasPendingAuthorization(context)) {
    // the callback will arrive through onNewIntent / onCreate
} else {
    aceID.login(activity)
}
```

`cancelLogin()` abandons a login the user walked away from.

## Session state

```kotlin
aceID.authState.collect { state ->
    when (state) {
        is AidSessionState.Authenticated -> showSignedIn(state.account)
        AidSessionState.Unauthenticated -> showSignIn()
        AidSessionState.Expired -> showSessionExpired()
        is AidSessionState.RefreshFailed -> showRetry(state.error)
    }
}
```

`sessionState` is an alias of `authState`. The four states are distinct because
they need distinct UI: a login screen, a silent refresh, and a "please sign in
again" prompt are not the same thing.

## Tokens and refresh

```kotlin
val token = aceID.getValidAccessToken(context)        // sync, refreshes when needed
val token = aceID.getValidAccessTokenAsync(context)   // suspend, runs on IO
val session = aceID.refreshSession(context)           // forces a refresh
```

All entry points share one refresh lock, so a rotating refresh token is never
submitted twice by concurrent callers. A refresh that fails for a reason other
than `invalid_grant` emits `RefreshFailed` and keeps the session; `invalid_grant`
clears it and emits `Unauthenticated`.

## Profile

```kotlin
val user = aceID.getProfile(context)                  // UserInfo, cached for 30s
val user = aceID.getAccount(context, cache = false)   // bypass the cache
```

The UserInfo `sub` must match the session subject; a mismatch throws rather than
overwriting the session.

## Network policy

```kotlin
val aceID = AceID(
    issuer = "https://id.ace-base.cc",
    clientId = "your-public-client-id",
    redirectUri = "com.example.app:/oauth/callback",
    networkPolicy = AidNetworkPolicy(
        connectTimeoutMs = 15_000,
        readTimeoutMs = 20_000,
        maxRetries = 3,
    ),
)
```

Retries apply to discovery, JWKS and UserInfo requests only. Authorization-code
exchanges and refresh requests are never retried: the code is single-use and a
retried refresh can invalidate a rotating token.

`AidNetworkPolicy.standard()` is the default policy; `AidNetworkPolicy.noRetries()`
disables retries while keeping the timeouts.

## Optional biometric unlock

```kotlin
if (AidBiometricUnlock.isSupported(context)) {
    val session = aceID.unlockSession(activity)
    if (session != null) showDashboard() else showSignIn()
}
```

This is a *local* convenience lock, not a second authentication factor: the
provider still governs the session, MFA and token lifetimes. It is built on
`androidx.biometric` (`BiometricPrompt`), which is the only supported entry point —
the platform class has a package-private constructor and its `PromptInfo` builder
is not public on every API level. `unlockSession()` therefore takes a
`FragmentActivity`.

`isSupported()` checks *enrolment*, not just hardware presence: a device with a
sensor but no enrolled biometric cannot authenticate anyone. Pass
`AidBiometricOptions(allowDeviceCredential = true)` to accept the device PIN as a
fallback. On unsupported devices `isSupported()` returns false — fall back to a
normal sign-in.

## Configuration validation

```kotlin
val report = aceID.validateConfiguration()
report.checks.forEach { check -> Log.i("AceID", "${check.name}: ${check.passed} ${check.detail}") }
```

Checks cover the issuer scheme, redirect URI, discovery, endpoints, PKCE S256,
network timeouts and retry budget.

## Storage

Session, transaction and cached profile live in `SharedPreferences` encrypted
with an AES-256-GCM key in the Android Keystore, scoped per issuer and client ID.
`signOut()` removes the session, transaction and cached profile.

## Java interop

The facade is Java-friendly: `AceID` uses `@JvmOverloads`, models are immutable
data classes with getters, and `AidNetworkPolicy.standard()` is `@JvmStatic` (it is not called `default()`, which is a Java keyword).

```java
AceID client = new AceID(issuer, clientId, redirectUri);
AidUser user = client.getUser(context);
```

Suspend functions are Kotlin-only; from Java use the synchronous methods or
`AidAsync` from a coroutine bridge.

## Threading

Synchronous methods block and are kept for compatibility. New code should use the
suspend APIs (`login`, `handleCallbackAsync`, `getValidAccessTokenAsync`,
`refreshSession`, `getProfile`, `restoreSession`), which dispatch to
`Dispatchers.IO` and never touch the main thread.
