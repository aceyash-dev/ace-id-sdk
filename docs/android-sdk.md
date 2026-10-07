# Android SDK 0.2.1

The Ace ID Android SDK provides native OpenID Connect authentication and account/session APIs for Android applications.

## Compatibility

- Namespace: `tab.aid.sdk`
- Minimum Android: API 23
- Compile SDK: API 36
- Java/Kotlin target: Java 17
- Authentication: Authorization Code + PKCE (S256)
- Distribution: AAR

## Basic authentication

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

The callback-based API remains available for integrations that prefer callbacks:

```kotlin
ace.login(this) { session ->
    // Route the redirect URI to the SDK callback handler.
}
```

## Account and access tokens

```kotlin
lifecycleScope.launch {
    val account = ace.getAccount(this@MainActivity)
    val token = ace.getValidAccessTokenAsync(this@MainActivity)
}
```

The SDK coordinates concurrent token refreshes so callers do not create a refresh storm. Rotated refresh tokens are persisted securely.

## Session state

The SDK exposes headless state flows and does not require Jetpack Compose:

```kotlin
val account by ace.account.collectAsState()
val sessionState by ace.sessionState.collectAsState()
```

## Security model

- Authorization Code + PKCE S256 only.
- Authorization state is validated on callback.
- ID tokens are verified against provider JWKS.
- Issuer, audience, expiration, subject, and applicable nonce checks are enforced.
- Discovery metadata is issuer-validated before use.
- Authentication/session data is scoped by issuer and client ID.
- Sensitive session material uses encrypted Android storage.
- Client secrets must never be embedded in Android or browser applications.

## Caching and performance

The SDK uses bounded, issuer/client-scoped caches for OIDC discovery and short-lived account data. Token refresh uses a single-flight mutex to avoid duplicate refresh requests when multiple callers need a valid token at the same time.

Default timings:

| Setting | Default |
| --- | ---: |
| Transaction TTL | 10 minutes |
| Discovery cache TTL | 6 hours |
| Account cache TTL | 30 seconds |
| Token expiry leeway | 60 seconds |

## AAR build

The Android workflow is intentionally **manual-only**.

In GitHub Actions, run **Android SDK** and choose:

- **release_tag:** `v0.2.1`
- **publish_release:** `false` to build and upload only the AAR
- **publish_release:** `true` to also attempt GitHub Release creation

The build job runs:

```text
gradle test assemble
```

A successful run uploads:

```text
ace-id-sdk-android-v0.2.1.aar
```

Release creation is deliberately opt-in. Repository-level GitHub Actions token policy must allow release writes for that step to succeed.

## What the SDK does not do

The Android SDK does not create or manage AIDC clients, applications, programs, provisioning resources, or project configuration. Those concerns belong to AIDC/CLI tooling.

## Versioning

This document describes the Android SDK for the **0.2.1** release line.
