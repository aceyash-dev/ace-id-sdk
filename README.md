# Ace ID SDK

JavaScript/TypeScript, Android, and iOS SDKs for authenticating users with Ace ID through OpenID Connect (OIDC) Authorization Code + PKCE.

**Documentation:** [docs.ace-base.cc/projects/ace-id-sdk](https://docs.ace-base.cc/projects/ace-id-sdk)  
**Source:** [aceyash-dev/ace-id-sdk](https://github.com/aceyash-dev/ace-id-sdk)

## Release status

The current release work targets version `0.2.3`. It is a release candidate and is **not published yet**. Do not install this version or distribute platform binaries until the release is tagged and its official artifacts are available.

## JavaScript / TypeScript

Once the version is published:

```bash
npm install ace-id-sdk
```

Basic browser setup:

```ts
import { AID } from "ace-id-sdk";

const aid = new AID({
  issuer: "https://identity.ace-base.cc",
  clientId: "your-public-client-id",
  redirectUri: "https://app.example.com/callback",
});

await aid.signIn();

// Call on the registered callback route.
const session = await aid.handleCallback();
console.log(session.user);
```

Use `ace-id-sdk/server` only in trusted server runtimes. The optional React adapter is available from `ace-id-sdk/react`. Never expose a client secret in browser or mobile code.

## Post-login redirects

`signIn({ returnTo })` accepts a path (`/dashboard`) or an absolute URL on the registered redirect URI origin. The SDK validates the value before redirecting to the provider, keeps it in the authorization transaction, and returns it from `handleCallback()` — also exposed as `useAuth().returnTo` by the React adapter. The SDK never navigates after the callback: routing stays with the host application. Off-origin, protocol-relative, credentialed or non-HTTP values are rejected with a `CONFIGURATION_ERROR`.

## Token and session behaviour

`expires_in` is only RECOMMENDED by RFC 6749 §5.1, so the SDK never invents a lifetime. A token response without `expires_in` keeps `expiresAt` undefined and records `obtainedAt` instead. `getValidAccessToken()` then reuses that token for `unknownExpiryRefreshIntervalMs` (default 60 seconds) before requesting a new one, which bounds refreshes to one per interval instead of one per call and keeps refresh-token rotation intact. `isAuthenticated()` stays conservative and reports `false` when the expiry is unknown.

ID token verification keeps one remote JWK set per `jwks_uri` for the life of the process, so repeated verifications no longer re-fetch the issuer's keys. Rotated signing keys are picked up after a 5-second refetch cooldown; call `clearJwksCache()` to drop the cache explicitly.

Discovery documents (512 KiB) and token responses (1 MiB) are read with a size limit and rejected when exceeded. A refresh or callback that completes after `signOut()` does not recreate the session.

## Native SDKs

- [Android SDK guide](https://docs.ace-base.cc/projects/ace-id-sdk-android)
- [iOS SDK guide](https://docs.ace-base.cc/projects/ace-id-sdk-ios)
- [React, Next.js, and SSR guide](https://docs.ace-base.cc/projects/ace-id-sdk-framework-adapters)

## Security

The SDK uses Authorization Code with PKCE S256 and validates the authorization transaction. Step-up parameters are requests to the identity provider, not proof of MFA or a risk decision. Enforce permissions and sensitive actions on the server.

For installation, API details, AIDC configuration, token refresh, logout, troubleshooting, and release status, use the [full SDK documentation](https://docs.ace-base.cc/projects/ace-id-sdk).

## License

MIT
