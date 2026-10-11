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

## Native SDKs

- [Android SDK guide](https://docs.ace-base.cc/projects/ace-id-sdk-android)
- [iOS SDK guide](https://docs.ace-base.cc/projects/ace-id-sdk-ios)
- [React, Next.js, and SSR guide](https://docs.ace-base.cc/projects/ace-id-sdk-framework-adapters)

## Security

The SDK uses Authorization Code with PKCE S256 and validates the authorization transaction. Step-up parameters are requests to the identity provider, not proof of MFA or a risk decision. Enforce permissions and sensitive actions on the server.

For installation, API details, AIDC configuration, token refresh, logout, troubleshooting, and release status, use the [full SDK documentation](https://docs.ace-base.cc/projects/ace-id-sdk).

## License

MIT
