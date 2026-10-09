# Framework and SSR integration

The SDK deliberately keeps browser and server entry points separate:

- `ace-id-sdk` is for browser applications and browser redirects.
- `ace-id-sdk/server` is for trusted server runtimes and requires a client secret.
- `ace-id-sdk/react` is an optional React peer integration; React must be installed by the application.

## React

Create one `AID` client in a client-only module and provide it with `AuthProvider`. Use `useAuth()` for explicit `loading`, `authenticated`, `unauthenticated`, and `error` states. `ProtectedRoute` is router-neutral: the host application owns redirect/navigation behavior.

Do not import the React subpath from server-only modules. Do not instantiate a browser client during server rendering, and do not assume browser storage exists during SSR.

## Next.js and other SSR frameworks

Use a server-only module for `AIDServer` and keep `ACE_ID_CLIENT_SECRET` in server environment variables. Add the framework's server-only marker where supported. Client Components must not import `ace-id-sdk/server` or receive client secrets through props, serialized data, or environment variables prefixed for public exposure.

Use a dedicated server callback route/action to exchange the authorization code. Validate state and PKCE transaction data server-side, then create an application session. Prefer a framework-managed, cryptographically signed/encrypted session cookie with:

- `HttpOnly`
- `Secure` in production
- `SameSite=Lax` or stricter when compatible with the callback flow
- a narrow `Path`, appropriate expiry, and rotation on authentication
- CSRF protection for state-changing application routes

The SDK's `AIDServer` returns protocol tokens; it does not implement your application's cookie session store. Do not put refresh tokens in localStorage, client-side React state, URLs, logs, or serialized page props.

## Safe diagnostics

`diagnoseAID()` checks discovery and local configuration and returns a redacted report. It cannot prove that a callback is registered at the identity provider unless the caller supplies the expected callback list; provider registration is not generally discoverable via public OIDC metadata. The report does not request tokens and must still be treated as operational metadata.

## Development test issuer

`createMockOIDCIssuer()` provides deterministic discovery, token, refresh, rotation, revocation, and UserInfo responses for unit/integration tests. Its dummy ID token is not signed and must never be used as a production identity token. For full protocol verification, also run a test suite against a dedicated development issuer with real signing keys and a disposable client.
