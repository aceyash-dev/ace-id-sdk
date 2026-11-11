# Server (SSR, Next.js, Remix, Hono, Workers)

`ace-id-sdk/server` covers two things: a confidential-client wrapper around the
OIDC endpoints (`AIDServer`), and Web-Fetch-compatible request handlers that keep
the session in an encrypted cookie.

Tokens never reach the browser as readable values: the session cookie is sealed
with AES-GCM under a key derived from your secret, and the `/session` endpoint
returns the user, not the tokens.

## Next.js App Router

```ts
// app/api/auth/[...ace]/route.ts
import { AIDServer, createAuthHandlers } from 'ace-id-sdk/server';

const client = new AIDServer({
  issuer: process.env.ACE_ID_ISSUER!,
  clientId: process.env.ACE_ID_CLIENT_ID!,
  clientSecret: process.env.ACE_ID_CLIENT_SECRET!,
});

const handlers = createAuthHandlers({
  client,
  redirectUri: process.env.ACE_ID_REDIRECT_URI!,   // https://app.example.com/api/auth/callback
  secret: process.env.ACE_ID_SESSION_SECRET!,       // 32+ random bytes, per environment
  afterLogin: '/dashboard',
  afterLogout: '/',
});

const routes: Record<string, (request: Request) => Promise<Response>> = {
  signin: handlers.signIn,
  callback: handlers.callback,
  session: handlers.session,
  refresh: handlers.refresh,
  signout: handlers.signOut,
};

export async function GET(request: Request, context: { params: Promise<{ ace: string[] }> }) {
  const { ace } = await context.params;
  const handler = routes[ace?.[0] ?? ''];
  if (!handler) return new Response('Not found', { status: 404 });
  return handler(request);
}
```

Routes: `/api/auth/signin`, `/api/auth/callback`, `/api/auth/session`,
`/api/auth/refresh`, `/api/auth/signout`.

The same handlers work unchanged in a Remix loader/action, a Hono route
(`app.get('/api/auth/signin', (c) => handlers.signIn(c.req.raw))`) and a Worker.

## Reading the session

```ts
import { getServerSession } from 'ace-id-sdk/server';

export default async function Page({ request }: { request: Request }) {
  const session = await getServerSession(request, { secret: process.env.ACE_ID_SESSION_SECRET! });
  if (!session) return redirect('/api/auth/signin');
  return <h1>Hello {session.user.email}</h1>;
}
```

`session.exp` is enforced when the cookie is opened, so an expired cookie is
indistinguishable from no cookie.

## Cookie options

| Option | Default | Notes |
| --- | --- | --- |
| `cookieName` | `ace_id_session` | Session cookie name. |
| `stateCookieName` | `ace_id_state` | Short-lived OAuth state cookie. |
| `sessionTtlSeconds` | 7 days | Absolute cookie lifetime. |
| `stateTtlSeconds` | 10 minutes | Lifetime of the state/PKCE cookie. |
| `secure` | `true` | Set `false` only for local HTTP development. |
| `afterLogin` / `afterLogout` | `/` | Same-origin redirect targets. |

Cookies are always `HttpOnly` and `SameSite=Lax`.

## PKCE and state

The server flow still uses PKCE (S256) in addition to the client secret. `state`,
`nonce` and the verifier are stored in the sealed state cookie and checked on the
callback; a forged or expired state cookie is rejected with `400` before the code
is exchanged.

## Verifying tokens yourself

```ts
const user = await client.verifyIdToken(idToken, { nonce });
```

Verification checks signature, issuer, audience, algorithm allowlist, `exp`,
`iat`, `azp` and `nonce` against the issuer's JWKS. Decoding a JWT is not
verification, and this method exists so no application needs to write that code.

## `AIDServer` reference

| Method | Purpose |
| --- | --- |
| `discovery()` | Cached discovery document. |
| `authorizationUrl({ redirectUri, state, nonce, codeChallenge, extra })` | Builds an authorization URL. |
| `exchangeCode(code, redirectUri, { codeVerifier })` | Confidential-client code exchange. |
| `refresh(refreshToken, scope?)` | Redeem a refresh token. |
| `userInfo(accessToken)` | Fetch the profile. |
| `verifyIdToken(idToken, { nonce })` | Verify and map an ID token to a user. |

`AIDServer` accepts `requestTimeoutMs`, `maxRetries`, `debug` and `logger`.

## Security notes

- Keep the client secret and session secret server-side; the sealed cookie is
  useless without the latter.
- Rotate the session secret by re-issuing cookies: old cookies fail closed and
  the user simply signs in again.
- The `/session` endpoint returns `authenticated`, `user` and `expiresAt` only.
- Logout clears local cookies first, then redirects to the provider's
  `end_session_endpoint` when it is advertised.
