aid-sdk

Official JavaScript/TypeScript SDK for Ace ID — an OpenID Connect identity provider.

- Browser ("aid-sdk") — public client. Authorization Code + PKCE (S256). No client secret.
- Server ("ace-id-sdk/server") — confidential client. Token exchange + UserInfo.

Install

npm i aid-sdk

Browser

import { AID } from "aid-sdk";

const aid = new AID({
  issuer: "https://identity.ace-base.cc",
  clientId: "my-public-client",
  redirectUri: "https://example.com/callback",
});

// Step 1 — redirect the user
await aid.signIn();

// Step 2 — on the redirect URI
const session = await aid.handleCallback();
console.log(session.user);

Methods: "signIn" · "handleCallback" · "getSession" · "isAuthenticated" · "getUser" · "getAccessToken" · "signOut".

Storage defaults to "sessionStorage". Use "MemoryStorage" only in tests or fully controlled environments.

Server

import { AIDServer } from "ace-id-sdk/server";

const aid = new AIDServer({
  issuer: "https://identity.ace-base.cc",
  clientId: process.env.ACE_ID_CLIENT_ID!,
  clientSecret: process.env.ACE_ID_CLIENT_SECRET!,
});

const tokens = await aid.exchangeCode(code, redirectUri);
const user   = await aid.userInfo(tokens.accessToken);

Security notes

- PKCE S256 only. No plain fallback.
- ID tokens are verified against the provider JWKS ("iss", "aud", "exp", "sub", "nonce").
- Never import "ace-id-sdk/server" in browser bundles.
- Endpoints are discovered from "{issuer}/.well-known/openid-configuration". The issuer is validated against the document.

License

MIT