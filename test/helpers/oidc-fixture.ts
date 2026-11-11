import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

/**
 * Local OIDC issuer used by tests that need real JWT verification.
 *
 * `jose` fetches remote JWK sets with `node:http`/`node:https` rather than the
 * global `fetch`, so a stubbed `fetch` cannot intercept a JWKS request. This
 * fixture serves discovery, JWKS, token, revocation and logout endpoints over a
 * real loopback HTTP server, which is also exempt from the SDK's HTTPS rule.
 */
export interface OidcFixtureOptions {
  clientId?: string;
  nonce?: string;
  kid?: string;
  /** Lifetime reported by the token endpoint; `null` omits `expires_in`. */
  expiresIn?: number | null;
  /** Optional gate applied to token requests, for race tests. */
  tokenGate?: Promise<void>;
}

export interface OidcFixture {
  issuer: string;
  jwksUrl: string;
  jwksFetches(): number;
  tokenRequests(): number;
  requests: Array<{ path: string; body?: string }>;
  setJwks(jwks: unknown): void;
  signIdToken(claims: Record<string, unknown>, kid?: string): Promise<string>;
  close(): Promise<void>;
}

export async function startOidcFixture(options: OidcFixtureOptions = {}): Promise<OidcFixture> {
  const clientId = options.clientId ?? 'client-1';
  const nonce = options.nonce ?? 'nonce-1';
  const kid = options.kid ?? 'k1';
  const expiresIn = options.expiresIn === undefined ? 3600 : options.expiresIn;

  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  let jwks: unknown = { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] };
  let jwksFetches = 0;
  let tokenRequests = 0;
  const requests: Array<{ path: string; body?: string }> = [];

  const signIdToken = async (
    claims: Record<string, unknown>,
    tokenKid = kid,
  ): Promise<string> =>
    new SignJWT({ sub: 'user-1', nonce, ...claims })
      .setProtectedHeader({ alg: 'RS256', kid: tokenKid })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

  let issuer = '';
  const server = http.createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0] as string;
    const send = (payload: unknown, status = 200): void => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(payload));
    };

    if (path === '/.well-known/openid-configuration') {
      send({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        revocation_endpoint: `${issuer}/revoke`,
        end_session_endpoint: `${issuer}/logout`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
      });
      return;
    }

    if (path === '/jwks') {
      jwksFetches += 1;
      send(jwks);
      return;
    }

    if (path === '/revoke' || path === '/logout') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
      return;
    }

    if (path === '/token') {
      let raw = '';
      req.on('data', (chunk: Buffer) => {
        raw += chunk.toString();
      });
      req.on('end', () => {
        void (async () => {
          const form = new URLSearchParams(raw);
          requests.push({ path, body: raw });
          tokenRequests += 1;
          const generation = tokenRequests;

          if (options.tokenGate) await options.tokenGate;

          if (form.get('grant_type') === 'refresh_token') {
            send({
              access_token: `refreshed-access-${generation}`,
              refresh_token: `refreshed-refresh-${generation}`,
              token_type: 'Bearer',
              ...(expiresIn === null ? {} : { expires_in: expiresIn }),
            });
            return;
          }

          send({
            access_token: `access-token-${generation}`,
            id_token: await signIdToken({}),
            refresh_token: `refresh-${generation}`,
            token_type: 'Bearer',
            ...(expiresIn === null ? {} : { expires_in: expiresIn }),
          });
        })();
      });
      return;
    }

    send({ error: 'not_found' }, 404);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  issuer = `http://127.0.0.1:${port}`;

  return {
    get issuer() {
      return issuer;
    },
    get jwksUrl() {
      return `${issuer}/jwks`;
    },
    jwksFetches: () => jwksFetches,
    tokenRequests: () => tokenRequests,
    requests,
    setJwks: (next: unknown) => {
      jwks = next;
    },
    signIdToken,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
