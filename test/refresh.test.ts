import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
} from 'jose';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';

function createStorage() {
  return new MemoryStorage();
}

function createSession(expiresAt: number) {
  return {
    user: {
      sub: 'user-123',
      email: 'user@example.com',
    },
    tokens: {
      accessToken: 'old-access',
      refreshToken: 'old-refresh',
      tokenType: 'Bearer',
      expiresAt,
      scope: 'openid profile email',
    },
    nonce: 'original-nonce',
  };
}

async function createSignedIdToken(
  nonce: string | undefined,
) {
  const { privateKey, publicKey } =
    await generateKeyPair('RS256');

  const jwk = await exportJWK(publicKey);

  const builder = new SignJWT({
    sub: 'user-123',
    ...(nonce !== undefined ? { nonce } : {}),
  })
    .setProtectedHeader({
      alg: 'RS256',
      kid: 'test-key',
    })
    .setIssuer('https://identity.ace-base.cc')
    .setAudience('client')
    .setIssuedAt()
    .setExpirationTime('1h');

  return {
    token: await builder.sign(privateKey),
    jwks: {
      keys: [
        {
          ...jwk,
          kid: 'test-key',
          alg: 'RS256',
          use: 'sig',
        },
      ],
    },
  };
}

function discoveryWithJwks(
  jwksPath = '/jwks',
) {
  return {
    issuer: 'https://identity.ace-base.cc',
    authorization_endpoint:
      'https://identity.ace-base.cc/authorize',
    token_endpoint:
      'https://identity.ace-base.cc/token',
    jwks_uri:
      `https://identity.ace-base.cc${jwksPath}`,
    grant_types_supported: [
      'authorization_code',
      'refresh_token',
    ],
  };
}

describe('AID token lifecycle', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns the existing token when it is still valid', async () => {
    const storage = createStorage();

    storage.set(
      'aid:session',
      JSON.stringify(
        createSession(Date.now() + 300_000),
      ),
    );

    const aid = new AID({
      issuer: 'https://identity.ace-base.cc',
      clientId: 'client',
      redirectUri: 'https://example.com/callback',
      storage,
    });

    const token = await aid.getValidAccessToken();

    expect(token).toBe('old-access');
  });

  it('refreshes an expired token', async () => {
    const storage = createStorage();

    storage.set(
      'aid:session',
      JSON.stringify(
        createSession(Date.now() - 10_000),
      ),
    );

    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              issuer:
                'https://identity.ace-base.cc',
              authorization_endpoint:
                'https://identity.ace-base.cc/authorize',
              token_endpoint:
                'https://identity.ace-base.cc/token',
              grant_types_supported: [
                'authorization_code',
                'refresh_token',
              ],
            }),
            {
              status: 200,
              headers: {
                'Content-Type':
                  'application/json',
              },
            },
          ),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              access_token: 'new-access',
              refresh_token: 'new-refresh',
              token_type: 'Bearer',
              expires_in: 3600,
            }),
            {
              status: 200,
              headers: {
                'Content-Type':
                  'application/json',
              },
            },
          ),
        ),
    );

    const aid = new AID({
      issuer: 'https://identity.ace-base.cc',
      clientId: 'client',
      redirectUri: 'https://example.com/callback',
      storage,
    });

    const token = await aid.getValidAccessToken();

    expect(token).toBe('new-access');

    const session = aid.getSession();

    expect(session?.tokens.accessToken).toBe(
      'new-access',
    );

    expect(session?.tokens.refreshToken).toBe(
      'new-refresh',
    );
  });


  it('sends the stored scope when refreshing tokens', async () => {
    const storage = createStorage();

    storage.set(
      'aid:session',
      JSON.stringify(
        createSession(Date.now() - 10_000),
      ),
    );

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            issuer:
              'https://identity.ace-base.cc',
            authorization_endpoint:
              'https://identity.ace-base.cc/authorize',
            token_endpoint:
              'https://identity.ace-base.cc/token',
            grant_types_supported: [
              'authorization_code',
              'refresh_token',
            ],
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: 'new-access',
            refresh_token: 'new-refresh',
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'openid profile email',
          }),
          { status: 200 },
        ),
      );

    vi.stubGlobal('fetch', fetchMock);

    const aid = new AID({
      issuer: 'https://identity.ace-base.cc',
      clientId: 'client',
      redirectUri: 'https://example.com/callback',
      storage,
    });

    await aid.getValidAccessToken();

    const refreshCall = fetchMock.mock.calls[1];

    expect(refreshCall).toBeDefined();

    const refreshRequest = refreshCall?.[1];

    expect(refreshRequest?.method).toBe('POST');

    const body = new URLSearchParams(
      refreshRequest?.body as string,
    );

    expect(body.get('grant_type')).toBe('refresh_token');
    expect(body.get('refresh_token')).toBe('old-refresh');
    expect(body.get('client_id')).toBe('client');
    expect(body.get('scope')).toBe(
      'openid profile email',
    );
  });

  it('returns null when an expired session has no refresh token', async () => {
    const storage = createStorage();

    const session = createSession(
      Date.now() - 10_000,
    );

    const storedSession = {
      ...session,
      tokens: {
        ...session.tokens,
        refreshToken: undefined,
      },
    };

    storage.set(
      'aid:session',
      JSON.stringify(storedSession),
    );

    const aid = new AID({
      issuer: 'https://identity.ace-base.cc',
      clientId: 'client',
      redirectUri: 'https://example.com/callback',
      storage,
    });

    const token = await aid.getValidAccessToken();

    expect(token).toBeNull();
    expect(aid.getSession()).toBeNull();
  });


  it('deduplicates concurrent refresh requests', async () => {
    const storage = createStorage();

    storage.set(
      'aid:session',
      JSON.stringify(
        createSession(Date.now() - 10_000),
      ),
    );

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            issuer:
              'https://identity.ace-base.cc',
            authorization_endpoint:
              'https://identity.ace-base.cc/authorize',
            token_endpoint:
              'https://identity.ace-base.cc/token',
            grant_types_supported: [
              'authorization_code',
              'refresh_token',
            ],
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: 'new-access',
            refresh_token: 'new-refresh',
            token_type: 'Bearer',
            expires_in: 3600,
          }),
          { status: 200 },
        ),
      );

    vi.stubGlobal('fetch', fetchMock);

    const aid = new AID({
      issuer: 'https://identity.ace-base.cc',
      clientId: 'client',
      redirectUri: 'https://example.com/callback',
      storage,
    });

    const [first, second] = await Promise.all([
      aid.getValidAccessToken(),
      aid.getValidAccessToken(),
    ]);

    expect(first).toBe('new-access');
    expect(second).toBe('new-access');

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
