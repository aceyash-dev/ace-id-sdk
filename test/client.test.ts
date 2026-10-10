import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';
import { AIDCallbackError, AIDDiscoveryError, AIDError } from '../src/core/errors.js';

const ISSUER = 'https://identity.example.test';

function discoveryDoc(overrides: Record<string, unknown> = {}) {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/auth`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/me`,
    jwks_uri: `${ISSUER}/jwks`,
    end_session_endpoint: `${ISSUER}/session/end`,
    revocation_endpoint: `${ISSUER}/oauth/revoke`,
    ...overrides,
  };
}


function mockLocation() {
  const assign = vi.fn();

  Object.defineProperty(globalThis, 'location', {
    configurable: true,
    value: {
      href: 'https://app.example.test/cb',
      assign,
    },
  });

  return assign;
}

describe('AID (browser)', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('requires issuer, clientId and redirectUri', () => {
    expect(() => new AID({} as never)).toThrow(AIDError);
    expect(() => new AID({ issuer: ISSUER } as never)).toThrow(AIDError);
    expect(() => new AID({ issuer: ISSUER, clientId: 'x' } as never)).toThrow(AIDError);
  });

  it('rejects non-HTTPS issuer (non-localhost)', () => {
    expect(
      () =>
        new AID({
          issuer: 'http://identity.example.test',
          clientId: 'x',
          redirectUri: 'https://app.example.test/cb',
          storage: new MemoryStorage(),
        }),
    ).toThrow(AIDDiscoveryError);
  });

  it('rejects discovery documents whose issuer does not match', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify(discoveryDoc({ issuer: 'https://evil.example.test' })), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    ) as unknown as typeof fetch;

    const storage = new MemoryStorage();
    // Seed a matching, fresh transaction so the callback gets past the
    // state check and reaches discovery.
    storage.set(
      'aid:transaction',
      JSON.stringify({
        state: 's',
        nonce: 'n',
        codeVerifier: 'v'.repeat(43),
        redirectUri: 'https://app.example.test/cb',
        createdAt: Date.now(),
      }),
    );

    const aid = new AID({
      issuer: ISSUER,
      clientId: 'aid-sdk-test',
      redirectUri: 'https://app.example.test/cb',
      storage,
    });

    await expect(
      aid.handleCallback('https://app.example.test/cb?code=abc&state=s'),
    ).rejects.toBeInstanceOf(AIDDiscoveryError);
  });

  it('rejects callbacks where state does not match the stored transaction', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify(discoveryDoc()), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    ) as unknown as typeof fetch;

    const storage = new MemoryStorage();
    storage.set(
      'aid:transaction',
      JSON.stringify({
        state: 'expected-state',
        nonce: 'n',
        codeVerifier: 'v'.repeat(43),
        redirectUri: 'https://app.example.test/cb',
        createdAt: Date.now(),
      }),
    );

    const aid = new AID({
      issuer: ISSUER,
      clientId: 'aid-sdk-test',
      redirectUri: 'https://app.example.test/cb',
      storage,
    });

    await expect(
      aid.handleCallback('https://app.example.test/cb?code=abc&state=wrong-state'),
    ).rejects.toBeInstanceOf(AIDCallbackError);
  });


  it('revokes the refresh token before OIDC logout', async () => {
    const storage = new MemoryStorage();

    storage.set(
      'aid:session',
      JSON.stringify({
        user: {
          sub: 'user-123',
        },
        tokens: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
          idToken: 'id-token',
          tokenType: 'Bearer',
        },
      }),
    );

    const assign = mockLocation();

    const fetchMock = vi
      .fn<
        (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
      >()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(discoveryDoc()),
          {
            status: 200,
            headers: {
              'content-type': 'application/json',
            },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(null, { status: 200 }),
      );

    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const aid = new AID({
      issuer: ISSUER,
      clientId: 'aid-sdk-test',
      redirectUri: 'https://app.example.test/cb',
      storage,
    });

    await aid.signOut({
      redirectTo: 'https://app.example.test/signed-out',
    });

    expect(storage.get('aid:session')).toBeNull();

    expect(fetchMock).toHaveBeenCalledTimes(2);

    const revocationCall = fetchMock.mock.calls[1]!;
    
    const url = revocationCall[0];
    const request = revocationCall[1];

    expect(url).toBe(`${ISSUER}/oauth/revoke`);
    expect(request?.method).toBe('POST');

    const body = new URLSearchParams(
      request?.body as string,
    );

    expect(body.get('token')).toBe('refresh-token');
    expect(body.get('client_id')).toBe('aid-sdk-test');
    expect(body.get('token_type_hint')).toBe(
      'refresh_token',
    );

    expect(assign).toHaveBeenCalledTimes(1);

    const assignCall = assign.mock.calls[0]!;
    
    const logoutUrl = new URL(
      String(assignCall[0]),
    );

    expect(logoutUrl.origin).toBe(ISSUER);
    expect(logoutUrl.pathname).toBe('/session/end');
    expect(logoutUrl.searchParams.get('id_token_hint')).toBe(
      'id-token',
    );
    expect(
      logoutUrl.searchParams.get(
        'post_logout_redirect_uri',
      ),
    ).toBe('https://app.example.test/signed-out');
  });

  it('does not revoke when the provider has no revocation endpoint', async () => {
    const storage = new MemoryStorage();

    storage.set(
      'aid:session',
      JSON.stringify({
        user: {
          sub: 'user-123',
        },
        tokens: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
          idToken: 'id-token',
          tokenType: 'Bearer',
        },
      }),
    );

    const assign = mockLocation();

    const fetchMock = vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >(async () =>
      new Response(
        JSON.stringify(
          discoveryDoc({
            revocation_endpoint: undefined,
          }),
        ),
        {
          status: 200,
          headers: {
            'content-type': 'application/json',
          },
        },
      ),
    );

    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const aid = new AID({
      issuer: ISSUER,
      clientId: 'aid-sdk-test',
      redirectUri: 'https://app.example.test/cb',
      storage,
    });

    await aid.signOut();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const discoveryCall = fetchMock.mock.calls[0]!;

    expect(
      discoveryCall[0],
    ).toBe(`${ISSUER}/.well-known/openid-configuration`);

    expect(storage.get('aid:session')).toBeNull();
    expect(assign).toHaveBeenCalledTimes(1);
  });

  it('still completes local logout when revocation fails', async () => {
    const storage = new MemoryStorage();

    storage.set(
      'aid:session',
      JSON.stringify({
        user: {
          sub: 'user-123',
        },
        tokens: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
          idToken: 'id-token',
          tokenType: 'Bearer',
        },
      }),
    );

    const assign = mockLocation();

    const fetchMock = vi
      .fn<
        (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
      >()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(discoveryDoc()),
          {
            status: 200,
            headers: {
              'content-type': 'application/json',
            },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(null, { status: 500 }),
      );

    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const aid = new AID({
      issuer: ISSUER,
      clientId: 'aid-sdk-test',
      redirectUri: 'https://app.example.test/cb',
      storage,
    });

    await expect(
      aid.signOut({
        redirectTo: 'https://app.example.test/signed-out',
      }),
    ).resolves.toBeUndefined();

    expect(storage.get('aid:session')).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(assign).toHaveBeenCalledTimes(1);
  });

  it('adds step-up authentication hints to authorization requests', async () => {
    const assign = mockLocation();
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(discoveryDoc()), {
      status: 200, headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;
    const aid = new AID({ issuer: ISSUER, clientId: 'aid-sdk-test', redirectUri: 'https://app.example.test/cb', storage: new MemoryStorage() });
    await aid.signIn({
      prompt: ['login', 'consent'], loginHint: 'alice@example.test', maxAge: 0,
      acrValues: ['urn:ace:loa:2'], uiLocales: ['en-US', 'fr-FR'], additionalParameters: { organization: 'acme' },
    });
    const authUrl = new URL(String(assign.mock.calls[0]?.[0]));
    expect(authUrl.searchParams.get('prompt')).toBe('login consent');
    expect(authUrl.searchParams.get('login_hint')).toBe('alice@example.test');
    expect(authUrl.searchParams.get('max_age')).toBe('0');
    expect(authUrl.searchParams.get('acr_values')).toBe('urn:ace:loa:2');
    expect(authUrl.searchParams.get('ui_locales')).toBe('en-US fr-FR');
    expect(authUrl.searchParams.get('organization')).toBe('acme');
    expect(authUrl.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('rejects attempts to override OAuth security parameters', async () => {
    const aid = new AID({ issuer: ISSUER, clientId: 'aid-sdk-test', redirectUri: 'https://app.example.test/cb', storage: new MemoryStorage() });
    await expect(aid.signIn({ additionalParameters: { STATE: 'bad' } })).rejects.toBeInstanceOf(AIDError);
    await expect(aid.signIn({ additionalParameters: { request_uri: 'https://attacker.test/request' } })).rejects.toBeInstanceOf(AIDError);
    await expect(aid.signIn({ maxAge: -1 })).rejects.toBeInstanceOf(AIDError);
  });


    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify(discoveryDoc()), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    ) as unknown as typeof fetch;

    const storage = new MemoryStorage();
    storage.set(
      'aid:transaction',
      JSON.stringify({
        state: 's',
        nonce: 'n',
        codeVerifier: 'v'.repeat(43),
        redirectUri: 'https://app.example.test/cb',
        createdAt: Date.now() - 60 * 60 * 1000,
      }),
    );

    const aid = new AID({
      issuer: ISSUER,
      clientId: 'aid-sdk-test',
      redirectUri: 'https://app.example.test/cb',
      storage,
      transactionTtlMs: 60_000,
    });

    await expect(
      aid.handleCallback('https://app.example.test/cb?code=abc&state=s'),
    ).rejects.toBeInstanceOf(AIDCallbackError);
  });
});