import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AIDServer } from '../src/server/client.js';
import {
  AIDAuthenticationError,
  AIDDiscoveryError,
  AIDError,
  AIDTokenError,
} from '../src/core/errors.js';

const ISSUER = 'https://identity.example.test';
const CLIENT_ID = 'server-test';
const CLIENT_SECRET = 'shhh-secret';

function discoveryDoc(overrides: Record<string, unknown> = {}) {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/auth`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/me`,
    jwks_uri: `${ISSUER}/jwks`,
    end_session_endpoint: `${ISSUER}/session/end`,
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function mockFetch(routes: {
  discovery?: () => Response | Promise<Response>;
  token?: (init: RequestInit) => Response | Promise<Response>;
  userinfo?: (init: RequestInit) => Response | Promise<Response>;
}) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.endsWith('/.well-known/openid-configuration')) {
      return routes.discovery ? routes.discovery() : jsonResponse(discoveryDoc());
    }
    if (url === `${ISSUER}/token`) {
      if (!routes.token) throw new Error('unexpected token call');
      return routes.token(init ?? {});
    }
    if (url === `${ISSUER}/me`) {
      if (!routes.userinfo) throw new Error('unexpected userinfo call');
      return routes.userinfo(init ?? {});
    }
    throw new Error(`unexpected fetch: ${url}`);
  }) as unknown as typeof fetch;
}

describe('AIDServer', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('requires issuer, clientId and clientSecret', () => {
    expect(() => new AIDServer({} as never)).toThrow(AIDError);
    expect(() => new AIDServer({ issuer: ISSUER } as never)).toThrow(AIDError);
    expect(() => new AIDServer({ issuer: ISSUER, clientId: 'x' } as never)).toThrow(AIDError);
  });

  it('rejects non-HTTPS issuer', () => {
    expect(
      () =>
        new AIDServer({
          issuer: 'http://identity.example.test',
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
        }),
    ).toThrow(AIDDiscoveryError);
  });

  it('exchangeCode sends Basic auth and the correct form body', async () => {
    let capturedInit: RequestInit | undefined;
    globalThis.fetch = mockFetch({
      token: (init) => {
        capturedInit = init;
        return jsonResponse({
          access_token: 'at_123',
          token_type: 'Bearer',
          expires_in: 3600,
          id_token: 'idt',
          refresh_token: 'rt_1',
          scope: 'openid profile email',
        });
      },
    });

    const aid = new AIDServer({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    const tokens = await aid.exchangeCode('CODE_XYZ', 'https://app.test/cb');

    expect(tokens.accessToken).toBe('at_123');
    expect(tokens.idToken).toBe('idt');
    expect(tokens.refreshToken).toBe('rt_1');
    expect(tokens.tokenType).toBe('Bearer');
    expect(tokens.expiresIn).toBe(3600);
    expect(typeof tokens.expiresAt).toBe('number');

    const headers = new Headers(capturedInit?.headers);
    const expected = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);
    expect(headers.get('authorization')).toBe(`Basic ${expected}`);
    expect(headers.get('content-type')).toBe('application/x-www-form-urlencoded');

    const body = new URLSearchParams(capturedInit?.body as string);
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('CODE_XYZ');
    expect(body.get('redirect_uri')).toBe('https://app.test/cb');
    expect(body.get('client_id')).toBeNull();
    expect(body.get('client_secret')).toBeNull();
  });

  it('exchangeCode forwards code_verifier when provided', async () => {
    let capturedInit: RequestInit | undefined;
    globalThis.fetch = mockFetch({
      token: (init) => {
        capturedInit = init;
        return jsonResponse({ access_token: 'at', token_type: 'Bearer' });
      },
    });

    const aid = new AIDServer({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    await aid.exchangeCode('C', 'https://app.test/cb', { codeVerifier: 'verifier-abc' });
    const body = new URLSearchParams(capturedInit?.body as string);
    expect(body.get('code_verifier')).toBe('verifier-abc');
  });

  it('exchangeCode maps token endpoint errors to AIDTokenError', async () => {
    globalThis.fetch = mockFetch({
      token: () =>
        jsonResponse({ error: 'invalid_grant', error_description: 'code expired' }, 400),
    });

    const aid = new AIDServer({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    await expect(aid.exchangeCode('bad', 'https://app.test/cb')).rejects.toBeInstanceOf(
      AIDTokenError,
    );
  });

  it('exchangeCode rejects responses without access_token', async () => {
    globalThis.fetch = mockFetch({
      token: () => jsonResponse({ token_type: 'Bearer' }),
    });

    const aid = new AIDServer({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    await expect(aid.exchangeCode('c', 'https://app.test/cb')).rejects.toBeInstanceOf(
      AIDTokenError,
    );
  });

  it('userInfo sends Bearer auth and returns an AIDUser', async () => {
    let capturedInit: RequestInit | undefined;
    globalThis.fetch = mockFetch({
      userinfo: (init) => {
        capturedInit = init;
        return jsonResponse({
          sub: 'user_42',
          email: 'a@b.test',
          email_verified: true,
          given_name: 'Ada',
          family_name: 'Lovelace',
          preferred_username: 'ada',
          locale: 'en',
        });
      },
    });

    const aid = new AIDServer({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    const user = await aid.userInfo('at_123');

    expect(user.sub).toBe('user_42');
    expect(user.email).toBe('a@b.test');
    expect(user.emailVerified).toBe(true);
    expect(user.givenName).toBe('Ada');
    expect(user.familyName).toBe('Lovelace');
    expect(user.preferredUsername).toBe('ada');

    const headers = new Headers(capturedInit?.headers);
    expect(headers.get('authorization')).toBe('Bearer at_123');
  });

  it('userInfo maps HTTP errors to AIDAuthenticationError', async () => {
    globalThis.fetch = mockFetch({
      userinfo: () => new Response('nope', { status: 401 }),
    });

    const aid = new AIDServer({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    await expect(aid.userInfo('bad')).rejects.toBeInstanceOf(AIDAuthenticationError);
  });

  it('userInfo rejects responses without sub', async () => {
    globalThis.fetch = mockFetch({
      userinfo: () => jsonResponse({ email: 'x@y.test' }),
    });

    const aid = new AIDServer({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    await expect(aid.userInfo('at')).rejects.toBeInstanceOf(AIDAuthenticationError);
  });

  it('caches the discovery document across calls', async () => {
    let discoveryHits = 0;
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/.well-known/openid-configuration')) {
        discoveryHits++;
        return jsonResponse(discoveryDoc());
      }
      if (url === `${ISSUER}/token`) {
        return jsonResponse({ access_token: 'at', token_type: 'Bearer' });
      }
      if (url === `${ISSUER}/me`) {
        return jsonResponse({ sub: 'u' });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as unknown as typeof fetch;

    const aid = new AIDServer({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    await aid.exchangeCode('c1', 'https://app.test/cb');
    await aid.exchangeCode('c2', 'https://app.test/cb');
    await aid.userInfo('at');
    await aid.userInfo('at');

    expect(discoveryHits).toBe(1);
  });
});
