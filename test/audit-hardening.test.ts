import { afterEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { act, create, type ReactTestRenderer } from 'react-test-renderer';
import { AIDServer } from '../src/server/client.js';
import { createAuthHandlers } from '../src/server/handlers.js';
import { parseCookies } from '../src/server/session.js';
import { AceIDProvider, useAceIDSession } from '../src/react/index.js';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';

const ISSUER = 'https://identity.example.test';
const REDIRECT = 'https://app.example.test/api/auth/callback';
const doc = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/auth`,
  token_endpoint: `${ISSUER}/token`,
  userinfo_endpoint: `${ISSUER}/me`,
  jwks_uri: `${ISSUER}/jwks`,
};
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

function server(fetchImpl: typeof fetch): AIDServer {
  globalThis.fetch = fetchImpl;
  return new AIDServer({ issuer: ISSUER, clientId: 'c', clientSecret: 's' });
}
const discoveryOnly = vi.fn(async () => new Response(JSON.stringify(doc), { headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch;

describe('server authorization parameters', () => {
  it.each(['state', 'nonce', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'client_id', 'Scope'])(
    'refuses to override reserved parameter %s',
    async (key) => {
      await expect(
        server(discoveryOnly).authorizationUrl({ redirectUri: REDIRECT, state: 's', extra: { [key]: 'x' } }),
      ).rejects.toThrow(/reserved/);
    },
  );

  it('still allows supported extension parameters', async () => {
    const url = await server(discoveryOnly).authorizationUrl({ redirectUri: REDIRECT, state: 's', extra: { prompt: 'login' } });
    expect(new URL(url).searchParams.get('prompt')).toBe('login');
  });
});

describe('server response bounds', () => {
  it('rejects an oversized token response instead of buffering it', async () => {
    const huge = 'x'.repeat(2 * 1024 * 1024);
    const s = server((async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return new Response(JSON.stringify(doc), { headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify({ access_token: huge }), { headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch);
    await expect(s.exchangeCode('code', REDIRECT)).rejects.toThrow();
  });
});

describe('server callback validation parity', () => {
  const auth = createAuthHandlers({
    client: {} as AIDServer,
    secret: 'a-test-secret-with-enough-length',
    redirectUri: REDIRECT,
  } as never);

  it.each([
    ['duplicate code', `${REDIRECT}?code=a&code=b&state=s`],
    ['duplicate state', `${REDIRECT}?code=a&state=s&state=t`],
    ['wrong path', 'https://app.example.test/other?code=a&state=s'],
    ['wrong origin', 'https://evil.example.test/api/auth/callback?code=a&state=s'],
  ])('rejects %s', async (_name, url) => {
    const response = await auth.callback(new Request(url));
    expect(response.status).toBe(400);
  });
});

describe('cookie parsing', () => {
  it('drops malformed percent-encoding without throwing', () => {
    expect(() => parseCookies('a=%E0%A4%A; b=ok')).not.toThrow();
    expect(parseCookies('a=%E0%A4%A; b=ok')).toEqual({ b: 'ok' });
  });
});

describe('React provider with hydrateOnMount=false', () => {
  it('still reflects an already-authenticated client and clears stale errors', async () => {
    const storage = new MemoryStorage();
    storage.set('aid:session', JSON.stringify({
      user: { sub: 'u1', email: 'u@example.test' },
      tokens: { accessToken: 'a', tokenType: 'Bearer', refreshToken: 'r', expiresAt: Date.now() + 3_600_000, obtainedAt: Date.now() },
    }));
    const client = new AID({ issuer: ISSUER, clientId: 'c', redirectUri: 'https://app.example.test/cb', storage });
    const Probe = () => {
      const { status, error } = useAceIDSession();
      return createElement('span', null, `${status}|${error ? 'err' : 'ok'}`);
    };
    let renderer: ReactTestRenderer | undefined;
    await act(async () => {
      renderer = create(createElement(AceIDProvider, { client, hydrateOnMount: false }, createElement(Probe)));
    });
    expect(JSON.stringify(renderer!.toJSON())).toContain('authenticated|ok');
    renderer!.unmount();
  });
});
