import { afterEach, describe, expect, it, vi } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';
import { AIDAuthenticationError, AIDCallbackError } from '../src/core/errors.js';
import { startOidcFixture, type OidcFixture } from './helpers/oidc-fixture.js';

const ISSUER = 'https://identity.example.test';
const REDIRECT = 'https://app.example.test/cb';
const CLIENT_ID = 'client-1';

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function discoveryDoc(): Record<string, unknown> {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/jwks`,
    end_session_endpoint: `${ISSUER}/logout`,
    revocation_endpoint: `${ISSUER}/revoke`,
    grant_types_supported: ['authorization_code', 'refresh_token'],
  };
}

function mockLocation() {
  const assign = vi.fn();
  Object.defineProperty(globalThis, 'location', {
    configurable: true,
    value: { href: REDIRECT, assign },
  });
  return assign;
}

function seedExpiredSession(storage: MemoryStorage): void {
  storage.set(
    'aid:session',
    JSON.stringify({
      user: { sub: 'user-1' },
      tokens: {
        accessToken: 'old-access',
        tokenType: 'Bearer',
        refreshToken: 'old-refresh',
        expiresAt: Date.now() - 10_000,
      },
    }),
  );
}

async function waitFor(predicate: () => boolean, label: string): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

describe('refresh and logout races', () => {
  let fixture: OidcFixture | undefined;

  afterEach(async () => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    await fixture?.close();
    fixture = undefined;
  });

  it('does not resurrect a session that was signed out mid-refresh', async () => {
    const storage = new MemoryStorage();
    seedExpiredSession(storage);
    mockLocation();

    let releaseToken: () => void = () => {};
    const tokenGate = new Promise<void>((resolve) => {
      releaseToken = resolve;
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) return json(discoveryDoc());
      if (url === `${ISSUER}/token`) {
        await tokenGate;
        return json({
          access_token: 'rotated-access',
          refresh_token: 'rotated-refresh',
          token_type: 'Bearer',
          expires_in: 3600,
        });
      }
      if (url === `${ISSUER}/revoke`) return new Response(null, { status: 200 });
      if (url === `${ISSUER}/logout`) return new Response(null, { status: 204 });
      return json({ error: 'not_found' }, 404);
    });
    vi.stubGlobal('fetch', fetchMock);

    const aid = new AID({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      storage,
    });

    const pending = aid.getValidAccessToken();
    await waitFor(
      () => fetchMock.mock.calls.some(([input]) => String(input) === `${ISSUER}/token`),
      'the refresh token request',
    );

    await aid.signOut();

    releaseToken();

    await expect(pending).rejects.toBeInstanceOf(AIDAuthenticationError);
    expect(aid.getSession()).toBeNull();
    expect(storage.get('aid:session')).toBeNull();
  });

  it('rejects concurrent refreshes that would rotate the same refresh token twice', async () => {
    const storage = new MemoryStorage();
    seedExpiredSession(storage);

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) return json(discoveryDoc());
      return json({
        access_token: 'rotated-access',
        refresh_token: 'rotated-refresh',
        token_type: 'Bearer',
        expires_in: 3600,
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    const aid = new AID({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      storage,
    });

    const results = await Promise.all([
      aid.getValidAccessToken(),
      aid.getValidAccessToken(),
      aid.refresh(),
      aid.getValidAccessToken(),
    ]);

    expect(results.every((value) => value === 'rotated-access' || typeof value === 'object'))
      .toBe(true);

    const tokenCalls = fetchMock.mock.calls.filter(
      ([input]) => String(input) === `${ISSUER}/token`,
    );
    expect(tokenCalls).toHaveLength(1);
    expect(aid.getSession()?.tokens.refreshToken).toBe('rotated-refresh');
  });

  it('does not create a session when sign-out happens during the callback', async () => {
    let releaseExchange: () => void = () => {};
    const exchangeGate = new Promise<void>((resolve) => {
      releaseExchange = resolve;
    });
    fixture = await startOidcFixture({
      clientId: CLIENT_ID,
      nonce: 'nonce-1',
      tokenGate: exchangeGate,
    });

    const storage = new MemoryStorage();
    storage.set(
      'aid:transaction',
      JSON.stringify({
        state: 'state-1',
        nonce: 'nonce-1',
        codeVerifier: 'v'.repeat(43),
        redirectUri: REDIRECT,
        createdAt: Date.now(),
      }),
    );
    mockLocation();

    const aid = new AID({
      issuer: fixture.issuer,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      storage,
    });

    const pending = aid.handleCallback(`${REDIRECT}?code=abc&state=state-1`);
    await waitFor(() => fixture!.tokenRequests() === 1, 'the code exchange request');

    await aid.signOut();
    releaseExchange();

    await expect(pending).rejects.toBeInstanceOf(AIDCallbackError);
    expect(storage.get('aid:session')).toBeNull();
  });
});
