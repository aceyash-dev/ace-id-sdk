import { afterEach, describe, expect, it, vi } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';
import {
  DEFAULT_UNKNOWN_EXPIRY_REFRESH_INTERVAL_MS,
  hasKnownExpiry,
  isTokenExpired,
  normalizeTokenResponse,
  shouldRefreshToken,
} from '../src/core/tokens.js';

const ISSUER = 'https://identity.example.test';

function discovery(): Response {
  return new Response(
    JSON.stringify({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      grant_types_supported: ['authorization_code', 'refresh_token'],
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function tokenResponse(accessToken: string, includeExpiry: boolean): Response {
  return new Response(
    JSON.stringify({
      access_token: accessToken,
      refresh_token: `refresh-${accessToken}`,
      token_type: 'Bearer',
      ...(includeExpiry ? { expires_in: 3600 } : {}),
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function makeClient(storage: MemoryStorage, unknownExpiryRefreshIntervalMs?: number): AID {
  return new AID({
    issuer: ISSUER,
    clientId: 'client',
    redirectUri: 'https://app.example.test/cb',
    storage,
    ...(unknownExpiryRefreshIntervalMs === undefined ? {} : { unknownExpiryRefreshIntervalMs }),
  });
}

function seedSession(storage: MemoryStorage, tokens: Record<string, unknown>): void {
  storage.set(
    'aid:session',
    JSON.stringify({
      user: { sub: 'user-1' },
      tokens: { accessToken: 'stored-access', tokenType: 'Bearer', refreshToken: 'stored-refresh', ...tokens },
    }),
  );
}

describe('token expiry reporting', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('never invents an expiry when the token endpoint omits expires_in', () => {
    const before = Date.now();
    const tokens = normalizeTokenResponse({ access_token: 'at', token_type: 'Bearer' });

    expect(tokens.expiresAt).toBeUndefined();
    expect(tokens.expiresIn).toBeUndefined();
    expect(tokens.obtainedAt).toBeGreaterThanOrEqual(before);
    expect(hasKnownExpiry(tokens)).toBe(false);
  });

  it('records the reported lifetime unchanged', () => {
    const now = 1_700_000_000_000;
    const tokens = normalizeTokenResponse(
      { access_token: 'at', expires_in: 900 },
      undefined,
      now,
    );

    expect(tokens.expiresAt).toBe(now + 900_000);
    expect(tokens.obtainedAt).toBe(now);
    expect(hasKnownExpiry(tokens)).toBe(true);
  });

  it('keeps unknown expiry out of the valid set while bounding refreshes', () => {
    const now = 1_700_000_000_000;
    const tokens = normalizeTokenResponse({ access_token: 'at' }, undefined, now);

    // Unknown expiry is never reported as unexpired...
    expect(isTokenExpired(tokens, 60, now)).toBe(true);
    // ...but a token just obtained is not refreshed again immediately.
    expect(shouldRefreshToken(tokens, { now })).toBe(false);
    expect(
      shouldRefreshToken(tokens, { now: now + DEFAULT_UNKNOWN_EXPIRY_REFRESH_INTERVAL_MS }),
    ).toBe(true);
  });

  it('reports expiry-based refresh decisions for tokens with a known lifetime', () => {
    const now = 1_700_000_000_000;
    const tokens = normalizeTokenResponse({ access_token: 'at', expires_in: 300 }, undefined, now);

    expect(shouldRefreshToken(tokens, { now, leewaySeconds: 60 })).toBe(false);
    expect(shouldRefreshToken(tokens, { now: now + 250_000, leewaySeconds: 60 })).toBe(true);
  });

  it('does not re-request a token whose expiry was never reported', async () => {
    const storage = new MemoryStorage();
    seedSession(storage, { obtainedAt: Date.now() });
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const aid = makeClient(storage);

    await expect(aid.getValidAccessToken()).resolves.toBe('stored-access');
    await expect(aid.getValidAccessToken()).resolves.toBe('stored-access');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refreshes once the unknown-expiry interval elapses, then stops storming', async () => {
    const storage = new MemoryStorage();
    seedSession(storage, { obtainedAt: Date.now() - DEFAULT_UNKNOWN_EXPIRY_REFRESH_INTERVAL_MS - 1_000 });

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(discovery())
      .mockResolvedValueOnce(tokenResponse('refreshed-access', false));
    vi.stubGlobal('fetch', fetchMock);

    const aid = makeClient(storage);

    await expect(aid.getValidAccessToken()).resolves.toBe('refreshed-access');

    const session = aid.getSession();
    expect(session?.tokens.expiresAt).toBeUndefined();
    expect(session?.tokens.obtainedAt).toBeGreaterThan(Date.now() - 5_000);

    // The refreshed token has no reported expiry either; it must not trigger
    // another round trip on the very next call.
    await expect(aid.getValidAccessToken()).resolves.toBe('refreshed-access');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('honours a configured unknown-expiry refresh interval', async () => {
    const storage = new MemoryStorage();
    seedSession(storage, { obtainedAt: Date.now() - 2_000 });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(discovery())
      .mockResolvedValueOnce(tokenResponse('refreshed-access', false));
    vi.stubGlobal('fetch', fetchMock);

    const lenient = makeClient(storage, 60_000);
    await expect(lenient.getValidAccessToken()).resolves.toBe('stored-access');
    expect(fetchMock).not.toHaveBeenCalled();

    const strict = makeClient(storage, 0);
    await expect(strict.getValidAccessToken()).resolves.toBe('refreshed-access');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects an invalid unknown-expiry refresh interval', () => {
    expect(() => makeClient(new MemoryStorage(), -1)).toThrow(/unknownExpiryRefreshIntervalMs/);
    expect(() => makeClient(new MemoryStorage(), Number.NaN)).toThrow(
      /unknownExpiryRefreshIntervalMs/,
    );
  });
});
