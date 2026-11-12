import { afterEach, describe, expect, it, vi } from 'vitest';
import { DiscoveryCache } from '../src/core/discovery.js';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';

const ISSUER_A = 'https://a.example.test';
const ISSUER_B = 'https://b.example.test';

function discovery(issuer: string): Record<string, unknown> {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
  };
}

function json(payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

describe('DiscoveryCache', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('fetches once and reuses the document within the TTL', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => json(discovery(String(input).startsWith(ISSUER_A) ? ISSUER_A : ISSUER_B)));
    vi.stubGlobal('fetch', fetchMock);

    const cache = new DiscoveryCache({ ttlMs: 60_000 });
    const first = await cache.get(ISSUER_A);
    const second = await cache.get(ISSUER_A);

    expect(second).toBe(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('refetches once the entry expires', async () => {
    let now = 1_000_000;
    const fetchMock = vi.fn(async () => json(discovery(ISSUER_A)));
    vi.stubGlobal('fetch', fetchMock);

    const cache = new DiscoveryCache({ ttlMs: 1_000, now: () => now });
    await cache.get(ISSUER_A);
    now += 1_500;
    await cache.get(ISSUER_A);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('keeps issuers isolated', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      json(discovery(String(input).includes('a.example.test') ? ISSUER_A : ISSUER_B)));
    vi.stubGlobal('fetch', fetchMock);

    const cache = new DiscoveryCache({ ttlMs: 60_000 });
    const a = await cache.get(ISSUER_A);
    const b = await cache.get(ISSUER_B);

    expect(a.issuer).toBe(ISSUER_A);
    expect(b.issuer).toBe(ISSUER_B);
    expect(cache.size).toBe(2);
  });

  it('collapses concurrent misses into one request', async () => {
    const fetchMock = vi.fn(async () => json(discovery(ISSUER_A)));
    vi.stubGlobal('fetch', fetchMock);

    const cache = new DiscoveryCache({ ttlMs: 60_000 });
    await Promise.all([cache.get(ISSUER_A), cache.get(ISSUER_A), cache.get(ISSUER_A)]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('honours forceRefresh', async () => {
    const fetchMock = vi.fn(async () => json(discovery(ISSUER_A)));
    vi.stubGlobal('fetch', fetchMock);

    const cache = new DiscoveryCache({ ttlMs: 60_000 });
    await cache.get(ISSUER_A);
    await cache.get(ISSUER_A, { forceRefresh: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not cache when the TTL is zero', async () => {
    const fetchMock = vi.fn(async () => json(discovery(ISSUER_A)));
    vi.stubGlobal('fetch', fetchMock);

    const cache = new DiscoveryCache({ ttlMs: 0 });
    await cache.get(ISSUER_A);
    await cache.get(ISSUER_A);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not cache a failed fetch', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ error: 'nope' }))
      .mockResolvedValueOnce(json(discovery(ISSUER_A)));
    vi.stubGlobal('fetch', fetchMock);

    const cache = new DiscoveryCache({ ttlMs: 60_000 });
    await expect(cache.get(ISSUER_A)).rejects.toThrow();
    await expect(cache.get(ISSUER_A)).resolves.toMatchObject({ issuer: ISSUER_A });
  });

  it('rejects a negative TTL', () => {
    expect(() => new DiscoveryCache({ ttlMs: -1 })).toThrow();
  });
});

describe('AID discovery caching', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('reuses discovery across sign-in attempts on one client', async () => {
    const assign = vi.fn();
    vi.stubGlobal('location', { href: 'https://app.example.test/cb', assign });
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => json(discovery(ISSUER_A)));
    vi.stubGlobal('fetch', fetchMock);

    const client = new AID({
      issuer: ISSUER_A,
      clientId: 'c',
      redirectUri: 'https://app.example.test/cb',
      storage: new MemoryStorage(),
    });
    await client.signIn();
    await client.signIn();

    const discoveryCalls = fetchMock.mock.calls.filter(([input]) =>
      String(input).includes('.well-known'));
    expect(discoveryCalls).toHaveLength(1);
    vi.unstubAllGlobals();
  });

  it('refetches after clearDiscoveryCache', async () => {
    const assign = vi.fn();
    vi.stubGlobal('location', { href: 'https://app.example.test/cb', assign });
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => json(discovery(ISSUER_A)));
    vi.stubGlobal('fetch', fetchMock);

    const client = new AID({
      issuer: ISSUER_A,
      clientId: 'c',
      redirectUri: 'https://app.example.test/cb',
      storage: new MemoryStorage(),
    });
    await client.signIn();
    client.clearDiscoveryCache();
    await client.signIn();

    const discoveryCalls = fetchMock.mock.calls.filter(([input]) =>
      String(input).includes('.well-known'));
    expect(discoveryCalls).toHaveLength(2);
    vi.unstubAllGlobals();
  });
});
