import { afterEach, describe, expect, it, vi } from 'vitest';
import { AID } from '../src/browser/client.js';
import { fetchDiscovery, normalizeIssuer } from '../src/core/discovery.js';
import { MemoryStorage } from '../src/browser/storage.js';
import { AIDError, AIDDiscoveryError } from '../src/core/errors.js';

const ISSUER = 'https://identity.example.test';

function discoveryDoc(overrides: Record<string, unknown> = {}) {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/auth`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/me`,
    jwks_uri: `${ISSUER}/jwks`,
    revocation_endpoint: `${ISSUER}/revoke`,
    end_session_endpoint: `${ISSUER}/logout`,
    ...overrides,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('SDK request and redirect hardening', () => {
  it('rejects issuer URLs containing credentials', () => {
    expect(() => normalizeIssuer('https://user:pass@identity.example.test')).toThrow(AIDDiscoveryError);
  });

  it('rejects non-HTTPS endpoints in discovery metadata', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(
      discoveryDoc({ token_endpoint: 'http://untrusted.example/token' }),
    ), { status: 200, headers: { 'content-type': 'application/json' } })));

    await expect(fetchDiscovery(ISSUER)).rejects.toThrow(/token_endpoint.*HTTPS/i);
  });

  it('attaches a bounded abort signal to discovery requests', async () => {
    const fetchMock = vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >(async () => new Response(JSON.stringify(discoveryDoc()), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);

    await fetchDiscovery(ISSUER, 2_500);

    const request = fetchMock.mock.calls[0]?.[1];
    expect(request?.signal).toBeInstanceOf(AbortSignal);
    expect(request?.cache).toBe('no-store');
  });

  it('rejects unsafe cross-origin logout redirects before network work', async () => {
    const assign = vi.fn();
    Object.defineProperty(globalThis, 'location', {
      configurable: true,
      value: { href: 'https://app.example.test/cb', assign },
    });
    const fetchMock = vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >();
    vi.stubGlobal('fetch', fetchMock);
    const aid = new AID({
      issuer: ISSUER,
      clientId: 'client',
      redirectUri: 'https://app.example.test/cb',
      storage: new MemoryStorage(),
    });

    await expect(aid.signOut({ redirectTo: 'https://evil.example.test/landing' }))
      .rejects.toThrow(AIDError);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
  });

  it('rejects invalid timeout configuration early', () => {
    expect(() => new AID({
      issuer: ISSUER,
      clientId: 'client',
      redirectUri: 'https://app.example.test/cb',
      storage: new MemoryStorage(),
      requestTimeoutMs: 0,
    })).toThrow(AIDError);
  });
});
