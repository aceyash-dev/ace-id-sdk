import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryStorage } from '../src/browser/storage.js';
import { AID } from '../src/browser/client.js';
import { deriveSessionState, SessionStateEmitter } from '../src/core/session-state.js';
import type { AIDSession } from '../src/core/types.js';

const ISSUER = 'https://identity.example.test';
const REDIRECT = 'https://app.example.test/cb';

function discoveryDoc(): Record<string, unknown> {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/jwks`,
    grant_types_supported: ['authorization_code', 'refresh_token'],
  };
}

function session(overrides: Partial<AIDSession['tokens']> = {}): AIDSession {
  return {
    user: { sub: 'user-1', email: 'user@example.test' },
    tokens: {
      accessToken: 'access-1',
      tokenType: 'Bearer',
      refreshToken: 'refresh-1',
      expiresAt: Date.now() + 3_600_000,
      obtainedAt: Date.now(),
      ...overrides,
    },
  };
}

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('session state derivation', () => {
  it('reports unauthenticated without a session', () => {
    expect(deriveSessionState(null)).toEqual({ status: 'unauthenticated' });
  });

  it('reports authenticated for a live session', () => {
    const state = deriveSessionState(session());
    expect(state.status).toBe('authenticated');
  });

  it('reports expired once inside the leeway window', () => {
    const state = deriveSessionState(
      session({ expiresAt: Date.now() + 10_000 }),
      { leewaySeconds: 60 },
    );
    expect(state.status).toBe('expired');
  });

  it('does not call an unreported expiry expired', () => {
    const state = deriveSessionState(session({ expiresAt: undefined }));
    expect(state.status).toBe('authenticated');
    if (state.status === 'authenticated') expect(state.expiryUnknown).toBe(true);
  });
});

describe('SessionStateEmitter', () => {
  it('notifies subscribers only when the state actually changes', () => {
    const emitter = new SessionStateEmitter();
    const listener = vi.fn();
    emitter.subscribe(listener);
    const stable = session();

    emitter.set({ status: 'unauthenticated' });
    expect(listener).not.toHaveBeenCalled();

    emitter.set({ status: 'authenticated', session: stable, expiryUnknown: false });
    expect(listener).toHaveBeenCalledTimes(1);

    // Re-reporting the same session must not wake every subscriber.
    emitter.set({ status: 'authenticated', session: stable, expiryUnknown: false });
    expect(listener).toHaveBeenCalledTimes(1);

    // A rotated token is a real change.
    const rotated = { ...stable, tokens: { ...stable.tokens, accessToken: 'access-2' } };
    emitter.set({ status: 'authenticated', session: rotated, expiryUnknown: false });
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('isolates a throwing listener from the others', () => {
    const emitter = new SessionStateEmitter();
    const good = vi.fn();
    emitter.subscribe(() => {
      throw new Error('listener exploded');
    });
    emitter.subscribe(good);

    expect(() => emitter.set({ status: 'authenticated', session: session(), expiryUnknown: false })).not.toThrow();
    expect(good).toHaveBeenCalledTimes(1);
  });

  it('stops notifying after unsubscribe', () => {
    const emitter = new SessionStateEmitter();
    const listener = vi.fn();
    const unsubscribe = emitter.subscribe(listener);
    unsubscribe();
    emitter.set({ status: 'unauthenticated' });
    expect(listener).not.toHaveBeenCalled();
  });
});

describe('AID session state API', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('hydrates from storage and streams changes', () => {
    const storage = new MemoryStorage();
    storage.set('aid:session', JSON.stringify(session()));
    const client = new AID({ issuer: ISSUER, clientId: 'c', redirectUri: REDIRECT, storage });

    const seen: string[] = [];
    const unsubscribe = client.onAuthStateChange((state) => seen.push(state.status));
    // The listener is called once immediately with the current state.
    expect(seen).toEqual(['authenticated']);
    expect(client.currentSession()?.user.sub).toBe('user-1');

    unsubscribe();
    expect(client.getAuthState().status).toBe('authenticated');
  });

  it('reports expired for a stale token', () => {
    const storage = new MemoryStorage();
    storage.set('aid:session', JSON.stringify(session({ expiresAt: Date.now() - 1_000 })));
    const client = new AID({ issuer: ISSUER, clientId: 'c', redirectUri: REDIRECT, storage });
    expect(client.getAuthState().status).toBe('expired');
    expect(client.isAuthenticated()).toBe(false);
  });

  it('shares one refresh across concurrent callers', async () => {
    const storage = new MemoryStorage();
    storage.set('aid:session', JSON.stringify(session({ expiresAt: Date.now() - 1_000 })));
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) return json(discoveryDoc());
      if (url.endsWith('/token')) {
        return json({
          access_token: 'access-2',
          refresh_token: 'refresh-2',
          token_type: 'Bearer',
          expires_in: 3600,
        });
      }
      throw new Error(`unexpected ${url}`);
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new AID({ issuer: ISSUER, clientId: 'c', redirectUri: REDIRECT, storage });
    const results = await Promise.all([client.refreshSession(), client.refresh(), client.refreshSession()]);

    expect(results.every((result) => result.tokens.accessToken === 'access-2')).toBe(true);
    const tokenCalls = fetchMock.mock.calls.filter(([input]) => String(input).endsWith('/token'));
    expect(tokenCalls).toHaveLength(1);
  });

  it('emits refresh-failed and keeps the session when a refresh is rejected', async () => {
    const storage = new MemoryStorage();
    storage.set('aid:session', JSON.stringify(session({ expiresAt: Date.now() - 1_000 })));
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) return json(discoveryDoc());
      return json({ error: 'server_error' }, 500);
    }) as unknown as typeof fetch;

    const client = new AID({ issuer: ISSUER, clientId: 'c', redirectUri: REDIRECT, storage });
    const states: string[] = [];
    client.onAuthStateChange((state) => states.push(state.status));

    await expect(client.getValidAccessToken()).rejects.toThrow('Token endpoint error');
    expect(states).toContain('refresh-failed');
    expect(client.getSession()).not.toBeNull();
  });

  it('refreshes automatically before expiry when autoRefresh is enabled', async () => {
    vi.useFakeTimers();
    const storage = new MemoryStorage();
    storage.set('aid:session', JSON.stringify(session({ expiresAt: Date.now() + 120_000 })));
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) return json(discoveryDoc());
      return json({ access_token: 'auto-refreshed', token_type: 'Bearer', expires_in: 3600 });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new AID({
      issuer: ISSUER,
      clientId: 'c',
      redirectUri: REDIRECT,
      storage,
      autoRefresh: true,
      leewaySeconds: 60,
    });
    client.startAutoRefresh();

    await vi.advanceTimersByTimeAsync(70_000);
    expect(client.getAccessToken()).toBe('auto-refreshed');

    client.stopAutoRefresh();
  });

  it('never refreshes on a timer unless asked', async () => {
    vi.useFakeTimers();
    const storage = new MemoryStorage();
    storage.set('aid:session', JSON.stringify(session({ expiresAt: Date.now() + 5_000 })));
    const fetchMock = vi.fn(async () => json(discoveryDoc()));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const client = new AID({ issuer: ISSUER, clientId: 'c', redirectUri: REDIRECT, storage });
    await vi.advanceTimersByTimeAsync(120_000);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(client.getAccessToken()).toBe('access-1');
  });
});
