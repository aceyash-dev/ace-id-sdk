import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchUserProfile } from '../src/core/profile.js';
import { AIDAuthenticationError, AIDProfileError } from '../src/core/errors.js';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';
import type { AIDSession } from '../src/core/types.js';

const ISSUER = 'https://identity.example.test';
const REDIRECT = 'https://app.example.test/cb';

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('fetchUserProfile', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('maps claims onto a user', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => json({
      sub: 'user-1',
      email: 'user@example.test',
      given_name: 'Asha',
      custom_claim: 'kept',
    }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchUserProfile({
      userinfoEndpoint: `${ISSUER}/userinfo`,
      accessToken: 'token',
      expectedSubject: 'user-1',
    });

    expect(result.user).toMatchObject({
      sub: 'user-1',
      email: 'user@example.test',
      givenName: 'Asha',
      custom_claim: 'kept',
    });
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined;
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer token');
  });

  it('rejects a subject that does not match the session', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ sub: 'someone-else' })));
    await expect(fetchUserProfile({
      userinfoEndpoint: `${ISSUER}/userinfo`,
      accessToken: 'token',
      expectedSubject: 'user-1',
    })).rejects.toThrow(AIDAuthenticationError);
  });

  it('treats a rejected token as an authentication failure', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ error: 'invalid_token' }, 401)));
    await expect(fetchUserProfile({
      userinfoEndpoint: `${ISSUER}/userinfo`,
      accessToken: 'expired',
    })).rejects.toThrow(AIDAuthenticationError);
  });

  it('rejects a response without a subject', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ email: 'a@b.test' })));
    await expect(fetchUserProfile({
      userinfoEndpoint: `${ISSUER}/userinfo`,
      accessToken: 'token',
    })).rejects.toThrow(/missing "sub"/);
  });

  it('retries a transient failure and reports the retryable flag', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ error: 'busy' }, 503))
      .mockResolvedValueOnce(json({ sub: 'user-1' }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchUserProfile({
      userinfoEndpoint: `${ISSUER}/userinfo`,
      accessToken: 'token',
      retry: { maxRetries: 1, baseDelayMs: 1 },
    });
    expect(result.user.sub).toBe('user-1');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('marks a server error as retryable and a client error as not', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({}, 500)));
    await expect(fetchUserProfile({
      userinfoEndpoint: `${ISSUER}/userinfo`,
      accessToken: 't',
      retry: false,
    })).rejects.toMatchObject({ retryable: true });

    vi.stubGlobal('fetch', vi.fn(async () => json({}, 404)));
    await expect(fetchUserProfile({
      userinfoEndpoint: `${ISSUER}/userinfo`,
      accessToken: 't',
      retry: false,
    })).rejects.toMatchObject({ retryable: false });
  });

  it('requires an endpoint and a token', async () => {
    await expect(fetchUserProfile({ userinfoEndpoint: '', accessToken: 't' }))
      .rejects.toThrow(AIDProfileError);
    await expect(fetchUserProfile({ userinfoEndpoint: `${ISSUER}/userinfo`, accessToken: '' }))
      .rejects.toThrow(AIDAuthenticationError);
  });
});

describe('AID#fetchUserProfile', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function seeded(storage: MemoryStorage): void {
    const session: AIDSession = {
      user: { sub: 'user-1', email: 'stale@example.test' },
      tokens: {
        accessToken: 'access-1',
        tokenType: 'Bearer',
        expiresAt: Date.now() + 3_600_000,
        obtainedAt: Date.now(),
      },
    };
    storage.set('aid:session', JSON.stringify(session));
  }

  it('fetches the profile and persists it in the session', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('.well-known')) {
        return json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
          userinfo_endpoint: `${ISSUER}/userinfo`,
        });
      }
      return json({ sub: 'user-1', email: 'fresh@example.test', name: 'Fresh Name' });
    }));

    const storage = new MemoryStorage();
    seeded(storage);
    const client = new AID({ issuer: ISSUER, clientId: 'c', redirectUri: REDIRECT, storage });

    const user = await client.fetchUserProfile();
    expect(user.email).toBe('fresh@example.test');
    expect(client.getUser()?.name).toBe('Fresh Name');
  });

  it('returns the cached user without a request when asked', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const storage = new MemoryStorage();
    seeded(storage);
    const client = new AID({ issuer: ISSUER, clientId: 'c', redirectUri: REDIRECT, storage });

    const user = await client.fetchUserProfile({ useCachedSession: true });
    expect(user.email).toBe('stale@example.test');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fails clearly when the provider advertises no UserInfo endpoint', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks`,
    })));
    const storage = new MemoryStorage();
    seeded(storage);
    const client = new AID({ issuer: ISSUER, clientId: 'c', redirectUri: REDIRECT, storage });

    await expect(client.fetchUserProfile()).rejects.toThrow(/userinfo_endpoint/);
  });

  it('requires a session', async () => {
    const client = new AID({
      issuer: ISSUER,
      clientId: 'c',
      redirectUri: REDIRECT,
      storage: new MemoryStorage(),
    });
    await expect(client.fetchUserProfile()).rejects.toThrow(AIDAuthenticationError);
  });
});
