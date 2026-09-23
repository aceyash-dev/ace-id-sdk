import { describe, expect, it } from 'vitest';
import { AID } from '../src/browser/client.js';
import type { AIDSession } from '../src/core/types.js';

function makeSession(overrides: Partial<AIDSession['tokens']> = {}): AIDSession {
  return {
    user: {
      sub: 'user-123',
    },
    tokens: {
      accessToken: 'access-token',
      tokenType: 'Bearer',
      ...overrides,
    },
  };
}

function makeClient(session?: AIDSession): {
  client: AID;
  storage: {
    get: (key: string) => string | null;
    set: (key: string, value: string) => void;
    remove: (key: string) => void;
  };
} {
  const data = new Map<string, string>();

  if (session) {
    data.set('aid:session', JSON.stringify(session));
  }

  const storage = {
    get: (key: string) => data.get(key) ?? null,
    set: (key: string, value: string) => {
      data.set(key, value);
    },
    remove: (key: string) => {
      data.delete(key);
    },
  };

  const client = new AID({
    issuer: 'https://id.example.com',
    clientId: 'test-client',
    redirectUri: 'http://localhost/callback',
    storage,
  });

  return { client, storage };
}

describe('isAuthenticated', () => {
  it('returns false when there is no session', () => {
    const { client } = makeClient();

    expect(client.isAuthenticated()).toBe(false);
  });

  it('returns true for a valid unexpired session', () => {
    const { client } = makeClient(
      makeSession({
        expiresAt: Date.now() + 300_000,
      }),
    );

    expect(client.isAuthenticated()).toBe(true);
  });

  it('returns false for an expired access token', () => {
    const { client } = makeClient(
      makeSession({
        expiresAt: Date.now() - 1_000,
        refreshToken: 'refresh-token',
      }),
    );

    expect(client.isAuthenticated()).toBe(false);
  });

  it('returns true when the access token is within the refresh leeway but not expired', () => {
    const { client } = makeClient(
      makeSession({
        expiresAt: Date.now() + 30_000,
      }),
    );

    expect(client.isAuthenticated()).toBe(true);
  });

  it('returns true when expiresAt is unavailable', () => {
    const { client } = makeClient(
      makeSession(),
    );

    expect(client.isAuthenticated()).toBe(true);
  });

  it('returns false for an invalid persisted session', () => {
    const { client, storage } = makeClient();

    storage.set('aid:session', JSON.stringify({
      user: { sub: 'user-123' },
      tokens: {
        accessToken: 'access-token',
      },
    }));

    expect(client.isAuthenticated()).toBe(false);
  });
});
