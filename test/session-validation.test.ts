import { describe, expect, it } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';

const SESSION_KEY = 'aid:session';

function createClient(storage: MemoryStorage): AID {
  return new AID({
    issuer: 'https://id.example.com',
    clientId: 'client-123',
    redirectUri: 'https://app.example.com/callback',
    storage,
  });
}

describe('AID persisted session validation', () => {
  it('returns null and removes malformed JSON', () => {
    const storage = new MemoryStorage();

    storage.set(SESSION_KEY, '{invalid-json');

    const client = createClient(storage);

    expect(client.getSession()).toBeNull();
    expect(storage.get(SESSION_KEY)).toBeNull();
  });

  it('returns null and removes an invalid session shape', () => {
    const storage = new MemoryStorage();

    storage.set(
      SESSION_KEY,
      JSON.stringify({
        user: {
          sub: 'user-123',
        },
      }),
    );

    const client = createClient(storage);

    expect(client.getSession()).toBeNull();
    expect(storage.get(SESSION_KEY)).toBeNull();
  });

  it('returns null when the user subject is missing', () => {
    const storage = new MemoryStorage();

    storage.set(
      SESSION_KEY,
      JSON.stringify({
        user: {},
        tokens: {
          accessToken: 'access-token',
          tokenType: 'Bearer',
        },
      }),
    );

    const client = createClient(storage);

    expect(client.getSession()).toBeNull();
    expect(storage.get(SESSION_KEY)).toBeNull();
  });

  it('returns null when the access token is missing', () => {
    const storage = new MemoryStorage();

    storage.set(
      SESSION_KEY,
      JSON.stringify({
        user: {
          sub: 'user-123',
        },
        tokens: {
          tokenType: 'Bearer',
        },
      }),
    );

    const client = createClient(storage);

    expect(client.getSession()).toBeNull();
    expect(storage.get(SESSION_KEY)).toBeNull();
  });

  it('accepts a valid persisted session', () => {
    const storage = new MemoryStorage();

    const session = {
      user: {
        sub: 'user-123',
      },
      tokens: {
        accessToken: 'access-token',
        tokenType: 'Bearer',
        expiresIn: 3600,
        expiresAt: Date.now() + 3600_000,
        refreshToken: 'refresh-token',
        idToken: 'id-token',
        scope: 'openid profile',
      },
    };

    storage.set(SESSION_KEY, JSON.stringify(session));

    const client = createClient(storage);

    expect(client.getSession()).toEqual(session);
  });
});
