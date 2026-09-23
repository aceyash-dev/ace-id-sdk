import { describe, expect, it, vi } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';
import type { AIDSession } from '../src/core/types.js';

const SESSION_KEY = 'aid:session';
const DISCOVERY_URL =
  'https://id.example.com/.well-known/openid-configuration';
const TOKEN_URL = 'https://id.example.com/token';

function createSession(): AIDSession {
  return {
    user: {
      sub: 'user-123',
    },
    tokens: {
      accessToken: 'expired-access-token',
      tokenType: 'Bearer',
      expiresAt: Date.now() - 10_000,
      refreshToken: 'refresh-token',
      idToken: 'id-token',
    },
  };
}

function createClient(storage: MemoryStorage): AID {
  return new AID({
    issuer: 'https://id.example.com',
    clientId: 'client-123',
    redirectUri: 'https://app.example.com/callback',
    storage,
  });
}

function discoveryResponse(): Response {
  return new Response(
    JSON.stringify({
      issuer: 'https://id.example.com',
      authorization_endpoint:
        'https://id.example.com/authorize',
      token_endpoint: TOKEN_URL,
      jwks_uri: 'https://id.example.com/jwks',
      grant_types_supported: [
        'authorization_code',
        'refresh_token',
      ],
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
      },
    },
  );
}

function mockFetchWithTokenResponse(
  tokenResponse: Response | Error,
): void {
  vi.spyOn(globalThis, 'fetch').mockImplementation(
    async (input) => {
      const url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;

      if (url === DISCOVERY_URL) {
        return discoveryResponse();
      }

      if (url === TOKEN_URL) {
        if (tokenResponse instanceof Error) {
          throw tokenResponse;
        }

        return tokenResponse;
      }

      throw new Error(`Unexpected fetch URL: ${url}`);
    },
  );
}


describe('AID refresh failure handling', () => {
  it('clears the session when the refresh token is rejected with invalid_grant', async () => {
    const storage = new MemoryStorage();

    storage.set(
      SESSION_KEY,
      JSON.stringify(createSession()),
    );

    mockFetchWithTokenResponse(
      new Response(
        JSON.stringify({
          error: 'invalid_grant',
          error_description: 'Refresh token is invalid',
        }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      ),
    );

    const client = createClient(storage);

    await expect(client.refresh()).rejects.toThrow(
      'Token endpoint error: invalid_grant',
    );

    expect(client.getSession()).toBeNull();

    vi.restoreAllMocks();
  });

  it('preserves the session when the token endpoint returns a server error', async () => {
    const storage = new MemoryStorage();
    const session = createSession();

    storage.set(
      SESSION_KEY,
      JSON.stringify(session),
    );

    mockFetchWithTokenResponse(
      new Response(
        JSON.stringify({
          error: 'server_error',
        }),
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      ),
    );

    const client = createClient(storage);

    await expect(client.refresh()).rejects.toThrow(
      'Token endpoint error',
    );

    expect(client.getSession()).not.toBeNull();

    vi.restoreAllMocks();
  });

  it('preserves the session when the refresh request fails at the network layer', async () => {
    const storage = new MemoryStorage();
    const session = createSession();

    storage.set(
      SESSION_KEY,
      JSON.stringify(session),
    );

    mockFetchWithTokenResponse(
      new TypeError('Network unavailable'),
    );

    const client = createClient(storage);

    await expect(client.refresh()).rejects.toThrow(
      'Token refresh request failed',
    );

    expect(client.getSession()).not.toBeNull();

    vi.restoreAllMocks();
  });

  it('preserves the session for non-invalid-grant OAuth errors', async () => {
    const storage = new MemoryStorage();

    storage.set(
      SESSION_KEY,
      JSON.stringify(createSession()),
    );

    mockFetchWithTokenResponse(
      new Response(
        JSON.stringify({
          error: 'temporarily_unavailable',
        }),
        {
          status: 503,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      ),
    );

    const client = createClient(storage);

    await expect(client.refresh()).rejects.toThrow(
      'Token endpoint error',
    );

    expect(client.getSession()).not.toBeNull();

    vi.restoreAllMocks();
  });
});
