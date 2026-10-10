import { afterEach, describe, expect, it, vi } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';

const ISSUER = 'https://identity.example.test';
const TRANSACTION_KEY = 'aid:transaction';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('OAuth transaction lifecycle', () => {
  it('clears a valid transaction after token exchange fails', async () => {
    const storage = new MemoryStorage();
    storage.set(TRANSACTION_KEY, JSON.stringify({
      state: 'state-value',
      nonce: 'nonce-value',
      codeVerifier: 'v'.repeat(43),
      redirectUri: 'https://app.example.test/callback',
      createdAt: Date.now(),
    }));

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return new Response(JSON.stringify({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/auth`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    }));

    const client = new AID({
      issuer: ISSUER,
      clientId: 'client',
      redirectUri: 'https://app.example.test/callback',
      storage,
    });

    await expect(client.handleCallback(
      'https://app.example.test/callback?code=once&state=state-value',
    )).rejects.toThrow();

    expect(storage.get(TRANSACTION_KEY)).toBeNull();
  });
});
