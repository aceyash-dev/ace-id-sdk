import { afterEach, describe, expect, it, vi } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';
import { fetchDiscovery } from '../src/core/discovery.js';
import { AIDDiscoveryError, AIDTokenError } from '../src/core/errors.js';

const ISSUER = 'https://identity.example.test';
const LIMIT = 1024;

function discoveryDoc(): Record<string, unknown> {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/jwks`,
  };
}

function streamedBody(totalBytes: number): ReadableStream<Uint8Array> {
  const chunk = new Uint8Array(256).fill(0x20);
  let sent = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= totalBytes) {
        controller.close();
        return;
      }
      sent += chunk.byteLength;
      controller.enqueue(chunk);
    },
  });
}

describe('bounded discovery parsing', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('rejects a discovery document whose declared length exceeds the limit', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify(discoveryDoc()), {
          status: 200,
          headers: { 'content-type': 'application/json', 'content-length': String(LIMIT * 8) },
        }),
      ),
    );

    await expect(fetchDiscovery(ISSUER, 5_000, LIMIT)).rejects.toBeInstanceOf(AIDDiscoveryError);
  });

  it('rejects a streamed discovery document that exceeds the limit without Content-Length', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(streamedBody(LIMIT * 8), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );

    await expect(fetchDiscovery(ISSUER, 5_000, LIMIT)).rejects.toThrow(/byte limit/);
  });

  it('still parses a discovery document within the limit', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify(discoveryDoc()), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );

    const doc = await fetchDiscovery(ISSUER, 5_000, LIMIT);
    expect(doc.token_endpoint).toBe(`${ISSUER}/token`);
  });

  it('rejects a token response that exceeds the token body limit', async () => {
    const storage = new MemoryStorage();
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

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return new Response(
          JSON.stringify({
            ...discoveryDoc(),
            grant_types_supported: ['authorization_code', 'refresh_token'],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(streamedBody(2 * 1024 * 1024), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    const aid = new AID({
      issuer: ISSUER,
      clientId: 'client',
      redirectUri: 'https://app.example.test/cb',
      storage,
    });

    await expect(aid.getValidAccessToken()).rejects.toBeInstanceOf(AIDTokenError);
  });
});
