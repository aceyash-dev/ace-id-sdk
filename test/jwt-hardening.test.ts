import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { verifyIdToken } from '../src/core/jwt.js';

const ISSUER = 'https://issuer.example.test';
const CLIENT_ID = 'ace-sdk-test';
const JWKS_URI = `${ISSUER}/jwks`;
let privateKey: CryptoKey;
let publicJwk: Record<string, unknown>;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  publicJwk = {
    ...(await exportJWK(pair.publicKey)),
    kid: 'test-key',
    alg: 'RS256',
    use: 'sig',
  };
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function signToken(claims: Record<string, unknown> = {}, audience: string | string[] = CLIENT_ID) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    auth_time: now - 10,
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setSubject('user-123')
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
}

function mockJwks(): void {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ keys: [publicJwk] }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })));
}

describe('ID token claim hardening', () => {
  it('accepts a recent authentication when max_age is requested', async () => {
    mockJwks();
    const token = await signToken();
    await expect(verifyIdToken({
      idToken: token, jwksUri: JWKS_URI, issuer: ISSUER, audience: CLIENT_ID,
      nonce: 'expected', maxAgeSeconds: 60,
    })).rejects.toThrow(/nonce mismatch/i);
  });

  it('enforces auth_time for max_age and rejects stale authentication', async () => {
    mockJwks();
    const now = Math.floor(Date.now() / 1000);
    const token = await signToken({ auth_time: now - 600, nonce: 'expected' });
    await expect(verifyIdToken({
      idToken: token, jwksUri: JWKS_URI, issuer: ISSUER, audience: CLIENT_ID,
      nonce: 'expected', maxAgeSeconds: 30,
    })).rejects.toThrow(/exceeds the requested max_age/i);
  });

  it('requires auth_time when max_age was requested', async () => {
    mockJwks();
    const token = await signToken({ auth_time: undefined, nonce: 'expected' });
    await expect(verifyIdToken({
      idToken: token, jwksUri: JWKS_URI, issuer: ISSUER, audience: CLIENT_ID,
      nonce: 'expected', maxAgeSeconds: 0,
    })).rejects.toThrow(/auth_time/i);
  });

  it('rejects a mismatched authorized party and multiple audiences without azp', async () => {
    mockJwks();
    const wrongAzp = await signToken({ nonce: 'expected', azp: 'another-client' });
    await expect(verifyIdToken({
      idToken: wrongAzp, jwksUri: JWKS_URI, issuer: ISSUER, audience: CLIENT_ID,
      nonce: 'expected',
    })).rejects.toThrow(/authorized party/i);

    const multipleAudiences = await signToken({ nonce: 'expected' }, [CLIENT_ID, 'another-client']);
    await expect(verifyIdToken({
      idToken: multipleAudiences, jwksUri: JWKS_URI, issuer: ISSUER, audience: CLIENT_ID,
      nonce: 'expected',
    })).rejects.toThrow(/multiple audiences/i);
  });
});
