import { afterEach, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { clearJwksCache, jwksFor, verifyIdToken } from '../src/core/jwt.js';
import { startOidcFixture, type OidcFixture } from './helpers/oidc-fixture.js';

const CLIENT_ID = 'client-1';
const NONCE = 'nonce-1';

describe('remote JWKS caching', () => {
  let fixture: OidcFixture | undefined;

  afterEach(async () => {
    vi.useRealTimers();
    clearJwksCache();
    vi.restoreAllMocks();
    await fixture?.close();
    fixture = undefined;
  });

  it('reuses one remote key set per JWKS URI', () => {
    clearJwksCache();
    const first = jwksFor('https://issuer.example.test/jwks');
    const second = jwksFor('https://issuer.example.test/jwks');
    const other = jwksFor('https://issuer.example.test/other-jwks');

    expect(second).toBe(first);
    expect(other).not.toBe(first);
  });

  it('clears the cache on demand', () => {
    clearJwksCache();
    const first = jwksFor('https://issuer.example.test/jwks');
    clearJwksCache();
    expect(jwksFor('https://issuer.example.test/jwks')).not.toBe(first);
  });

  it('fetches the JWKS once for repeated verifications', async () => {
    clearJwksCache();
    fixture = await startOidcFixture({ clientId: CLIENT_ID, nonce: NONCE });

    const options = {
      jwksUri: fixture.jwksUrl,
      issuer: fixture.issuer,
      audience: CLIENT_ID,
      nonce: NONCE,
    };

    for (let i = 0; i < 3; i += 1) {
      const payload = await verifyIdToken({
        ...options,
        idToken: await fixture.signIdToken({ attempt: i }),
      });
      expect(payload.sub).toBe('user-1');
    }

    expect(fixture.jwksFetches()).toBe(1);
  });

  it('picks up a rotated signing key once the refetch cooldown has elapsed', async () => {
    // Only `Date` is faked: real timers keep the loopback HTTP server responsive.
    vi.useFakeTimers({ toFake: ['Date'] });
    clearJwksCache();
    fixture = await startOidcFixture({ clientId: CLIENT_ID, nonce: NONCE });

    const options = {
      jwksUri: fixture.jwksUrl,
      issuer: fixture.issuer,
      audience: CLIENT_ID,
      nonce: NONCE,
    };

    await verifyIdToken({ ...options, idToken: await fixture.signIdToken({}) });
    expect(fixture.jwksFetches()).toBe(1);

    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const rotatedJwk = await exportJWK(publicKey);
    fixture.setJwks({ keys: [{ ...rotatedJwk, kid: 'k2', alg: 'RS256', use: 'sig' }] });

    const rotatedToken = await new SignJWT({ sub: 'user-1', nonce: NONCE })
      .setProtectedHeader({ alg: 'RS256', kid: 'k2' })
      .setIssuer(fixture.issuer)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    vi.setSystemTime(Date.now() + 6_000);

    const payload = await verifyIdToken({ ...options, idToken: rotatedToken });

    expect(payload.sub).toBe('user-1');
    expect(fixture.jwksFetches()).toBe(2);
  });
});
