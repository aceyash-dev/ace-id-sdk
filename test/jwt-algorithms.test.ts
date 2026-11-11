import { describe, expect, it } from 'vitest';
import { SignJWT } from 'jose';
import {
  DEFAULT_ALLOWED_SIGNING_ALGORITHMS,
  resolveSigningAlgorithms,
  verifyIdToken,
} from '../src/core/jwt.js';
import { AIDTokenError } from '../src/core/errors.js';
import { startOidcFixture } from './helpers/oidc-fixture.js';

describe('resolveSigningAlgorithms', () => {
  it('narrows the allowlist to what the provider advertises', () => {
    expect(resolveSigningAlgorithms(['RS256'])).toEqual(['RS256']);
  });

  it('uses the full allowlist when the provider advertises nothing', () => {
    expect(resolveSigningAlgorithms(undefined)).toEqual([...DEFAULT_ALLOWED_SIGNING_ALGORITHMS]);
  });

  it('never widens the allowlist from provider metadata', () => {
    expect(resolveSigningAlgorithms(['RS256', 'HS256', 'none'])).toEqual(['RS256']);
  });

  it('refuses when no advertised algorithm is acceptable', () => {
    expect(() => resolveSigningAlgorithms(['HS256'])).toThrow(AIDTokenError);
    expect(() => resolveSigningAlgorithms(['none'])).toThrow(/signing algorithm/i);
  });

  it('drops symmetric algorithms from a caller allowlist', () => {
    expect(resolveSigningAlgorithms(undefined, ['HS256', 'ES256'])).toEqual(['ES256']);
    expect(() => resolveSigningAlgorithms(undefined, ['HS256'])).toThrow(AIDTokenError);
  });
});

describe('verifyIdToken algorithm policy', () => {
  it('rejects a token whose algorithm is outside the allowlist', async () => {
    const fixture = await startOidcFixture();
    try {
      const idToken = await fixture.signIdToken({});
      await expect(verifyIdToken({
        idToken,
        jwksUri: fixture.jwksUrl,
        issuer: fixture.issuer,
        audience: 'client-1',
        nonce: 'nonce-1',
        algorithms: ['ES256'],
      })).rejects.toThrow(AIDTokenError);
    } finally {
      await fixture.close();
    }
  });

  it('rejects an unsigned (alg: none) token', async () => {
    const fixture = await startOidcFixture();
    try {
      const unsigned = [
        Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url'),
        Buffer.from(JSON.stringify({
          iss: fixture.issuer, aud: 'client-1', sub: 'attacker', exp: Math.floor(Date.now() / 1000) + 600,
        })).toString('base64url'),
        '',
      ].join('.');
      await expect(verifyIdToken({
        idToken: unsigned,
        jwksUri: fixture.jwksUrl,
        issuer: fixture.issuer,
        audience: 'client-1',
      })).rejects.toThrow(AIDTokenError);
    } finally {
      await fixture.close();
    }
  });

  it('rejects a token signed with a shared secret (HS256)', async () => {
    const fixture = await startOidcFixture();
    try {
      const forged = await new SignJWT({ sub: 'attacker' })
        .setProtectedHeader({ alg: 'HS256', kid: 'k1' })
        .setIssuer(fixture.issuer)
        .setAudience('client-1')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(new TextEncoder().encode('a-shared-secret-that-is-long-enough'));

      await expect(verifyIdToken({
        idToken: forged,
        jwksUri: fixture.jwksUrl,
        issuer: fixture.issuer,
        audience: 'client-1',
      })).rejects.toThrow(AIDTokenError);
    } finally {
      await fixture.close();
    }
  });

  it('accepts a correctly signed token', async () => {
    const fixture = await startOidcFixture();
    try {
      const idToken = await fixture.signIdToken({});
      const claims = await verifyIdToken({
        idToken,
        jwksUri: fixture.jwksUrl,
        issuer: fixture.issuer,
        audience: 'client-1',
        nonce: 'nonce-1',
      });
      expect(claims.sub).toBe('user-1');
    } finally {
      await fixture.close();
    }
  });
});
