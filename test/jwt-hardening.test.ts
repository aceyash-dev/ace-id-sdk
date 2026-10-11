import { describe, expect, it } from 'vitest';
import { validateVerifiedIdTokenClaims } from '../src/core/jwt.js';

const ISSUER = 'https://issuer.example.test';
const CLIENT_ID = 'ace-sdk-test';

function claims(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: 'user-123',
    iat: now,
    exp: now + 300,
    nonce: 'expected',
    auth_time: now - 10,
    ...overrides,
  };
}

const options = {
  issuer: ISSUER,
  audience: CLIENT_ID,
  nonce: 'expected',
  maxAgeSeconds: 60,
};

describe('ID token claim hardening', () => {
  it('accepts a correctly issued token with a recent authentication time', () => {
    expect(() => validateVerifiedIdTokenClaims(claims(), options)).not.toThrow();
  });

  it('requires a valid iat and rejects future-issued tokens', () => {
    expect(() => validateVerifiedIdTokenClaims(claims({ iat: undefined }), options))
      .toThrow(/iat/i);
    expect(() => validateVerifiedIdTokenClaims(claims({
      iat: Math.floor(Date.now() / 1000) + 120,
    }), options)).toThrow(/future/i);
  });

  it('enforces auth_time for max_age and rejects stale authentication', () => {
    expect(() => validateVerifiedIdTokenClaims(claims({
      auth_time: Math.floor(Date.now() / 1000) - 600,
    }), options)).toThrow(/exceeds the requested max_age/i);
  });

  it('requires auth_time when max_age was requested', () => {
    expect(() => validateVerifiedIdTokenClaims(claims({ auth_time: undefined }), options))
      .toThrow(/auth_time/i);
  });

  it('rejects a mismatched authorized party and multiple audiences without azp', () => {
    expect(() => validateVerifiedIdTokenClaims(claims({ azp: 'another-client' }), options))
      .toThrow(/authorized party/i);
    expect(() => validateVerifiedIdTokenClaims(claims({
      aud: [CLIENT_ID, 'another-client'],
    }), options)).toThrow(/multiple audiences/i);
  });

  it('requires nonce on initial authentication', () => {
    expect(() => validateVerifiedIdTokenClaims(claims({ nonce: 'wrong' }), options))
      .toThrow(/nonce mismatch/i);
  });
});
