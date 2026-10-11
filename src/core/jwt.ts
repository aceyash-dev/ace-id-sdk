import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { AIDTokenError } from './errors.js';

export interface VerifyIdTokenOptions {
  idToken: string;
  jwksUri: string;
  issuer: string;
  audience: string;
  nonce?: string;
  /**
   * Whether nonce must be present when an expected nonce is supplied.
   *
   * Initial authentication requires nonce. Refresh responses may omit it.
   */
  nonceRequired?: boolean;
  /** Clock skew tolerance in seconds. Defaults to 60. */
  clockToleranceSeconds?: number;
  /** Requested OIDC max_age in seconds; requires a recent auth_time claim. */
  maxAgeSeconds?: number;
}

export async function verifyIdToken(opts: VerifyIdTokenOptions): Promise<JWTPayload> {
  let payload: JWTPayload;
  try {
    const jwks = createRemoteJWKSet(new URL(opts.jwksUri));
    const { payload: verified } = await jwtVerify(opts.idToken, jwks, {
      issuer: opts.issuer,
      audience: opts.audience,
      clockTolerance: opts.clockToleranceSeconds ?? 60,
    });
    payload = verified;
  } catch (err) {
    throw new AIDTokenError('ID token verification failed', err);
  }

  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new AIDTokenError('ID token is missing "sub" claim');
  }
  if (typeof payload.exp !== 'number') {
    throw new AIDTokenError('ID token is missing "exp" claim');
  }
  if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat)) {
    throw new AIDTokenError('ID token is missing a valid "iat" claim');
  }
  const tolerance = opts.clockToleranceSeconds ?? 60;
  const now = Date.now() / 1000;
  if (payload.iat > now + tolerance) {
    throw new AIDTokenError('ID token "iat" claim is in the future');
  }
  if (payload.azp !== undefined && payload.azp !== opts.audience) {
    throw new AIDTokenError('ID token authorized party does not match this client');
  }
  if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== opts.audience) {
    throw new AIDTokenError('ID token with multiple audiences must identify this client as authorized party');
  }
  if (opts.maxAgeSeconds !== undefined) {
    if (!Number.isSafeInteger(opts.maxAgeSeconds) || opts.maxAgeSeconds < 0) {
      throw new AIDTokenError('Requested max_age must be a non-negative safe integer');
    }
    if (typeof payload.auth_time !== 'number' || !Number.isFinite(payload.auth_time)) {
      throw new AIDTokenError('ID token is missing a valid "auth_time" claim required by max_age');
    }
    if (payload.auth_time > now + tolerance || now - payload.auth_time > opts.maxAgeSeconds + tolerance) {
      throw new AIDTokenError('ID token authentication time exceeds the requested max_age');
    }
  }
  if (opts.nonce !== undefined) {
    if (payload.nonce === undefined) {
      if (opts.nonceRequired ?? true) {
        throw new AIDTokenError('ID token nonce mismatch');
      }
    } else if (
      typeof payload.nonce !== 'string' ||
      payload.nonce !== opts.nonce
    ) {
      throw new AIDTokenError('ID token nonce mismatch');
    }
  }
  return payload;
}