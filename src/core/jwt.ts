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