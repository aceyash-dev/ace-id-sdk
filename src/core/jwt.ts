import { jwtVerify, type JWTPayload } from 'jose';
import type { OIDCDiscoveryDocument } from './discovery.js';
import { AIDTokenError } from './errors.js';
import { clearJwksCache, jwksFor } from './jwks.js';

export { clearJwksCache, jwksCacheSize, jwksFor } from './jwks.js';

/**
 * Signing algorithms the SDK will accept when the caller does not narrow them.
 *
 * This is an allowlist of asymmetric algorithms only. `none` is never accepted,
 * and HMAC algorithms (HS*) are refused because a client secret must never be
 * used as a signing key: a token signed with a shared secret proves nothing
 * about the issuer.
 */
export const DEFAULT_ALLOWED_SIGNING_ALGORITHMS: readonly string[] = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
];

const ASYMMETRIC_ALGORITHM = /^(RS|PS|ES)\d{3}$|^EdDSA$/;

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
  /** Signing algorithms accepted for this token. Defaults to the asymmetric allowlist. */
  algorithms?: readonly string[];
}

export interface VerifyIdTokenWithDiscoveryOptions
  extends Omit<VerifyIdTokenOptions, 'jwksUri' | 'issuer' | 'algorithms'> {
  discovery: OIDCDiscoveryDocument;
  /** Extra algorithms to intersect with the provider metadata. */
  algorithms?: readonly string[];
}

/**
 * Resolve the algorithms to accept from provider metadata and an allowlist.
 *
 * Provider metadata narrows the allowlist; it can never widen it. A provider
 * that advertises only an algorithm this SDK refuses is a configuration error,
 * not a silent downgrade, so the intersection is checked for emptiness.
 */
export function resolveSigningAlgorithms(
  advertised: unknown,
  allowed: readonly string[] = DEFAULT_ALLOWED_SIGNING_ALGORITHMS,
): string[] {
  const allowlist = allowed.filter((algorithm) => ASYMMETRIC_ALGORITHM.test(algorithm));
  if (allowlist.length === 0) {
    throw new AIDTokenError(
      'No acceptable ID token signing algorithm is configured; only asymmetric algorithms are supported',
    );
  }
  if (!Array.isArray(advertised) || advertised.length === 0) return allowlist;

  const intersection = advertised.filter(
    (algorithm): algorithm is string => typeof algorithm === 'string' && allowlist.includes(algorithm),
  );
  if (intersection.length === 0) {
    throw new AIDTokenError(
      'The identity provider does not advertise an ID token signing algorithm this SDK accepts',
    );
  }
  return intersection;
}

export async function verifyIdToken(opts: VerifyIdTokenOptions): Promise<JWTPayload> {
  const algorithms = opts.algorithms ?? DEFAULT_ALLOWED_SIGNING_ALGORITHMS;
  let payload: JWTPayload;
  try {
    const jwks = jwksFor(opts.jwksUri);
    const { payload: verified } = await jwtVerify(opts.idToken, jwks, {
      issuer: opts.issuer,
      audience: opts.audience,
      clockTolerance: opts.clockToleranceSeconds ?? 60,
      algorithms: [...algorithms],
    });
    payload = verified;
  } catch (err) {
    throw new AIDTokenError('ID token verification failed', err, undefined, {
      retryable: isKeyFetchFailure(err),
    });
  }

  validateVerifiedIdTokenClaims(payload, opts);
  return payload;
}

/**
 * Verify an ID token using endpoints and algorithms from a discovery document.
 *
 * Keeping this in one place means every entry point (browser, server, refresh)
 * applies the same issuer, JWKS and algorithm policy instead of each one
 * re-deriving it.
 */
export async function verifyIdTokenWithDiscovery(
  opts: VerifyIdTokenWithDiscoveryOptions,
): Promise<JWTPayload> {
  const { discovery, algorithms, ...rest } = opts;
  if (!discovery.jwks_uri) {
    throw new AIDTokenError('Discovery document is missing "jwks_uri" required to verify the ID token');
  }
  return verifyIdToken({
    ...rest,
    jwksUri: discovery.jwks_uri,
    issuer: discovery.issuer,
    algorithms: resolveSigningAlgorithms(discovery.id_token_signing_alg_values_supported, algorithms),
  });
}

export function validateVerifiedIdTokenClaims(
  payload: JWTPayload,
  opts: Pick<VerifyIdTokenOptions, 'issuer' | 'audience' | 'nonce' | 'nonceRequired' | 'clockToleranceSeconds' | 'maxAgeSeconds'>,
): void {
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
}

/** True when a verification failure looks like a key-fetch problem worth retrying. */
function isKeyFetchFailure(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code === 'string') {
    return code === 'ERR_JWKS_TIMEOUT' || code === 'ERR_JWKS_INVALID' || code === 'ERR_JOSE_GENERIC';
  }
  return false;
}
