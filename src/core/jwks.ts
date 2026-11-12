import { createRemoteJWKSet } from 'jose';

/**
 * Bounded, issuer-keyed cache of remote JWK sets.
 *
 * `jose` caches fetched keys per `createRemoteJWKSet` instance and applies its
 * own cooldown plus refetch-on-unknown-`kid` behaviour, so reusing the instance
 * per JWKS URI is sufficient: keys stay cached, rotation still works, and
 * verification no longer costs a JWKS round trip on every call.
 *
 * The cache key is the JWKS URI rather than the issuer string, which keeps two
 * issuers that happen to share a host — or one issuer with a rotated JWKS
 * location — from reading each other's keys.
 */
export type RemoteJWKSet = ReturnType<typeof createRemoteJWKSet>;

const jwksSets = new Map<string, RemoteJWKSet>();
const MAX_CACHED_JWKS_SETS = 16;

/**
 * How long `jose` waits before re-fetching a key set after an unknown `kid`.
 *
 * The library default is 30s, which delays picking up a rotated signing key by
 * up to half a minute. 5s keeps rotation responsive while still collapsing a
 * burst of unknown-kid failures into a single refetch.
 */
export const DEFAULT_JWKS_COOLDOWN_MS = 5_000;

export interface JwksCacheOptions {
  cooldownMs?: number;
  maxEntries?: number;
  /** Per-request timeout for the underlying key fetch. */
  timeoutMs?: number;
}

/** Return the cached remote JWK set for `jwksUri`, creating it on first use. */
export function jwksFor(jwksUri: string, options: JwksCacheOptions = {}): RemoteJWKSet {
  const cached = jwksSets.get(jwksUri);
  if (cached) return cached;

  const created = createRemoteJWKSet(new URL(jwksUri), {
    cooldownDuration: options.cooldownMs ?? DEFAULT_JWKS_COOLDOWN_MS,
    ...(options.timeoutMs !== undefined ? { timeoutDuration: options.timeoutMs } : {}),
  });
  const limit = options.maxEntries ?? MAX_CACHED_JWKS_SETS;
  if (jwksSets.size >= limit) {
    // Evict the oldest entry; issuers per process are few, so this is a guard
    // against unbounded growth rather than a hot path.
    const oldest = jwksSets.keys().next();
    if (!oldest.done) jwksSets.delete(oldest.value);
  }
  jwksSets.set(jwksUri, created);
  return created;
}

/**
 * Drop the cached key set for one URI, or all of them.
 *
 * Called when a rotated key must be picked up immediately (for example after an
 * unknown-`kid` verification failure outside the cooldown window) or by tests.
 */
export function clearJwksCache(jwksUri?: string): void {
  if (jwksUri === undefined) jwksSets.clear();
  else jwksSets.delete(jwksUri);
}

/** Number of cached key sets; used by diagnostics and tests. */
export function jwksCacheSize(): number {
  return jwksSets.size;
}
