import { AIDDiscoveryError } from './errors.js';
import {
  DEFAULT_MAX_RESPONSE_BYTES,
  ResponseSizeError,
  fetchWithRetry,
  isRetryableNetworkError,
  isRetryableStatus,
  readBoundedText,
  type RetryPolicy,
} from './http.js';
import { SingleFlight } from './single-flight.js';

export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  end_session_endpoint?: string;
  revocation_endpoint?: string;
  code_challenge_methods_supported?: string[];
  response_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  scopes_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  grant_types_supported?: string[];
  [key: string]: unknown;
}

export function normalizeIssuer(issuer: string): string {
  if (typeof issuer !== 'string' || issuer.trim().length === 0) {
    throw new AIDDiscoveryError('Issuer must be a non-empty string');
  }

  let url: URL;
  try {
    url = new URL(issuer);
  } catch (err) {
    throw new AIDDiscoveryError('Issuer is not a valid URL', err);
  }

  if (url.username || url.password) {
    throw new AIDDiscoveryError('Issuer URL must not contain user information');
  }

  if (url.search || url.hash) {
    throw new AIDDiscoveryError('Issuer URL must not contain a query string or fragment');
  }

  const isLocalhost = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname.toLowerCase());
  if (url.protocol !== 'https:' && !(isLocalhost && url.protocol === 'http:')) {
    throw new AIDDiscoveryError(
      'Issuer must use HTTPS (HTTP localhost/127.0.0.1 exempt for development)',
    );
  }

  url.pathname = url.pathname.replace(/\/+$/, '');
  return url.toString().replace(/\/$/, '');
}

export interface FetchDiscoveryOptions {
  /** Retry policy for the discovery GET. Pass `false` to disable retries. */
  retry?: Partial<RetryPolicy> | false;
  /** Caller cancellation, propagated to the request. */
  signal?: AbortSignal;
}

export async function fetchDiscovery(
  issuer: string,
  timeoutMs?: number,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  options: FetchDiscoveryOptions = {},
): Promise<OIDCDiscoveryDocument> {
  const normalized = normalizeIssuer(issuer);
  const url = `${normalized}/.well-known/openid-configuration`;

  let res: Response;
  try {
    // A discovery GET is idempotent, so it is safe to retry transient failures.
    res = await fetchWithRetry(url, { headers: { Accept: 'application/json' } }, {
      timeoutMs,
      retry: options.retry,
      ...(options.signal ? { signal: options.signal } : {}),
    });
  } catch (err) {
    throw new AIDDiscoveryError(
      `Failed to fetch OIDC discovery document from ${url}`,
      err,
      { retryable: isRetryableNetworkError(err) },
    );
  }

  if (!res.ok) {
    throw new AIDDiscoveryError(`OIDC discovery request failed: HTTP ${res.status}`, undefined, {
      retryable: isRetryableStatus(res.status),
    });
  }

  let doc: OIDCDiscoveryDocument;
  try {
    // Bounded read: discovery documents are small, so an oversized body is
    // either a misconfiguration or an attempt to exhaust client memory.
    const text = await readBoundedText(res, maxResponseBytes);
    doc = JSON.parse(text) as OIDCDiscoveryDocument;
  } catch (err) {
    if (err instanceof ResponseSizeError) {
      throw new AIDDiscoveryError(
        `OIDC discovery document exceeds the ${maxResponseBytes}-byte limit`,
        err,
      );
    }
    throw new AIDDiscoveryError('OIDC discovery document is not valid JSON', err);
  }

  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new AIDDiscoveryError('OIDC discovery document must be a JSON object');
  }
  if (typeof doc.issuer !== 'string' || doc.issuer.length === 0) {
    throw new AIDDiscoveryError('OIDC discovery document is missing "issuer"');
  }
  if (normalizeIssuer(doc.issuer) !== normalized) {
    throw new AIDDiscoveryError(
      `OIDC issuer mismatch: expected ${normalized}, received ${doc.issuer}`,
    );
  }

  validateEndpoint(doc.authorization_endpoint, 'authorization_endpoint', normalized);
  validateEndpoint(doc.token_endpoint, 'token_endpoint', normalized);
  if (doc.userinfo_endpoint !== undefined) validateEndpoint(doc.userinfo_endpoint, 'userinfo_endpoint', normalized);
  if (doc.jwks_uri !== undefined) validateEndpoint(doc.jwks_uri, 'jwks_uri', normalized);
  if (doc.revocation_endpoint !== undefined) validateEndpoint(doc.revocation_endpoint, 'revocation_endpoint', normalized);
  if (doc.end_session_endpoint !== undefined) validateEndpoint(doc.end_session_endpoint, 'end_session_endpoint', normalized);
  return doc;
}

/** How long a discovery document is reused by default. */
export const DEFAULT_DISCOVERY_CACHE_TTL_MS = 5 * 60 * 1000;

export interface DiscoveryCacheOptions {
  /** Reuse window. `0` disables caching and refetches every call. */
  ttlMs?: number;
  /** Per-request timeout. */
  timeoutMs?: number;
  /** Retry policy for cache misses. */
  retry?: Partial<RetryPolicy> | false;
  /** Injectable clock, for deterministic expiry tests. */
  now?: () => number;
}

/**
 * Time-bounded, issuer-isolated discovery cache with single-flight misses.
 *
 * Entries are keyed by the *normalised issuer*, so a cache shared by several
 * clients cannot serve one issuer's endpoints to another. Concurrent misses for
 * the same issuer share one request: a burst of sign-ins at cold start must not
 * produce a burst of discovery calls.
 */
export class DiscoveryCache {
  private readonly entries = new Map<string, { doc: OIDCDiscoveryDocument; expiresAt: number }>();
  private readonly flights = new SingleFlight();
  private readonly ttlMs: number;
  private readonly timeoutMs: number | undefined;
  private readonly retry: Partial<RetryPolicy> | false | undefined;
  private readonly now: () => number;

  constructor(options: DiscoveryCacheOptions = {}) {
    this.ttlMs = options.ttlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS;
    if (!Number.isFinite(this.ttlMs) || this.ttlMs < 0) {
      throw new AIDDiscoveryError('discoveryCacheTtlMs must be a non-negative finite number');
    }
    this.timeoutMs = options.timeoutMs;
    this.retry = options.retry;
    this.now = options.now ?? Date.now;
  }

  /** Cached document for `issuer`, fetching it when absent or expired. */
  async get(issuer: string, options: { forceRefresh?: boolean } = {}): Promise<OIDCDiscoveryDocument> {
    const normalized = normalizeIssuer(issuer);
    const cached = this.entries.get(normalized);
    if (!options.forceRefresh && cached && cached.expiresAt > this.now()) {
      return cached.doc;
    }

    return this.flights.run(normalized, async () => {
      const doc = await fetchDiscovery(normalized, this.timeoutMs, undefined, {
        ...(this.retry !== undefined ? { retry: this.retry } : {}),
      });
      if (this.ttlMs > 0) {
        this.entries.set(normalized, { doc, expiresAt: this.now() + this.ttlMs });
      }
      return doc;
    });
  }

  /** Drop one issuer's entry, or every entry. */
  clear(issuer?: string): void {
    if (issuer === undefined) {
      this.entries.clear();
      this.flights.clear();
      return;
    }
    this.entries.delete(normalizeIssuer(issuer));
  }

  /** Number of cached issuers; used by diagnostics and tests. */
  get size(): number {
    return this.entries.size;
  }
}

function validateEndpoint(
  endpoint: unknown,
  name: string,
  issuer: string,
): asserts endpoint is string {
  if (typeof endpoint !== 'string' || endpoint.length === 0) {
    throw new AIDDiscoveryError(`OIDC discovery document is missing "${name}"`);
  }

  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch (err) {
    throw new AIDDiscoveryError(`OIDC discovery "${name}" is not a valid URL`, err);
  }

  const issuerUrl = new URL(issuer);
  const allowsHttpLocalhost =
    issuerUrl.hostname === 'localhost' || issuerUrl.hostname === '127.0.0.1';
  if (
    parsed.protocol !== 'https:' &&
    !(allowsHttpLocalhost && parsed.protocol === 'http:' &&
      (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'))
  ) {
    throw new AIDDiscoveryError(`OIDC discovery "${name}" must use HTTPS`);
  }
  if (parsed.username || parsed.password) {
    throw new AIDDiscoveryError(`OIDC discovery "${name}" must not contain user information`);
  }
  // OAuth/OIDC endpoint URIs must not contain fragments. A fragment also causes
  // browser query parameters to be interpreted client-side instead of sent to the OP.
  if (endpoint.includes('#') || parsed.hash) {
    throw new AIDDiscoveryError(`OIDC discovery "${name}" must not contain a fragment`);
  }
}

/**
 * Process-wide discovery cache.
 *
 * The SDK never uses it implicitly: a client owns its own cache so tests and
 * multi-tenant processes stay isolated. Long-running servers that want one
 * fetch per issuer across many clients can pass this instance in explicitly.
 */
export const sharedDiscoveryCache = new DiscoveryCache();

/** Drop every entry in the shared cache. */
export function clearDiscoveryCache(): void {
  sharedDiscoveryCache.clear();
}
