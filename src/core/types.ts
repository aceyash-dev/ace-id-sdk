import type { AIDLogSink } from './logging.js';

export interface AIDStorage {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

export interface AIDConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  storage?: AIDStorage;
  /** Lifetime of an in-flight authorization transaction. Defaults to 10 minutes. */
  transactionTtlMs?: number;
  /** Network request timeout in milliseconds. Defaults to 10 seconds. */
  requestTimeoutMs?: number;
  /**
   * How long a fetched discovery document is reused. Defaults to 5 minutes;
   * `0` disables caching and refetches on every flow.
   */
  discoveryCacheTtlMs?: number;
  /**
   * Refresh the access token shortly before it expires and emit the resulting
   * session state. Defaults to `false`; `getValidAccessToken()` refreshes on
   * demand regardless.
   */
  autoRefresh?: boolean;
  /** Seconds before expiry at which a token counts as expiring. Defaults to 60. */
  leewaySeconds?: number;
  /** Clock skew tolerated when verifying ID token times, in seconds. Defaults to 60. */
  clockSkewSeconds?: number;
  /** Additional attempts for retry-safe requests. Defaults to 2; `0` disables. */
  maxRetries?: number;
  /** Emit debug-level log entries. Defaults to false. */
  debug?: boolean;
  /** Receives redacted log entries. Without one, the SDK logs nothing. */
  logger?: AIDLogSink;
  /** Extra origins a `returnTo` target may use, e.g. `['https://app.example.com']`. */
  additionalRedirectOrigins?: string[];
  /** Narrow the accepted ID token signing algorithms (asymmetric only). */
  allowedSigningAlgorithms?: string[];
  /** Prefix for storage keys. Defaults to `aid`, giving keys such as `aid:session`. */
  storageKeyPrefix?: string;
  /**
   * Minimum interval between token refreshes that happen only because the token
   * endpoint omitted `expires_in`. Defaults to 60 seconds.
   *
   * The SDK never invents an expiry for such a token; this bounds how often it
   * re-requests one so an unreported lifetime cannot cause a refresh storm or
   * invalidate a rotating refresh token.
   */
  unknownExpiryRefreshIntervalMs?: number;
}

/** Optional OIDC hints for step-up and risk-based authorization. */
export interface AIDAuthorizationOptions {
  prompt?: string | string[];
  loginHint?: string;
  /** Maximum authentication age in seconds; zero requests fresh authentication. */
  maxAge?: number;
  acrValues?: string[];
  uiLocales?: string[];
  additionalParameters?: Record<string, string>;
}

export interface AIDServerConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  /** Network request timeout in milliseconds. Defaults to 10 seconds. */
  requestTimeoutMs?: number;
  /** Additional attempts for retry-safe requests. Defaults to 2; `0` disables. */
  maxRetries?: number;
  /** Emit debug-level log entries. Defaults to false. */
  debug?: boolean;
  /** Receives redacted log entries. Without one, the SDK logs nothing. */
  logger?: AIDLogSink;
}

export interface AIDUser {
  sub: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  middleName?: string;
  nickname?: string;
  preferredUsername?: string;
  username?: string;
  email?: string;
  emailVerified?: boolean;
  picture?: string;
  locale?: string;
  [key: string]: unknown;
}

export interface AIDTokens {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  tokenType: string;
  expiresIn?: number;
  /**
   * Absolute expiry, set only when the provider reported `expires_in`.
   *
   * Left undefined when the token endpoint omitted `expires_in`: the SDK does not
   * fabricate a lifetime. Use `obtainedAt` plus the refresh policy instead.
   */
  expiresAt?: number;
  /** When the SDK received this token (epoch milliseconds). */
  obtainedAt?: number;
  scope?: string;
}

export interface AIDSession {
  user: AIDUser;
  tokens: AIDTokens;
  /** Nonce from the original OIDC authentication; refresh ID tokens may omit it. */
  nonce?: string;
}

/**
 * Result of a successful authorization callback.
 *
 * `returnTo` echoes the same-origin target supplied to `signIn({ returnTo })`.
 * Navigating there remains the host application's responsibility; the SDK never
 * redirects on its own after a callback.
 */
export interface AIDCallbackResult extends AIDSession {
  returnTo?: string;
}

export interface AuthTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  createdAt: number;
  /** Requested maximum authentication age, enforced against the verified ID token's auth_time. */
  maxAgeSeconds?: number;
  /**
   * Validated, same-origin target supplied to `signIn({ returnTo })`.
   *
   * Consumed by `handleCallback()` and returned on its result. The SDK never
   * navigates to it automatically; the host application decides when to.
   */
  returnTo?: string;
}

export interface AIDProjectConfig {
  issuer: string;
  app_id: string;
  client_id: string;
  redirect_uri: string;
  scopes: string[];
  project_type?: string;
  framework?: string;
  sdk?: string;
}
