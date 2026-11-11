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
