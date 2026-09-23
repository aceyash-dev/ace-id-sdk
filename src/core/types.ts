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
  /**
   * Proposal (additive): how long an in-flight authorization transaction
   * may remain valid before the callback is rejected. Defaults to 10 minutes.
   */
  transactionTtlMs?: number;
}

export interface AIDServerConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
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
  expiresAt?: number;
  scope?: string;
}

export interface AIDSession {
  user: AIDUser;
  tokens: AIDTokens;
  /**
   * Nonce from the original OIDC authentication.
   *
   * Refresh responses may omit nonce, but if they include it,
   * it must match this original authentication nonce.
   */
  nonce?: string;
}

export interface AuthTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  createdAt: number;
  /**
   * Proposal (additive): opaque application-supplied path to return to
   * after a successful callback. The SDK does not follow it — the app does.
   */
  returnTo?: string;
}