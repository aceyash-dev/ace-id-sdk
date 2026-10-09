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
  expiresAt?: number;
  scope?: string;
}

export interface AIDSession {
  user: AIDUser;
  tokens: AIDTokens;
  /** Nonce from the original OIDC authentication; refresh ID tokens may omit it. */
  nonce?: string;
}

export interface AuthTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  createdAt: number;
  /** Opaque app-supplied value; the SDK does not navigate to it automatically. */
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
