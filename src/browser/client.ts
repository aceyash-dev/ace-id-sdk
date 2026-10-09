import { normalizeTokens, userFromClaims } from '../core/claims.js';
import {
  fetchDiscovery,
  normalizeIssuer,
  type OIDCDiscoveryDocument,
} from '../core/discovery.js';
import {
  AIDCallbackError,
  AIDDiscoveryError,
  AIDError,
  AIDTokenError,
  AIDAuthenticationError,
} from '../core/errors.js';
import { withRequestTimeout, DEFAULT_REQUEST_TIMEOUT_MS } from '../core/http.js';
import { verifyIdToken } from '../core/jwt.js';
import {
  isTokenExpired,
  normalizeTokenResponse,
  type TokenResponse,
} from '../core/tokens.js';
import type {
  AIDConfig,
  AIDSession,
  AIDStorage,
  AIDTokens,
  AIDUser,
  AuthTransaction,
} from '../core/types.js';
import { parseCallback } from './callback.js';
import { createCodeChallenge, createCodeVerifier, randomString } from './pkce.js';
import { SessionStorage } from './storage.js';

const TRANSACTION_KEY = 'aid:transaction';
const SESSION_KEY = 'aid:session';
const DEFAULT_SCOPE = 'openid profile email';
const DEFAULT_TRANSACTION_TTL_MS = 10 * 60 * 1000;
const DEFAULT_TOKEN_LEEWAY_SECONDS = 60;

interface ResolvedAIDConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  storage: AIDStorage;
  transactionTtlMs: number;
  requestTimeoutMs: number;
}

export class AID {
  private readonly config: ResolvedAIDConfig;
  private discoveryPromise?: Promise<OIDCDiscoveryDocument>;
  private refreshPromise?: Promise<AIDSession>;

  constructor(config: AIDConfig) {
    if (!config || typeof config !== 'object') {
      throw new AIDError('CONFIGURATION_ERROR', 'AID constructor requires a configuration object');
    }
    if (typeof config.issuer !== 'string' || !config.issuer.trim()) {
      throw new AIDError('CONFIGURATION_ERROR', 'config.issuer is required');
    }
    if (typeof config.clientId !== 'string' || !config.clientId.trim()) {
      throw new AIDError('CONFIGURATION_ERROR', 'config.clientId is required');
    }
    if (typeof config.redirectUri !== 'string' || !config.redirectUri.trim()) {
      throw new AIDError('CONFIGURATION_ERROR', 'config.redirectUri is required');
    }

    let redirectUrl: URL;
    try {
      redirectUrl = new URL(config.redirectUri);
    } catch (err) {
      throw new AIDError('CONFIGURATION_ERROR', 'config.redirectUri must be an absolute URL', err);
    }
    const isLocalRedirect =
      redirectUrl.hostname === 'localhost' || redirectUrl.hostname === '127.0.0.1';
    if (
      (redirectUrl.protocol !== 'https:' && !(isLocalRedirect && redirectUrl.protocol === 'http:')) ||
      redirectUrl.username ||
      redirectUrl.password
    ) {
      throw new AIDError(
        'CONFIGURATION_ERROR',
        'config.redirectUri must use HTTPS (HTTP localhost is allowed for development) and must not contain credentials',
      );
    }

    const transactionTtlMs = config.transactionTtlMs ?? DEFAULT_TRANSACTION_TTL_MS;
    const requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    if (!Number.isFinite(transactionTtlMs) || transactionTtlMs <= 0) {
      throw new AIDError('CONFIGURATION_ERROR', 'transactionTtlMs must be a positive finite number');
    }
    if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
      throw new AIDError('CONFIGURATION_ERROR', 'requestTimeoutMs must be a positive finite number');
    }

    this.config = {
      issuer: normalizeIssuer(config.issuer),
      clientId: config.clientId,
      redirectUri: redirectUrl.toString(),
      scope: config.scope ?? DEFAULT_SCOPE,
      storage: config.storage ?? new SessionStorage(),
      transactionTtlMs,
      requestTimeoutMs,
    };
  }

  private getDiscovery(): Promise<OIDCDiscoveryDocument> {
    if (!this.discoveryPromise) {
      this.discoveryPromise = fetchDiscovery(this.config.issuer, this.config.requestTimeoutMs)
        .catch((err) => {
          this.discoveryPromise = undefined;
          throw err;
        });
    }
    return this.discoveryPromise;
  }

  async signIn(options: { returnTo?: string } = {}): Promise<void> {
    const discovery = await this.getDiscovery();
    const state = randomString(32);
    const nonce = randomString(32);
    const codeVerifier = createCodeVerifier();
    const codeChallenge = await createCodeChallenge(codeVerifier);
    const transaction: AuthTransaction = {
      state,
      nonce,
      codeVerifier,
      redirectUri: this.config.redirectUri,
      createdAt: Date.now(),
      returnTo: options.returnTo,
    };

    try {
      this.config.storage.set(TRANSACTION_KEY, JSON.stringify(transaction));
    } catch (err) {
      throw new AIDError('STORAGE_ERROR', 'Failed to persist authorization transaction', err);
    }

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scope,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });
    redirectTo(`${discovery.authorization_endpoint}?${params.toString()}`);
  }

  async handleCallback(url?: string): Promise<AIDSession> {
    const params = parseCallback(url ?? getCurrentUrl());
    if (params.error) {
      this.clearTransaction();
      throw new AIDCallbackError(
        `Authorization error: ${params.error}` +
          (params.errorDescription ? ` — ${params.errorDescription}` : ''),
      );
    }
    if (!params.code || !params.state) {
      throw new AIDCallbackError('Callback is missing "code" or "state" parameter');
    }

    const transaction = this.loadTransaction();
    if (!transaction) {
      throw new AIDCallbackError(
        'No authorization transaction found — the flow may have expired or been tampered with',
      );
    }
    if (!Number.isFinite(transaction.createdAt) ||
        transaction.createdAt > Date.now() ||
        Date.now() - transaction.createdAt > this.config.transactionTtlMs) {
      this.clearTransaction();
      throw new AIDCallbackError('Authorization transaction has expired or is invalid');
    }
    if (!transaction.state || !transaction.nonce || !transaction.codeVerifier ||
        !transaction.redirectUri || !timingSafeEqual(transaction.state, params.state)) {
      this.clearTransaction();
      throw new AIDCallbackError('OAuth state mismatch or invalid authorization transaction');
    }

    try {
      const discovery = await this.getDiscovery();
      const tokens = await exchangeCodeForTokens({
        tokenEndpoint: discovery.token_endpoint,
        clientId: this.config.clientId,
        code: params.code,
        redirectUri: transaction.redirectUri,
        codeVerifier: transaction.codeVerifier,
        timeoutMs: this.config.requestTimeoutMs,
      });
      if (!tokens.idToken) throw new AIDTokenError('Token response is missing "id_token"');
      if (!discovery.jwks_uri) {
        throw new AIDDiscoveryError('Discovery document is missing "jwks_uri" (required to verify the ID token)');
      }

      const claims = await verifyIdToken({
        idToken: tokens.idToken,
        jwksUri: discovery.jwks_uri,
        issuer: discovery.issuer,
        audience: this.config.clientId,
        nonce: transaction.nonce,
      });
      const session: AIDSession = {
        user: userFromClaims(claims as Record<string, unknown>),
        tokens,
        nonce: transaction.nonce,
      };
      this.saveSession(session);
      return session;
    } finally {
      this.clearTransaction();
    }
  }

  getSession(): AIDSession | null {
    const raw = this.config.storage.get(SESSION_KEY);
    if (!raw) return null;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (!isValidSession(parsed)) {
        this.config.storage.remove(SESSION_KEY);
        return null;
      }
      return parsed;
    } catch {
      this.config.storage.remove(SESSION_KEY);
      return null;
    }
  }

  isAuthenticated(): boolean {
    const session = this.getSession();
    if (!session) return false;
    const expiresAt = session.tokens.expiresAt;
    return typeof expiresAt !== 'number' || Date.now() < expiresAt;
  }

  getUser(): AIDUser | null {
    return this.getSession()?.user ?? null;
  }

  /** Synchronous getter; does not perform a network request. */
  getAccessToken(): string | null {
    return this.getSession()?.tokens.accessToken ?? null;
  }

  /** Concurrent calls share the same refresh operation. */
  async refresh(): Promise<AIDSession> {
    if (this.refreshPromise) return this.refreshPromise;
    this.refreshPromise = this.performRefresh();
    try {
      return await this.refreshPromise;
    } finally {
      this.refreshPromise = undefined;
    }
  }

  /** Return a usable access token and refresh it when expired or near expiry. */
  async getValidAccessToken(leewaySeconds = DEFAULT_TOKEN_LEEWAY_SECONDS): Promise<string | null> {
    if (!Number.isFinite(leewaySeconds) || leewaySeconds < 0) {
      throw new AIDError('CONFIGURATION_ERROR', 'leewaySeconds must be a non-negative finite number');
    }
    const session = this.getSession();
    if (!session) return null;
    if (!isTokenExpired(session.tokens, leewaySeconds)) return session.tokens.accessToken;
    if (!session.tokens.refreshToken) {
      this.clearSession();
      return null;
    }
    return (await this.refresh()).tokens.accessToken;
  }

  async signOut(options: { redirectTo?: string } = {}): Promise<void> {
    const session = this.getSession();
    this.config.storage.remove(SESSION_KEY);
    this.config.storage.remove(TRANSACTION_KEY);

    const safeRedirect = options.redirectTo
      ? validateRedirectTarget(options.redirectTo, this.config.redirectUri)
      : undefined;
    let endSession: string | undefined;
    try {
      const discovery = await this.getDiscovery();
      if (discovery.revocation_endpoint && session?.tokens.refreshToken) {
        try {
          await revokeToken({
            revocationEndpoint: discovery.revocation_endpoint,
            clientId: this.config.clientId,
            token: session.tokens.refreshToken,
            tokenTypeHint: 'refresh_token',
            timeoutMs: this.config.requestTimeoutMs,
          });
        } catch {
          // Local logout must not depend on remote revocation.
        }
      }
      endSession = discovery.end_session_endpoint;
    } catch {
      endSession = undefined;
    }

    if (endSession) {
      const params = new URLSearchParams();
      if (session?.tokens.idToken) params.set('id_token_hint', session.tokens.idToken);
      if (safeRedirect) params.set('post_logout_redirect_uri', safeRedirect);
      const query = params.toString();
      redirectTo(query ? `${endSession}?${query}` : endSession);
      return;
    }
    if (safeRedirect) redirectTo(safeRedirect);
  }

  private async performRefresh(): Promise<AIDSession> {
    const session = this.getSession();
    if (!session) throw new AIDAuthenticationError('No authenticated session exists');
    if (!session.tokens.refreshToken) {
      this.clearSession();
      throw new AIDAuthenticationError('The current session does not contain a refresh token');
    }

    const discovery = await this.getDiscovery();
    if (!discovery.grant_types_supported?.includes('refresh_token')) {
      throw new AIDAuthenticationError('The identity provider does not advertise refresh_token support');
    }

    let tokens: AIDTokens;
    try {
      tokens = await refreshTokens({
        tokenEndpoint: discovery.token_endpoint,
        clientId: this.config.clientId,
        refreshToken: session.tokens.refreshToken,
        scope: session.tokens.scope,
        timeoutMs: this.config.requestTimeoutMs,
      });
    } catch (err) {
      if (isInvalidRefreshTokenError(err)) this.clearSession();
      throw err;
    }

    let user = session.user;
    if (tokens.idToken) {
      if (!discovery.jwks_uri) {
        throw new AIDDiscoveryError('Discovery document is missing "jwks_uri" required to verify the refreshed ID token');
      }
      const claims = await verifyIdToken({
        idToken: tokens.idToken,
        jwksUri: discovery.jwks_uri,
        issuer: discovery.issuer,
        audience: this.config.clientId,
        nonce: session.nonce,
        nonceRequired: false,
      });
      if (typeof claims.sub !== 'string' || claims.sub !== session.user.sub) {
        throw new AIDTokenError('Refreshed ID token subject does not match the current session');
      }
      user = userFromClaims(claims as Record<string, unknown>);
    } else if (session.tokens.idToken) {
      tokens.idToken = session.tokens.idToken;
    }

    const refreshedSession: AIDSession = { user, tokens, nonce: session.nonce };
    this.saveSession(refreshedSession);
    return refreshedSession;
  }

  private saveSession(session: AIDSession): void {
    try {
      this.config.storage.set(SESSION_KEY, JSON.stringify(session));
    } catch (err) {
      throw new AIDError('STORAGE_ERROR', 'Failed to persist session', err);
    }
  }

  private clearSession(): void {
    this.config.storage.remove(SESSION_KEY);
  }

  private loadTransaction(): AuthTransaction | null {
    const raw = this.config.storage.get(TRANSACTION_KEY);
    if (!raw) return null;
    try {
      const value: unknown = JSON.parse(raw);
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        this.clearTransaction();
        return null;
      }
      const transaction = value as Record<string, unknown>;
      if (
        typeof transaction.state !== 'string' ||
        typeof transaction.nonce !== 'string' ||
        typeof transaction.codeVerifier !== 'string' ||
        typeof transaction.redirectUri !== 'string' ||
        typeof transaction.createdAt !== 'number'
      ) {
        this.clearTransaction();
        return null;
      }
      return transaction as unknown as AuthTransaction;
    } catch {
      this.clearTransaction();
      return null;
    }
  }

  private clearTransaction(): void {
    this.config.storage.remove(TRANSACTION_KEY);
  }
}

interface ExchangeOpts {
  tokenEndpoint: string;
  clientId: string;
  code: string;
  redirectUri: string;
  codeVerifier: string;
  timeoutMs: number;
}

async function exchangeCodeForTokens(opts: ExchangeOpts): Promise<AIDTokens> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: opts.code,
    redirect_uri: opts.redirectUri,
    client_id: opts.clientId,
    code_verifier: opts.codeVerifier,
  });
  const json = await postFormJson(opts.tokenEndpoint, body, 'Token endpoint request failed', opts.timeoutMs);
  return parseTokenResponse(json.response, json.payload);
}

interface RefreshOpts {
  tokenEndpoint: string;
  clientId: string;
  refreshToken: string;
  scope?: string;
  timeoutMs: number;
}

async function refreshTokens(opts: RefreshOpts): Promise<AIDTokens> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: opts.refreshToken,
    client_id: opts.clientId,
  });
  if (opts.scope) body.set('scope', opts.scope);
  const result = await postFormJson(opts.tokenEndpoint, body, 'Token refresh request failed', opts.timeoutMs);
  return parseTokenResponse(result.response, result.payload, opts.refreshToken);
}

interface RevokeTokenOpts {
  revocationEndpoint: string;
  clientId: string;
  token: string;
  tokenTypeHint?: 'access_token' | 'refresh_token';
  timeoutMs: number;
}

async function revokeToken(opts: RevokeTokenOpts): Promise<void> {
  const body = new URLSearchParams({ token: opts.token, client_id: opts.clientId });
  if (opts.tokenTypeHint) body.set('token_type_hint', opts.tokenTypeHint);
  const result = await postFormJson(
    opts.revocationEndpoint,
    body,
    'Token revocation request failed',
    opts.timeoutMs,
  );
  if (!result.response.ok) {
    throw new AIDTokenError(`Token revocation request failed: HTTP ${result.response.status}`);
  }
}

async function postFormJson(
  url: string,
  body: URLSearchParams,
  errorMessage: string,
  timeoutMs: number,
): Promise<{ response: Response; payload: Record<string, unknown> }> {
  const timeout = withRequestTimeout(timeoutMs);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: body.toString(),
      signal: timeout.signal,
      cache: 'no-store',
    });
    const payload = await readResponseJson(response);
    return { response, payload };
  } catch (err) {
    if (err instanceof AIDTokenError) throw err;
    throw new AIDTokenError(errorMessage, err);
  } finally {
    timeout.dispose();
  }
}

async function readResponseJson(res: Response): Promise<Record<string, unknown>> {
  const text = await res.text();
  let value: unknown;
  try {
    value = text ? JSON.parse(text) as unknown : {};
  } catch (err) {
    throw new AIDTokenError(`Token endpoint returned non-JSON response (HTTP ${res.status})`, err);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new AIDTokenError('Token endpoint response must be a JSON object');
  }
  return value as Record<string, unknown>;
}

function validateRedirectTarget(target: string, redirectUri: string): string {
  let candidate: URL;
  let callback: URL;
  try {
    candidate = new URL(target);
    callback = new URL(redirectUri);
  } catch (err) {
    throw new AIDError('CONFIGURATION_ERROR', 'signOut redirectTo must be an absolute URL', err);
  }
  if (candidate.protocol !== 'https:' &&
      !(candidate.protocol === 'http:' &&
        (candidate.hostname === 'localhost' || candidate.hostname === '127.0.0.1'))) {
    throw new AIDError('CONFIGURATION_ERROR', 'signOut redirectTo must use HTTPS');
  }
  if (candidate.username || candidate.password) {
    throw new AIDError('CONFIGURATION_ERROR', 'signOut redirectTo must not contain credentials');
  }
  if (candidate.origin !== callback.origin) {
    throw new AIDError('CONFIGURATION_ERROR', 'signOut redirectTo must share the registered redirect URI origin');
  }
  return candidate.toString();
}

function isValidSession(value: unknown): value is AIDSession {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const session = value as Record<string, unknown>;
  if (!session.user || typeof session.user !== 'object' || Array.isArray(session.user)) return false;
  const user = session.user as Record<string, unknown>;
  if (typeof user.sub !== 'string' || user.sub.length === 0) return false;
  if (!session.tokens || typeof session.tokens !== 'object' || Array.isArray(session.tokens)) return false;
  const tokens = session.tokens as Record<string, unknown>;
  if (typeof tokens.accessToken !== 'string' || tokens.accessToken.length === 0) return false;
  if (typeof tokens.tokenType !== 'string' || tokens.tokenType.length === 0) return false;
  if (tokens.expiresIn !== undefined && (
    typeof tokens.expiresIn !== 'number' || !Number.isFinite(tokens.expiresIn) || tokens.expiresIn < 0
  )) return false;
  if (tokens.expiresAt !== undefined && (
    typeof tokens.expiresAt !== 'number' || !Number.isFinite(tokens.expiresAt)
  )) return false;
  if (tokens.refreshToken !== undefined && (
    typeof tokens.refreshToken !== 'string' || tokens.refreshToken.length === 0
  )) return false;
  if (tokens.idToken !== undefined && typeof tokens.idToken !== 'string') return false;
  if (tokens.scope !== undefined && typeof tokens.scope !== 'string') return false;
  return true;
}

function isInvalidRefreshTokenError(err: unknown): boolean {
  return err instanceof AIDTokenError && err.error === 'invalid_grant';
}

function parseTokenResponse(
  res: Response,
  json: Record<string, unknown>,
  previousRefreshToken?: string,
): AIDTokens {
  if (!res.ok) {
    const code = typeof json.error === 'string' ? json.error : `HTTP ${res.status}`;
    const desc = typeof json.error_description === 'string' ? ` — ${json.error_description}` : '';
    throw new AIDTokenError(
      `Token endpoint error: ${code}${desc}`,
      undefined,
      typeof json.error === 'string' ? json.error : undefined,
    );
  }
  if (typeof json.access_token !== 'string' || json.access_token.length === 0) {
    throw new AIDTokenError('Token response did not contain a valid access_token');
  }
  try {
    return normalizeTokenResponse(json as unknown as TokenResponse, previousRefreshToken);
  } catch (err) {
    if (err instanceof AIDError) throw err;
    throw new AIDTokenError('Invalid token response', err);
  }
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function getCurrentUrl(): string {
  if (typeof globalThis.location === 'undefined') {
    throw new AIDCallbackError('handleCallback requires an explicit URL argument in non-browser environments');
  }
  return globalThis.location.href;
}

function redirectTo(url: string): void {
  if (typeof globalThis.location === 'undefined') {
    throw new AIDError('CONFIGURATION_ERROR', 'signIn/signOut require a browser environment (window.location)');
  }
  globalThis.location.assign(url);
}
