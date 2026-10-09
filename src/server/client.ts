import { normalizeTokens, userFromClaims } from '../core/claims.js';
import {
  fetchDiscovery,
  normalizeIssuer,
  type OIDCDiscoveryDocument,
} from '../core/discovery.js';
import {
  AIDAuthenticationError,
  AIDError,
  AIDDiscoveryError,
  AIDTokenError,
} from '../core/errors.js';
import { withRequestTimeout, DEFAULT_REQUEST_TIMEOUT_MS } from '../core/http.js';
import type { AIDServerConfig, AIDTokens, AIDUser } from '../core/types.js';

interface ResolvedServerConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  requestTimeoutMs: number;
}

export class AIDServer {
  private readonly config: ResolvedServerConfig;
  private discoveryPromise?: Promise<OIDCDiscoveryDocument>;

  constructor(config: AIDServerConfig) {
    if (!config || typeof config !== 'object') {
      throw new AIDError('CONFIGURATION_ERROR', 'AIDServer requires a configuration object');
    }
    if (typeof config.issuer !== 'string' || !config.issuer.trim()) {
      throw new AIDError('CONFIGURATION_ERROR', 'config.issuer is required');
    }
    if (typeof config.clientId !== 'string' || !config.clientId.trim()) {
      throw new AIDError('CONFIGURATION_ERROR', 'config.clientId is required');
    }
    if (typeof config.clientSecret !== 'string' || !config.clientSecret) {
      throw new AIDError('CONFIGURATION_ERROR', 'config.clientSecret is required');
    }

    const requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
      throw new AIDError('CONFIGURATION_ERROR', 'requestTimeoutMs must be a positive finite number');
    }
    this.config = {
      issuer: normalizeIssuer(config.issuer),
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scope: config.scope ?? 'openid profile email',
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

  async discovery(): Promise<OIDCDiscoveryDocument> {
    return this.getDiscovery();
  }

  async exchangeCode(
    code: string,
    redirectUri: string,
    opts: { codeVerifier?: string } = {},
  ): Promise<AIDTokens> {
    if (!code) throw new AIDError('CONFIGURATION_ERROR', 'authorization code is required');
    validateRedirectUri(redirectUri);

    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
    });
    if (opts.codeVerifier) body.set('code_verifier', opts.codeVerifier);

    const basic = base64Basic(this.config.clientId, this.config.clientSecret);
    const { response, payload } = await requestJson(
      discovery.token_endpoint,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          Authorization: `Basic ${basic}`,
        },
        body: body.toString(),
      },
      this.config.requestTimeoutMs,
      'Token endpoint request failed',
    );

    if (!response.ok) {
      const code_ = typeof payload.error === 'string' ? payload.error : `HTTP ${response.status}`;
      const desc = typeof payload.error_description === 'string' ? ` (${payload.error_description})` : '';
      throw new AIDTokenError(
        `Token endpoint error: ${code_}${desc}`,
        undefined,
        typeof payload.error === 'string' ? payload.error : undefined,
      );
    }
    try {
      return normalizeTokens(payload);
    } catch (err) {
      throw new AIDTokenError('Invalid token response', err);
    }
  }

  async userInfo(accessToken: string): Promise<AIDUser> {
    if (!accessToken) throw new AIDAuthenticationError('accessToken is required');
    const discovery = await this.getDiscovery();
    if (!discovery.userinfo_endpoint) {
      throw new AIDDiscoveryError('Discovery document is missing "userinfo_endpoint"');
    }

    const { response, payload } = await requestJson(
      discovery.userinfo_endpoint,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
      },
      this.config.requestTimeoutMs,
      'UserInfo request failed',
      true,
    );
    if (!response.ok) {
      throw new AIDAuthenticationError(`UserInfo request failed: HTTP ${response.status}`);
    }
    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new AIDAuthenticationError('UserInfo response is missing "sub"');
    }
    return userFromClaims(payload);
  }
}

async function requestJson(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  errorMessage: string,
  authenticationError = false,
): Promise<{ response: Response; payload: Record<string, unknown> }> {
  const timeout = withRequestTimeout(timeoutMs);
  try {
    const response = await fetch(url, {
      ...init,
      signal: timeout.signal,
      cache: 'no-store',
    });

    let value: unknown;
    try {
      value = await response.json();
    } catch (err) {
      if (authenticationError) {
        throw new AIDAuthenticationError(`${errorMessage}: invalid JSON response`, err);
      }
      throw new AIDTokenError(`${errorMessage}: invalid JSON response`, err);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      if (authenticationError) throw new AIDAuthenticationError('UserInfo response must be a JSON object');
      throw new AIDTokenError('Token endpoint response must be a JSON object');
    }
    return { response, payload: value as Record<string, unknown> };
  } catch (err) {
    if (err instanceof AIDTokenError || err instanceof AIDAuthenticationError) throw err;
    if (authenticationError) throw new AIDAuthenticationError(errorMessage, err);
    throw new AIDTokenError(errorMessage, err);
  } finally {
    timeout.dispose();
  }
}

function validateRedirectUri(value: string): void {
  let uri: URL;
  try {
    uri = new URL(value);
  } catch (err) {
    throw new AIDError('CONFIGURATION_ERROR', 'redirectUri must be an absolute URL', err);
  }
  const local = uri.hostname === 'localhost' || uri.hostname === '127.0.0.1';
  if ((uri.protocol !== 'https:' && !(local && uri.protocol === 'http:')) ||
      uri.username || uri.password) {
    throw new AIDError(
      'CONFIGURATION_ERROR',
      'redirectUri must use HTTPS (HTTP localhost is allowed for development) and must not contain credentials',
    );
  }
}

function base64Basic(clientId: string, clientSecret: string): string {
  const raw = `${clientId}:${clientSecret}`;
  if (typeof btoa === 'function') return btoa(raw);
  return Buffer.from(raw, 'utf8').toString('base64');
}
