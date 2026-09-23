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
import type { AIDServerConfig, AIDTokens, AIDUser } from '../core/types.js';

interface ResolvedServerConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scope: string;
}

export class AIDServer {
  private readonly config: ResolvedServerConfig;
  private discoveryPromise?: Promise<OIDCDiscoveryDocument>;

  constructor(config: AIDServerConfig) {
    if (!config || typeof config !== 'object') {
      throw new AIDError('CONFIGURATION_ERROR', 'AIDServer requires a configuration object');
    }
    if (!config.issuer) throw new AIDError('CONFIGURATION_ERROR', 'config.issuer is required');
    if (!config.clientId) throw new AIDError('CONFIGURATION_ERROR', 'config.clientId is required');
    if (!config.clientSecret) {
      throw new AIDError('CONFIGURATION_ERROR', 'config.clientSecret is required');
    }
    this.config = {
      issuer: normalizeIssuer(config.issuer),
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scope: config.scope ?? 'openid profile email',
    };
  }

  private getDiscovery(): Promise<OIDCDiscoveryDocument> {
    if (!this.discoveryPromise) {
      this.discoveryPromise = fetchDiscovery(this.config.issuer).catch((err) => {
        this.discoveryPromise = undefined;
        throw err;
      });
    }
    return this.discoveryPromise;
  }

  /** Expose the discovery document read-only for callers that need it. */
  async discovery(): Promise<OIDCDiscoveryDocument> {
    return this.getDiscovery();
  }

  /**
   * Exchange an authorization code for tokens using confidential client
   * authentication (HTTP Basic, client_secret_basic).
   */
  async exchangeCode(
    code: string,
    redirectUri: string,
    opts: { codeVerifier?: string } = {},
  ): Promise<AIDTokens> {
    if (!code) throw new AIDError('CONFIGURATION_ERROR', 'authorization code is required');
    if (!redirectUri) throw new AIDError('CONFIGURATION_ERROR', 'redirectUri is required');

    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
    });
    if (opts.codeVerifier) body.set('code_verifier', opts.codeVerifier);

    const basic = base64Basic(this.config.clientId, this.config.clientSecret);

    let res: Response;
    try {
      res = await fetch(discovery.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          Authorization: `Basic ${basic}`,
        },
        body: body.toString(),
      });
    } catch (err) {
      throw new AIDTokenError('Token endpoint request failed', err);
    }

    const text = await res.text();
    let json: Record<string, unknown>;
    try {
      json = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    } catch (err) {
      throw new AIDTokenError(`Token endpoint returned non-JSON (HTTP ${res.status})`, err);
    }
    if (!res.ok) {
      const code_ = typeof json.error === 'string' ? json.error : `HTTP ${res.status}`;
      const desc =
        typeof json.error_description === 'string' ? ` — ${json.error_description}` : '';
      throw new AIDTokenError(`Token endpoint error: ${code_}${desc}`);
    }

    try {
      return normalizeTokens(json);
    } catch (err) {
      throw new AIDTokenError((err as Error).message, err);
    }
  }

  async userInfo(accessToken: string): Promise<AIDUser> {
    if (!accessToken) throw new AIDAuthenticationError('accessToken is required');
    const discovery = await this.getDiscovery();
    if (!discovery.userinfo_endpoint) {
      throw new AIDDiscoveryError('Discovery document is missing "userinfo_endpoint"');
    }

    let res: Response;
    try {
      res = await fetch(discovery.userinfo_endpoint, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
      });
    } catch (err) {
      throw new AIDAuthenticationError('UserInfo request failed', err);
    }
    if (!res.ok) {
      throw new AIDAuthenticationError(`UserInfo request failed: HTTP ${res.status}`);
    }
    const json = (await res.json()) as Record<string, unknown>;
    if (typeof json.sub !== 'string') {
      throw new AIDAuthenticationError('UserInfo response is missing "sub"');
    }
    return userFromClaims(json);
  }
}

function base64Basic(clientId: string, clientSecret: string): string {
  const raw = `${clientId}:${clientSecret}`;
  if (typeof btoa === 'function') return btoa(raw);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (globalThis as any).Buffer.from(raw, 'utf8').toString('base64');
}