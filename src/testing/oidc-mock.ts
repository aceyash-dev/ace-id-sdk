import type { OIDCDiscoveryDocument } from '../core/discovery.js';

export interface MockOIDCOptions {
  issuer?: string;
  user?: Record<string, unknown>;
  accessTokenExpiresIn?: number;
  refreshToken?: string;
  rotateRefreshTokens?: boolean;
  failTokenExchange?: boolean;
  failRefresh?: boolean;
  clock?: () => number;
}

export interface MockOIDCIssuer {
  issuer: string;
  discovery: OIDCDiscoveryDocument;
  fetch: typeof fetch;
  requests: Array<{ url: string; method: string; body?: string }>;
  setFailures(failures: { tokenExchange?: boolean; refresh?: boolean }): void;
}

/** Deterministic fetch-compatible issuer for SDK tests. Tokens are test fixtures, never cryptographically valid ID tokens. */
export function createMockOIDCIssuer(options: MockOIDCOptions = {}): MockOIDCIssuer {
  const issuer = (options.issuer ?? 'https://issuer.test').replace(/\/+$/, '');
  const requests: MockOIDCIssuer['requests'] = [];
  let tokenExchangeFailure = options.failTokenExchange ?? false;
  let refreshFailure = options.failRefresh ?? false;
  let refreshGeneration = 0;
  const now = options.clock ?? Date.now;
  const discovery: OIDCDiscoveryDocument = {
    issuer,
    authorization_endpoint: issuer + '/authorize',
    token_endpoint: issuer + '/token',
    userinfo_endpoint: issuer + '/userinfo',
    jwks_uri: issuer + '/jwks',
    end_session_endpoint: issuer + '/logout',
    revocation_endpoint: issuer + '/revoke',
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    id_token_signing_alg_values_supported: ['RS256'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
  };

  const fetchMock: typeof fetch = async (input, init = {}) => {
    const request = input instanceof Request ? input : undefined;
    const url = request ? request.url : String(input);
    const method = (init.method ?? request?.method ?? 'GET').toUpperCase();
    const signal = init.signal === undefined ? request?.signal : init.signal;
    if (signal?.aborted) {
      throw signal.reason ?? new DOMException('The operation was aborted.', 'AbortError');
    }
    const headers = new Headers(request?.headers);
    if (init.headers !== undefined) {
      new Headers(init.headers).forEach((value, key) => headers.set(key, value));
    }
    const requestBody = init.body !== undefined
      ? init.body
      : request && method !== 'GET' && method !== 'HEAD' ? await request.clone().text() : undefined;
    const body = typeof requestBody === 'string'
      ? requestBody
      : requestBody instanceof URLSearchParams ? requestBody.toString() : undefined;
    requests.push({ url, method, body });
    const json = (payload: unknown, status = 200) => new Response(JSON.stringify(payload), {
      status,
      headers: { 'content-type': 'application/json' },
    });
    if (url === issuer + '/.well-known/openid-configuration') return json(discovery);
    if (url === issuer + '/token' && method === 'POST') {
      const form = new URLSearchParams(body ?? '');
      if (form.get('grant_type') === 'authorization_code') {
        if (tokenExchangeFailure) return json({ error: 'invalid_grant' }, 400);
        return json({
          access_token: 'mock-access-token',
          id_token: 'mock.id.token',
          refresh_token: options.refreshToken ?? 'mock-refresh-token',
          token_type: 'Bearer',
          expires_in: options.accessTokenExpiresIn ?? 3600,
          scope: 'openid profile email',
        });
      }
      if (form.get('grant_type') === 'refresh_token') {
        if (refreshFailure) return json({ error: 'invalid_grant' }, 400);
        refreshGeneration += 1;
        return json({
          access_token: 'mock-access-token-' + refreshGeneration,
          refresh_token: options.rotateRefreshTokens === false
            ? (options.refreshToken ?? 'mock-refresh-token')
            : 'mock-refresh-token-' + refreshGeneration,
          token_type: 'Bearer',
          expires_in: options.accessTokenExpiresIn ?? 3600,
        });
      }
    }
    if (url === issuer + '/userinfo') {
      const auth = headers.get('authorization');
      if (!auth?.startsWith('Bearer ')) return json({ error: 'unauthorized' }, 401);
      return json(options.user ?? { sub: 'mock-user', email: 'mock@example.test' });
    }
    if (url === issuer + '/revoke' && method === 'POST') return new Response(null, { status: 200 });
    if (url === issuer + '/logout') return new Response(null, { status: 204 });
    if (url === issuer + '/jwks') return json({ keys: [] });
    return json({ error: 'not_found', now: now() }, 404);
  };

  return {
    issuer,
    discovery,
    fetch: fetchMock,
    requests,
    setFailures: (failures) => {
      if (failures.tokenExchange !== undefined) tokenExchangeFailure = failures.tokenExchange;
      if (failures.refresh !== undefined) refreshFailure = failures.refresh;
    },
  };
}
