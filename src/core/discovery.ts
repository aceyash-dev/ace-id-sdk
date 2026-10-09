import { AIDDiscoveryError } from './errors.js';
import { withRequestTimeout } from './http.js';

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

  const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !isLocalhost) {
    throw new AIDDiscoveryError(
      'Issuer must use HTTPS (localhost/127.0.0.1 exempt for development)',
    );
  }

  url.search = '';
  url.hash = '';
  url.pathname = url.pathname.replace(/\/+$/, '');
  return url.toString().replace(/\/$/, '');
}

export async function fetchDiscovery(
  issuer: string,
  timeoutMs?: number,
): Promise<OIDCDiscoveryDocument> {
  const normalized = normalizeIssuer(issuer);
  const url = `${normalized}/.well-known/openid-configuration`;
  const timeout = withRequestTimeout(timeoutMs);

  let res: Response;
  try {
    res = await fetch(url, {
      headers: { Accept: 'application/json' },
      signal: timeout.signal,
      cache: 'no-store',
    });
  } catch (err) {
    throw new AIDDiscoveryError(
      `Failed to fetch OIDC discovery document from ${url}`,
      err,
    );
  } finally {
    timeout.dispose();
  }

  if (!res.ok) {
    throw new AIDDiscoveryError(`OIDC discovery request failed: HTTP ${res.status}`);
  }

  let doc: OIDCDiscoveryDocument;
  try {
    doc = (await res.json()) as OIDCDiscoveryDocument;
  } catch (err) {
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
  if (doc.userinfo_endpoint !== undefined) {
    validateEndpoint(doc.userinfo_endpoint, 'userinfo_endpoint', normalized);
  }
  if (doc.jwks_uri !== undefined) {
    validateEndpoint(doc.jwks_uri, 'jwks_uri', normalized);
  }
  if (doc.revocation_endpoint !== undefined) {
    validateEndpoint(doc.revocation_endpoint, 'revocation_endpoint', normalized);
  }
  if (doc.end_session_endpoint !== undefined) {
    validateEndpoint(doc.end_session_endpoint, 'end_session_endpoint', normalized);
  }

  return doc;
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
}
