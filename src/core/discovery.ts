import { AIDDiscoveryError } from './errors.js';

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
  if (typeof issuer !== 'string' || issuer.length === 0) {
    throw new AIDDiscoveryError('Issuer must be a non-empty string');
  }
  let url: URL;
  try {
    url = new URL(issuer);
  } catch (err) {
    throw new AIDDiscoveryError(`Issuer is not a valid URL: ${issuer}`, err);
  }
  const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !isLocalhost) {
    throw new AIDDiscoveryError('Issuer must use HTTPS (localhost/127.0.0.1 exempt for development)');
  }
  url.search = '';
  url.hash = '';
  // Strip trailing slashes on the path
  url.pathname = url.pathname.replace(/\/+$/, '');
  return url.toString().replace(/\/$/, '');
}

export async function fetchDiscovery(issuer: string): Promise<OIDCDiscoveryDocument> {
  const normalized = normalizeIssuer(issuer);
  const url = `${normalized}/.well-known/openid-configuration`;

  let res: Response;
  try {
    res = await fetch(url, { headers: { Accept: 'application/json' } });
  } catch (err) {
    throw new AIDDiscoveryError(`Failed to fetch OIDC discovery document from ${url}`, err);
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

  if (typeof doc.issuer !== 'string' || doc.issuer.length === 0) {
    throw new AIDDiscoveryError('OIDC discovery document is missing "issuer"');
  }
  if (normalizeIssuer(doc.issuer) !== normalized) {
    throw new AIDDiscoveryError(
      `OIDC issuer mismatch: expected ${normalized}, received ${doc.issuer}`,
    );
  }
  if (typeof doc.authorization_endpoint !== 'string' || !doc.authorization_endpoint) {
    throw new AIDDiscoveryError('OIDC discovery document is missing "authorization_endpoint"');
  }
  if (typeof doc.token_endpoint !== 'string' || !doc.token_endpoint) {
    throw new AIDDiscoveryError('OIDC discovery document is missing "token_endpoint"');
  }
  return doc;
}