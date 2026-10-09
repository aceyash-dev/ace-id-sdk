import { fetchDiscovery, normalizeIssuer, type OIDCDiscoveryDocument } from './core/discovery.js';
import { AIDError } from './core/errors.js';

export interface AIDDiagnosticsConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  expectedCallbacks?: string[];
  clockSkewSeconds?: number;
  requestTimeoutMs?: number;
}

export interface AIDDiagnosticsReport {
  ok: boolean;
  checkedAt: string;
  issuer: string;
  clientIdPresent: boolean;
  redirectUri: string;
  checks: Array<{ name: string; status: 'pass' | 'warn' | 'fail'; message: string }>;
  capabilities?: {
    authorizationCode: boolean;
    pkceS256: boolean;
    idTokenSigningAlgorithms: string[];
    userInfoAvailable: boolean;
    logoutAvailable: boolean;
    refreshAdvertised: boolean;
  };
}

/** Produces a redacted report. It never requests tokens or includes secrets/token contents. */
export async function diagnoseAID(config: AIDDiagnosticsConfig): Promise<AIDDiagnosticsReport> {
  const checks: AIDDiagnosticsReport['checks'] = [];
  let normalizedIssuer: string;
  let redirect: URL;
  try {
    normalizedIssuer = normalizeIssuer(config.issuer);
    redirect = new URL(config.redirectUri);
  } catch (error) {
    throw new AIDError('CONFIGURATION_ERROR', 'Diagnostics require valid issuer and absolute redirectUri values', error);
  }

  const local = redirect.hostname === 'localhost' || redirect.hostname === '127.0.0.1';
  const secureRedirect = redirect.protocol === 'https:' || (local && redirect.protocol === 'http:');
  checks.push({
    name: 'redirect-uri',
    status: secureRedirect && !redirect.username && !redirect.password ? 'pass' : 'fail',
    message: secureRedirect && !redirect.username && !redirect.password
      ? 'Redirect URI uses an allowed protocol and contains no URL credentials.'
      : 'Redirect URI must use HTTPS (HTTP localhost only for development) and contain no credentials.',
  });

  const expected = config.expectedCallbacks ?? [];
  const callbackMatches = expected.length === 0 || expected.some((candidate) => {
    try { return new URL(candidate).href === redirect.href; } catch { return false; }
  });
  checks.push({
    name: 'registered-callback',
    status: callbackMatches ? (expected.length ? 'pass' : 'warn') : 'fail',
    message: callbackMatches
      ? expected.length ? 'Redirect URI matches one of the supplied expected callbacks.' : 'No expected callback list supplied; provider registration was not verified.'
      : 'Redirect URI does not match any supplied expected callback.',
  });

  if (config.clockSkewSeconds !== undefined) {
    const valid = Number.isFinite(config.clockSkewSeconds) && config.clockSkewSeconds >= 0 && config.clockSkewSeconds <= 300;
    checks.push({
      name: 'clock-skew',
      status: valid ? 'pass' : 'warn',
      message: valid ? 'Configured clock-skew tolerance is within 0–300 seconds.' : 'Clock-skew tolerance is outside the recommended 0–300 second range.',
    });
  } else {
    checks.push({ name: 'clock-skew', status: 'warn', message: 'Clock-skew tolerance was not supplied; token verification defaults apply.' });
  }

  let discovery: OIDCDiscoveryDocument;
  try {
    discovery = await fetchDiscovery(normalizedIssuer, config.requestTimeoutMs);
    checks.push({ name: 'discovery', status: 'pass', message: 'OIDC discovery succeeded and the issuer and required endpoints validated.' });
  } catch {
    checks.push({ name: 'discovery', status: 'fail', message: 'OIDC discovery failed. Details were omitted to avoid exposing endpoint data or server responses.' });
    return {
      ok: false,
      checkedAt: new Date().toISOString(),
      issuer: normalizedIssuer,
      clientIdPresent: typeof config.clientId === 'string' && config.clientId.trim().length > 0,
      redirectUri: redirect.origin + redirect.pathname,
      checks,
    };
  }

  const responseTypes = discovery.response_types_supported ?? [];
  const methods = discovery.code_challenge_methods_supported ?? [];
  const algorithms = discovery.id_token_signing_alg_values_supported ?? [];
  const authCode = responseTypes.length === 0 || responseTypes.includes('code');
  const pkce = methods.includes('S256');
  checks.push({ name: 'authorization-code', status: authCode ? 'pass' : 'fail', message: authCode ? 'Authorization Code is advertised or response types are unspecified.' : 'Provider metadata does not advertise Authorization Code response support.' });
  checks.push({ name: 'pkce-s256', status: pkce ? 'pass' : 'warn', message: pkce ? 'Provider metadata advertises S256 PKCE.' : 'Provider metadata does not advertise S256 PKCE; runtime policy still requires S256.' });
  checks.push({ name: 'jwks', status: discovery.jwks_uri ? 'pass' : 'fail', message: discovery.jwks_uri ? 'JWKS endpoint is present.' : 'JWKS endpoint is missing; ID-token verification cannot work.' });
  checks.push({ name: 'userinfo', status: discovery.userinfo_endpoint ? 'pass' : 'warn', message: discovery.userinfo_endpoint ? 'UserInfo endpoint is present.' : 'UserInfo endpoint is not advertised.' });

  return {
    ok: checks.every((check) => check.status !== 'fail'),
    checkedAt: new Date().toISOString(),
    issuer: normalizedIssuer,
    clientIdPresent: typeof config.clientId === 'string' && config.clientId.trim().length > 0,
    redirectUri: redirect.origin + redirect.pathname,
    checks,
    capabilities: {
      authorizationCode: authCode,
      pkceS256: pkce,
      idTokenSigningAlgorithms: algorithms.filter((algorithm) => /^[A-Za-z0-9_-]{1,32}$/.test(algorithm)),
      userInfoAvailable: Boolean(discovery.userinfo_endpoint),
      logoutAvailable: Boolean(discovery.end_session_endpoint),
      refreshAdvertised: (discovery.grant_types_supported ?? []).includes('refresh_token'),
    },
  };
}
