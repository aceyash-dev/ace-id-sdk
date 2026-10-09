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
  const redirectSafe = secureRedirect && !redirect.username && !redirect.password && !redirect.hash;
  checks.push({
    name: 'redirect-uri',
    status: redirectSafe ? 'pass' : 'fail',
    message: redirectSafe
      ? 'Redirect URI uses an allowed protocol and contains no credentials or fragment.'
      : 'Redirect URI must use HTTPS (HTTP localhost only for development) and contain no credentials or fragment.',
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

  const clientIdValid = typeof config.clientId === 'string' && config.clientId.trim().length > 0;
  checks.push({
    name: 'client-id',
    status: clientIdValid ? 'pass' : 'fail',
    message: clientIdValid ? 'A public client ID is configured.' : 'A non-empty public client ID is required.',
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
      clientIdPresent: clientIdValid,
      redirectUri: redirect.origin + redirect.pathname,
      checks,
    };
  }

  const responseTypes = readStringArray(discovery.response_types_supported);
  const methods = readStringArray(discovery.code_challenge_methods_supported);
  const algorithmsResult = readStringArray(discovery.id_token_signing_alg_values_supported);
  const grantTypes = readStringArray(discovery.grant_types_supported);
  const metadataInvalid = responseTypes.invalid || methods.invalid || algorithmsResult.invalid || grantTypes.invalid;
  if (metadataInvalid) {
    checks.push({ name: 'discovery-metadata-arrays', status: 'fail', message: 'Provider metadata contains an invalid value for one or more supported-method arrays.' });
  }

  // An absent response_types_supported field is allowed by OIDC metadata. An explicitly
  // empty list is not evidence that Authorization Code is supported.
  const responseTypeSupportsCode = responseTypes.values === undefined
    ? !responseTypes.invalid && discovery.response_types_supported === undefined
    : responseTypes.values.includes('code');
  const grantSupportsCode = grantTypes.values === undefined
    ? !grantTypes.invalid && discovery.grant_types_supported === undefined
    : grantTypes.values.includes('authorization_code');
  const authCode = responseTypeSupportsCode && grantSupportsCode;
  const pkce = methods.values?.includes('S256') ?? false;
  checks.push({ name: 'authorization-code', status: authCode ? 'pass' : 'fail', message: authCode ? 'Authorization Code response and grant support are advertised or unspecified.' : 'Provider metadata explicitly excludes or invalidates Authorization Code response or grant support.' });
  checks.push({
    name: 'pkce-s256',
    status: methods.invalid ? 'fail' : methods.values === undefined ? 'warn' : pkce ? 'pass' : 'fail',
    message: pkce ? 'Provider metadata advertises S256 PKCE.' : methods.values === undefined && !methods.invalid ? 'Provider metadata does not specify PKCE methods; runtime policy still requires S256.' : 'Provider metadata explicitly does not support the required S256 PKCE method.',
  });
  checks.push({ name: 'id-token-signing-algorithm', status: algorithmsResult.invalid ? 'fail' : algorithmsResult.values === undefined ? 'warn' : algorithmsResult.values.includes('RS256') ? 'pass' : 'fail', message: algorithmsResult.values?.includes('RS256') ? 'Provider metadata advertises the required RS256 ID-token signature algorithm.' : algorithmsResult.values === undefined && !algorithmsResult.invalid ? 'Provider metadata does not specify ID-token signing algorithms.' : 'Provider metadata does not advertise the required RS256 ID-token signature algorithm.' });
  checks.push({ name: 'jwks', status: discovery.jwks_uri ? 'pass' : 'fail', message: discovery.jwks_uri ? 'JWKS endpoint is present.' : 'JWKS endpoint is missing; ID-token verification cannot work.' });
  checks.push({ name: 'userinfo', status: discovery.userinfo_endpoint ? 'pass' : 'warn', message: discovery.userinfo_endpoint ? 'UserInfo endpoint is present.' : 'UserInfo endpoint is not advertised.' });
  checks.push({ name: 'logout', status: discovery.end_session_endpoint ? 'pass' : 'warn', message: discovery.end_session_endpoint ? 'Provider logout endpoint is advertised.' : 'Provider logout endpoint is not advertised.' });
  const refreshAdvertised = grantTypes.values?.includes('refresh_token') ?? false;
  checks.push({
    name: 'refresh',
    status: grantTypes.invalid ? 'fail' : grantTypes.values === undefined ? 'warn' : refreshAdvertised ? 'pass' : 'warn',
    message: refreshAdvertised ? 'Refresh-token grant is advertised.' : 'Refresh-token grant is not advertised.',
  });

  const failed = checks.some((check) => check.status === 'fail');
  const redirectUri = redirect.origin + redirect.pathname;
  return {
    ok: !failed,
    checkedAt: new Date().toISOString(),
    issuer: normalizedIssuer,
    clientIdPresent: clientIdValid,
    redirectUri,
    checks,
    capabilities: {
      authorizationCode: authCode,
      pkceS256: pkce,
      idTokenSigningAlgorithms: algorithmsResult.values ?? [],
      userInfoAvailable: Boolean(discovery.userinfo_endpoint),
      logoutAvailable: Boolean(discovery.end_session_endpoint),
      refreshAdvertised,
    },
  };
}


function readStringArray(value: unknown): { values?: string[]; invalid: boolean } {
  if (value === undefined) return { invalid: false };
  if (!Array.isArray(value) || !value.every((item): item is string => typeof item === 'string')) {
    return { invalid: true };
  }
  return { values: value, invalid: false };
}
