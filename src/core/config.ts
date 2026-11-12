import { normalizeIssuer } from './discovery.js';
import { AIDError } from './errors.js';
import { isSecureUrl } from './redirect.js';
import type { AIDConfig } from './types.js';

/**
 * Configuration diagnostics.
 *
 * A misconfigured OIDC client fails in confusing ways: a wrong redirect URI
 * produces an opaque `invalid_request` from the provider, a missing client ID a
 * blank page. This module turns configuration into a list of named checks so
 * both the constructor and `AID#validateConfiguration()` can say exactly what is
 * wrong, and so the same report can be shown to a developer without a network
 * round trip.
 */

export type AIDCheckStatus = 'pass' | 'warn' | 'fail';

export interface AIDConfigCheck {
  name: string;
  status: AIDCheckStatus;
  message: string;
}

export interface AIDConfigReport {
  ok: boolean;
  checks: AIDConfigCheck[];
  /** Human-readable summary of every failing check. */
  summary: string;
}

const ASYMMETRIC_ALGORITHM = /^(RS|PS|ES|EdDSA)\d*/;

function isPositiveFinite(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0;
}

function isNonNegativeFinite(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function check(
  checks: AIDConfigCheck[],
  name: string,
  ok: boolean,
  message: string,
  status: AIDCheckStatus = ok ? 'pass' : 'fail',
): void {
  checks.push({ name, status, message });
}

/**
 * Inspect a configuration object without touching the network and without
 * throwing. Every check is reported, so a developer fixes all problems in one
 * pass instead of one restart per mistake.
 */
export function validateAIDConfig(config: unknown): AIDConfigReport {
  const checks: AIDConfigCheck[] = [];

  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return summarizeAIDChecks([{ name: 'config-object', status: 'fail', message: 'Configuration must be an object.' }]);
  }
  const value = config as Record<string, unknown>;

  check(checks, 'issuer-present',
    typeof value.issuer === 'string' && value.issuer.trim().length > 0,
    'issuer is required.');

  if (typeof value.issuer === 'string' && value.issuer.trim().length > 0) {
    try {
      const normalized = normalizeIssuer(value.issuer);
      check(checks, 'issuer-valid', true, `Issuer normalised to ${normalized}.`);
    } catch (err) {
      check(checks, 'issuer-valid', false,
        `issuer is not a valid OIDC issuer URL: ${(err as Error).message}`);
    }
  }

  check(checks, 'client-id',
    typeof value.clientId === 'string' && value.clientId.trim().length > 0,
    'clientId is required and must be non-empty.');

  let redirect: URL | undefined;
  if (typeof value.redirectUri !== 'string' || value.redirectUri.trim().length === 0) {
    check(checks, 'redirect-uri', false, 'redirectUri is required.');
  } else {
    try {
      redirect = new URL(value.redirectUri);
      const secure = isSecureUrl(redirect);
      const clean = !redirect.username && !redirect.password && !redirect.hash;
      check(checks, 'redirect-uri', secure && clean,
        secure && clean
          ? 'redirectUri is absolute, uses an allowed protocol and contains no credentials or fragment.'
          : 'redirectUri must use HTTPS (HTTP localhost only for development) and contain no credentials or fragment.');
    } catch {
      check(checks, 'redirect-uri', false, 'redirectUri must be an absolute URL.');
    }
  }

  if (value.scope !== undefined) {
    const scope = value.scope;
    const valid = typeof scope === 'string' && scope.trim().length > 0 &&
      scope.trim().split(/\s+/).every((item) => item.length > 0);
    check(checks, 'scope', valid, valid
      ? 'scope is a space-delimited list of non-empty values.'
      : 'scope must be a non-empty space-delimited string.');
  }

  if (value.storage !== undefined) {
    const storage = value.storage as Record<string, unknown> | undefined;
    const valid = !!storage && typeof storage.get === 'function' &&
      typeof storage.set === 'function' && typeof storage.remove === 'function';
    check(checks, 'storage', valid,
      valid
        ? 'storage implements get/set/remove.'
        : 'storage must implement get(key), set(key, value) and remove(key).');
  }

  for (const [field, defaultValue] of [
    ['requestTimeoutMs', '10 seconds'],
    ['transactionTtlMs', '10 minutes'],
    ['discoveryCacheTtlMs', '5 minutes'],
  ] as const) {
    const candidate = value[field];
    if (candidate === undefined) continue;
    check(checks, field, isPositiveFinite(candidate),
      isPositiveFinite(candidate)
        ? `${field} is ${candidate} ms.`
        : `${field} must be a positive finite number (default ${defaultValue}).`);
  }

  for (const field of ['unknownExpiryRefreshIntervalMs', 'leewaySeconds', 'clockSkewSeconds'] as const) {
    const candidate = value[field];
    if (candidate === undefined) continue;
    check(checks, field, isNonNegativeFinite(candidate),
      isNonNegativeFinite(candidate)
        ? `${field} is ${candidate}.`
        : `${field} must be a non-negative finite number.`);
  }

  if (value.clockSkewSeconds !== undefined && isNonNegativeFinite(value.clockSkewSeconds)) {
    check(checks, 'clock-skew-range', value.clockSkewSeconds <= 300,
      value.clockSkewSeconds <= 300
        ? 'Clock-skew tolerance is within the recommended 0–300 second range.'
        : 'Clock-skew tolerance above 300 seconds is outside the recommended range.',
      value.clockSkewSeconds <= 300 ? 'pass' : 'warn');
  }

  if (value.maxRetries !== undefined) {
    const candidate = value.maxRetries;
    const valid = typeof candidate === 'number' && Number.isSafeInteger(candidate) && candidate >= 0 && candidate <= 5;
    check(checks, 'max-retries', valid,
      valid ? `maxRetries is ${candidate}.` : 'maxRetries must be an integer between 0 and 5.');
  }

  if (value.autoRefresh !== undefined) {
    check(checks, 'auto-refresh', typeof value.autoRefresh === 'boolean',
      typeof value.autoRefresh === 'boolean'
        ? `autoRefresh is ${value.autoRefresh ? 'enabled' : 'disabled'}.`
        : 'autoRefresh must be a boolean.');
  }

  if (value.additionalRedirectOrigins !== undefined) {
    const origins = value.additionalRedirectOrigins;
    const valid = Array.isArray(origins) && origins.every((origin) => {
      if (typeof origin !== 'string') return false;
      try {
        const parsed = new URL(origin);
        return isSecureUrl(parsed) && parsed.origin === origin.replace(/\/+$/, '') && !parsed.pathname.replace(/\/+$/, '');
      } catch {
        return false;
      }
    });
    check(checks, 'additional-redirect-origins', valid,
      valid
        ? 'Every additional redirect origin is a bare HTTPS origin.'
        : 'additionalRedirectOrigins must contain bare HTTPS origins such as "https://app.example.com".');
  }

  if (value.allowedSigningAlgorithms !== undefined) {
    const algorithms = value.allowedSigningAlgorithms;
    const valid = Array.isArray(algorithms) && algorithms.length > 0 &&
      algorithms.every((algorithm) => typeof algorithm === 'string' && ASYMMETRIC_ALGORITHM.test(algorithm));
    check(checks, 'signing-algorithms', valid,
      valid
        ? 'Signing algorithm allowlist contains asymmetric algorithms only.'
        : 'allowedSigningAlgorithms must be a non-empty list of asymmetric algorithms (RS*, PS*, ES*, EdDSA); symmetric and "none" are refused.');
  }

  if (value.storageKeyPrefix !== undefined) {
    const prefix = value.storageKeyPrefix;
    const valid = typeof prefix === 'string' && /^[A-Za-z0-9._:-]{1,32}$/.test(prefix);
    check(checks, 'storage-key-prefix', valid,
      valid ? `storageKeyPrefix is "${prefix}".` : 'storageKeyPrefix must be 1–32 characters of [A-Za-z0-9._:-].');
  }

  if (redirect) {
    const secureContext = isSecureUrl(redirect);
    check(checks, 'browser-context', secureContext,
      secureContext
        ? 'The redirect URI implies a secure browser context, so Web Crypto and PKCE are available.'
        : 'Web Crypto requires a secure context; use HTTPS in production.',
      secureContext ? 'pass' : 'fail');
  }

  return summarizeAIDChecks(checks);
}

export function summarizeAIDChecks(checks: AIDConfigCheck[]): AIDConfigReport {
  const failures = checks.filter((item) => item.status === 'fail');
  const warnings = checks.filter((item) => item.status === 'warn');
  const parts: string[] = [];
  if (failures.length) parts.push(`${failures.length} failing check(s): ${failures.map((item) => item.name).join(', ')}`);
  if (warnings.length) parts.push(`${warnings.length} warning(s): ${warnings.map((item) => item.name).join(', ')}`);
  return {
    ok: failures.length === 0,
    checks,
    summary: parts.length ? parts.join('; ') : 'All configuration checks passed.',
  };
}

/**
 * Throw a single aggregated `CONFIGURATION_ERROR` when the configuration is
 * unusable. Callers see every problem at once rather than one per restart.
 */
export function assertAIDConfig(config: AIDConfig): void {
  const report = validateAIDConfig(config);
  if (report.ok) return;
  const failures = report.checks.filter((item) => item.status === 'fail');
  throw new AIDError(
    'CONFIGURATION_ERROR',
    `Invalid Ace ID configuration — ${failures.map((item) => `${item.name}: ${item.message}`).join(' ')}`,
  );
}
