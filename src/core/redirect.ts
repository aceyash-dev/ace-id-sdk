import { AIDCallbackError, AIDError } from './errors.js';

/**
 * Redirect and callback validation.
 *
 * Every URL the SDK accepts from an application or from the authorization
 * server is validated here, once, against the registered redirect URI:
 *
 * - `returnTo` and post-logout targets must stay on the application's origin,
 *   so a tampered link cannot turn the SDK into an open redirect.
 * - the authorization callback must arrive on the registered origin *and* path,
 *   so a code delivered to an unrelated endpoint is refused instead of exchanged.
 *
 * Relative paths are resolved against the redirect URI, which keeps the common
 * `returnTo: '/dashboard'` usage working.
 */

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

export function isLocalHost(hostname: string): boolean {
  return LOCAL_HOSTS.has(hostname.toLowerCase());
}

/** HTTPS, or HTTP on a loopback host for development. */
export function isSecureUrl(url: URL): boolean {
  return url.protocol === 'https:' || (url.protocol === 'http:' && isLocalHost(url.hostname));
}

/** Parse an absolute URL, or throw the supplied error. */
export function parseAbsoluteUrl(value: string, message: string): URL {
  try {
    return new URL(value);
  } catch (err) {
    throw new AIDError('CONFIGURATION_ERROR', message, err);
  }
}

/**
 * Validate an application-supplied post-login target.
 *
 * The value is resolved against the registered redirect URI and must stay on
 * that origin (or one of `additionalOrigins`), so `returnTo` can never become an
 * open redirect. Relative paths (`/dashboard`, `dashboard`) are supported and
 * normalised to absolute URLs.
 */
export function normalizeReturnTo(
  returnTo: unknown,
  redirectUri: string,
  additionalOrigins: readonly string[] = [],
): string | undefined {
  if (returnTo === undefined || returnTo === null) return undefined;
  if (typeof returnTo !== 'string' || returnTo.trim().length === 0) {
    throw new AIDError('CONFIGURATION_ERROR', 'returnTo must be a non-empty string');
  }
  if (CONTROL_CHARACTERS.test(returnTo)) {
    throw new AIDError('CONFIGURATION_ERROR', 'returnTo must not contain control characters');
  }

  const callback = new URL(redirectUri);
  let target: URL;
  try {
    target = new URL(returnTo, callback);
  } catch (err) {
    throw new AIDError(
      'CONFIGURATION_ERROR',
      'returnTo must be an absolute URL or a path within the application',
      err,
    );
  }

  if (!isAllowedOrigin(target, callback, additionalOrigins)) {
    throw new AIDError('CONFIGURATION_ERROR', 'returnTo must share the registered redirect URI origin');
  }
  if (target.username || target.password) {
    throw new AIDError('CONFIGURATION_ERROR', 'returnTo must not contain credentials');
  }
  if (!isSecureUrl(target)) {
    throw new AIDError('CONFIGURATION_ERROR', 'returnTo must use HTTPS');
  }

  return target.toString();
}

/** Validate a post-logout redirect target. Same rules, stricter error messages. */
export function validatePostLogoutRedirect(
  target: string,
  redirectUri: string,
  additionalOrigins: readonly string[] = [],
): string {
  let candidate: URL;
  let callback: URL;
  try {
    candidate = new URL(target);
    callback = new URL(redirectUri);
  } catch (err) {
    throw new AIDError('CONFIGURATION_ERROR', 'signOut redirectTo must be an absolute URL', err);
  }
  if (!isSecureUrl(candidate)) {
    throw new AIDError('CONFIGURATION_ERROR', 'signOut redirectTo must use HTTPS');
  }
  if (candidate.username || candidate.password) {
    throw new AIDError('CONFIGURATION_ERROR', 'signOut redirectTo must not contain credentials');
  }
  if (!isAllowedOrigin(candidate, callback, additionalOrigins)) {
    throw new AIDError(
      'CONFIGURATION_ERROR',
      'signOut redirectTo must share the registered redirect URI origin',
    );
  }
  return candidate.toString();
}

function isAllowedOrigin(
  candidate: URL,
  callback: URL,
  additionalOrigins: readonly string[],
): boolean {
  if (candidate.origin === callback.origin) return true;
  return additionalOrigins.some((origin) => origin === candidate.origin);
}

export interface CallbackUrlOptions {
  /** Extra origins the callback may legitimately arrive on. */
  additionalOrigins?: readonly string[];
  /**
   * Require the callback path to equal the registered redirect path.
   * Defaults to true: a code delivered to another path is not this client's code.
   */
  strictPath?: boolean;
}

/**
 * Validate that an authorization response arrived on the registered endpoint.
 *
 * Checks, in order: a parseable absolute URL, a secure protocol, no embedded
 * credentials, an origin the application registered, and — unless disabled —
 * the registered callback path. Duplicated `code`, `state` or `error`
 * parameters are refused: a request carrying two codes is ambiguous, and
 * parameter pollution is a classic way to slip a second value past a
 * first-wins parser.
 */
export function assertCallbackUrl(
  rawUrl: string,
  redirectUri: string,
  options: CallbackUrlOptions = {},
): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    throw new AIDCallbackError('Callback URL is not a valid URL', err);
  }

  const registered = new URL(redirectUri);
  if (!isSecureUrl(parsed)) {
    throw new AIDCallbackError('Callback URL must use HTTPS (HTTP localhost is allowed for development)');
  }
  if (parsed.username || parsed.password) {
    throw new AIDCallbackError('Callback URL must not contain credentials');
  }
  if (!isAllowedOrigin(parsed, registered, options.additionalOrigins ?? [])) {
    throw new AIDCallbackError('Callback URL origin does not match the registered redirect URI');
  }
  if (options.strictPath !== false) {
    const expectedPath = registered.pathname.replace(/\/+$/, '') || '/';
    const actualPath = parsed.pathname.replace(/\/+$/, '') || '/';
    if (expectedPath !== actualPath) {
      throw new AIDCallbackError('Callback URL path does not match the registered redirect URI');
    }
  }
  if (parsed.searchParams.has('redirect_uri')) {
    throw new AIDCallbackError('Callback URL must not contain a redirect_uri parameter');
  }
  for (const parameter of ['code', 'state', 'error']) {
    if (parsed.searchParams.getAll(parameter).length > 1) {
      throw new AIDCallbackError(`Callback URL contains duplicate "${parameter}" parameters`);
    }
  }

  return parsed;
}
