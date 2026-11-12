/**
 * Error model.
 *
 * Every failure the SDK raises is an {@link AIDError} carrying a stable `code`.
 * The codes are the same strings the Android and Swift SDKs use, so a host
 * application can map one set of codes to its UI regardless of platform:
 *
 * | code                  | meaning                                                        |
 * | --------------------- | -------------------------------------------------------------- |
 * | `CONFIGURATION_ERROR` | the SDK was constructed or called with unusable input           |
 * | `DISCOVERY_ERROR`     | the issuer's discovery document was missing, invalid or unreachable |
 * | `CALLBACK_ERROR`      | the authorization response was malformed, replayed or rejected  |
 * | `TOKEN_ERROR`         | the token endpoint failed or returned an unusable response      |
 * | `AUTHENTICATION_ERROR`| no usable session, or the provider rejected the credentials     |
 * | `SESSION_ERROR`       | the stored session was corrupt or ended during an operation     |
 * | `PROFILE_ERROR`       | the UserInfo request failed or returned the wrong subject       |
 * | `NETWORK_ERROR`       | the request did not complete (offline, DNS, timeout, abort)     |
 * | `STORAGE_ERROR`       | the configured storage rejected a read or write                 |
 *
 * `retryable` says whether repeating the same operation could succeed. The SDK
 * sets it for transport failures and 5xx/429 responses, and never for
 * authorization-code exchanges, where a blind retry can burn a single-use code.
 */

export type AIDErrorCode =
  | 'DISCOVERY_ERROR'
  | 'CALLBACK_ERROR'
  | 'TOKEN_ERROR'
  | 'AUTHENTICATION_ERROR'
  | 'CONFIGURATION_ERROR'
  | 'STORAGE_ERROR'
  | 'NETWORK_ERROR'
  | 'SESSION_ERROR'
  | 'PROFILE_ERROR';

export interface AIDErrorOptions {
  cause?: unknown;
  /** Whether repeating the operation could plausibly succeed. */
  retryable?: boolean;
  /** Structured, non-secret context for logs and support. */
  details?: Record<string, unknown>;
}

export class AIDError extends Error {
  readonly code: AIDErrorCode;
  override readonly cause?: unknown;
  /** True when the same call could succeed if repeated. */
  readonly retryable: boolean;
  /** Redaction-safe context; never contains tokens or codes. */
  readonly details?: Record<string, unknown>;

  constructor(
    code: AIDErrorCode,
    message: string,
    causeOrOptions?: unknown,
    extra?: { retryable?: boolean; details?: Record<string, unknown> },
  ) {
    super(message);
    this.name = 'AIDError';
    this.code = code;

    // Historically the third argument was a bare `cause`. Accept both shapes so
    // existing call sites keep working while new ones can pass options.
    let options: AIDErrorOptions = {};
    if (causeOrOptions !== undefined) {
      if (
        typeof causeOrOptions === 'object' &&
        causeOrOptions !== null &&
        ('cause' in causeOrOptions || 'retryable' in causeOrOptions || 'details' in causeOrOptions) &&
        !(causeOrOptions instanceof Error)
      ) {
        options = causeOrOptions as AIDErrorOptions;
      } else {
        options = { cause: causeOrOptions };
      }
    }
    const merged = { ...options, ...(extra ?? {}) };
    if (merged.cause !== undefined) this.cause = merged.cause;
    this.retryable = merged.retryable ?? false;
    if (merged.details !== undefined) this.details = merged.details;
  }
}

export class AIDDiscoveryError extends AIDError {
  constructor(message: string, cause?: unknown, extra?: { retryable?: boolean }) {
    super('DISCOVERY_ERROR', message, cause, extra);
    this.name = 'AIDDiscoveryError';
  }
}

export class AIDCallbackError extends AIDError {
  constructor(message: string, cause?: unknown, extra?: { retryable?: boolean; details?: Record<string, unknown> }) {
    super('CALLBACK_ERROR', message, cause, extra);
    this.name = 'AIDCallbackError';
  }
}

export class AIDTokenError extends AIDError {
  readonly error?: string;

  constructor(
    message: string,
    cause?: unknown,
    error?: string,
    extra?: { retryable?: boolean; details?: Record<string, unknown> },
  ) {
    super('TOKEN_ERROR', message, cause, extra);
    this.name = 'AIDTokenError';
    this.error = error;
  }
}

export class AIDAuthenticationError extends AIDError {
  constructor(message: string, cause?: unknown, extra?: { retryable?: boolean; details?: Record<string, unknown> }) {
    super('AUTHENTICATION_ERROR', message, cause, extra);
    this.name = 'AIDAuthenticationError';
  }
}

export class AIDStorageError extends AIDError {
  constructor(message: string, cause?: unknown) {
    super('STORAGE_ERROR', message, cause);
    this.name = 'AIDStorageError';
  }
}

export class AIDNetworkError extends AIDError {
  constructor(message: string, cause?: unknown, details?: Record<string, unknown>) {
    super('NETWORK_ERROR', message, cause, { retryable: true, details });
    this.name = 'AIDNetworkError';
  }
}

export class AIDSessionError extends AIDError {
  constructor(message: string, cause?: unknown, details?: Record<string, unknown>) {
    super('SESSION_ERROR', message, cause, { details });
    this.name = 'AIDSessionError';
  }
}

export class AIDProfileError extends AIDError {
  constructor(message: string, cause?: unknown, extra?: { retryable?: boolean; details?: Record<string, unknown> }) {
    super('PROFILE_ERROR', message, cause, extra);
    this.name = 'AIDProfileError';
  }
}

/** Narrow an unknown thrown value to an SDK error. */
export function isAIDError(value: unknown): value is AIDError {
  return value instanceof AIDError;
}

/** Stable code for any thrown value, so callers can branch without instanceof. */
export function aidErrorCode(value: unknown): AIDErrorCode | 'UNKNOWN' {
  return value instanceof AIDError ? value.code : 'UNKNOWN';
}

/** Whether repeating the operation that produced this error could succeed. */
export function isRetryableError(value: unknown): boolean {
  return value instanceof AIDError ? value.retryable : false;
}
