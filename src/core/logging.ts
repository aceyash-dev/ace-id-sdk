/**
 * Structured, redacted logging for the Ace ID SDK.
 *
 * Two rules drive this module:
 *
 * 1. An authentication library must never write credentials to a log sink.
 *    Access tokens, refresh tokens, authorization codes, ID tokens, client
 *    secrets and OIDC nonces are redacted before they reach a sink, whatever
 *    the caller passes in.
 * 2. The SDK is silent by default. It only emits when the host application
 *    supplies a `logger` or enables `debug`, so importing the SDK never
 *    surprises an application with console output.
 */

export type AIDLogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface AIDLogEntry {
  level: AIDLogLevel;
  /** Short, stable event name, e.g. `token.refresh.failed`. */
  event: string;
  message: string;
  /** Redacted, non-secret context. */
  context?: Record<string, unknown>;
  timestamp: number;
}

export type AIDLogSink = (entry: AIDLogEntry) => void;

export interface AIDLoggingOptions {
  /** Emit debug-level entries. Defaults to false. */
  debug?: boolean;
  /** Receives redacted entries. Without one, nothing is emitted. */
  logger?: AIDLogSink;
}

export interface AIDLogger {
  debug(event: string, message: string, context?: Record<string, unknown>): void;
  info(event: string, message: string, context?: Record<string, unknown>): void;
  warn(event: string, message: string, context?: Record<string, unknown>): void;
  error(event: string, message: string, context?: Record<string, unknown>): void;
  readonly enabled: boolean;
}

/** Keys whose values must never be logged, matched case-insensitively. */
const SENSITIVE_KEY = /(?:^|[_.-])(?:access_?token|refresh_?token|id_?token|token|secret|password|passwd|authorization|auth_?code|code_?verifier|code_?challenge|assertion|assertion_?jwt|client_?secret|nonce|cookie|set-?cookie|session_?id|private_?key|api_?key|jwt|state)(?:$|[_.-])/i;

/** A compact JWS/JWE: three or five dot-separated base64url segments. */
const JWT_SHAPED = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;

const MAX_DEPTH = 4;
const MAX_ARRAY_ITEMS = 20;
const MAX_STRING_LENGTH = 512;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

/**
 * Deep-copy a value with credentials removed.
 *
 * Sensitive keys become `'[redacted]'`, JWT-shaped strings are replaced
 * wholesale, `Error` instances keep only name/message/code, and cyclic or
 * over-deep structures are cut off rather than logged unbounded.
 */
export function redact(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  if (depth >= MAX_DEPTH) return '[truncated]';

  if (typeof value === 'string') {
    if (JWT_SHAPED.test(value)) return '[redacted-token]';
    return value.length > MAX_STRING_LENGTH ? `${value.slice(0, MAX_STRING_LENGTH)}…` : value;
  }
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'function' || typeof value === 'symbol') return '[function]';

  if (value instanceof Error) {
    const out: Record<string, unknown> = { name: value.name, message: value.message };
    const code = (value as { code?: unknown }).code;
    if (typeof code === 'string') out.code = code;
    return out;
  }
  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY_ITEMS).map((item) => redact(item, depth + 1));
  }
  if (value instanceof URL) return value.toString();
  if (value instanceof URLSearchParams) return '[url-search-params]';
  if (value instanceof Headers) return '[headers]';
  if (!isPlainObject(value)) return '[object]';

  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    out[key] = SENSITIVE_KEY.test(key) ? '[redacted]' : redact(item, depth + 1);
  }
  return out;
}

/** Redact a single URL so tokens in query strings or fragments never reach a sink. */
export function redactUrl(input: string): string {
  try {
    const url = new URL(input);
    for (const key of [...url.searchParams.keys()]) {
      url.searchParams.set(key, '[redacted]');
    }
    if (url.username) url.username = '[redacted]';
    if (url.password) url.password = '[redacted]';
    if (url.hash) url.hash = '#[redacted]';
    return url.toString();
  } catch {
    return '[unparseable-url]';
  }
}

const NOOP_LOGGER: AIDLogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  enabled: false,
};

/**
 * Build a logger from host options.
 *
 * Without a sink the returned logger is inert: `warn`/`error` are not printed to
 * the console behind the application's back. Passing `debug` alone enables the
 * console sink, which is the documented opt-in for troubleshooting.
 */
export function createLogger(options: AIDLoggingOptions = {}): AIDLogger {
  const debugEnabled = options.debug === true;
  let sink = options.logger;
  if (!sink && debugEnabled) {
    sink = (entry) => {
      const line = `[ace-id] ${entry.event}: ${entry.message}`;
      // eslint-disable-next-line no-console
      const write = entry.level === 'error' ? console.error
        : entry.level === 'warn' ? console.warn
          : console.log;
      if (entry.context) write(line, redact(entry.context));
      else write(line);
    };
  }
  if (!sink) return NOOP_LOGGER;

  const emit = (level: AIDLogLevel, event: string, message: string, context?: Record<string, unknown>): void => {
    if (level === 'debug' && !debugEnabled) return;
    const entry: AIDLogEntry = {
      level,
      event,
      message,
      timestamp: Date.now(),
    };
    if (context !== undefined) entry.context = redact(context) as Record<string, unknown>;
    try {
      sink(entry);
    } catch {
      // A throwing sink must never break authentication.
    }
  };

  return {
    debug: (event, message, context) => emit('debug', event, message, context),
    info: (event, message, context) => emit('info', event, message, context),
    warn: (event, message, context) => emit('warn', event, message, context),
    error: (event, message, context) => emit('error', event, message, context),
    enabled: true,
  };
}

/** A logger that discards everything. Exported for hosts that want the type only. */
export const silentLogger: AIDLogger = NOOP_LOGGER;
