/**
 * Shared bounded fetch helper for SDK network requests.
 *
 * The fallback controller is used on runtimes without AbortSignal.timeout.
 * Always dispose fallback timers after consuming the response body.
 */
export const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

/**
 * Upper bound applied to JSON bodies the SDK parses (discovery documents,
 * JWKS payloads, token responses). A malicious or misconfigured endpoint must
 * not be able to exhaust client memory with an unbounded response.
 */
export const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;

/** Thrown when a response body exceeds the configured byte limit. */
export class ResponseSizeError extends Error {
  constructor(readonly maxBytes: number) {
    super(`Response body exceeds the ${maxBytes}-byte limit`);
    this.name = 'ResponseSizeError';
  }
}

/**
 * Read a response body as text, refusing to buffer more than `maxBytes`.
 *
 * The declared Content-Length is checked first (cheap rejection), then the
 * body is consumed incrementally so a streamed or understated length cannot
 * bypass the limit.
 */
export async function readBoundedText(
  response: Response,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES,
): Promise<string> {
  if (!Number.isFinite(maxBytes) || maxBytes <= 0) {
    throw new TypeError('maxBytes must be a positive finite number');
  }

  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const declaredBytes = Number(declared);
    if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
      throw new ResponseSizeError(maxBytes);
    }
  }

  if (!response.body) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw new ResponseSizeError(maxBytes);
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new ResponseSizeError(maxBytes);
      }
      chunks.push(value);
    }
  } catch (err) {
    try {
      await reader.cancel();
    } catch {
      // The body is already unusable; cancellation failure must not mask the cause.
    }
    throw err;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Lock release is best-effort on runtimes that drop the stream early.
    }
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

export function withRequestTimeout(
  timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
): { signal: AbortSignal; dispose: () => void } {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError('request timeout must be a positive finite number');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new DOMException('The request timed out', 'TimeoutError'));
  }, timeoutMs);

  return {
    signal: controller.signal,
    dispose: () => clearTimeout(timer),
  };
}

/** Bounded retry policy for network operations that are safe to repeat. */
export interface RetryPolicy {
  /** Additional attempts after the first. Defaults to 2. */
  maxRetries: number;
  /** First backoff delay. Defaults to 200 ms. */
  baseDelayMs: number;
  /** Backoff ceiling. Defaults to 2 s. */
  maxDelayMs: number;
  /** Randomise each delay by up to 50% so retries do not synchronise. */
  jitter: boolean;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxRetries: 2,
  baseDelayMs: 200,
  maxDelayMs: 2_000,
  jitter: true,
};

/**
 * Statuses worth repeating: transient transport and capacity problems.
 *
 * 401/403/400 are excluded on purpose — repeating them only burns rate limit,
 * and for a token endpoint a repeated `invalid_grant` can invalidate a rotating
 * refresh token.
 */
export function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 ||
    (status >= 500 && status <= 599 && status !== 501 && status !== 505);
}

/** Honour `Retry-After` when the server sends one, in either supported format. */
export function retryAfterMs(response: Response): number | undefined {
  const header = response.headers.get('retry-after');
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(header);
  if (Number.isFinite(date)) {
    const delta = date - Date.now();
    return delta > 0 ? delta : 0;
  }
  return undefined;
}

export interface RequestOptions {
  /** Per-attempt timeout. Defaults to {@link DEFAULT_REQUEST_TIMEOUT_MS}. */
  timeoutMs?: number;
  /**
   * Retry policy. `false` disables retries entirely — required for any request
   * that is not safe to repeat, such as an authorization-code exchange.
   */
  retry?: Partial<RetryPolicy> | false;
  /** Caller cancellation, combined with the per-attempt timeout. */
  signal?: AbortSignal;
  /** Maximum body size accepted for JSON responses. */
  maxBytes?: number;
}

function resolveRetryPolicy(retry: RequestOptions['retry']): RetryPolicy {
  if (retry === false) return { ...DEFAULT_RETRY_POLICY, maxRetries: 0 };
  const merged = { ...DEFAULT_RETRY_POLICY, ...(retry ?? {}) };
  if (!Number.isSafeInteger(merged.maxRetries) || merged.maxRetries < 0 || merged.maxRetries > 5) {
    throw new TypeError('maxRetries must be an integer between 0 and 5');
  }
  if (!Number.isFinite(merged.baseDelayMs) || merged.baseDelayMs < 0) {
    throw new TypeError('baseDelayMs must be a non-negative finite number');
  }
  if (!Number.isFinite(merged.maxDelayMs) || merged.maxDelayMs < merged.baseDelayMs) {
    throw new TypeError('maxDelayMs must be a finite number at least as large as baseDelayMs');
  }
  return merged;
}

function backoffDelay(attempt: number, policy: RetryPolicy): number {
  const exponential = Math.min(policy.baseDelayMs * 2 ** attempt, policy.maxDelayMs);
  if (!policy.jitter) return exponential;
  // Full jitter is recommended by AWS's retry guidance: spread retries instead
  // of stampeding the identity provider after an outage.
  return Math.round(exponential * (0.5 + Math.random() * 0.5));
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason ?? new DOMException('The operation was aborted.', 'AbortError'));
    };
    if (signal?.aborted) {
      onAbort();
      return;
    }
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function combineSignals(timeoutSignal: AbortSignal, callerSignal?: AbortSignal): AbortSignal {
  if (!callerSignal) return timeoutSignal;
  const controller = new AbortController();
  const forward = (source: AbortSignal): void => {
    if (source.aborted) {
      controller.abort(source.reason);
      return;
    }
    source.addEventListener('abort', () => controller.abort(source.reason), { once: true });
  };
  forward(timeoutSignal);
  forward(callerSignal);
  return controller.signal;
}

/**
 * `fetch` with a per-attempt timeout, bounded retries and cancellation.
 *
 * Only the response *status* is inspected between attempts, so a retried body is
 * never half-consumed. The final response is returned unread for the caller.
 */
export async function fetchWithRetry(
  url: string,
  init: RequestInit = {},
  options: RequestOptions = {},
): Promise<Response> {
  const policy = resolveRetryPolicy(options.retry);
  const timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  let lastError: unknown;

  for (let attempt = 0; attempt <= policy.maxRetries; attempt += 1) {
    const timeout = withRequestTimeout(timeoutMs);
    try {
      const response = await fetch(url, {
        ...init,
        signal: combineSignals(timeout.signal, options.signal),
        cache: 'no-store',
      });
      if (!isRetryableStatus(response.status) || attempt === policy.maxRetries) {
        return response;
      }
      // Drain nothing: the body is discarded with the response object.
      const hinted = retryAfterMs(response);
      const delay = hinted !== undefined
        ? Math.min(hinted, policy.maxDelayMs)
        : backoffDelay(attempt, policy);
      await sleep(delay, options.signal);
    } catch (err) {
      lastError = err;
      if (options.signal?.aborted) throw err;
      if (attempt === policy.maxRetries) throw err;
      await sleep(backoffDelay(attempt, policy), options.signal);
    } finally {
      timeout.dispose();
    }
  }
  throw lastError ?? new Error('Request failed');
}

/**
 * Request JSON with the SDK's safety defaults: bounded body, no cache, retries
 * only where the caller allows them.
 */
export async function requestJson(
  url: string,
  init: RequestInit = {},
  options: RequestOptions = {},
): Promise<{ response: Response; payload: Record<string, unknown>; text: string }> {
  const response = await fetchWithRetry(url, init, options);
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const text = await readBoundedText(response, maxBytes);
  let value: unknown = {};
  if (text.trim()) {
    value = JSON.parse(text) as unknown;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Response body must be a JSON object');
  }
  return { response, payload: value as Record<string, unknown>, text };
}

/** True for the failures a caller may retry: timeouts, aborts and transport errors. */
export function isRetryableNetworkError(err: unknown): boolean {
  if (err instanceof ResponseSizeError) return false;
  if (err instanceof DOMException) return err.name === 'TimeoutError' || err.name === 'AbortError';
  if (err instanceof Error) {
    return err.name === 'TimeoutError' || err.name === 'AbortError' || err instanceof TypeError;
  }
  return false;
}
