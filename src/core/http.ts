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
