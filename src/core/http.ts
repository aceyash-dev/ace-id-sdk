/**
 * Shared bounded fetch helper for SDK network requests.
 *
 * The fallback controller is used on runtimes without AbortSignal.timeout.
 * Always dispose fallback timers after consuming the response body.
 */
export const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

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
