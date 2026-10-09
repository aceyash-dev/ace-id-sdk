/**
 * Shared bounded fetch helper for SDK network requests.
 *
 * Uses AbortSignal.timeout where available, with an AbortController fallback
 * for runtimes that do not implement it.
 */
export const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

export function withRequestTimeout(
  timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
): { signal: AbortSignal; dispose: () => void } {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError('request timeout must be a positive finite number');
  }

  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
    return { signal: AbortSignal.timeout(timeoutMs), dispose: () => undefined };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(
    new DOMException('The request timed out', 'TimeoutError'),
  ), timeoutMs);

  return {
    signal: controller.signal,
    dispose: () => clearTimeout(timer),
  };
}
