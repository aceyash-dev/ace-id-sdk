import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  fetchWithRetry,
  isRetryableNetworkError,
  isRetryableStatus,
  requestJson,
  retryAfterMs,
} from '../src/core/http.js';
import { SingleFlight } from '../src/core/single-flight.js';

const URL_UNDER_TEST = 'https://id.test/jwks';

function json(payload: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

describe('isRetryableStatus', () => {
  it('retries capacity and transport statuses only', () => {
    for (const status of [408, 425, 429, 500, 502, 503, 504]) {
      expect(isRetryableStatus(status)).toBe(true);
    }
    for (const status of [400, 401, 403, 404, 501, 505]) {
      expect(isRetryableStatus(status)).toBe(false);
    }
  });
});

describe('retryAfterMs', () => {
  it('reads the seconds form', () => {
    expect(retryAfterMs(json({}, 429, { 'retry-after': '3' }))).toBe(3000);
  });

  it('reads the HTTP-date form', () => {
    const at = new Date(Date.now() + 5_000).toUTCString();
    const value = retryAfterMs(json({}, 429, { 'retry-after': at }));
    expect(value).toBeGreaterThan(2_000);
    expect(value).toBeLessThanOrEqual(5_000);
  });

  it('returns undefined without the header', () => {
    expect(retryAfterMs(json({}, 429))).toBeUndefined();
  });
});

describe('fetchWithRetry', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('retries a 503 and returns the eventual success', async () => {
    const responses = [json({ error: 'busy' }, 503), json({ ok: true })];
    const fetchMock = vi.fn(async () => responses.shift() as Response);
    vi.stubGlobal('fetch', fetchMock);

    const response = await fetchWithRetry(URL_UNDER_TEST, {}, { retry: { maxRetries: 2, baseDelayMs: 1, jitter: false } });
    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not retry a client error', async () => {
    const fetchMock = vi.fn(async () => json({ error: 'invalid_grant' }, 400));
    vi.stubGlobal('fetch', fetchMock);

    const response = await fetchWithRetry(URL_UNDER_TEST, {}, { retry: { maxRetries: 3, baseDelayMs: 1 } });
    expect(response.status).toBe(400);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('honours retry:false', async () => {
    const fetchMock = vi.fn(async () => json({ error: 'busy' }, 503));
    vi.stubGlobal('fetch', fetchMock);

    const response = await fetchWithRetry(URL_UNDER_TEST, {}, { retry: false });
    expect(response.status).toBe(503);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('gives up after the configured attempts and returns the last response', async () => {
    const fetchMock = vi.fn(async () => json({ error: 'busy' }, 503));
    vi.stubGlobal('fetch', fetchMock);

    const response = await fetchWithRetry(URL_UNDER_TEST, {}, { retry: { maxRetries: 2, baseDelayMs: 1, jitter: false } });
    expect(response.status).toBe(503);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('retries a transport failure', async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockResolvedValueOnce(json({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const response = await fetchWithRetry(URL_UNDER_TEST, {}, { retry: { maxRetries: 1, baseDelayMs: 1 } });
    expect(response.status).toBe(200);
  });

  it('aborts on the caller signal', async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      if (init.signal?.aborted) throw init.signal.reason;
      return json({ ok: true });
    });
    vi.stubGlobal('fetch', fetchMock);
    controller.abort(new DOMException('cancelled', 'AbortError'));

    await expect(fetchWithRetry(URL_UNDER_TEST, {}, { signal: controller.signal })).rejects.toThrow();
  });

  it('rejects an out-of-range retry budget', async () => {
    await expect(fetchWithRetry(URL_UNDER_TEST, {}, { retry: { maxRetries: 9 } })).rejects.toThrow(TypeError);
  });
});

describe('requestJson', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns the parsed object', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ issuer: 'https://id.test' })));
    const { payload, response } = await requestJson(URL_UNDER_TEST);
    expect(response.status).toBe(200);
    expect(payload.issuer).toBe('https://id.test');
  });

  it('refuses a non-object body', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json([1, 2, 3])));
    await expect(requestJson(URL_UNDER_TEST)).rejects.toThrow(/JSON object/);
  });

  it('refuses an oversized body', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ padding: 'x'.repeat(2048) })));
    await expect(requestJson(URL_UNDER_TEST, {}, { maxBytes: 128 })).rejects.toThrow(/byte limit/);
  });
});

describe('isRetryableNetworkError', () => {
  it('treats timeouts, aborts and transport errors as retryable', () => {
    expect(isRetryableNetworkError(new DOMException('timed out', 'TimeoutError'))).toBe(true);
    expect(isRetryableNetworkError(new TypeError('fetch failed'))).toBe(true);
    expect(isRetryableNetworkError(new Error('business logic'))).toBe(false);
  });
});

describe('SingleFlight', () => {
  it('runs one operation for concurrent callers and clears afterwards', async () => {
    const flight = new SingleFlight();
    let calls = 0;
    const operation = async (): Promise<number> => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return 42;
    };

    const results = await Promise.all([
      flight.run('key', operation),
      flight.run('key', operation),
      flight.run('key', operation),
    ]);

    expect(results).toEqual([42, 42, 42]);
    expect(calls).toBe(1);
    expect(flight.size).toBe(0);
  });

  it('does not cache a failure', async () => {
    const flight = new SingleFlight();
    await expect(flight.run('key', async () => {
      throw new Error('boom');
    })).rejects.toThrow('boom');

    await expect(flight.run('key', async () => 'ok')).resolves.toBe('ok');
  });
});
