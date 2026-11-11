import { describe, expect, it, vi } from 'vitest';
import { createLogger, redact, redactUrl, silentLogger } from '../src/core/logging.js';

describe('redact', () => {
  it('masks credential-bearing keys at any depth', () => {
    const redacted = redact({
      accessToken: 'secret-access',
      refresh_token: 'secret-refresh',
      nested: { idToken: 'secret-id', clientSecret: 'shh', authorizationCode: 'code' },
      list: [{ password: 'pw' }],
    }) as Record<string, unknown>;

    expect(redacted.accessToken).toBe('[redacted]');
    expect(redacted.refresh_token).toBe('[redacted]');
    const nested = redacted.nested as Record<string, unknown>;
    expect(nested.idToken).toBe('[redacted]');
    expect(nested.clientSecret).toBe('[redacted]');
    const list = redacted.list as Array<Record<string, unknown>>;
    expect(list[0]?.password).toBe('[redacted]');
  });

  it('masks JWT-shaped strings even under an innocent key', () => {
    const redacted = redact({ note: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl' }) as Record<string, unknown>;
    expect(redacted.note).toBe('[redacted-token]');
  });

  it('keeps harmless context readable', () => {
    const redacted = redact({ issuer: 'https://id.test', status: 401, retryable: false }) as Record<string, unknown>;
    expect(redacted.issuer).toBe('https://id.test');
    expect(redacted.status).toBe(401);
  });

  it('keeps only name, message and code from an error', () => {
    const error = Object.assign(new Error('token expired'), { code: 'TOKEN_ERROR', accessToken: 'secret' });
    const redacted = redact(error) as Record<string, unknown>;
    expect(redacted).toEqual({ name: 'Error', message: 'token expired', code: 'TOKEN_ERROR' });
  });

  it('bounds deep and cyclic structures', () => {
    const cyclic: Record<string, unknown> = { name: 'root' };
    cyclic.self = cyclic;
    expect(() => redact(cyclic)).not.toThrow();
    expect(redact(cyclic)).toMatchObject({ name: 'root' });
  });
});

describe('redactUrl', () => {
  it('strips query values, credentials and fragments', () => {
    const safe = redactUrl('https://user:pw@id.test/cb?code=abc&state=xyz#access_token=leak');
    expect(safe).not.toContain('abc');
    expect(safe).not.toContain('leak');
    expect(safe).not.toContain('pw');
  });

  it('does not throw on an unparseable URL', () => {
    expect(redactUrl('not a url')).toBe('[unparseable-url]');
  });
});

describe('createLogger', () => {
  it('emits nothing without a sink', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const logger = createLogger();
    logger.info('event', 'message', { accessToken: 'secret' });
    logger.warn('event', 'message');
    expect(consoleSpy).not.toHaveBeenCalled();
    expect(logger.enabled).toBe(false);
    consoleSpy.mockRestore();
  });

  it('emits to a supplied sink with redacted context', () => {
    const entries: Array<{ level: string; context?: unknown }> = [];
    const logger = createLogger({
      logger: (entry) => entries.push({ level: entry.level, context: entry.context }),
    });
    logger.warn('token.refresh.failed', 'refresh failed', { accessToken: 'secret', status: 500 });
    expect(entries).toHaveLength(1);
    expect(entries[0]?.context).toMatchObject({ accessToken: '[redacted]', status: 500 });
  });

  it('suppresses debug entries unless debug is enabled', () => {
    const entries: string[] = [];
    const logger = createLogger({ logger: (entry) => entries.push(entry.level) });
    logger.debug('a', 'b');
    expect(entries).toHaveLength(0);

    const debugLogger = createLogger({ debug: true, logger: (entry) => entries.push(entry.level) });
    debugLogger.debug('a', 'b');
    expect(entries).toEqual(['debug']);
  });

  it('survives a throwing sink', () => {
    const logger = createLogger({
      logger: () => {
        throw new Error('sink is broken');
      },
    });
    expect(() => logger.error('a', 'b')).not.toThrow();
  });

  it('exposes an inert logger for hosts that only need the type', () => {
    expect(silentLogger.enabled).toBe(false);
  });
});
