import { afterEach, describe, expect, it, vi } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';
import { validateAIDConfig } from '../src/core/config.js';
import { AIDError } from '../src/core/errors.js';

const ISSUER = 'https://identity.example.test';
const REDIRECT = 'https://app.example.test/cb';

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('validateAIDConfig', () => {
  it('passes a complete configuration', () => {
    const report = validateAIDConfig({
      issuer: ISSUER,
      clientId: 'client-1',
      redirectUri: REDIRECT,
      storage: new MemoryStorage(),
    });
    expect(report.ok).toBe(true);
    expect(report.summary).toMatch(/passed/i);
  });

  it('reports every problem at once instead of only the first', () => {
    const report = validateAIDConfig({
      issuer: 'http://identity.example.test',
      clientId: '',
      redirectUri: 'not-a-url',
      requestTimeoutMs: -1,
      leewaySeconds: -5,
      allowedSigningAlgorithms: ['HS256'],
    });
    expect(report.ok).toBe(false);
    const failing = report.checks.filter((item) => item.status === 'fail').map((item) => item.name);
    expect(failing).toEqual(expect.arrayContaining([
      'issuer-valid',
      'client-id',
      'redirect-uri',
      'requestTimeoutMs',
      'leewaySeconds',
      'signing-algorithms',
    ]));
  });

  it('refuses symmetric or "none" signing algorithms', () => {
    const report = validateAIDConfig({
      issuer: ISSUER,
      clientId: 'c',
      redirectUri: REDIRECT,
      allowedSigningAlgorithms: ['none'],
    });
    expect(report.ok).toBe(false);
  });

  it('refuses a redirect URI carrying a fragment or credentials', () => {
    for (const redirectUri of ['https://app.example.test/cb#token', 'https://u:p@app.example.test/cb']) {
      const report = validateAIDConfig({ issuer: ISSUER, clientId: 'c', redirectUri });
      expect(report.ok).toBe(false);
    }
  });

  it('warns rather than fails on an excessive clock-skew tolerance', () => {
    const report = validateAIDConfig({
      issuer: ISSUER,
      clientId: 'c',
      redirectUri: REDIRECT,
      clockSkewSeconds: 900,
    });
    expect(report.ok).toBe(true);
    expect(report.checks.find((item) => item.name === 'clock-skew-range')?.status).toBe('warn');
  });

  it('requires a bare origin in additionalRedirectOrigins', () => {
    const report = validateAIDConfig({
      issuer: ISSUER,
      clientId: 'c',
      redirectUri: REDIRECT,
      additionalRedirectOrigins: ['https://app.example.test/path'],
    });
    expect(report.ok).toBe(false);
  });
});

describe('AID configuration errors', () => {
  it('aggregates failures into one configuration error', () => {
    expect(() => new AID({
      issuer: ISSUER,
      clientId: '',
      redirectUri: REDIRECT,
      leewaySeconds: -1,
    })).toThrow(/Invalid Ace ID configuration/);
  });

  it('still reports an insecure issuer as a discovery error', () => {
    expect(() => new AID({
      issuer: 'http://identity.example.test',
      clientId: 'c',
      redirectUri: REDIRECT,
    })).toThrow(AIDError);
  });

  it('rejects a non-boolean autoRefresh', () => {
    expect(() => new AID({
      issuer: ISSUER,
      clientId: 'c',
      redirectUri: REDIRECT,
      autoRefresh: 'yes' as unknown as boolean,
    })).toThrow(AIDError);
  });
});

describe('AID#validateConfiguration', () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('adds live capability checks when discovery succeeds', async () => {
    globalThis.fetch = vi.fn(async () => json({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks`,
      userinfo_endpoint: `${ISSUER}/userinfo`,
      end_session_endpoint: `${ISSUER}/logout`,
      code_challenge_methods_supported: ['S256'],
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    })) as unknown as typeof fetch;

    const client = new AID({
      issuer: ISSUER,
      clientId: 'c',
      redirectUri: REDIRECT,
      storage: new MemoryStorage(),
    });
    const report = await client.validateConfiguration();

    expect(report.ok).toBe(true);
    const names = report.checks.map((item) => item.name);
    expect(names).toEqual(expect.arrayContaining(['discovery', 'pkce-s256', 'jwks', 'refresh-grant', 'userinfo']));
  });

  it('fails the report, not the call, when discovery is unreachable', async () => {
    globalThis.fetch = vi.fn(async () => json({ error: 'boom' }, 503)) as unknown as typeof fetch;

    const client = new AID({
      issuer: ISSUER,
      clientId: 'c',
      redirectUri: REDIRECT,
      storage: new MemoryStorage(),
      maxRetries: 0,
    });
    const report = await client.validateConfiguration();

    expect(report.ok).toBe(false);
    expect(report.checks.find((item) => item.name === 'discovery')?.status).toBe('fail');
  });

  it('flags a provider that does not advertise S256', async () => {
    globalThis.fetch = vi.fn(async () => json({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks`,
      code_challenge_methods_supported: ['plain'],
    })) as unknown as typeof fetch;

    const client = new AID({
      issuer: ISSUER,
      clientId: 'c',
      redirectUri: REDIRECT,
      storage: new MemoryStorage(),
    });
    const report = await client.validateConfiguration();
    expect(report.checks.find((item) => item.name === 'pkce-s256')?.status).toBe('fail');
  });
});
