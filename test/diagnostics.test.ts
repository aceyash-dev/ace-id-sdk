import { afterEach, describe, expect, it, vi } from 'vitest';
import { diagnoseAID } from '../src/diagnostics.js';

const ISSUER = 'https://issuer.test';

afterEach(() => vi.unstubAllGlobals());

describe('safe SDK diagnostics', () => {
  it('reports supported capabilities without including tokens or secrets', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      issuer: ISSUER,
      authorization_endpoint: ISSUER + '/authorize',
      token_endpoint: ISSUER + '/token',
      userinfo_endpoint: ISSUER + '/userinfo',
      jwks_uri: ISSUER + '/jwks',
      end_session_endpoint: ISSUER + '/logout',
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    }), { status: 200, headers: { 'content-type': 'application/json' } })));
    const report = await diagnoseAID({
      issuer: ISSUER,
      clientId: 'client-secret-like-but-public-client-id',
      redirectUri: 'https://app.test/callback',
      expectedCallbacks: ['https://app.test/callback'],
    });
    expect(report.ok).toBe(true);
    expect(report.capabilities?.pkceS256).toBe(true);
    expect(JSON.stringify(report)).not.toContain('client-secret-like-but-public-client-id');
    expect(JSON.stringify(report)).not.toContain('access_token');
  });

  it('flags callback mismatches without echoing sensitive data', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      issuer: ISSUER, authorization_endpoint: ISSUER + '/authorize',
      token_endpoint: ISSUER + '/token', jwks_uri: ISSUER + '/jwks',
    }), { status: 200, headers: { 'content-type': 'application/json' } })));
    const report = await diagnoseAID({
      issuer: ISSUER, clientId: 'client',
      redirectUri: 'https://app.test/callback',
      expectedCallbacks: ['https://other.test/callback'],
    });
    expect(report.ok).toBe(false);
    expect(report.checks.find((check) => check.name === 'registered-callback')?.status).toBe('fail');
  });

  it('fails diagnostics for a missing client ID and an unsafe redirect', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      issuer: ISSUER,
      authorization_endpoint: ISSUER + '/authorize',
      token_endpoint: ISSUER + '/token',
      jwks_uri: ISSUER + '/jwks',
    }), { status: 200, headers: { 'content-type': 'application/json' } })));
    const report = await diagnoseAID({
      issuer: ISSUER,
      clientId: ' ',
      redirectUri: 'https://user@app.test/callback#fragment',
    });
    expect(report.ok).toBe(false);
    expect(report.checks.find((check) => check.name === 'client-id')?.status).toBe('fail');
    expect(report.checks.find((check) => check.name === 'redirect-uri')?.status).toBe('fail');
    expect(report.redirectUri).toBe('https://app.test/callback');
  });
});
