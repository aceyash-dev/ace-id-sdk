import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchDiscovery } from '../src/core/discovery.js';
import { AIDDiscoveryError } from '../src/core/errors.js';

const ISSUER = 'https://issuer.test';

afterEach(() => vi.unstubAllGlobals());

describe('OIDC protocol compatibility', () => {
  it('accepts a valid authorization-code and S256 discovery document', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      issuer: ISSUER, authorization_endpoint: ISSUER + '/authorize',
      token_endpoint: ISSUER + '/token', jwks_uri: ISSUER + '/jwks',
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
    }), { status: 200, headers: { 'content-type': 'application/json' } })));
    const document = await fetchDiscovery(ISSUER);
    expect(document.issuer).toBe(ISSUER);
    expect(document.code_challenge_methods_supported).toContain('S256');
  });

  it('rejects issuer mismatches and malformed discovery documents', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      issuer: 'https://attacker.test', authorization_endpoint: 'https://attacker.test/auth',
      token_endpoint: 'https://attacker.test/token',
    }), { status: 200, headers: { 'content-type': 'application/json' } })));
    await expect(fetchDiscovery(ISSUER)).rejects.toThrow(AIDDiscoveryError);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('[]', {
      status: 200, headers: { 'content-type': 'application/json' },
    })));
    await expect(fetchDiscovery(ISSUER)).rejects.toThrow(AIDDiscoveryError);
  });

  it('rejects insecure token endpoints returned by discovery', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      issuer: ISSUER, authorization_endpoint: ISSUER + '/authorize',
      token_endpoint: 'http://issuer.test/token',
    }), { status: 200, headers: { 'content-type': 'application/json' } })));
    await expect(fetchDiscovery(ISSUER)).rejects.toThrow(/HTTPS/i);
  });
});
