import { describe, expect, it } from 'vitest';
import { fetchDiscovery, normalizeIssuer } from '../src/core/discovery.js';

const issuer = (globalThis as typeof globalThis & {
  process?: { env?: Record<string, string | undefined> };
}).process?.env?.ACE_ID_TEST_ISSUER;

/**
 * Optional live-provider smoke test.
 * Set ACE_ID_TEST_ISSUER to a dedicated non-production development issuer.
 * Never point this test at a production tenant with real credentials.
 */
describe('live development issuer compatibility', () => {
  it.skipIf(!issuer)('publishes valid OIDC discovery metadata', async () => {
    const discovery = await fetchDiscovery(issuer as string, 10_000);
    const normalizedIssuer = normalizeIssuer(issuer as string);
    expect(normalizeIssuer(discovery.issuer)).toBe(normalizedIssuer);
    const issuerUrl = new URL(normalizedIssuer);
    const isLoopback = ['localhost', '127.0.0.1', '[::1]'].includes(issuerUrl.hostname.toLowerCase());
    for (const endpoint of [discovery.authorization_endpoint, discovery.token_endpoint]) {
      const url = new URL(endpoint);
      expect(url.protocol === 'https:' || (isLoopback && url.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname.toLowerCase()))).toBe(true);
    }
    expect(discovery.jwks_uri).toBeTruthy();
    expect(discovery.code_challenge_methods_supported ?? []).toContain('S256');
  });
});
