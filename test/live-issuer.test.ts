import { describe, expect, it } from 'vitest';
import { fetchDiscovery } from '../src/core/discovery.js';

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
    expect(discovery.issuer).toBe(issuer);
    expect(new URL(discovery.authorization_endpoint).protocol).toBe('https:');
    expect(new URL(discovery.token_endpoint).protocol).toBe('https:');
    expect(discovery.jwks_uri).toBeTruthy();
    expect(discovery.code_challenge_methods_supported ?? []).toContain('S256');
  });
});
