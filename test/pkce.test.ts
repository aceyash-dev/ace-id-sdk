import { describe, expect, it } from 'vitest';
import { createCodeChallenge, createCodeVerifier } from '../src/browser/pkce.js';

describe('PKCE', () => {
  it('produces verifiers within RFC 7636 bounds', () => {
    const v = createCodeVerifier();
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
    expect(v).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it('produces unique verifiers', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) seen.add(createCodeVerifier());
    expect(seen.size).toBe(200);
  });

  it('derives the RFC 7636 Appendix B S256 challenge', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = await createCodeChallenge(verifier);
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('rejects verifier lengths outside 43..128', async () => {
    await expect(createCodeChallenge('short')).rejects.toThrow(RangeError);
    await expect(createCodeChallenge('x'.repeat(129))).rejects.toThrow(RangeError);
  });
});