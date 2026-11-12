import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { AID } from '../src/browser/client.js';
import type { AIDStorage } from '../src/core/types.js';

const REDIRECT = 'https://app.example.test/cb';

describe('storage failure', () => {
  it('treats corrupted stored session data as signed out', () => {
    const data = new Map<string, string>([['aid:session', '{not json']]);
    const storage: AIDStorage = {
      get: (k) => data.get(k) ?? null,
      set: (k, v) => void data.set(k, v),
      remove: (k) => void data.delete(k),
    };
    const aid = new AID({ issuer: 'https://issuer.invalid', clientId: 'c', redirectUri: REDIRECT, storage });
    expect(aid.getSession()).toBeNull();
    expect(aid.isAuthenticated()).toBe(false);
  });

  it('signOut clears local state even when the provider is unreachable', async () => {
    const data = new Map<string, string>();
    const storage: AIDStorage = {
      get: (k) => data.get(k) ?? null,
      set: (k, v) => void data.set(k, v),
      remove: (k) => void data.delete(k),
    };
    const aid = new AID({ issuer: 'https://issuer.invalid', clientId: 'c', redirectUri: REDIRECT, storage, requestTimeoutMs: 500 });
    data.set('aid:session', JSON.stringify({ user: { sub: 'u' }, tokens: { accessToken: 'a' }, nonce: 'n' }));
    await aid.signOut().catch(() => undefined);
    expect(data.get('aid:session')).toBeUndefined();
  });
});

describe('package manifest', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  it('exposes every documented entry point with types, import and require', () => {
    for (const entry of ['.', './react', './server', './testing', './diagnostics']) {
      const e = pkg.exports[entry];
      expect(e, entry).toBeDefined();
      expect(e.types ?? e.import?.types, entry).toBeTruthy();
      expect(JSON.stringify(e), entry).toMatch(/import/);
      expect(JSON.stringify(e), entry).toMatch(/require/);
    }
  });
  it('keeps jose as the only runtime dependency', () => {
    expect(Object.keys(pkg.dependencies)).toEqual(['jose']);
  });
});
