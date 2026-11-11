import { afterEach, describe, expect, it, vi } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';
import { AIDCallbackError, AIDError } from '../src/core/errors.js';
import { startOidcFixture, type OidcFixture } from './helpers/oidc-fixture.js';

const REDIRECT = 'https://app.example.test/cb';
const CLIENT_ID = 'client-1';

function mockLocation() {
  const assign = vi.fn();
  Object.defineProperty(globalThis, 'location', {
    configurable: true,
    value: { href: REDIRECT, assign },
  });
  return assign;
}

function seedTransaction(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    state: 'expected-state',
    nonce: 'nonce-1',
    codeVerifier: 'v'.repeat(43),
    redirectUri: REDIRECT,
    createdAt: Date.now(),
    ...overrides,
  });
}

describe('returnTo handling', () => {
  let fixture: OidcFixture | undefined;

  afterEach(async () => {
    vi.restoreAllMocks();
    await fixture?.close();
    fixture = undefined;
  });

  function makeClient(storage: MemoryStorage, issuer: string): AID {
    return new AID({ issuer, clientId: CLIENT_ID, redirectUri: REDIRECT, storage });
  }

  it('stores a normalised same-origin returnTo in the authorization transaction', async () => {
    fixture = await startOidcFixture();
    const assign = mockLocation();
    const storage = new MemoryStorage();

    await makeClient(storage, fixture.issuer).signIn({ returnTo: '/dashboard?tab=security' });

    expect(assign).toHaveBeenCalledTimes(1);
    const transaction = JSON.parse(storage.get('aid:transaction') as string);
    expect(transaction.returnTo).toBe('https://app.example.test/dashboard?tab=security');
  });

  it('accepts an absolute URL on the redirect URI origin', async () => {
    fixture = await startOidcFixture();
    mockLocation();
    const storage = new MemoryStorage();

    await makeClient(storage, fixture.issuer).signIn({
      returnTo: 'https://app.example.test/settings/profile',
    });

    expect(JSON.parse(storage.get('aid:transaction') as string).returnTo)
      .toBe('https://app.example.test/settings/profile');
  });

  it('rejects cross-origin, protocol-relative, credentialed and script return targets', async () => {
    fixture = await startOidcFixture();
    mockLocation();

    for (const returnTo of [
      'https://evil.example.test/steal',
      '//evil.example.test/steal',
      'https://user:pass@app.example.test/x',
      'javascript:alert(1)',
      '   ',
    ]) {
      const storage = new MemoryStorage();
      const aid = makeClient(storage, fixture.issuer);
      await expect(aid.signIn({ returnTo })).rejects.toBeInstanceOf(AIDError);
      expect(storage.get('aid:transaction')).toBeNull();
    }
  });

  it('returns the returnTo from handleCallback without persisting it in the session', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    storage.set(
      'aid:transaction',
      seedTransaction({ returnTo: 'https://app.example.test/dashboard' }),
    );

    const result = await makeClient(storage, fixture.issuer).handleCallback(
      `${REDIRECT}?code=abc&state=expected-state`,
    );

    expect(result.returnTo).toBe('https://app.example.test/dashboard');
    expect(result.user.sub).toBe('user-1');

    const storedSession = JSON.parse(storage.get('aid:session') as string);
    expect(storedSession.returnTo).toBeUndefined();
    expect(storage.get('aid:transaction')).toBeNull();
  });

  it('omits returnTo when signIn was called without one', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    storage.set('aid:transaction', seedTransaction());

    const result = await makeClient(storage, fixture.issuer).handleCallback(
      `${REDIRECT}?code=abc&state=expected-state`,
    );

    expect('returnTo' in result).toBe(false);
  });

  it('rejects a persisted transaction whose returnTo points off-origin', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    storage.set(
      'aid:transaction',
      seedTransaction({ returnTo: 'https://evil.example.test/steal' }),
    );

    await expect(
      makeClient(storage, fixture.issuer).handleCallback(
        `${REDIRECT}?code=abc&state=expected-state`,
      ),
    ).rejects.toBeInstanceOf(AIDCallbackError);
    expect(storage.get('aid:transaction')).toBeNull();
  });
});
