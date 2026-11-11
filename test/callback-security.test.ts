import { afterEach, describe, expect, it } from 'vitest';
import { AID } from '../src/browser/client.js';
import { MemoryStorage } from '../src/browser/storage.js';
import { AIDCallbackError, AIDTokenError } from '../src/core/errors.js';
import { startOidcFixture, type OidcFixture } from './helpers/oidc-fixture.js';

const REDIRECT = 'https://app.example.test/auth/callback';
const CLIENT_ID = 'client-1';

let fixture: OidcFixture | undefined;

afterEach(async () => {
  await fixture?.close();
  fixture = undefined;
});

function client(storage: MemoryStorage, issuer: string): AID {
  return new AID({ issuer, clientId: CLIENT_ID, redirectUri: REDIRECT, storage });
}

function seedTransaction(
  storage: MemoryStorage,
  overrides: Record<string, unknown> = {},
): void {
  storage.set('aid:transaction', JSON.stringify({
    state: 'expected-state',
    nonce: 'nonce-1',
    codeVerifier: 'v'.repeat(43),
    redirectUri: REDIRECT,
    createdAt: Date.now(),
    ...overrides,
  }));
}

describe('callback hardening', () => {
  it('rejects a code delivered to a different path on the same origin', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    seedTransaction(storage);

    await expect(
      client(storage, fixture.issuer).handleCallback(
        `https://app.example.test/other?code=abc&state=expected-state`,
      ),
    ).rejects.toThrow(/path/i);

    // The transaction survives: the request never reached the exchange.
    expect(storage.get('aid:transaction')).not.toBeNull();
    expect(fixture.tokenRequests()).toBe(0);
  });

  it('rejects a callback on a foreign origin', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    seedTransaction(storage);

    await expect(
      client(storage, fixture.issuer).handleCallback(
        `https://evil.example.test/auth/callback?code=abc&state=expected-state`,
      ),
    ).rejects.toThrow(AIDCallbackError);
    expect(fixture.tokenRequests()).toBe(0);
  });

  it('rejects duplicate authorization parameters', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    seedTransaction(storage);

    await expect(
      client(storage, fixture.issuer).handleCallback(
        `${REDIRECT}?code=abc&code=def&state=expected-state`,
      ),
    ).rejects.toThrow(/duplicate/i);
    expect(fixture.tokenRequests()).toBe(0);
  });

  it('rejects a callback carrying both error and code', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    seedTransaction(storage);

    await expect(
      client(storage, fixture.issuer).handleCallback(
        `${REDIRECT}?error=access_denied&code=abc&state=expected-state`,
      ),
    ).rejects.toThrow(/both/i);
    expect(fixture.tokenRequests()).toBe(0);
  });

  it('clears the transaction when the provider returns an error', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    seedTransaction(storage);

    await expect(
      client(storage, fixture.issuer).handleCallback(
        `${REDIRECT}?error=access_denied&error_description=user+cancelled&state=expected-state`,
      ),
    ).rejects.toThrow(/access_denied/);

    expect(storage.get('aid:transaction')).toBeNull();
    expect(storage.get('aid:session')).toBeNull();
  });

  it('cannot replay a consumed code', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    seedTransaction(storage);
    const aid = client(storage, fixture.issuer);

    const first = await aid.handleCallback(`${REDIRECT}?code=abc&state=expected-state`);
    expect(first.user.sub).toBe('user-1');
    expect(storage.get('aid:transaction')).toBeNull();

    await expect(
      aid.handleCallback(`${REDIRECT}?code=abc&state=expected-state`),
    ).rejects.toThrow(/No authorization transaction/i);
  });

  it('rejects an ID token whose nonce does not match the transaction', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    seedTransaction(storage, { nonce: 'a-different-nonce' });

    await expect(
      client(storage, fixture.issuer).handleCallback(`${REDIRECT}?code=abc&state=expected-state`),
    ).rejects.toThrow(AIDTokenError);
    expect(storage.get('aid:session')).toBeNull();
  });

  it('rejects an expired transaction', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    seedTransaction(storage, { createdAt: Date.now() - 60 * 60 * 1000 });

    await expect(
      client(storage, fixture.issuer).handleCallback(`${REDIRECT}?code=abc&state=expected-state`),
    ).rejects.toThrow(/expired/i);
    expect(fixture.tokenRequests()).toBe(0);
  });

  it('rejects a transaction whose redirectUri was tampered with', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    seedTransaction(storage, { redirectUri: 'https://evil.example.test/cb' });

    await expect(
      client(storage, fixture.issuer).handleCallback(`${REDIRECT}?code=abc&state=expected-state`),
    ).rejects.toThrow(AIDCallbackError);
    expect(fixture.tokenRequests()).toBe(0);
  });

  it('rejects a corrupt transaction instead of trusting it', async () => {
    fixture = await startOidcFixture();
    const storage = new MemoryStorage();
    storage.set('aid:transaction', '{"state":42}');

    await expect(
      client(storage, fixture.issuer).handleCallback(`${REDIRECT}?code=abc&state=expected-state`),
    ).rejects.toThrow(/No authorization transaction/i);
  });
});
