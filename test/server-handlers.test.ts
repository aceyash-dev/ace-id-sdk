import { describe, expect, it, vi } from 'vitest';
import { createAuthHandlers, getServerSession } from '../src/server/handlers.js';
import {
  clearCookie,
  openPayload,
  parseCookies,
  sealPayload,
  serializeCookie,
} from '../src/server/session.js';
import { AIDAuthenticationError } from '../src/core/errors.js';
import type { AIDServer } from '../src/server/client.js';
import type { AIDTokens, AIDUser } from '../src/core/types.js';

const ISSUER = 'https://identity.example.test';
const REDIRECT = 'https://app.example.test/api/auth/callback';
const SECRET = 'a-test-secret-with-enough-length';

const USER: AIDUser = { sub: 'user-1', email: 'user@example.test' };

/** Minimal stand-in for AIDServer: these handlers are unit-tested without a network. */
function stubClient(overrides: Partial<Record<string, unknown>> = {}): AIDServer {
  const tokens: AIDTokens = {
    accessToken: 'access-1',
    refreshToken: 'refresh-1',
    idToken: 'id-1',
    tokenType: 'Bearer',
    expiresIn: 3600,
    expiresAt: Date.now() + 3_600_000,
  };
  return {
    authorizationUrl: vi.fn(async (params: { redirectUri: string; state: string; nonce?: string }) =>
      `${ISSUER}/authorize?client_id=c&state=${params.state}&nonce=${params.nonce ?? ''}&redirect_uri=${encodeURIComponent(params.redirectUri)}`),
    exchangeCode: vi.fn(async () => tokens),
    verifyIdToken: vi.fn(async () => USER),
    refresh: vi.fn(async () => ({ ...tokens, accessToken: 'access-2', refreshToken: 'refresh-2' })),
    discovery: vi.fn(async () => ({ issuer: ISSUER, end_session_endpoint: `${ISSUER}/logout` })),
    ...overrides,
  } as unknown as AIDServer;
}

function allSetCookies(response: Response): string[] {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

/** The `name=value` pair of the named cookie from a response, or '' when absent. */
function cookieValue(response: Response, name: string): string {
  const match = allSetCookies(response).find((cookie) => cookie.startsWith(`${name}=`));
  return match ? match.split(';')[0] ?? '' : '';
}

function sealedValue(response: Response, name: string): string {
  const pair = cookieValue(response, name);
  return decodeURIComponent(pair.slice(name.length + 1));
}

describe('sealed session payloads', () => {
  it('round-trips a payload', async () => {
    const sealed = await sealPayload(SECRET, { user: USER }, { ttlSeconds: 60 });
    const opened = await openPayload<{ user: AIDUser }>(SECRET, sealed);
    expect(opened?.user.sub).toBe('user-1');
  });

  it('rejects a tampered payload', async () => {
    const sealed = await sealPayload(SECRET, { user: USER }, { ttlSeconds: 60 });
    const [version, iv, data] = sealed.split('.');
    const flipped = `${version}.${iv}.${(data ?? '').slice(0, -2)}AA`;
    expect(await openPayload(SECRET, flipped)).toBeNull();
  });

  it('rejects a payload sealed with another secret', async () => {
    const sealed = await sealPayload(SECRET, { user: USER }, { ttlSeconds: 60 });
    expect(await openPayload('another-secret-of-sufficient-length', sealed)).toBeNull();
  });

  it('rejects an expired payload', async () => {
    let now = 1_700_000_000_000;
    const sealed = await sealPayload(SECRET, { user: USER }, { ttlSeconds: 60, now: () => now });
    now += 61_000;
    expect(await openPayload(SECRET, sealed, { now: () => now })).toBeNull();
  });

  it('rejects malformed values and short secrets', async () => {
    expect(await openPayload(SECRET, 'not-a-token')).toBeNull();
    expect(await openPayload(SECRET, null)).toBeNull();
    await expect(sealPayload('short', {}, { ttlSeconds: 60 })).rejects.toThrow(/16 characters/);
  });
});

describe('cookie helpers', () => {
  it('parses a Cookie header', () => {
    expect(parseCookies('a=1; b=two; malformed')).toEqual({ a: '1', b: 'two' });
    expect(parseCookies(null)).toEqual({});
  });

  it('serialises with secure defaults', () => {
    const cookie = serializeCookie({ name: 'sid', value: 'v', maxAgeSeconds: 60 });
    expect(cookie).toContain('sid=v');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Max-Age=60');
  });

  it('can opt out of Secure for local HTTP development', () => {
    const cookie = serializeCookie({ name: 'sid', value: 'v', secure: false });
    expect(cookie).not.toContain('Secure');
  });

  it('clears a cookie', () => {
    expect(clearCookie('sid')).toContain('Max-Age=0');
  });
});

describe('createAuthHandlers', () => {
  function handlers(client: AIDServer, extra: Record<string, unknown> = {}) {
    return createAuthHandlers({
      client,
      redirectUri: REDIRECT,
      secret: SECRET,
      afterLogin: '/dashboard',
      afterLogout: '/goodbye',
      ...extra,
    });
  }

  it('starts the flow with state, nonce and a sealed state cookie', async () => {
    const client = stubClient();
    const response = await handlers(client).signIn(new Request(`${REDIRECT.replace('/callback', '/signin')}`));

    expect(response.status).toBe(302);
    const location = response.headers.get('location') ?? '';
    expect(location).toContain(`${ISSUER}/authorize`);
    const stateCookie = cookieValue(response, 'ace_id_state');
    expect(stateCookie).not.toBe('');
    expect(allSetCookies(response).join(';')).toContain('HttpOnly');

    const sealed = sealedValue(response, 'ace_id_state');
    const payload = await openPayload<{ state: string; codeVerifier: string }>(SECRET, sealed);
    expect(payload?.state).toBeTruthy();
    expect(payload?.codeVerifier).toBeTruthy();
    // The state in the cookie must match the one sent to the provider.
    expect(location).toContain(`state=${payload?.state}`);
  });

  it('rejects a cross-origin returnTo', async () => {
    const response = await handlers(stubClient()).signIn(
      new Request(`${REDIRECT.replace('/callback', '/signin')}?returnTo=https://evil.test/steal`),
    );
    expect(response.status).toBe(400);
  });

  it('completes the callback, sets a session cookie and redirects to the validated target', async () => {
    const client = stubClient();
    const auth = handlers(client);
    const start = await auth.signIn(new Request(`${REDIRECT.replace('/callback', '/signin')}?returnTo=/settings`));
    const stateCookie = cookieValue(start, 'ace_id_state');
    const location = new URL(start.headers.get('location') as string);
    const state = location.searchParams.get('state');

    const callback = await auth.callback(new Request(`${REDIRECT}?code=abc&state=${state}`, {
      headers: { cookie: stateCookie },
    }));

    expect(callback.status).toBe(302);
    expect(callback.headers.get('location')).toBe('https://app.example.test/settings');
    const sessionCookie = cookieValue(callback, 'ace_id_session');
    expect(sessionCookie).not.toBe('');

    const sealed = sealedValue(callback, 'ace_id_session');
    const session = await openPayload<{ user: AIDUser; refreshToken?: string }>(SECRET, sealed);
    expect(session?.user.sub).toBe('user-1');
    expect(session?.refreshToken).toBe('refresh-1');
  });

  it('rejects a callback whose state does not match the sealed cookie', async () => {
    const auth = handlers(stubClient());
    const start = await auth.signIn(new Request(REDIRECT.replace('/callback', '/signin')));
    const response = await auth.callback(new Request(`${REDIRECT}?code=abc&state=forged`, {
      headers: { cookie: cookieValue(start, 'ace_id_state') },
    }));
    expect(response.status).toBe(400);
  });

  it('rejects a callback without a state cookie', async () => {
    const auth = handlers(stubClient());
    const response = await auth.callback(new Request(`${REDIRECT}?code=abc&state=whatever`));
    expect(response.status).toBe(400);
  });

  it('reports provider errors without exchanging a code', async () => {
    const client = stubClient();
    const auth = handlers(client);
    const response = await auth.callback(new Request(`${REDIRECT}?error=access_denied`));
    expect(response.status).toBe(400);
    expect(client.exchangeCode).not.toHaveBeenCalled();
  });

  it('returns the session without exposing tokens', async () => {
    const client = stubClient();
    const auth = handlers(client);
    const start = await auth.signIn(new Request(REDIRECT.replace('/callback', '/signin')));
    const state = new URL(start.headers.get('location') as string).searchParams.get('state');
    const callback = await auth.callback(new Request(`${REDIRECT}?code=abc&state=${state}`, {
      headers: { cookie: cookieValue(start, 'ace_id_state') },
    }));
    const sessionCookie = cookieValue(callback, 'ace_id_session');

    const response = await auth.session(new Request(`${REDIRECT.replace('/callback', '/session')}`, {
      headers: { cookie: sessionCookie },
    }));
    const body = await response.json() as Record<string, unknown>;
    expect(body.authenticated).toBe(true);
    expect(JSON.stringify(body)).not.toContain('access-1');
    expect(JSON.stringify(body)).not.toContain('refresh-1');
  });

  it('reports an unauthenticated session without a cookie', async () => {
    const response = await handlers(stubClient()).session(new Request(`${REDIRECT.replace('/callback', '/session')}`));
    expect(await response.json()).toEqual({ authenticated: false, user: null });
  });

  it('rotates the session on refresh', async () => {
    const client = stubClient();
    const auth = handlers(client);
    const start = await auth.signIn(new Request(REDIRECT.replace('/callback', '/signin')));
    const state = new URL(start.headers.get('location') as string).searchParams.get('state');
    const callback = await auth.callback(new Request(`${REDIRECT}?code=abc&state=${state}`, {
      headers: { cookie: cookieValue(start, 'ace_id_state') },
    }));
    const sessionCookie = cookieValue(callback, 'ace_id_session');

    const refreshed = await auth.refresh(new Request(`${REDIRECT.replace('/callback', '/refresh')}`, {
      headers: { cookie: sessionCookie },
    }));
    expect(refreshed.status).toBe(200);
    const sealed = sealedValue(refreshed, 'ace_id_session');
    const session = await openPayload<{ accessToken: string; refreshToken: string }>(SECRET, sealed);
    expect(session?.accessToken).toBe('access-2');
    expect(session?.refreshToken).toBe('refresh-2');
  });

  it('clears the cookie on refresh failure', async () => {
    const client = stubClient({
      refresh: vi.fn(async () => {
        throw new AIDAuthenticationError('invalid_grant');
      }),
    });
    const auth = handlers(client);
    const start = await auth.signIn(new Request(REDIRECT.replace('/callback', '/signin')));
    const state = new URL(start.headers.get('location') as string).searchParams.get('state');
    const callback = await auth.callback(new Request(`${REDIRECT}?code=abc&state=${state}`, {
      headers: { cookie: cookieValue(start, 'ace_id_state') },
    }));

    const response = await auth.refresh(new Request(REDIRECT.replace('/callback', '/refresh'), {
      headers: { cookie: cookieValue(callback, 'ace_id_session') },
    }));
    expect(response.status).toBe(401);
    expect(allSetCookies(response).join(';')).toContain('Max-Age=0');
  });

  it('signs out to the provider endpoint and clears local cookies', async () => {
    const client = stubClient();
    const auth = handlers(client);
    const start = await auth.signIn(new Request(REDIRECT.replace('/callback', '/signin')));
    const state = new URL(start.headers.get('location') as string).searchParams.get('state');
    const callback = await auth.callback(new Request(`${REDIRECT}?code=abc&state=${state}`, {
      headers: { cookie: cookieValue(start, 'ace_id_state') },
    }));

    const response = await auth.signOut(new Request(REDIRECT.replace('/callback', '/signout'), {
      headers: { cookie: cookieValue(callback, 'ace_id_session') },
    }));
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toContain(`${ISSUER}/logout`);
    expect(response.headers.get('location')).toContain('post_logout_redirect_uri=');
    expect(allSetCookies(response).join(';')).toContain('Max-Age=0');
  });

  it('falls back to a local redirect when the provider has no logout endpoint', async () => {
    const client = stubClient({ discovery: vi.fn(async () => ({ issuer: ISSUER })) });
    const response = await handlers(client).signOut(new Request(REDIRECT.replace('/callback', '/signout')));
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('/goodbye');
  });

  it('reads the session through getServerSession', async () => {
    const sealed = await sealPayload(SECRET, { user: USER, accessToken: 'a', exp: 0 }, { ttlSeconds: 60 });
    const session = await getServerSession(
      new Request(REDIRECT, { headers: { cookie: `ace_id_session=${sealed}` } }),
      { secret: SECRET },
    );
    expect(session?.user.sub).toBe('user-1');
  });
});
