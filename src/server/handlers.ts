import { AIDAuthenticationError, AIDCallbackError, AIDError, AIDTokenError, aidErrorCode } from '../core/errors.js';
import { normalizeReturnTo } from '../core/redirect.js';
import { createCodeChallenge, createCodeVerifier, randomString } from '../browser/pkce.js';
import type { AIDUser } from '../core/types.js';
import type { AIDServer } from './client.js';
import { clearCookie, openPayload, parseCookies, sealPayload, serializeCookie } from './session.js';

/**
 * Framework-agnostic authorization handlers built on the Web Fetch API.
 *
 * They run unchanged in Next.js App Router route handlers, Remix loaders and
 * actions, Hono, Cloudflare Workers and Node's own `http` bridge, because they
 * take a `Request` and return a `Response`.
 *
 * The flow is the confidential-client variant: the code is exchanged with the
 * client secret, PKCE is still used as defence in depth, and the resulting
 * session lives in an encrypted, HttpOnly cookie. Tokens never reach the browser
 * as readable values.
 */

export interface ServerAuthOptions {
  client: AIDServer;
  /** The absolute callback URL registered with the identity provider. */
  redirectUri: string;
  /** Key material for the encrypted session cookie. At least 16 characters. */
  secret: string;
  /** Session cookie name. Defaults to `ace_id_session`. */
  cookieName?: string;
  /** Short-lived cookie holding the OAuth state. Defaults to `ace_id_state`. */
  stateCookieName?: string;
  /** Where to send the browser after a successful callback. */
  afterLogin?: string;
  /** Where to send the browser after sign-out. */
  afterLogout?: string;
  /** Session cookie lifetime in seconds. Defaults to 7 days. */
  sessionTtlSeconds?: number;
  /** State cookie lifetime in seconds. Defaults to 10 minutes. */
  stateTtlSeconds?: number;
  /** Set `false` only for local HTTP development. Defaults to true. */
  secure?: boolean;
  /** Extra authorization parameters, e.g. `{ prompt: 'login' }`. */
  authorizationParams?: Record<string, string>;
  now?: () => number;
}

export interface ServerSession {
  user: AIDUser;
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt?: number;
  nonce?: string;
  exp: number;
}

interface StatePayload {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  returnTo?: string;
  exp: number;
}

export interface AuthHandlers {
  signIn(request: Request): Promise<Response>;
  callback(request: Request): Promise<Response>;
  session(request: Request): Promise<Response>;
  refresh(request: Request): Promise<Response>;
  signOut(request: Request): Promise<Response>;
}

export function createAuthHandlers(options: ServerAuthOptions): AuthHandlers {
  const cookieName = options.cookieName ?? 'ace_id_session';
  const stateCookieName = options.stateCookieName ?? 'ace_id_state';
  const sessionTtlSeconds = options.sessionTtlSeconds ?? 7 * 24 * 60 * 60;
  const stateTtlSeconds = options.stateTtlSeconds ?? 10 * 60;
  const secure = options.secure !== false;
  const now = options.now ?? Date.now;

  const cookieAttributes = {
    name: cookieName,
    secure,
    httpOnly: true,
    sameSite: 'Lax' as const,
  };

  function json(body: unknown, status = 200, cookies: string[] = []): Response {
    const headers = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    for (const cookie of cookies) headers.append('set-cookie', cookie);
    return new Response(JSON.stringify(body), { status, headers });
  }

  function redirect(location: string, cookies: string[] = []): Response {
    const headers = new Headers({ location, 'cache-control': 'no-store' });
    for (const cookie of cookies) headers.append('set-cookie', cookie);
    return new Response(null, { status: 302, headers });
  }

  function errorResponse(err: unknown, status = 400): Response {
    const code = aidErrorCode(err);
    const message = err instanceof Error ? err.message : 'Authentication failed';
    return json({ error: code, message }, status);
  }

  async function readSession(request: Request): Promise<ServerSession | null> {
    const cookies = parseCookies(request.headers.get('cookie'));
    const sealed = cookies[cookieName];
    return openPayload<ServerSession>(options.secret, sealed, { now });
  }

  return {
    async signIn(request) {
      try {
        const url = new URL(request.url);
        const returnTo = normalizeReturnTo(url.searchParams.get('returnTo') ?? undefined, options.redirectUri);
        const state = randomString(32);
        const nonce = randomString(32);
        const codeVerifier = createCodeVerifier();
        const codeChallenge = await createCodeChallenge(codeVerifier);

        const statePayload: StatePayload = {
          state,
          nonce,
          codeVerifier,
          redirectUri: options.redirectUri,
          ...(returnTo !== undefined ? { returnTo } : {}),
          exp: 0,
        };
        const sealedState = await sealPayload(
          options.secret,
          statePayload as unknown as Record<string, unknown>,
          { ttlSeconds: stateTtlSeconds, now },
        );

        const authorizationUrl = await options.client.authorizationUrl({
          redirectUri: options.redirectUri,
          state,
          nonce,
          codeChallenge,
          extra: options.authorizationParams,
        });

        return redirect(authorizationUrl, [
          serializeCookie({
            name: stateCookieName,
            value: sealedState,
            maxAgeSeconds: stateTtlSeconds,
            secure,
            httpOnly: true,
            sameSite: 'Lax',
          }),
        ]);
      } catch (err) {
        return errorResponse(err, err instanceof AIDError ? 400 : 500);
      }
    },

    async callback(request) {
      const url = new URL(request.url);
      const clearStateCookie = clearCookie(stateCookieName);

      const providerError = url.searchParams.get('error');
      if (providerError) {
        return json({ error: 'CALLBACK_ERROR', message: `Authorization error: ${providerError}` }, 400, [clearStateCookie]);
      }

      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state) {
        return json({ error: 'CALLBACK_ERROR', message: 'Callback is missing "code" or "state"' }, 400, [clearStateCookie]);
      }

      const cookies = parseCookies(request.headers.get('cookie'));
      const statePayload = await openPayload<StatePayload>(options.secret, cookies[stateCookieName], { now });
      if (!statePayload) {
        return json(
          { error: 'CALLBACK_ERROR', message: 'Authorization state is missing, expired or tampered with' },
          400,
          [clearStateCookie],
        );
      }
      if (statePayload.state !== state) {
        return json({ error: 'CALLBACK_ERROR', message: 'Authorization state mismatch' }, 400, [clearStateCookie]);
      }

      try {
        const tokens = await options.client.exchangeCode(code, statePayload.redirectUri, {
          codeVerifier: statePayload.codeVerifier,
        });
        if (!tokens.idToken) {
          throw new AIDTokenError('Token response is missing "id_token"');
        }
        const user = await options.client.verifyIdToken(tokens.idToken, {
          nonce: statePayload.nonce,
        });
        const sealedSession = await sealPayload(
          options.secret,
          {
            user,
            accessToken: tokens.accessToken,
            ...(tokens.refreshToken ? { refreshToken: tokens.refreshToken } : {}),
            ...(tokens.idToken ? { idToken: tokens.idToken } : {}),
            ...(tokens.expiresAt !== undefined ? { expiresAt: tokens.expiresAt } : {}),
            nonce: statePayload.nonce,
          },
          { ttlSeconds: sessionTtlSeconds, now },
        );

        const destination = statePayload.returnTo ?? options.afterLogin ?? '/';
        return redirect(destination, [
          clearStateCookie,
          serializeCookie({
            ...cookieAttributes,
            value: sealedSession,
            maxAgeSeconds: sessionTtlSeconds,
          }),
        ]);
      } catch (err) {
        return json(
          { error: aidErrorCode(err), message: err instanceof Error ? err.message : 'Code exchange failed' },
          401,
          [clearStateCookie],
        );
      }
    },

    async session(request) {
      const session = await readSession(request);
      if (!session) return json({ authenticated: false, user: null }, 200);
      return json({
        authenticated: true,
        user: session.user,
        expiresAt: session.expiresAt ?? null,
      }, 200);
    },

    async refresh(request) {
      const session = await readSession(request);
      if (!session) return json({ authenticated: false, user: null }, 401);
      if (!session.refreshToken) {
        return json({ error: 'SESSION_ERROR', message: 'No refresh token in the server session' }, 400);
      }
      try {
        const tokens = await options.client.refresh(session.refreshToken);
        const user = tokens.idToken
          ? await options.client.verifyIdToken(tokens.idToken, { nonceRequired: false })
          : session.user;
        if (user.sub !== session.user.sub) {
          throw new AIDAuthenticationError('Refreshed ID token subject does not match the session');
        }
        const sealedSession = await sealPayload(
          options.secret,
          {
            user,
            accessToken: tokens.accessToken,
            ...(tokens.refreshToken ? { refreshToken: tokens.refreshToken } : {}),
            ...(tokens.idToken ? { idToken: tokens.idToken } : {}),
            ...(tokens.expiresAt !== undefined ? { expiresAt: tokens.expiresAt } : {}),
            nonce: session.nonce,
          },
          { ttlSeconds: sessionTtlSeconds, now },
        );
        return json(
          { authenticated: true, user, expiresAt: tokens.expiresAt ?? null },
          200,
          [serializeCookie({ ...cookieAttributes, value: sealedSession, maxAgeSeconds: sessionTtlSeconds })],
        );
      } catch (err) {
        const status = err instanceof AIDAuthenticationError || err instanceof AIDTokenError ? 401 : 500;
        return json(
          { error: aidErrorCode(err), message: err instanceof Error ? err.message : 'Refresh failed' },
          status,
          [clearCookie(cookieName)],
        );
      }
    },

    async signOut(request) {
      const session = await readSession(request);
      const cleared = [clearCookie(cookieName), clearCookie(stateCookieName)];
      const destination = options.afterLogout ?? '/';

      if (!session) return redirect(destination, cleared);

      try {
        const discovery = await options.client.discovery();
        if (discovery.end_session_endpoint) {
          const url = new URL(discovery.end_session_endpoint);
          if (session.idToken) url.searchParams.set('id_token_hint', session.idToken);
          url.searchParams.set('post_logout_redirect_uri', destination);
          return redirect(url.toString(), cleared);
        }
      } catch {
        // Provider logout is best-effort; the local session is cleared regardless.
      }
      return redirect(destination, cleared);
    },
  };
}

/** Read the current server session from a request without rendering a response. */
export async function getServerSession(
  request: Request,
  options: Pick<ServerAuthOptions, 'secret' | 'cookieName' | 'now'>,
): Promise<ServerSession | null> {
  const cookies = parseCookies(request.headers.get('cookie'));
  const sealed = cookies[options.cookieName ?? 'ace_id_session'];
  return openPayload<ServerSession>(options.secret, sealed, options.now ? { now: options.now } : {});
}

export { AIDCallbackError };
