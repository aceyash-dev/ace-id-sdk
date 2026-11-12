import type { AIDSession, AIDTokens } from './types.js';
import { hasKnownExpiry, isTokenExpired } from './tokens.js';

/**
 * Explicit session states.
 *
 * Applications should not have to infer "am I signed in?" from a nullable
 * session plus an expiry timestamp. These four states are the ones an
 * application actually branches on, and they distinguish "no session" from
 * "session present but expired" from "refresh failed" — three situations that
 * call for three different UX responses.
 */
export type AIDSessionStatus = 'authenticated' | 'unauthenticated' | 'expired' | 'refresh-failed';

export interface AIDSessionStateAuthenticated {
  status: 'authenticated';
  session: AIDSession;
  /** True when the provider never reported `expires_in` for the current token. */
  expiryUnknown: boolean;
}

export interface AIDSessionStateUnauthenticated {
  status: 'unauthenticated';
}

export interface AIDSessionStateExpired {
  status: 'expired';
  session: AIDSession;
}

export interface AIDSessionStateRefreshFailed {
  status: 'refresh-failed';
  error: Error;
  /** The last known session, which the SDK did not discard. */
  session?: AIDSession;
}

export type AIDSessionState =
  | AIDSessionStateAuthenticated
  | AIDSessionStateUnauthenticated
  | AIDSessionStateExpired
  | AIDSessionStateRefreshFailed;

export type AIDSessionListener = (state: AIDSessionState) => void;

export interface DeriveSessionStateOptions {
  /** Seconds of clock skew tolerated before a token counts as expired. */
  leewaySeconds?: number;
  now?: number;
}

/**
 * Classify a stored session.
 *
 * An unreported expiry is *not* treated as expired: the SDK does not invent a
 * lifetime, and refusing to use such a session would break providers that omit
 * `expires_in`. It is surfaced as `expiryUnknown` so the application can decide
 * how aggressive to be.
 */
export function deriveSessionState(
  session: AIDSession | null | undefined,
  options: DeriveSessionStateOptions = {},
): AIDSessionState {
  if (!session) return { status: 'unauthenticated' };
  if (!hasKnownExpiry(session.tokens)) {
    return { status: 'authenticated', session, expiryUnknown: true };
  }
  if (isTokenExpired(session.tokens, options.leewaySeconds ?? 60, options.now ?? Date.now())) {
    return { status: 'expired', session };
  }
  return { status: 'authenticated', session, expiryUnknown: false };
}

function tokenFingerprint(tokens: AIDTokens | undefined): string {
  if (!tokens) return '';
  return `${tokens.accessToken}:${tokens.expiresAt ?? 'none'}:${tokens.obtainedAt ?? 'none'}`;
}

function isSameState(a: AIDSessionState, b: AIDSessionState): boolean {
  if (a.status !== b.status) return false;
  switch (a.status) {
    case 'unauthenticated':
      return true;
    case 'refresh-failed':
      return b.status === 'refresh-failed' && a.error.message === b.error.message;
    case 'expired':
      return b.status === 'expired' && tokenFingerprint(a.session.tokens) === tokenFingerprint(b.session.tokens);
    case 'authenticated':
      return b.status === 'authenticated' &&
        tokenFingerprint(a.session.tokens) === tokenFingerprint(b.session.tokens) &&
        a.session.user.sub === b.session.user.sub;
    default:
      return false;
  }
}

/**
 * Holds the latest state and fans it out to subscribers.
 *
 * Subscribers are notified only on a real change: a re-read of the same session
 * must not wake every React component in the tree. A throwing subscriber is
 * isolated so one bad listener cannot stop the others or break a sign-in.
 */
export class SessionStateEmitter {
  private state: AIDSessionState = { status: 'unauthenticated' };
  private readonly listeners = new Set<AIDSessionListener>();

  get current(): AIDSessionState {
    return this.state;
  }

  get listenerCount(): number {
    return this.listeners.size;
  }

  /** Replace the state, notifying subscribers when it actually changed. */
  set(next: AIDSessionState): AIDSessionState {
    if (isSameState(this.state, next)) return this.state;
    this.state = next;
    for (const listener of [...this.listeners]) {
      try {
        listener(next);
      } catch {
        // A listener must never break authentication or other listeners.
      }
    }
    return next;
  }

  /** Re-derive from a session without forcing a notification when nothing changed. */
  update(session: AIDSession | null | undefined, options: DeriveSessionStateOptions = {}): AIDSessionState {
    return this.set(deriveSessionState(session, options));
  }

  subscribe(listener: AIDSessionListener): () => void {
    if (typeof listener !== 'function') {
      throw new TypeError('onAuthStateChange requires a function listener');
    }
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  clear(): void {
    this.listeners.clear();
  }
}
