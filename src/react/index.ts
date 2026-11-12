import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type { ReactNode } from 'react';
import { AID } from '../browser/client.js';
import type { AIDAuthorizationOptions, AIDCallbackResult, AIDSession, AIDUser } from '../core/types.js';
import { AIDError } from '../core/errors.js';
import type { AIDSessionState } from '../core/session-state.js';

/**
 * React adapter.
 *
 * The provider is deliberately thin: it owns no token store and no refresh
 * implementation. It subscribes to the client's session-state stream, so a
 * sign-in that happened in another tab, another component or a server helper is
 * reflected here without a second source of truth.
 *
 * `status` collapses the SDK's four states into the three a view branches on:
 * an `expired` session still has a user and is refreshed on demand, so it counts
 * as authenticated here. Use `authState` when the precise state matters.
 */
export type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated' | 'error';

export interface AuthContextValue {
  client: AID;
  session: AIDSession | null;
  user: AIDUser | null;
  status: AuthStatus;
  /** False while the initial session is being read from storage. */
  isLoading: boolean;
  isAuthenticated: boolean;
  /** Precise SDK state, including `expired` and `refresh-failed`. */
  authState: AIDSessionState | null;
  error: Error | null;
  /**
   * Validated same-origin target from the callback that produced the current
   * session, or null. Navigating there is the host app's responsibility.
   */
  returnTo: string | null;
  refreshSession(): void;
  signIn(options?: AIDAuthorizationOptions & { returnTo?: string }): Promise<void>;
  handleCallback(url?: string): Promise<AIDCallbackResult>;
  signOut(options?: { redirectTo?: string }): Promise<void>;
  fetchProfile(): Promise<AIDUser>;
}

export interface AuthProviderProps {
  client: AID;
  children?: ReactNode;
  /** Disable initial session hydration when the host app controls hydration. */
  hydrateOnMount?: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ client, children, hydrateOnMount = true }: AuthProviderProps): ReactNode {
  const [session, setSession] = useState<AIDSession | null>(null);
  const [authState, setAuthState] = useState<AIDSessionState | null>(null);
  const [status, setStatus] = useState<AuthStatus>(hydrateOnMount ? 'loading' : 'unauthenticated');
  const [error, setError] = useState<Error | null>(null);
  const [returnTo, setReturnTo] = useState<string | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    if (!hydrateOnMount) return;
    // A single subscription keeps this provider in sync with every other
    // consumer of the same client, including a sign-out performed elsewhere.
    const unsubscribe = client.onAuthStateChange((next) => {
      if (!mounted.current) return;
      setAuthState(next);
      if (next.status === 'authenticated') {
        setSession(next.session);
        setStatus('authenticated');
      } else if (next.status === 'expired') {
        setSession(next.session);
        // Still signed in; the access token is refreshed on demand.
        setStatus('authenticated');
      } else if (next.status === 'refresh-failed') {
        setSession(next.session ?? null);
        setError(next.error);
        setStatus(next.session ? 'authenticated' : 'error');
      } else {
        setSession(null);
        setStatus('unauthenticated');
      }
    });
    return unsubscribe;
  }, [client, hydrateOnMount]);

  const refreshSession = useCallback(() => {
    try {
      const current = client.getSession();
      setSession(current);
      setStatus(current && client.isAuthenticated() ? 'authenticated' : 'unauthenticated');
      setError(null);
    } catch (cause) {
      setError(toError(cause));
      setStatus('error');
    }
  }, [client]);

  const signIn = useCallback(async (options?: AIDAuthorizationOptions & { returnTo?: string }) => {
    setError(null);
    try {
      await client.signIn(options ?? {});
    } catch (cause) {
      setError(toError(cause));
      setStatus('error');
      throw cause;
    }
  }, [client]);

  const handleCallback = useCallback(async (url?: string) => {
    setStatus('loading');
    setError(null);
    try {
      const next = await client.handleCallback(url);
      setSession(next);
      setReturnTo(next.returnTo ?? null);
      setStatus('authenticated');
      return next;
    } catch (cause) {
      setError(toError(cause));
      setStatus('error');
      throw cause;
    }
  }, [client]);

  const signOut = useCallback(async (options?: { redirectTo?: string }) => {
    setError(null);
    setSession(null);
    setReturnTo(null);
    setStatus('unauthenticated');
    try {
      await client.signOut(options ?? {});
    } catch (cause) {
      setError(toError(cause));
      setStatus('error');
      throw cause;
    }
  }, [client]);

  const fetchProfile = useCallback(async () => {
    try {
      const user = await client.fetchUserProfile();
      setSession(client.getSession());
      return user;
    } catch (cause) {
      setError(toError(cause));
      throw cause;
    }
  }, [client]);

  const value = useMemo<AuthContextValue>(() => ({
    client,
    session,
    user: session?.user ?? null,
    status,
    isLoading: status === 'loading',
    isAuthenticated: status === 'authenticated' && session !== null,
    authState,
    error,
    returnTo,
    refreshSession,
    signIn,
    handleCallback,
    signOut,
    fetchProfile,
  }), [
    client, session, status, authState, error, returnTo,
    refreshSession, signIn, handleCallback, signOut, fetchProfile,
  ]);

  return createElement(AuthContext.Provider, { value }, children);
}

/** Provider alias matching the cross-platform component name. */
export const AceIDProvider = AuthProvider;

/** Full auth context: state, derived flags and actions. */
export function useAceID(): AuthContextValue {
  const value = useContext<AuthContextValue | null>(AuthContext);
  if (!value) throw new AIDError('CONFIGURATION_ERROR', 'useAceID must be used inside AceIDProvider');
  return value;
}

/** The state half of the context, for components that only read. */
export function useAceIDSession(): {
  user: AIDUser | null;
  session: AIDSession | null;
  status: AuthStatus;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: Error | null;
  authState: AIDSessionState | null;
} {
  const { user, session, status, isAuthenticated, isLoading, error, authState } = useAceID();
  return { user, session, status, isAuthenticated, isLoading, error, authState };
}

/** The action half of the context, so a button can subscribe without re-rendering on every token change. */
export function useAceIDActions(): {
  signIn(options?: AIDAuthorizationOptions & { returnTo?: string }): Promise<void>;
  signOut(options?: { redirectTo?: string }): Promise<void>;
  logout(options?: { redirectTo?: string }): Promise<void>;
  refresh(): void;
  handleCallback(url?: string): Promise<AIDCallbackResult>;
  fetchProfile(): Promise<AIDUser>;
} {
  const { signIn, signOut, refreshSession, handleCallback, fetchProfile } = useAceID();
  return {
    signIn,
    signOut,
    logout: signOut,
    refresh: refreshSession,
    handleCallback,
    fetchProfile,
  };
}

/** Backwards-compatible alias of {@link useAceID}. */
export const useAuth = useAceID;

export interface ProtectedRouteProps {
  children?: ReactNode;
  fallback?: ReactNode;
  loadingFallback?: ReactNode;
  errorFallback?: (error: Error) => ReactNode;
}

/** Framework/router-neutral guard; navigation remains the host app's responsibility. */
export function ProtectedRoute({
  children,
  fallback = null,
  loadingFallback = null,
  errorFallback,
}: ProtectedRouteProps): ReactNode {
  const auth = useAceID();
  if (auth.status === 'loading') return loadingFallback;
  if (auth.status === 'error') return errorFallback ? errorFallback(auth.error ?? new Error('Authentication failed')) : fallback;
  if (auth.status !== 'authenticated' || !auth.session) return fallback;
  return children;
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error('Authentication operation failed');
}
