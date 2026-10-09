import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { AID } from '../browser/client.js';
import type { AIDSession } from '../core/types.js';
import { AIDError } from '../core/errors.js';

export type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated' | 'error';

export interface AuthContextValue {
  client: AID;
  session: AIDSession | null;
  status: AuthStatus;
  error: Error | null;
  refreshSession(): void;
  signIn(options?: { returnTo?: string }): Promise<void>;
  handleCallback(url?: string): Promise<AIDSession>;
  signOut(options?: { redirectTo?: string }): Promise<void>;
}

export interface AuthProviderProps {
  client: AID;
  children?: unknown;
  /** Disable initial session hydration when the host app controls hydration. */
  hydrateOnMount?: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Thin provider. It does not create a second token store or refresh implementation. */
export function AuthProvider({ client, children, hydrateOnMount = true }: AuthProviderProps): unknown {
  const [session, setSession] = useState<AIDSession | null>(null);
  const [status, setStatus] = useState<AuthStatus>(hydrateOnMount ? 'loading' : 'unauthenticated');
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!hydrateOnMount) return;
    let active = true;
    try {
      const current = client.getSession();
      if (active) {
        setSession(current);
        setStatus(current && client.isAuthenticated() ? 'authenticated' : 'unauthenticated');
      }
    } catch (cause) {
      if (active) {
        setError(toError(cause));
        setStatus('error');
      }
    }
    return () => { active = false; };
  }, [client, hydrateOnMount]);

  const value = useMemo<AuthContextValue>(() => ({
    client,
    session,
    status,
    error,
    refreshSession() {
      try {
        const current = client.getSession();
        setSession(current);
        setStatus(current && client.isAuthenticated() ? 'authenticated' : 'unauthenticated');
        setError(null);
      } catch (cause) {
        setError(toError(cause));
        setStatus('error');
      }
    },
    async signIn(options) {
      setError(null);
      try { await client.signIn(options); }
      catch (cause) { setError(toError(cause)); setStatus('error'); throw cause; }
    },
    async handleCallback(url) {
      setStatus('loading');
      setError(null);
      try {
        const next = await client.handleCallback(url);
        setSession(next);
        setStatus('authenticated');
        return next;
      } catch (cause) {
        setError(toError(cause));
        setStatus('error');
        throw cause;
      }
    },
    async signOut(options) {
      setError(null);
      setSession(null);
      setStatus('unauthenticated');
      try { await client.signOut(options); }
      catch (cause) { setError(toError(cause)); setStatus('error'); throw cause; }
    },
  }), [client, session, status, error]);

  return createElement(AuthContext.Provider, { value }, children);
}

export function useAuth(): AuthContextValue {
  const value = useContext<AuthContextValue | null>(AuthContext);
  if (!value) throw new AIDError('CONFIGURATION_ERROR', 'useAuth must be used inside AuthProvider');
  return value;
}

export interface ProtectedRouteProps {
  children?: ReactNode;
  fallback?: ReactNode;
  loadingFallback?: ReactNode;
  errorFallback?: (error: Error) => unknown;
}

/** Framework/router-neutral guard; navigation remains the host app's responsibility. */
export function ProtectedRoute({
  children,
  fallback = null,
  loadingFallback = null,
  errorFallback,
}: ProtectedRouteProps): unknown {
  const auth = useAuth();
  if (auth.status === 'loading') return loadingFallback;
  if (auth.status === 'error') return errorFallback ? errorFallback(auth.error ?? new Error('Authentication failed')) : fallback;
  if (auth.status !== 'authenticated' || !auth.session) return fallback;
  return children;
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error('Authentication operation failed');
}
