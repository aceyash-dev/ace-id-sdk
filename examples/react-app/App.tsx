/**
 * React integration with the Ace ID adapter.
 *
 * Vite: `npm create vite@latest my-app -- --template react-ts`, then
 * `npm install ace-id-sdk react-router-dom`.
 */
import { useEffect, useMemo } from 'react';
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useNavigate,
} from 'react-router-dom';
import { AID } from 'ace-id-sdk';
import {
  AceIDProvider,
  ProtectedRoute,
  useAceID,
  useAceIDActions,
} from 'ace-id-sdk/react';

const client = new AID({
  issuer: 'https://id.ace-base.cc',
  clientId: 'your-public-client-id',
  redirectUri: `${window.location.origin}/auth/callback`,
  autoRefresh: true,
});

function Header() {
  const { user, isAuthenticated, isLoading } = useAceID();
  const { signIn, signOut } = useAceIDActions();

  if (isLoading) return <span>Loading…</span>;
  if (!isAuthenticated) {
    return <button onClick={() => signIn({ returnTo: '/dashboard' })}>Sign in</button>;
  }
  return (
    <header>
      <span>{user?.name ?? user?.email ?? user?.sub}</span>
      <button onClick={() => signOut()}>Sign out</button>
    </header>
  );
}

function Callback() {
  const { handleCallback } = useAceID();
  const navigate = useNavigate();

  useEffect(() => {
    handleCallback()
      .then((result) => navigate(result.returnTo ?? '/', { replace: true }))
      .catch(() => navigate('/?error=callback', { replace: true }));
  }, [handleCallback, navigate]);

  return <p>Completing sign-in…</p>;
}

function Dashboard() {
  const { user, authState, fetchProfile } = useAceID();

  useEffect(() => {
    // Refresh claims from UserInfo once the dashboard mounts.
    void fetchProfile().catch(() => undefined);
  }, [fetchProfile]);

  return (
    <section>
      <h1>Dashboard</h1>
      <p>Subject: {user?.sub}</p>
      <p>State: {authState?.status}</p>
      {authState?.status === 'refresh-failed' && <p role="alert">Session refresh failed.</p>}
    </section>
  );
}

export function App() {
  // Stable provider identity: a new client per render would re-subscribe.
  const provider = useMemo(() => client, []);

  return (
    <BrowserRouter>
      <AceIDProvider client={provider}>
        <Header />
        <Routes>
          <Route path="/auth/callback" element={<Callback />} />
          <Route path="/" element={<p>Home</p>} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute fallback={<Navigate to="/" replace />} loadingFallback={<p>Loading…</p>}>
                <Dashboard />
              </ProtectedRoute>
            }
          />
        </Routes>
      </AceIDProvider>
    </BrowserRouter>
  );
}
