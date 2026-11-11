# React

The `ace-id-sdk/react` entry point is a thin adapter over the client. It owns no
token store and no refresh logic: it subscribes to the client's session-state
stream, so a sign-out in another component, another tab or a server helper is
reflected everywhere without a second source of truth.

```tsx
import { AID } from 'ace-id-sdk';
import { AceIDProvider, useAceID, useAceIDActions, ProtectedRoute } from 'ace-id-sdk/react';

const client = new AID({
  issuer: 'https://id.ace-base.cc',
  clientId: 'your-public-client-id',
  redirectUri: window.location.origin + '/auth/callback',
});

export function Root() {
  return (
    <AceIDProvider client={client}>
      <App />
    </AceIDProvider>
  );
}
```

`AuthProvider` is an alias of `AceIDProvider`, and `useAuth` an alias of
`useAceID`, so existing code keeps working.

## State

```tsx
function AccountButton() {
  const { user, isAuthenticated, isLoading, status, authState, error } = useAceID();

  if (isLoading) return <Spinner />;
  if (!isAuthenticated) return <SignInButton />;
  return <span>{user?.email}</span>;
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `session` | `AIDSession \| null` | Full session including tokens. |
| `user` | `AIDUser \| null` | Convenience for `session.user`. |
| `status` | `'loading' \| 'authenticated' \| 'unauthenticated' \| 'error'` | Collapsed view for views. |
| `isLoading` | `boolean` | True only during initial hydration. |
| `isAuthenticated` | `boolean` | True when a session exists. |
| `authState` | `AIDSessionState \| null` | Precise SDK state, including `expired` and `refresh-failed`. |
| `error` | `Error \| null` | Last failure. |
| `returnTo` | `string \| null` | Validated post-login target from the callback. |

An `expired` session still has a user and is refreshed on demand, so it counts as
`authenticated` here. Read `authState.status` when the distinction matters.

## Actions

```tsx
function SignInButton() {
  const { signIn, signOut, logout, refresh, fetchProfile } = useAceIDActions();
  return <button onClick={() => signIn({ returnTo: '/dashboard' })}>Sign in</button>;
}
```

`useAceIDActions()` returns only functions, so a button does not re-render when a
token refreshes.

## Callback route

```tsx
function Callback() {
  const { handleCallback, returnTo } = useAceID();
  const navigate = useNavigate();

  useEffect(() => {
    handleCallback()
      .then((result) => navigate(result.returnTo ?? '/', { replace: true }))
      .catch(() => navigate('/signin?error=callback', { replace: true }));
  }, [handleCallback, navigate]);

  return <Spinner />;
}
```

The SDK never navigates after a callback; the application decides when and where.

## Route guard

```tsx
<ProtectedRoute
  fallback={<Navigate to="/signin" replace />}
  loadingFallback={<Spinner />}
  errorFallback={(error) => <ErrorPanel error={error} />}
>
  <Dashboard />
</ProtectedRoute>
```

`ProtectedRoute` is router-neutral: it renders `children`, `fallback`,
`loadingFallback` or `errorFallback` and nothing else.

## Server rendering

During SSR the provider reports `loading`, because the session is read on the
client. For SSR, resolve the session on the server with
`ace-id-sdk/server` (see [SERVER.md](./SERVER.md)) and pass the user into your
tree, or render a skeleton until hydration completes.
