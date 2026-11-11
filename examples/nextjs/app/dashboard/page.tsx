// Next.js server component reading the sealed Ace ID session.
//
// File: app/dashboard/page.tsx
import { headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { getServerSession } from 'ace-id-sdk/server';

export default async function DashboardPage() {
  const requestHeaders = await headers();
  // Reconstruct a Request-shaped object for the session reader.
  const request = new Request('https://app.local/dashboard', {
    headers: requestHeaders,
  });

  const session = await getServerSession(request, {
    secret: process.env.ACE_ID_SESSION_SECRET!,
  });

  if (!session) redirect('/api/auth/signin?returnTo=/dashboard');

  return (
    <main>
      <h1>Welcome, {session.user.name ?? session.user.email ?? session.user.sub}</h1>
      <p>Session expires at {session.expiresAt ? new Date(session.expiresAt).toISOString() : 'provider-defined time'}</p>
      <form action="/api/auth/signout" method="post">
        <button type="submit">Sign out</button>
      </form>
    </main>
  );
}
