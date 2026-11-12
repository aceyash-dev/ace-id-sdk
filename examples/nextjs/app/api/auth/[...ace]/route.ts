// Next.js App Router route handlers for Ace ID.
//
// File: app/api/auth/[...ace]/route.ts
// Environment: ACE_ID_ISSUER, ACE_ID_CLIENT_ID, ACE_ID_CLIENT_SECRET,
//              ACE_ID_REDIRECT_URI, ACE_ID_SESSION_SECRET
import { AIDServer, createAuthHandlers } from 'ace-id-sdk/server';

const client = new AIDServer({
  issuer: process.env.ACE_ID_ISSUER!,
  clientId: process.env.ACE_ID_CLIENT_ID!,
  clientSecret: process.env.ACE_ID_CLIENT_SECRET!,
  maxRetries: 2,
});

const handlers = createAuthHandlers({
  client,
  redirectUri: process.env.ACE_ID_REDIRECT_URI!,
  secret: process.env.ACE_ID_SESSION_SECRET!,
  afterLogin: '/dashboard',
  afterLogout: '/',
});

const routes: Record<string, (request: Request) => Promise<Response>> = {
  signin: handlers.signIn,
  callback: handlers.callback,
  session: handlers.session,
  refresh: handlers.refresh,
  signout: handlers.signOut,
};

async function route(
  request: Request,
  context: { params: Promise<{ ace: string[] }> },
): Promise<Response> {
  const { ace } = await context.params;
  const handler = routes[ace?.[0] ?? ''];
  if (!handler) return new Response('Not found', { status: 404 });
  return handler(request);
}

export const GET = route;
export const POST = route;
