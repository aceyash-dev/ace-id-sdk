/**
 * Plain browser integration — no framework.
 *
 * Two pages share one client: `index.html` starts the flow, `callback.html`
 * completes it. Run it with any static server on http://localhost:3000 and
 * register `http://localhost:3000/callback.html` as a redirect URI.
 */
import { AID, LocalStorage } from 'ace-id-sdk';

const aid = new AID({
  issuer: 'https://id.ace-base.cc',
  clientId: 'your-public-client-id',
  redirectUri: `${window.location.origin}/callback.html`,
  // LocalStorage keeps the user signed in across tabs and restarts.
  storage: new LocalStorage(),
  autoRefresh: true,
  debug: import.meta.env?.DEV === true,
});

const isCallback = window.location.pathname.endsWith('/callback.html');

if (isCallback) {
  // The callback page must run before anything renders: the code is single-use.
  try {
    const result = await aid.handleCallback();
    // The SDK validated returnTo as same-origin; navigating is our decision.
    window.location.replace(result.returnTo ?? '/index.html');
  } catch (error) {
    console.error('Sign-in failed', error);
    document.body.textContent = 'Sign-in failed. Please try again.';
  }
} else {
  const status = document.getElementById('status')!;
  const profile = document.getElementById('profile')!;
  const signIn = document.getElementById('sign-in') as HTMLButtonElement;
  const signOut = document.getElementById('sign-out') as HTMLButtonElement;

  function render(): void {
    const state = aid.getAuthState();
    signIn.hidden = state.status === 'authenticated';
    signOut.hidden = state.status !== 'authenticated';
    status.textContent = state.status;

    if (state.status === 'authenticated') {
      const user = state.session.user;
      profile.textContent = user.name ?? user.email ?? user.sub;
    } else {
      profile.textContent = '';
    }
  }

  // One subscription keeps every widget in sync with sign-in, refresh and logout.
  aid.onAuthStateChange(render);

  signIn.addEventListener('click', () => {
    void aid.signIn({ returnTo: '/index.html' });
  });

  signOut.addEventListener('click', () => {
    void aid.signOut({ redirectTo: '/index.html' });
  });

  // Optional: refresh the profile from UserInfo once, on load.
  if (aid.isAuthenticated()) {
    aid.fetchUserProfile().then(render).catch(() => render());
  }

  // Surface setup mistakes instead of guessing: this is a support-ticket saver.
  void aid.validateConfiguration().then((report) => {
    if (!report.ok) {
      console.warn('Ace ID configuration problems', report.checks.filter((c) => c.status !== 'pass'));
    }
  });
}
