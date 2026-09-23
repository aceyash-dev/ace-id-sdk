import { AID } from '../dist/index.js';

const statusEl = document.getElementById('status');
const logEl = document.getElementById('log');

function log(...args) {
  const line = args
    .map((a) => (typeof a === 'string' ? a : JSON.stringify(a, null, 2)))
    .join(' ');
  console.log(...args);
  logEl.textContent += line + '\n';
  logEl.scrollTop = logEl.scrollHeight;
}

const aid = new AID({
  issuer: 'https://identity.ace-base.cc',
  clientId: 'aidc_330d020d694a911f6dcf3e6631a3029defbeecbebeb14a47',
  redirectUri: 'http://localhost:4173/callback',
  scope: 'openid profile email',
});

log('pathname:', location.pathname);
log('href:', location.href);
log('---');

async function main() {
  if (location.pathname === '/callback') {
    await runCallback();
  } else {
    runHome();
  }
}

function renderSignedOut() {
  statusEl.innerHTML = '<p>Not signed in.</p>';
  const btn = document.createElement('button');
  btn.textContent = 'Sign in with Ace ID';
  btn.onclick = async () => {
    log('signIn() — redirecting…');
    await aid.signIn();
  };
  statusEl.appendChild(btn);
}

function renderSignedIn(user) {
  statusEl.innerHTML = `<p><strong>Signed in.</strong></p><pre>${escapeHtml(JSON.stringify(user, null, 2))}</pre>`;
  const btn = document.createElement('button');
  btn.textContent = 'Sign out';
  btn.onclick = async () => {
    log('signOut() — redirecting…');
    await aid.signOut({ redirectTo: 'http://localhost:4173/' });
  };
  statusEl.appendChild(btn);
}

function runHome() {
  const session = aid.getSession();
  if (session) {
    log('found existing session for sub:', session.user.sub);
    log('isAuthenticated():', aid.isAuthenticated());
    renderSignedIn(session.user);
  } else {
    log('no existing session');
    renderSignedOut();
  }
}

async function runCallback() {
  statusEl.innerHTML = '<p>Handling callback…</p>';
  try {
    const session = await aid.handleCallback();
    log('handleCallback() OK');
    log('user:', session.user);
    log('tokens (redacted):', {
      tokenType: session.tokens.tokenType,
      expiresIn: session.tokens.expiresIn,
      expiresAt: session.tokens.expiresAt,
      hasAccessToken: !!session.tokens.accessToken,
      hasIdToken: !!session.tokens.idToken,
      hasRefreshToken: !!session.tokens.refreshToken,
      scope: session.tokens.scope,
    });
    renderSignedIn(session.user);
    history.replaceState(null, '', '/');
  } catch (err) {
    const name = err instanceof Error ? err.name : 'Error';
    const message = err instanceof Error ? err.message : String(err);
    const code = err && typeof err === 'object' && 'code' in err ? err.code : undefined;
    log(`handleCallback() FAILED — ${name}: ${message}`, code ? { code } : '');
    statusEl.innerHTML = `<p style="color:#b00020">Callback failed: ${escapeHtml(name)}</p><p>${escapeHtml(message)}</p>`;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

main().catch((err) => log('FATAL:', String(err)));
