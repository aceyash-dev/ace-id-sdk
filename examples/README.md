# Examples

Runnable-shaped integrations, one per platform. They are intentionally small and
copy-pasteable rather than a demo application.

| Directory | Shows |
| --- | --- |
| [`browser-typescript`](./browser-typescript/index.ts) | Plain browser flow: sign in, session state, profile, diagnostics. |
| [`react-app`](./react-app/App.tsx) | Provider, hooks, callback route and a protected route. |
| [`nextjs`](./nextjs) | App Router handlers with a sealed server session and an SSR page. |
| [`android-kotlin`](./android-kotlin/LoginActivity.kt) | Compose UI, lifecycle-aware login, session state, biometric unlock. |
| [`android-java`](./android-java/LoginActivity.java) | Callback-based login from Java. |

Each example assumes an Ace ID project with:

- an issuer URL such as `https://id.ace-base.cc`;
- a public client ID for the browser and Android apps;
- a confidential client (with secret) for server-side flows;
- the redirect URIs registered: `http://localhost:3000/callback.html`,
  `http://localhost:5173/auth/callback`, `https://app.example.com/api/auth/callback`
  and `com.example.app:/oauth/callback`.

Replace the placeholders before running anything.

Related documentation: [API](../ACE-DOCS/API.md), [React](../ACE-DOCS/REACT.md),
[Server](../ACE-DOCS/SERVER.md), [Android](../ACE-DOCS/ANDROID.md),
[Errors](../ACE-DOCS/ERRORS.md), [Migration](../ACE-DOCS/MIGRATION-0.2.4.md).
