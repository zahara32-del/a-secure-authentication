# Northstar Identity

A production-style authentication and identity service built for Node.js 22.5+ with Express, built-in SQLite, Argon2id, and a small accessible browser UI.

## Prerequisites

- Node.js 22.5 or newer (the app uses Node's built-in `node:sqlite` API)
- npm
- Google Cloud project only if Google sign-in is required

## Install and run

```powershell
Copy-Item .env.example .env
npm install
npm run db:init
npm start
```

Open http://localhost:3000. Run `npm test` for the security tests. Use `npm run dev` during development.

## Environment variables

`NODE_ENV`, `PORT`, `DATABASE_PATH`, `SESSION_COOKIE_NAME`, `SESSION_TTL_DAYS`, `SESSION_IDLE_MINUTES`, `SESSION_SECRET`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, and `TRUST_PROXY` are documented in `.env.example`. Set a random 32+ character `SESSION_SECRET`; never commit `.env`.

## Google OAuth

Create an OAuth 2.0 Web application client in Google Cloud Console. Add the exact redirect URI from `GOOGLE_REDIRECT_URI` (for local development, `http://localhost:3000/auth/google/callback`) and set the client ID and secret in `.env`. The callback exchanges the code server-side, checks OAuth state, validates the Google userinfo response and verified email, then links the provider account by Google subject. Existing password users are matched by verified email without replacing their password.

## Security implemented

- Argon2id password hashes, strong length/complexity/common-password checks, generic authentication errors.
- Express IP/email rate limiting plus database tracking of failures and repeated-failure events.
- Opaque, random, hashed server-side sessions with expiration, idle timeout, HttpOnly/SameSite cookies, production Secure cookies, logout, session rotation after login, and revocation.
- Double-submit CSRF protection for state-changing requests, Helmet headers, JSON validation, parameterized SQLite statements, output escaping in the UI, and safe fixed redirects.
- Audit events for registration, login success/failure, Google login, sessions, logout, revocation, repeated failures, and new-IP suspicious activity.
- Protected dashboard, active session management, and security activity pages.

## Database

`schema.sql` defines `users`, `oauth_accounts`, `sessions`, `auth_attempts`, and `security_events` with foreign keys, uniqueness constraints, indexes, and timestamps. SQLite WAL mode is enabled.

## Production considerations

Serve behind HTTPS, set `NODE_ENV=production`, use a strong secret, configure `TRUST_PROXY` only for a trusted reverse proxy, restrict the database file permissions, back it up, and configure a shared durable database if deploying multiple application instances. Add email verification, password reset, account recovery, centralized monitoring, and a managed secrets system before exposing a high-risk production workload. Google access tokens are used only for the callback exchange and are not stored.
