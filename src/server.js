const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const { jwtVerify, createRemoteJWKSet } = require('jose');
const { z } = require('zod');
const { createDatabase } = require('./db');
const { DUMMY_HASH, normalizeEmail, validatePassword, token, hashToken, clientIp } = require('./security');
const { createSession, recordEvent, attachAuth, requireAuth, setSessionCookie, clearSessionCookie } = require('./auth');

function createApp(options = {}) {
  const db = options.db || createDatabase(options.databasePath);
  const config = {
    production: process.env.NODE_ENV === 'production', cookieName: process.env.SESSION_COOKIE_NAME || 'secure_sid',
    ttlMinutes: Number(process.env.SESSION_TTL_DAYS || 7) * 1440, idleMinutes: Number(process.env.SESSION_IDLE_MINUTES || 60),
    sessionSecret: process.env.SESSION_SECRET || 'development-only-change-this-secret',
    googleId: process.env.GOOGLE_CLIENT_ID, googleSecret: process.env.GOOGLE_CLIENT_SECRET,
    googleRedirect: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback'
  };
  if (config.production && config.sessionSecret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters in production.');

  const app = express();
  app.disable('x-powered-by');
  if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(express.json({ limit: '20kb' }));
  app.use(express.urlencoded({ extended: false, limit: '20kb' }));
  app.use(require('cookie-parser')());
  app.use((req, res, next) => { res.locals.csrf = req.cookies.csrf_token || token(24); res.cookie('csrf_token', res.locals.csrf, { httpOnly: false, secure: config.production, sameSite: 'lax', maxAge: 3600000, path: '/' }); next(); });
  app.use(attachAuth(db, config));

  const loginIpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Please try again later.' }, keyGenerator: req => clientIp(req) });
  const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Please try again later.' }, keyGenerator: req => `${clientIp(req)}:${normalizeEmail(req.body?.email || '')}` });
  const csrf = (req, res, next) => { const supplied = req.get('x-csrf-token') || req.body?._csrf; if (!supplied || supplied !== req.cookies.csrf_token) return res.status(403).json({ error: 'Request could not be verified.' }); next(); };
  const publicMessage = 'Unable to sign in with those details.';
  const googleKeys = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
  const rotateSession = (req) => { if (req.auth) db.prepare("UPDATE sessions SET revoked_at = datetime('now') WHERE id_hash = ?").run(req.auth.sessionIdHash); };

  app.get('/api/me', (req, res) => res.json({ authenticated: !!req.auth, user: req.auth ? { email: req.auth.email, displayName: req.auth.displayName } : null }));
  app.post('/api/register', loginLimiter, csrf, async (req, res, next) => {
    try {
      const parsed = z.object({ email: z.string().email().max(254), password: z.string(), displayName: z.string().trim().min(1).max(80) }).safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Enter a valid name, email, and password.' });
      const { email: inputEmail, password, displayName } = parsed.data;
      const email = normalizeEmail(inputEmail); const weak = validatePassword(password);
      if (weak) return res.status(400).json({ error: weak });
      if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(400).json({ error: 'Unable to create an account with those details.' });
      const userId = crypto.randomUUID(); const passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
      db.prepare('INSERT INTO users (id, email, password_hash, display_name) VALUES (?, ?, ?, ?)').run(userId, email, passwordHash, displayName);
      recordEvent(db, userId, 'successful_registration', true, null, req);
      rotateSession(req); const session = createSession(db, userId, req, config); setSessionCookie(res, config, session);
      res.status(201).json({ ok: true });
    } catch (error) { next(error); }
  });

  app.post('/api/login', loginIpLimiter, loginLimiter, csrf, async (req, res, next) => {
    const email = typeof req.body.email === 'string' ? normalizeEmail(req.body.email) : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    try {
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      const valid = await argon2.verify(user?.password_hash || await DUMMY_HASH, password).catch(() => false);
      db.prepare('INSERT INTO auth_attempts (email, ip_address, succeeded) VALUES (?, ?, ?)').run(email || 'unknown', clientIp(req), valid ? 1 : 0);
      if (!valid || !user) { recordEvent(db, user?.id, 'failed_login', false, 'invalid_credentials', req); const recent = db.prepare(`SELECT COUNT(*) AS count FROM auth_attempts WHERE email = ? AND succeeded = 0 AND created_at > datetime('now', '-15 minutes')`).get(email).count; if (recent >= 5) recordEvent(db, user?.id, 'repeated_failed_login_attempts', false, 'five_or_more_failures', req, { count: recent }); return res.status(401).json({ error: publicMessage }); }
      const knownIp = db.prepare(`SELECT 1 FROM security_events WHERE user_id = ? AND event_type IN ('successful_login', 'google_login') AND ip_address = ? LIMIT 1`).get(user.id, clientIp(req));
      recordEvent(db, user.id, 'successful_login', true, null, req);
      if (!knownIp) recordEvent(db, user.id, 'suspicious_login', true, 'new_ip_observed', req);
      rotateSession(req); const session = createSession(db, user.id, req, config); setSessionCookie(res, config, session); res.json({ ok: true });
    } catch (error) { next(error); }
  });

  app.post('/api/logout', csrf, (req, res) => { if (req.auth) { db.prepare('UPDATE sessions SET revoked_at = datetime(\'now\') WHERE id_hash = ?').run(req.auth.sessionIdHash); recordEvent(db, req.auth.userId, 'logout', true, null, req); } clearSessionCookie(res, config); res.json({ ok: true }); });
  app.get('/api/sessions', requireAuth, (req, res) => { const rows = db.prepare(`SELECT id_hash, created_at, last_active_at, expires_at, ip_address, device_label FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > datetime('now') ORDER BY last_active_at DESC`).all(req.auth.userId); res.json({ sessions: rows.map(row => ({ ...row, current: row.id_hash === req.auth.sessionIdHash, id: hashToken(row.id_hash) })) }); });
  app.delete('/api/sessions/:id', requireAuth, csrf, (req, res) => { const target = db.prepare('SELECT id_hash FROM sessions WHERE user_id = ? AND revoked_at IS NULL').all(req.auth.userId).find(row => hashToken(row.id_hash) === req.params.id); if (!target) return res.status(404).json({ error: 'Session not found.' }); db.prepare('UPDATE sessions SET revoked_at = datetime(\'now\') WHERE id_hash = ?').run(target.id_hash); recordEvent(db, req.auth.userId, 'session_revoked', true, 'individual_session', req); res.json({ ok: true }); });
  app.post('/api/sessions/revoke-others', requireAuth, csrf, (req, res) => { db.prepare('UPDATE sessions SET revoked_at = datetime(\'now\') WHERE user_id = ? AND id_hash != ? AND revoked_at IS NULL').run(req.auth.userId, req.auth.sessionIdHash); recordEvent(db, req.auth.userId, 'session_revoked', true, 'all_other_sessions', req); res.json({ ok: true }); });
  app.get('/api/security-events', requireAuth, (req, res) => res.json({ events: db.prepare(`SELECT event_type, success, reason, ip_address, user_agent, created_at FROM security_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`).all(req.auth.userId) }));

  app.get('/auth/google', (req, res) => { if (!config.googleId || !config.googleSecret) return res.status(503).send('Google sign-in is not configured.'); const state = token(24); const nonce = token(24); res.cookie('oauth_state', state, { httpOnly: true, secure: config.production, sameSite: 'lax', maxAge: 600000 }); res.cookie('oauth_nonce', nonce, { httpOnly: true, secure: config.production, sameSite: 'lax', maxAge: 600000 }); const params = new URLSearchParams({ client_id: config.googleId, redirect_uri: config.googleRedirect, response_type: 'code', scope: 'openid email profile', state, nonce, prompt: 'select_account' }); res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`); });
  app.get('/auth/google/callback', async (req, res, next) => { try { if (!config.googleId || !config.googleSecret || typeof req.query.state !== 'string' || req.query.state !== req.cookies.oauth_state || typeof req.query.code !== 'string' || typeof req.cookies.oauth_nonce !== 'string') return res.status(400).send('Google sign-in could not be verified.'); const body = new URLSearchParams({ code: req.query.code, client_id: config.googleId, client_secret: config.googleSecret, redirect_uri: config.googleRedirect, grant_type: 'authorization_code' }); const tokenResponse = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body }); if (!tokenResponse.ok) throw new Error('Google token exchange failed'); const tokens = await tokenResponse.json(); if (typeof tokens.id_token !== 'string' || typeof tokens.access_token !== 'string') return res.status(401).send('Google sign-in could not be verified.'); const verified = await jwtVerify(tokens.id_token, googleKeys, { issuer: ['https://accounts.google.com', 'accounts.google.com'], audience: config.googleId }); if (verified.payload.nonce !== req.cookies.oauth_nonce) return res.status(401).send('Google sign-in could not be verified.'); const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } }); if (!profileResponse.ok) throw new Error('Google profile lookup failed'); const profile = await profileResponse.json(); if (!profile.sub || !profile.email || profile.email_verified !== true || profile.sub !== verified.payload.sub) return res.status(401).send('Google sign-in could not be verified.'); const email = normalizeEmail(profile.email); const linked = db.prepare('SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_account_id = ?').get('google', profile.sub); let user = linked ? db.prepare('SELECT * FROM users WHERE id = ?').get(linked.user_id) : db.prepare('SELECT * FROM users WHERE email = ?').get(email); if (linked && (!user || user.id !== linked.user_id)) return res.status(401).send('Google sign-in could not be verified.'); if (!user) { const id = crypto.randomUUID(); db.prepare('INSERT INTO users (id, email, display_name) VALUES (?, ?, ?)').run(id, email, String(profile.name || profile.email).slice(0, 80)); user = db.prepare('SELECT * FROM users WHERE id = ?').get(id); } if (!linked) db.prepare('INSERT INTO oauth_accounts (id, user_id, provider, provider_account_id, email) VALUES (?, ?, ?, ?, ?)').run(crypto.randomUUID(), user.id, 'google', profile.sub, email); const knownIp = db.prepare(`SELECT 1 FROM security_events WHERE user_id = ? AND event_type IN ('successful_login', 'google_login') AND ip_address = ? LIMIT 1`).get(user.id, clientIp(req)); recordEvent(db, user.id, 'google_login', true, null, req); if (!knownIp) recordEvent(db, user.id, 'suspicious_login', true, 'new_ip_observed', req); rotateSession(req); const session = createSession(db, user.id, req, config); setSessionCookie(res, config, session); res.clearCookie('oauth_state'); res.clearCookie('oauth_nonce'); res.redirect('/dashboard.html'); } catch (error) { next(error); } });

  app.use(express.static(path.join(__dirname, '..', 'public')));
  app.use((error, req, res, next) => { console.error('request_error', error.message); res.status(500).json({ error: 'Something went wrong.' }); });
  return { app, db, config };
}

if (require.main === module) { const { app } = createApp(); const port = Number(process.env.PORT || 3000); app.listen(port, () => console.log(`Secure identity app listening on http://localhost:${port}`)); }
module.exports = { createApp };
