const crypto = require('node:crypto');
const { token, hashToken, clientIp, deviceLabel } = require('./security');

function sqliteTime(date = new Date()) { return date.toISOString().slice(0, 19).replace('T', ' '); }
function nowPlusMinutes(minutes) { return sqliteTime(new Date(Date.now() + minutes * 60000)); }
function createSession(db, userId, req, config) {
  const raw = token(32);
  const created = sqliteTime();
  db.prepare(`INSERT INTO sessions (id_hash, user_id, created_at, last_active_at, expires_at, ip_address, user_agent, device_label) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(hashToken(raw), userId, created, created, nowPlusMinutes(config.ttlMinutes), clientIp(req), req.get('user-agent') || '', deviceLabel(req.get('user-agent')));
  recordEvent(db, userId, 'new_session', true, null, req);
  return raw;
}
function recordEvent(db, userId, eventType, success, reason, req, metadata) {
  db.prepare(`INSERT INTO security_events (user_id, event_type, success, reason, ip_address, user_agent, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(userId || null, eventType, success ? 1 : 0, reason || null, req ? clientIp(req) : null, req ? (req.get('user-agent') || '') : null, metadata ? JSON.stringify(metadata) : null);
}
function attachAuth(db, config) {
  return (req, res, next) => {
    const raw = req.cookies?.[config.cookieName];
    if (!raw) return next();
    const row = db.prepare(`SELECT s.*, u.email, u.display_name FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ? AND s.revoked_at IS NULL AND s.expires_at > datetime('now') AND s.last_active_at > datetime('now', ?)`).get(hashToken(raw), `-${config.idleMinutes} minutes`);
    if (!row) { res.clearCookie(config.cookieName); return next(); }
    req.auth = { sessionIdHash: row.id_hash, userId: row.user_id, email: row.email, displayName: row.display_name, session: row };
    db.prepare(`UPDATE sessions SET last_active_at = datetime('now') WHERE id_hash = ?`).run(row.id_hash);
    next();
  };
}
function requireAuth(req, res, next) { if (!req.auth) return res.status(401).json({ error: 'Authentication required.' }); next(); }
function setSessionCookie(res, config, raw) { res.cookie(config.cookieName, raw, { httpOnly: true, secure: config.production, sameSite: 'lax', maxAge: config.ttlMinutes * 60000, path: '/' }); }
function clearSessionCookie(res, config) { res.clearCookie(config.cookieName, { httpOnly: true, secure: config.production, sameSite: 'lax', path: '/' }); }
module.exports = { createSession, recordEvent, attachAuth, requireAuth, setSessionCookie, clearSessionCookie };
