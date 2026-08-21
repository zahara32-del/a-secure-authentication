const crypto = require('node:crypto');
const argon2 = require('argon2');

const DUMMY_HASH = argon2.hash('not-a-real-password', { type: argon2.argon2id });
const COMMON = new Set(['password', 'password123', '12345678', 'qwertyui', 'letmein123', 'welcome123', 'admin123', 'iloveyou']);

function normalizeEmail(value) { return value.trim().toLowerCase(); }
function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) return 'Use a password between 12 and 128 characters.';
  if (COMMON.has(password.toLowerCase()) || /^(.)\1+$/.test(password)) return 'Choose a less common password.';
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) return 'Use upper and lowercase letters, a number, and a symbol.';
  return null;
}
function token(size = 32) { return crypto.randomBytes(size).toString('base64url'); }
function hashToken(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function timingSafeEqual(a, b) { const left = Buffer.from(a); const right = Buffer.from(b); return left.length === right.length && crypto.timingSafeEqual(left, right); }
function clientIp(req) { return req.ip || req.socket.remoteAddress || 'unknown'; }
function deviceLabel(userAgent = '') { return userAgent.slice(0, 160) || 'Unknown device'; }

module.exports = { DUMMY_HASH, normalizeEmail, validatePassword, token, hashToken, timingSafeEqual, clientIp, deviceLabel };
