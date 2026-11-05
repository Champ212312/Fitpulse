const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');
const { db } = require('./db');
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) throw new Error('JWT_SECRET must be configured with at least 32 characters.');
const ttlHours = Math.max(1, Number(process.env.SESSION_TTL_HOURS) || 12);

function issueSession(user, res) {
  const jti = crypto.randomUUID();
  const expires = new Date(Date.now() + ttlHours * 3600000);
  const token = jwt.sign({ sub: user.id, role: user.role, jti }, SECRET, { expiresIn: `${ttlHours}h`, issuer: 'fitpulse' });
  db.prepare('INSERT INTO sessions(token_id,user_id,expires_at) VALUES(?,?,?)').run(jti, user.id, expires.toISOString());
  res.cookie('fitpulse_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', path: '/', maxAge: ttlHours * 3600000 });
}
function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.fitpulse_session;
    if (!token) return res.status(401).json({ error: 'Authentication required.' });
    const payload = jwt.verify(token, SECRET, { issuer: 'fitpulse' });
    const session = db.prepare('SELECT token_id FROM sessions WHERE token_id=? AND user_id=? AND expires_at>?').get(payload.jti, payload.sub, new Date().toISOString());
    const user = db.prepare('SELECT id,name,email,role,plan,membership_start,membership_end,payment_status,disabled FROM users WHERE id=?').get(payload.sub);
    if (!session || !user || user.disabled) return res.status(401).json({ error: 'Session is invalid or expired.' });
    req.user = user;
    req.sessionTokenId = payload.jti;
    next();
  } catch { return res.status(401).json({ error: 'Session is invalid or expired.' }); }
}
function allowRoles(...roles) {
  return (req, res, next) => roles.includes(req.user?.role) ? next() : res.status(403).json({ error: 'You do not have permission to perform this action.' });
}
module.exports = { issueSession, requireAuth, allowRoles };
