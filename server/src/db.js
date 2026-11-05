const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const dbPath = path.resolve(process.env.DATABASE_PATH || './data/fitpulse.sqlite');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('member','staff','admin')),
  plan TEXT, membership_start TEXT, membership_end TEXT, payment_status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT, member_id TEXT REFERENCES users(id),
  display_name TEXT NOT NULL, check_in TEXT NOT NULL, check_out TEXT,
  created_by TEXT NOT NULL REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_attendance_member ON attendance(member_id, check_in);
CREATE INDEX IF NOT EXISTS idx_attendance_active ON attendance(check_out);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT, action TEXT NOT NULL,
  entity_type TEXT NOT NULL, entity_id TEXT, details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
  token_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function seedRole(role, email, password) {
  if (!email || !password) return;
  if (String(password).length < 12) throw new Error(`${role.toUpperCase()}_PASSWORD must be at least 12 characters.`);
  const existing = db.prepare('SELECT id FROM users WHERE lower(email)=lower(?)').get(email);
  if (!existing) {
    const id = require('node:crypto').randomUUID();
    const hash = bcrypt.hashSync(password, 12);
    db.prepare('INSERT INTO users(id,name,email,password_hash,role,payment_status) VALUES(?,?,?,?,?,?)')
      .run(id, role === 'admin' ? 'FitPulse Administrator' : 'FitPulse Staff', email.toLowerCase(), hash, role, 'paid');
  }
}
seedRole('admin', process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD);
seedRole('staff', process.env.STAFF_EMAIL, process.env.STAFF_PASSWORD);

module.exports = { db };
