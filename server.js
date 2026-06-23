/**
 * LocationRooftop - Backend Server
 * Node.js + Express + SQLite (persistent storage)
 * Ready for deployment on Render.com
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'locationrooftop-super-secret-key-change-in-render-env';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '119722';

// ---------- Middleware ----------
app.use(cors({ origin: '*', credentials: true }));
app.use(bodyParser.json({ limit: '25mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '25mb' }));

// ---------- Persistent storage on Render (use /var/data disk) ----------
const DATA_DIR = process.env.RENDER ? '/var/data' : path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'locationrooftop.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ---------- Schema ----------
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  full_name TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,           -- income | expense | purchase | sale | stock_in | stock_out
  category TEXT,
  description TEXT,
  amount REAL DEFAULT 0,
  quantity REAL DEFAULT 0,
  unit TEXT,
  reference TEXT,
  attachment TEXT,              -- base64 image from scan
  created_by TEXT,
  created_role TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  position TEXT,
  phone TEXT,
  email TEXT,
  national_id TEXT,
  salary REAL DEFAULT 0,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS conduct_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  staff_id INTEGER,
  staff_name TEXT,
  report_type TEXT,             -- behavior | code_of_conduct | commendation
  description TEXT,
  severity TEXT,
  action_taken TEXT,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS stock_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT,
  quantity REAL DEFAULT 0,
  unit TEXT,
  unit_price REAL DEFAULT 0,
  reorder_level REAL DEFAULT 0,
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT,
  action TEXT,
  details TEXT,
  ip TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
`);

// ---------- Seed default users (one per role) ----------
const ROLES = [
  'cost_controller','procurement','storekeeper','accounts',
  'finance_manager','supervisor','hr','director','auditor'
];

function seedUsers() {
  const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (count > 0) return;
  const insert = db.prepare('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)');
  const defaults = [
    ['cost',       'cost123',     'cost_controller', 'Cost Controller'],
    ['proc',       'proc123',     'procurement',     'Procurement Officer'],
    ['store',      'store123',    'storekeeper',     'Store Keeper'],
    ['accounts',   'acc123',      'accounts',        'Accounts Officer'],
    ['finance',    'fin123',      'finance_manager', 'Finance Manager'],
    ['supervisor', 'sup123',      'supervisor',      'Supervisor'],
    ['hr',         'hr123',       'hr',              'HR Manager'],
    ['director',   'dir123',      'director',        'Director'],
    ['auditor',    'aud123',      'auditor',         'Auditor']
  ];
  for (const [u, p, r, n] of defaults) {
    insert.run(u, bcrypt.hashSync(p, 10), r, n);
  }
  console.log('✅ Seeded default users');
}
seedUsers();

// ---------- Helpers ----------
function logAudit(actor, action, details, ip='') {
  db.prepare('INSERT INTO audit_log (actor, action, details, ip) VALUES (?, ?, ?, ?)').run(actor||'system', action, JSON.stringify(details||{}), ip);
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
}

function adminMiddleware(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  return res.status(403).json({ error: 'Admin only' });
}

// ---------- Routes ----------
app.get('/', (req, res) => {
  res.json({ ok: true, name: 'LocationRooftop API', time: new Date().toISOString() });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ----- Auth -----
app.post('/api/login', (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });
  if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid username or password' });
  if (role && user.role !== role) return res.status(403).json({ error: `This account is registered as ${user.role}, not ${role}` });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role, full_name: user.full_name }, JWT_SECRET, { expiresIn: '12h' });
  logAudit(user.username, 'login', { role: user.role }, req.ip);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, full_name: user.full_name } });
});

app.post('/api/admin-login', (req, res) => {
  const { password } = req.body || {};
  if (password !== ADMIN_PASSWORD) {
    logAudit('unknown', 'admin_login_failed', { ip: req.ip }, req.ip);
    return res.status(401).json({ error: 'Invalid admin password' });
  }
  const token = jwt.sign({ id: 0, username: 'admin', role: 'admin', full_name: 'Administrator' }, JWT_SECRET, { expiresIn: '12h' });
  logAudit('admin', 'admin_login', {}, req.ip);
  res.json({ token, user: { username: 'admin', role: 'admin', full_name: 'Administrator' } });
});

app.get('/api/me', authMiddleware, (req, res) => res.json({ user: req.user }));

// ----- Admin: user management -----
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const rows = db.prepare('SELECT id, username, role, full_name, created_at FROM users ORDER BY id').all();
  res.json({ users: rows });
});

app.post('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const { username, password, role, full_name } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: 'Missing fields' });
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  try {
    db.prepare('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)')
      .run(username, bcrypt.hashSync(password, 10), role, full_name||'');
    logAudit(req.user.username, 'create_user', { username, role });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/admin/reset-password', authMiddleware, adminMiddleware, (req, res) => {
  const { username, new_password } = req.body;
  if (!username || !new_password) return res.status(400).json({ error: 'Missing fields' });
  const r = db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(bcrypt.hashSync(new_password,10), username);
  if (r.changes === 0) return res.status(404).json({ error: 'User not found' });
  logAudit(req.user.username, 'reset_password', { username });
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  logAudit(req.user.username, 'delete_user', { id: req.params.id });
  res.json({ ok: true });
});

// ----- Transactions -----
app.get('/api/transactions', authMiddleware, (req, res) => {
  const { from, to, type } = req.query;
  let sql = 'SELECT * FROM transactions WHERE 1=1';
  const params = [];
  if (from) { sql += ' AND created_at >= ?'; params.push(from); }
  if (to)   { sql += ' AND created_at <= ?'; params.push(to); }
  if (type) { sql += ' AND type = ?'; params.push(type); }
  sql += ' ORDER BY id DESC LIMIT 1000';
  res.json({ transactions: db.prepare(sql).all(...params) });
});

app.post('/api/transactions', authMiddleware, (req, res) => {
  const t = req.body || {};
  const r = db.prepare(`INSERT INTO transactions
    (type, category, description, amount, quantity, unit, reference, attachment, created_by, created_role)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      t.type||'expense', t.category||'', t.description||'',
      Number(t.amount)||0, Number(t.quantity)||0, t.unit||'',
      t.reference||'', t.attachment||null,
      req.user.username, req.user.role
  );
  logAudit(req.user.username, 'add_transaction', { id: r.lastInsertRowid, type: t.type });
  res.json({ ok: true, id: r.lastInsertRowid });
});

app.delete('/api/transactions/:id', authMiddleware, adminMiddleware, (req, res) => {
  db.prepare('DELETE FROM transactions WHERE id = ?').run(req.params.id);
  logAudit(req.user.username, 'delete_transaction', { id: req.params.id });
  res.json({ ok: true });
});

// ----- Staff & HR -----
app.get('/api/staff', authMiddleware, (req, res) => {
  res.json({ staff: db.prepare('SELECT * FROM staff ORDER BY name').all() });
});

app.post('/api/staff', authMiddleware, (req, res) => {
  const s = req.body || {};
  const r = db.prepare(`INSERT INTO staff (name, position, phone, email, national_id, salary, status)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(s.name, s.position||'', s.phone||'', s.email||'', s.national_id||'', Number(s.salary)||0, s.status||'active');
  logAudit(req.user.username, 'add_staff', { id: r.lastInsertRowid });
  res.json({ ok: true, id: r.lastInsertRowid });
});

app.delete('/api/staff/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM staff WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/conduct', authMiddleware, (req, res) => {
  res.json({ reports: db.prepare('SELECT * FROM conduct_reports ORDER BY id DESC').all() });
});

app.post('/api/conduct', authMiddleware, (req, res) => {
  const c = req.body || {};
  const r = db.prepare(`INSERT INTO conduct_reports (staff_id, staff_name, report_type, description, severity, action_taken, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(c.staff_id||null, c.staff_name||'', c.report_type||'behavior', c.description||'', c.severity||'low', c.action_taken||'', req.user.username);
  res.json({ ok: true, id: r.lastInsertRowid });
});

// ----- Stock -----
app.get('/api/stock', authMiddleware, (req, res) => {
  res.json({ items: db.prepare('SELECT * FROM stock_items ORDER BY name').all() });
});

app.post('/api/stock', authMiddleware, (req, res) => {
  const s = req.body || {};
  const r = db.prepare(`INSERT INTO stock_items (name, category, quantity, unit, unit_price, reorder_level)
    VALUES (?, ?, ?, ?, ?, ?)`).run(s.name, s.category||'', Number(s.quantity)||0, s.unit||'', Number(s.unit_price)||0, Number(s.reorder_level)||0);
  res.json({ ok: true, id: r.lastInsertRowid });
});

app.put('/api/stock/:id', authMiddleware, (req, res) => {
  const s = req.body || {};
  db.prepare(`UPDATE stock_items SET name=?, category=?, quantity=?, unit=?, unit_price=?, reorder_level=?, updated_at=datetime('now') WHERE id=?`)
    .run(s.name, s.category||'', Number(s.quantity)||0, s.unit||'', Number(s.unit_price)||0, Number(s.reorder_level)||0, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/stock/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM stock_items WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ----- Reports -----
app.get('/api/reports/summary', authMiddleware, (req, res) => {
  const { from, to } = req.query;
  let where = '1=1', params = [];
  if (from) { where += ' AND created_at >= ?'; params.push(from); }
  if (to)   { where += ' AND created_at <= ?'; params.push(to); }
  const rows = db.prepare(`SELECT type, SUM(amount) AS total, COUNT(*) AS count FROM transactions WHERE ${where} GROUP BY type`).all(...params);
  const map = {}; rows.forEach(r => map[r.type] = r);
  const income = (map.income?.total||0) + (map.sale?.total||0);
  const expense = (map.expense?.total||0) + (map.purchase?.total||0);
  const profit = income - expense;
  const interest = profit > 0 ? profit * 0.05 : 0; // 5% reinvestment interest
  res.json({
    income, expense, profit, interest,
    margin: income > 0 ? (profit/income)*100 : 0,
    breakdown: rows
  });
});

app.get('/api/reports/daily', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT DATE(created_at) AS day,
           SUM(CASE WHEN type IN ('income','sale') THEN amount ELSE 0 END) AS income,
           SUM(CASE WHEN type IN ('expense','purchase') THEN amount ELSE 0 END) AS expense
    FROM transactions GROUP BY DATE(created_at) ORDER BY day DESC LIMIT 30
  `).all();
  res.json({ days: rows });
});

// ----- Audit log -----
app.get('/api/audit', authMiddleware, adminMiddleware, (req, res) => {
  res.json({ log: db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 500').all() });
});

// ----- Chatbot (rule + data based) -----
app.post('/api/chat', authMiddleware, (req, res) => {
  const q = (req.body.message || '').toLowerCase();
  const reply = generateChatReply(q, req.user);
  res.json({ reply });
});

function generateChatReply(q, user) {
  const summary = () => {
    const r = db.prepare(`SELECT type, SUM(amount) AS total FROM transactions GROUP BY type`).all();
    const m = {}; r.forEach(x => m[x.type]=x.total||0);
    const inc = (m.income||0)+(m.sale||0);
    const exp = (m.expense||0)+(m.purchase||0);
    return { inc, exp, profit: inc-exp };
  };
  if (/profit|earn|loss/i.test(q)) {
    const s = summary();
    return `📊 Current totals — Income: KES ${s.inc.toFixed(2)}, Expense: KES ${s.exp.toFixed(2)}, Net ${s.profit>=0?'Profit':'Loss'}: KES ${Math.abs(s.profit).toFixed(2)}.`;
  }
  if (/stock|inventory/.test(q)) {
    const c = db.prepare('SELECT COUNT(*) AS c FROM stock_items').get().c;
    const low = db.prepare('SELECT COUNT(*) AS c FROM stock_items WHERE quantity <= reorder_level').get().c;
    return `📦 You have ${c} stock items. ${low} item(s) are at or below reorder level.`;
  }
  if (/staff|employee|hr/.test(q)) {
    const c = db.prepare('SELECT COUNT(*) AS c FROM staff').get().c;
    return `👥 There are ${c} staff records in HR.`;
  }
  if (/help|what can|how/.test(q)) {
    return `🤖 I can answer about profit, loss, stock levels, staff count, reports, and how to use this system. Try: "show profit", "low stock", "today's report".`;
  }
  if (/hello|hi|hey/.test(q)) return `👋 Hello ${user.full_name||user.username}! How can I help you today?`;
  if (/logout|log out/.test(q)) return `To logout, click your profile (top right) and choose Logout. Your data stays safe.`;
  if (/report/.test(q)) return `📑 Reports are auto-generated every 12 hours. You can also download a PDF receipt from the Accounts panel anytime.`;
  return `I understand: "${q}". Try asking about profit, stock, staff, or reports.`;
}

// ---------- Auto reports every 12 hours ----------
function generateAutoReport() {
  const s = db.prepare(`SELECT type, SUM(amount) AS total FROM transactions WHERE created_at >= datetime('now','-12 hours') GROUP BY type`).all();
  const map = {}; s.forEach(x => map[x.type]=x.total||0);
  const inc = (map.income||0)+(map.sale||0);
  const exp = (map.expense||0)+(map.purchase||0);
  const report = { generated_at: new Date().toISOString(), income: inc, expense: exp, profit: inc-exp };
  db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)').run(`auto_report_${Date.now()}`, JSON.stringify(report));
  logAudit('system', 'auto_report_12h', report);
  console.log('🕛 Auto report generated:', report);
}
setInterval(generateAutoReport, 12 * 60 * 60 * 1000);

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`🚀 LocationRooftop backend running on port ${PORT}`);
  console.log(`📁 Database: ${DB_PATH}`);
});
