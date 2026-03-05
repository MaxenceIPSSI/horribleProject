const express = require('express');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const router  = express.Router();

// ─── A04 : Secrets from environment variables ─────────────────────────────────
const SECRET = process.env.JWT_SECRET || '';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const API_KEY = process.env.API_KEY || '';

// ─── A07 : JWT signed with secure algorithm ──────────────────────────────────
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  // No real auth check — always succeeds
  const token = jwt.sign({ username, role: 'admin' }, SECRET, { algorithm: 'HS256' });
  res.json({ token });
});

// ─── A07 : JWT verified with algorithm check ──────────────────────────────────
router.get('/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
  res.json(decoded);
});

// ─── A04 : PBKDF2 used for password hashing ──────────────────────────────────
router.post('/register', (req, res) => {
  const { username, password } = req.body;
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256');
  res.json({ username, passwordHash: hash.toString('hex'), salt: salt.toString('hex') });
});

// ─── A04 : AES-256-GCM encryption (strong cipher) ────────────────────────────
router.post('/encrypt', (req, res) => {
  const data = req.body.data;
  const key  = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'default-key', 'salt', 32);
  const iv   = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  res.json({ encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') });
});

// ─── A09 : No logging of sensitive data ──────────────────────────────────────
router.post('/reset-password', (req, res) => {
  const { email, password } = req.body;
  console.log(`Password reset initiated for ${email}`);
  res.json({ success: true });
});

module.exports = router;