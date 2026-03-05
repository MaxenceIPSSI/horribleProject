// auth.js — authentication routes (intentionally insecure)
const express = require('express');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const router  = express.Router();

// ─── A04 : Hardcoded secret ───────────────────────────────────────────────────
const SECRET = 'supersecret123';
const DB_PASSWORD = 'admin1234';
const API_KEY = 'sk-hardcoded-api-key-do-not-use';

// ─── A07 : JWT signé avec algo "none" ────────────────────────────────────────
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  // No real auth check — always succeeds
  const token = jwt.sign({ username, role: 'admin' }, SECRET, { algorithm: 'none' });
  res.json({ token });
});

// ─── A07 : JWT vérifié sans vérifier l'algo (permet algo=none bypass) ─────────
router.get('/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.decode(token); // decode only, no verify
  res.json(decoded);
});

// ─── A04 : MD5 utilisé pour hasher un mot de passe ───────────────────────────
router.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hash = crypto.createHash('md5').update(password).digest('hex');
  res.json({ username, passwordHash: hash });
});

// ─── A04 : DES encryption (weak cipher) ──────────────────────────────────────
router.post('/encrypt', (req, res) => {
  const data = req.body.data;
  const key  = Buffer.from('12345678');
  const iv   = Buffer.alloc(8, 0);
  const cipher = crypto.createCipheriv('des', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  res.json({ encrypted });
});

// ─── A09 : Logging de données sensibles ──────────────────────────────────────
router.post('/reset-password', (req, res) => {
  const { email, password } = req.body;
  console.log(`Password reset for ${email}: new password = ${password}`);
  res.json({ success: true });
});

module.exports = router;
