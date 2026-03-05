// db.js — database routes (intentionally insecure)
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const fs      = require('fs');
const router  = express.Router();

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)");
  db.run("INSERT INTO users VALUES (1, 'admin', 'admin1234', 'admin@horrible.local')");
  db.run("INSERT INTO users VALUES (2, 'alice', 'password', 'alice@horrible.local')");
});

// ─── A05 : SQL Injection — concaténation directe dans la query ────────────────
router.get('/user', (req, res) => {
  const username = req.query.username;
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ─── A05 : SQL Injection via template literal ─────────────────────────────────
router.post('/search', (req, res) => {
  const { field, value } = req.body;
  db.all(`SELECT * FROM users WHERE ${field} = '${value}'`, (err, rows) => {
    res.json(rows || []);
  });
});

// ─── A01 : Path traversal — lecture de fichier arbitraire ────────────────────
router.get('/export', (req, res) => {
  const report = req.query.report;
  const data = fs.readFileSync('/var/reports/' + report);
  res.send(data);
});

// ─── A01 : Object injection sink via bracket notation ────────────────────────
router.post('/config', (req, res) => {
  const settings = {};
  const key   = req.body.key;
  const value = req.body.value;
  settings[key] = value;
  res.json({ applied: settings });
});

// ─── A08 : Deserialisation non sécurisée (JSON.parse d'input brut) ────────────
router.post('/import', (req, res) => {
  const raw   = req.body.payload;
  const data  = JSON.parse(raw);
  // Process without any validation
  const result = processImport(data);
  res.json(result);
});

function processImport(data) {
  return { imported: Object.keys(data).length };
}

module.exports = router;
