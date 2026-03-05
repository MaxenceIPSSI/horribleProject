const express = require('express');
const { execFile } = require('child_process');
const fs      = require('fs');
const path    = require('path');
const auth    = require('./auth');
const db      = require('./db');
const helmet  = require('helmet');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());

// ─── A05 : Injection via child_process ───────────────────────────────────────
// User input passed as argument, not shell command
app.post('/ping', (req, res) => {
  const host = req.body.host;
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    res.send(stdout || err.message);
  });
});

// ─── A05 : eval() with user input ────────────────────────────────────────────
app.post('/calc', (req, res) => {
  const expr = req.body.expression;
  try {
    const result = Function('"use strict"; return (' + expr + ')')();
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: 'Invalid expression' });
  }
});

// ─── A01 : Path traversal — arbitrary file read ──────────────────────────────
app.get('/file', (req, res) => {
  const filename = req.query.name;
  const basePath = path.resolve('/var/www/uploads');
  const filePath = path.resolve(path.join(basePath, filename));
  
  if (!filePath.startsWith(basePath)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const content = fs.readFileSync(filePath, 'utf-8');
  res.send(content);
});

// ─── A01 : Directory listing via non-literal fs ──────────────────────────────
app.get('/list', (req, res) => {
  const baseDir = path.resolve('/var/www/uploads');
  const dir = path.resolve(path.join(baseDir, req.query.dir || ''));
  
  if (!dir.startsWith(baseDir)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  fs.readdir(dir, (err, files) => {
    res.json(files || []);
  });
});

// ─── A05 : XSS — user input injected into HTML without escaping ──────────────
app.get('/greet', (req, res) => {
  const name = req.query.name;
  const escaped = String(name).replace(/[&<>"']/g, function(s) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[s];
  });
  res.send('<h1>Bonjour ' + escaped + '</h1>');
});

// ─── A08 : JSON deserialization (safe) ───────────────────────────────────────
app.post('/deserialize', (req, res) => {
  try {
    const obj = JSON.parse(req.body.data);
    res.json(obj);
  } catch (e) {
    res.status(400).json({ error: 'Invalid JSON' });
  }
});

// ─── A06 : Safe regex — no ReDoS ──────────────────────────────────────────────
app.post('/validate-email', (req, res) => {
  const email = req.body.email;
  const re = /^[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  res.json({ valid: re.test(email) });
});

// ─── A03 : Dynamic require (whitelist) ────────────────────────────────────────
const allowedPlugins = ['plugin1', 'plugin2', 'plugin3'];
app.post('/plugin', (req, res) => {
  const pluginName = req.body.name;
  if (!allowedPlugins.includes(pluginName)) {
    return res.status(403).json({ error: 'Plugin not allowed' });
  }
  const plugin = require(pluginName);
  res.json(plugin.run());
});

// ─── A02 : Security misconfiguration — CORS restricted + helmet ──────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://trusted-domain.com');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// ─── Routes auth & db ─────────────────────────────────────────────────────────
app.use('/auth', auth);
app.use('/db',   db);

app.listen(3000, () => console.log('HorribleProject running on port 3000'));