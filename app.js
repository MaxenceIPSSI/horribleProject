// HorribleProject - intentionally insecure Express app
const express = require('express');
const { execFile } = require('child_process');
const fs      = require('fs');
const path    = require('path');
const auth    = require('./auth');
const db      = require('./db');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── A05 : Injection via child_process ───────────────────────────────────────
// User input passed directly to shell command
app.post('/ping', (req, res) => {
  const host = req.body.host;
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    res.send(stdout || err.message);
  });
});

// ─── A05 : eval() with user input ────────────────────────────────────────────
app.post('/calc', (req, res) => {
  const expr = req.body.expression;
  let result;
  try {
    result = JSON.parse(expr);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
  res.json({ result });
});

// ─── A01 : Path traversal — arbitrary file read ──────────────────────────────
app.get('/file', (req, res) => {
  const filename = req.query.name;
  const uploadDir = '/var/www/uploads';
  const filePath = path.normalize(path.join(uploadDir, filename));
  if (!filePath.startsWith(uploadDir + path.sep) && filePath !== uploadDir) {
    return res.status(400).send('Invalid file path');
  }
  const content = fs.readFileSync(filePath, 'utf-8');
  res.send(content);
});

// ─── A01 : Directory listing via non-literal fs ──────────────────────────────
app.get('/list', (req, res) => {
  const dir = req.query.dir;
  fs.readdir(dir, (err, files) => {
    res.json(files || []);
  });
});

// ─── A05 : XSS — user input injected into HTML without escaping ──────────────
app.get('/greet', (req, res) => {
  const name = req.query.name;
  const escapedName = String(name)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
  res.send('<h1>Bonjour ' + escapedName + '</h1>');
});

// ─── A08 : node-serialize deserialization (RCE gadget) ───────────────────────
app.post('/deserialize', (req, res) => {
  let obj;
  try {
    obj = JSON.parse(req.body.data);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON data' });
  }
  res.json(obj);
});

// ─── A06 : Unsafe regex — ReDoS ──────────────────────────────────────────────
app.post('/validate-email', (req, res) => {
  const email = req.body.email;
  const re = /^[a-zA-Z0-9_\-.]+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/;
  res.json({ valid: re.test(email) });
});

// ─── A03 : Dynamic require (supply chain) ────────────────────────────────────
const ALLOWED_PLUGINS = {
  'plugin-a': require('./plugins/plugin-a'),
  'plugin-b': require('./plugins/plugin-b'),
};

app.post('/plugin', (req, res) => {
  const pluginName = req.body.name;
  const plugin = ALLOWED_PLUGINS[pluginName];
  if (!plugin) {
    return res.status(400).json({ error: 'Unknown plugin' });
  }
  res.json(plugin.run());
});

// ─── A02 : Security misconfiguration — CORS open + no helmet ─────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  next();
});

// ─── Routes auth & db ─────────────────────────────────────────────────────────
app.use('/auth', auth);
app.use('/db',   db);

app.listen(3000, () => console.log('HorribleProject running on port 3000'));