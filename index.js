require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const XLSX = require('xlsx');
const cors = require('cors');

const app = express();
// Accept requests from any origin — auth is enforced by JWT, not by origin
app.use(cors({
  origin: true,          // reflect any requesting origin
  credentials: true,
  methods: ['GET','POST','PATCH','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
app.options('*', cors()); // handle preflight for all routes
app.use(express.json({ limit: '100mb' }));

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── Auth middleware ────────────────────────────────────────────────────────────
const auth = (roles = []) => (req, res, next) => {
  try {
    const token = (req.headers.authorization || '').split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    const user = jwt.verify(token, process.env.JWT_SECRET);
    if (roles.length && !roles.includes(user.role))
      return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ── Health check ───────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({
  ok: true,
  version: "2.0",          // bump this to confirm Railway has the latest code
  time: new Date().toISOString(),
  env: {
    db: !!process.env.DATABASE_URL,
    jwt: !!process.env.JWT_SECRET,
  }
}));

// ── Auth ───────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const { rows } = await db.query('SELECT * FROM rh_users WHERE username=$1', [username]);
    if (!rows[0]) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { id: rows[0].id, username: rows[0].username, role: rows[0].role },
      process.env.JWT_SECRET,
      { expiresIn: '10h' }
    );
    res.json({ token, role: rows[0].role, username: rows[0].username });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Users (admin only) ────────────────────────────────────────────────────────
app.get('/api/users', auth(['admin']), async (req, res) => {
  const { rows } = await db.query("SELECT id, username, role FROM rh_users ORDER BY username");
  res.json(rows);
});

app.post('/api/users', auth(['admin']), async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await db.query(
      'INSERT INTO rh_users(username, password_hash, role) VALUES($1,$2,$3) RETURNING id, username, role',
      [username.trim(), hash, role || 'user']
    );
    res.json(rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Username already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/users/:id/password', auth(['admin']), async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });
    const hash = await bcrypt.hash(password, 10);
    await db.query('UPDATE rh_users SET password_hash=$1 WHERE id=$2', [hash, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', auth(['admin']), async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    await db.query('DELETE FROM rh_users WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Reports ───────────────────────────────────────────────────────────────────
app.get('/api/reports', auth([]), async (req, res) => {
  try {
    const q = req.user.role === 'admin'
      ? 'SELECT id, name, config, card_fields, is_published, row_count, field_count, created_at FROM rh_reports ORDER BY created_at DESC'
      : 'SELECT id, name, config, card_fields, is_published, row_count, field_count, created_at FROM rh_reports WHERE is_published=true ORDER BY created_at DESC';
    const { rows } = await db.query(q);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reports', auth(['admin']), async (req, res) => {
  const client = await db.connect();
  try {
    const { name, config, cardFields, rows, fields, numFields } = req.body;
    await client.query('BEGIN');

    const rpt = await client.query(
      `INSERT INTO rh_reports(name, config, card_fields, num_fields, row_count, field_count, created_by)
       VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [name, JSON.stringify(config), JSON.stringify(cardFields || []),
       JSON.stringify(numFields || []), rows.length, fields.length, req.user.id]
    );
    const rptId = rpt.rows[0].id;

    // Store field list
    await client.query(
      'INSERT INTO rh_datasets(report_id, fields) VALUES($1,$2)',
      [rptId, JSON.stringify(fields)]
    );

    // Batch insert rows (500 at a time to avoid query size limits)
    for (let i = 0; i < rows.length; i += 500) {
      const batch = rows.slice(i, i + 500);
      const values = batch.map((_, j) => `($1, $${j + 2})`).join(',');
      await client.query(
        `INSERT INTO rh_rows(report_id, row_data) VALUES ${values}`,
        [rptId, ...batch.map(r => JSON.stringify(r))]
      );
    }

    await client.query('COMMIT');
    res.json({ id: rptId });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally { client.release(); }
});

app.delete('/api/reports/:id', auth(['admin']), async (req, res) => {
  try {
    await db.query('DELETE FROM rh_reports WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Publish — always sets published=true, never touches other reports
app.patch('/api/reports/:id/publish', auth(['admin']), async (req, res) => {
  try {
    await db.query('UPDATE rh_reports SET is_published=true WHERE id=$1', [req.params.id]);
    res.json({ ok: true, is_published: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Unpublish — always sets published=false
app.patch('/api/reports/:id/unpublish', auth(['admin']), async (req, res) => {
  try {
    await db.query('UPDATE rh_reports SET is_published=false WHERE id=$1', [req.params.id]);
    res.json({ ok: true, is_published: false });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Report data (rows + fields) ───────────────────────────────────────────────
app.get('/api/reports/:id/data', auth([]), async (req, res) => {
  try {
    const { rows: rpt } = await db.query(
      'SELECT is_published, num_fields FROM rh_reports WHERE id=$1', [req.params.id]
    );
    if (!rpt[0]) return res.status(404).json({ error: 'Not found' });
    if (!rpt[0].is_published && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Not published' });

    const { rows: ds } = await db.query('SELECT fields FROM rh_datasets WHERE report_id=$1', [req.params.id]);
    const { rows: dataRows } = await db.query(
      'SELECT row_data FROM rh_rows WHERE report_id=$1 ORDER BY id', [req.params.id]
    );
    res.json({
      fields: ds[0]?.fields || [],
      numFields: rpt[0].num_fields || [],
      rows: dataRows.map(r => r.row_data)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── URL refresh (re-download Excel from a URL and re-import) ──────────────────
app.post('/api/reports/:id/refresh-url', auth(['admin']), async (req, res) => {
  try {
    const { url, sheetName } = req.body;
    const resp = await fetch(url);
    if (!resp.ok) return res.status(400).json({ error: `Fetch failed: HTTP ${resp.status}` });
    const buf = await resp.arrayBuffer();
    const wb = XLSX.read(buf, { cellDates: true });
    const ws = wb.Sheets[sheetName || wb.SheetNames[0]];
    if (!ws) return res.status(400).json({ error: 'Sheet not found' });
    // Cap at 100k rows
    if (ws['!ref']) {
      const r = XLSX.utils.decode_range(ws['!ref']);
      if (r.e.r > 100000) { r.e.r = 100000; ws['!ref'] = XLSX.utils.encode_range(r); }
    }
    const rows = XLSX.utils.sheet_to_json(ws, { defval: null, cellDates: true });
    // Delete old rows and insert fresh
    const client = await db.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM rh_rows WHERE report_id=$1', [req.params.id]);
      for (let i = 0; i < rows.length; i += 500) {
        const batch = rows.slice(i, i + 500);
        const vals = batch.map((_, j) => `($1, $${j + 2})`).join(',');
        await client.query(
          `INSERT INTO rh_rows(report_id, row_data) VALUES ${vals}`,
          [req.params.id, ...batch.map(r => JSON.stringify(r))]
        );
      }
      await client.query('UPDATE rh_reports SET row_count=$1 WHERE id=$2', [rows.length, req.params.id]);
      await client.query('COMMIT');
      res.json({ ok: true, rowCount: rows.length });
    } catch (e) { await client.query('ROLLBACK'); throw e; }
    finally { client.release(); }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Proxy URL fetch — downloads Excel/CSV from any URL server-side ─────────────
// Used for OneDrive, SharePoint, Dropbox, etc. that block browser CORS fetches
app.post('/api/fetch-url', auth(['admin']), async (req, res) => {
  try {
    const { url, sheetName } = req.body;
    if (!url) return res.status(400).json({ error: 'url is required' });

    // Convert OneDrive share links to direct download URLs
    let downloadUrl = url;
    if (url.includes('1drv.ms') || url.includes('onedrive.live.com') || url.includes('sharepoint.com')) {
      // OneDrive/SharePoint: append ?download=1 or replace embed with download
      if (url.includes('?')) {
        downloadUrl = url.replace(/[?&]e=[^&]*/, '') + '&download=1';
      } else {
        downloadUrl = url + '?download=1';
      }
      // For SharePoint direct links, use the raw download form
      downloadUrl = downloadUrl.replace('/view.aspx', '/download.aspx')
                               .replace('embed?', 'download?');
    } else if (url.includes('dropbox.com')) {
      // Dropbox: replace dl=0 with dl=1
      downloadUrl = url.replace('dl=0', 'dl=1').replace('?dl=', '?dl=1').replace(/\?$/, '?dl=1');
      if (!downloadUrl.includes('dl=1')) downloadUrl += (downloadUrl.includes('?') ? '&' : '?') + 'dl=1';
    } else if (url.includes('drive.google.com')) {
      // Google Drive: convert share link to direct download
      const idMatch = url.match(/\/d\/([a-zA-Z0-9_-]+)/);
      if (idMatch) downloadUrl = `https://drive.google.com/uc?export=download&id=${idMatch[1]}`;
    }

    const resp = await fetch(downloadUrl, {
      headers: { 'User-Agent': 'ReportHub/1.0' },
      redirect: 'follow',
    });
    if (!resp.ok) return res.status(400).json({
      error: `Download failed: HTTP ${resp.status}. Try sharing the file with "Anyone with the link can view" and use a direct download link.`
    });

    const contentType = resp.headers.get('content-type') || '';
    const buf = await resp.arrayBuffer();

    let rows, sheetNames;

    if (contentType.includes('csv') || url.endsWith('.csv')) {
      // CSV via PapaParse-equivalent manual parse
      const text = Buffer.from(buf).toString('utf-8');
      const lines = text.split('\n').filter(l => l.trim());
      if (!lines.length) return res.status(400).json({ error: 'Empty file' });
      const headers = lines[0].split(',').map(h => h.replace(/^"|"$/g, '').trim());
      rows = lines.slice(1).map(line => {
        const vals = line.split(',');
        const obj = {};
        headers.forEach((h, i) => { obj[h] = vals[i]?.replace(/^"|"$/g, '').trim() || ''; });
        return obj;
      });
      sheetNames = ['Sheet1'];
    } else {
      // Excel via XLSX
      const wb = XLSX.read(buf, { type: 'buffer', cellDates: true });
      sheetNames = wb.SheetNames;
      const wsName = sheetName && wb.SheetNames.includes(sheetName) ? sheetName : wb.SheetNames[0];
      const ws = wb.Sheets[wsName];
      if (!ws) return res.status(400).json({ error: `Sheet "${wsName}" not found. Available: ${sheetNames.join(', ')}` });
      // Cap rows
      if (ws['!ref']) {
        const r = XLSX.utils.decode_range(ws['!ref']);
        if (r.e.r > 100000) { r.e.r = 100000; ws['!ref'] = XLSX.utils.encode_range(r); }
      }
      rows = XLSX.utils.sheet_to_json(ws, { defval: null, cellDates: true });
    }

    res.json({ ok: true, rows, sheetNames, rowCount: rows.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`ReportHub API running on port ${PORT}`));
