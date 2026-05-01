require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const XLSX = require('xlsx');
const cors = require('cors');

const app = express();
app.use(cors({ origin: true, credentials: true, methods: ['GET','POST','PATCH','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.options('*', cors());
app.use(express.json({ limit: '100mb' }));

const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ── Auth middleware ─────────────────────────────────────────────────────────────
const auth = (roles = []) => (req, res, next) => {
  try {
    const token = (req.headers.authorization || '').split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    const user = jwt.verify(token, process.env.JWT_SECRET);
    if (roles.length && !roles.includes(user.role)) return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

// ── Health ──────────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({
  ok: true, version: '3.0', time: new Date().toISOString(),
  oauth: {
    microsoft: !!(process.env.MS_CLIENT_ID && process.env.MS_CLIENT_SECRET),
    google: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
  },
  env: { db: !!process.env.DATABASE_URL, jwt: !!process.env.JWT_SECRET }
}));

// ────────────────────────────────────────────────────────────────────────────────
// ── OAUTH 2.0 ───────────────────────────────────────────────────────────────────
// ────────────────────────────────────────────────────────────────────────────────

const BACKEND_URL = process.env.BACKEND_URL || 'https://reporthub-api-production-5992.up.railway.app';

// In-memory state store (survives single session; tokens persist in DB)
const oauthStates = new Map(); // state -> { provider, userId, timestamp }

// ── Token helpers ───────────────────────────────────────────────────────────────
async function saveToken(userId, provider, tokenData) {
  await db.query(`
    INSERT INTO rh_oauth_tokens (user_id, provider, access_token, refresh_token, expires_at, token_data)
    VALUES ($1,$2,$3,$4,$5,$6)
    ON CONFLICT (user_id, provider)
    DO UPDATE SET access_token=$3, refresh_token=$4, expires_at=$5, token_data=$6, updated_at=now()
  `, [userId, provider, tokenData.access_token, tokenData.refresh_token||null,
      tokenData.expires_in ? new Date(Date.now() + tokenData.expires_in*1000) : null,
      JSON.stringify(tokenData)]);
}

async function getToken(userId, provider) {
  const { rows } = await db.query(
    'SELECT * FROM rh_oauth_tokens WHERE user_id=$1 AND provider=$2', [userId, provider]);
  return rows[0] || null;
}

async function refreshMsToken(stored) {
  const body = new URLSearchParams({
    client_id: process.env.MS_CLIENT_ID,
    client_secret: process.env.MS_CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: stored.refresh_token,
    scope: 'Files.Read Files.Read.All offline_access',
  });
  const r = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body
  });
  if (!r.ok) throw new Error('Token refresh failed: ' + await r.text());
  const data = await r.json();
  await saveToken(stored.user_id, 'microsoft', data);
  return data.access_token;
}

async function refreshGoogleToken(stored) {
  const body = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: stored.refresh_token,
  });
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body
  });
  if (!r.ok) throw new Error('Token refresh failed: ' + await r.text());
  const data = await r.json();
  await saveToken(stored.user_id, 'google', data);
  return data.access_token;
}

async function getValidAccessToken(userId, provider) {
  const stored = await getToken(userId, provider);
  if (!stored) return null;
  // Refresh if expired or expiring in next 5 minutes
  if (stored.expires_at && new Date(stored.expires_at) < new Date(Date.now() + 5*60*1000)) {
    try {
      if (provider === 'microsoft') return await refreshMsToken(stored);
      if (provider === 'google') return await refreshGoogleToken(stored);
    } catch(e) {
      console.error('Token refresh failed:', e.message);
      return null; // Will need re-auth
    }
  }
  return stored.access_token;
}

// ── Microsoft OAuth ─────────────────────────────────────────────────────────────
app.get('/auth/microsoft/start', auth(['admin']), (req, res) => {
  if (!process.env.MS_CLIENT_ID) return res.status(400).json({ error: 'MS_CLIENT_ID not set in Railway environment variables' });
  const state = Math.random().toString(36).slice(2) + Date.now();
  oauthStates.set(state, { provider: 'microsoft', userId: req.user.id, ts: Date.now() });
  const params = new URLSearchParams({
    client_id: process.env.MS_CLIENT_ID,
    response_type: 'code',
    redirect_uri: BACKEND_URL + '/auth/microsoft/callback',
    scope: 'Files.Read Files.Read.All offline_access User.Read',
    state,
    prompt: 'select_account',
  });
  res.json({ url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' + params });
});

app.get('/auth/microsoft/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.send(`<script>window.opener&&window.opener.postMessage({type:'oauth-error',error:'${error}'},'*');window.close();</script>`);
  const saved = oauthStates.get(state);
  if (!saved) return res.send('<script>window.close();</script>');
  oauthStates.delete(state);
  try {
    const body = new URLSearchParams({
      client_id: process.env.MS_CLIENT_ID,
      client_secret: process.env.MS_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: BACKEND_URL + '/auth/microsoft/callback',
    });
    const r = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
      method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body
    });
    const data = await r.json();
    if (data.error) throw new Error(data.error_description || data.error);
    await saveToken(saved.userId, 'microsoft', data);
    res.send(`<html><body style="font-family:system-ui;text-align:center;padding:60px;background:#F0E8DC">
      <div style="font-size:48px;margin-bottom:16px">✅</div>
      <h2 style="color:#5C2D1A">Microsoft account connected!</h2>
      <p style="color:#7A5C4A">You can close this window and return to ReportHub.</p>
      <script>setTimeout(()=>{window.opener&&window.opener.postMessage({type:'oauth-success',provider:'microsoft'},'*');window.close();},1500);</script>
    </body></html>`);
  } catch(e) {
    res.send(`<html><body style="font-family:system-ui;text-align:center;padding:60px;background:#F0E8DC">
      <div style="font-size:48px;margin-bottom:16px">❌</div>
      <h2 style="color:#5C2D1A">Connection failed</h2>
      <p style="color:#7A5C4A">${e.message}</p>
      <script>window.opener&&window.opener.postMessage({type:'oauth-error',error:'${e.message.replace(/'/g,"\\'")}'},'*');setTimeout(()=>window.close(),3000);</script>
    </body></html>`);
  }
});

// ── Google OAuth ────────────────────────────────────────────────────────────────
app.get('/auth/google/start', auth(['admin']), (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID) return res.status(400).json({ error: 'GOOGLE_CLIENT_ID not set in Railway environment variables' });
  const state = Math.random().toString(36).slice(2) + Date.now();
  oauthStates.set(state, { provider: 'google', userId: req.user.id, ts: Date.now() });
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: BACKEND_URL + '/auth/google/callback',
    response_type: 'code',
    scope: 'https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/drive.file',
    access_type: 'offline',
    prompt: 'consent',
    state,
  });
  res.json({ url: 'https://accounts.google.com/o/oauth2/v2/auth?' + params });
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.send(`<script>window.opener&&window.opener.postMessage({type:'oauth-error',error:'${error}'},'*');window.close();</script>`);
  const saved = oauthStates.get(state);
  if (!saved) return res.send('<script>window.close();</script>');
  oauthStates.delete(state);
  try {
    const body = new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: BACKEND_URL + '/auth/google/callback',
    });
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body
    });
    const data = await r.json();
    if (data.error) throw new Error(data.error_description || data.error);
    await saveToken(saved.userId, 'google', data);
    res.send(`<html><body style="font-family:system-ui;text-align:center;padding:60px;background:#F0E8DC">
      <div style="font-size:48px;margin-bottom:16px">✅</div>
      <h2 style="color:#5C2D1A">Google account connected!</h2>
      <p style="color:#7A5C4A">You can close this window and return to ReportHub.</p>
      <script>setTimeout(()=>{window.opener&&window.opener.postMessage({type:'oauth-success',provider:'google'},'*');window.close();},1500);</script>
    </body></html>`);
  } catch(e) {
    res.send(`<html><body style="font-family:system-ui;text-align:center;padding:60px;background:#F0E8DC">
      <div style="font-size:48px;margin-bottom:16px">❌</div>
      <h2 style="color:#5C2D1A">Connection failed</h2>
      <p>${e.message}</p>
      <script>window.opener&&window.opener.postMessage({type:'oauth-error',error:'${e.message.replace(/'/g,"\\'")}'},'*');setTimeout(()=>window.close(),3000);</script>
    </body></html>`);
  }
});

// ── OAuth status ────────────────────────────────────────────────────────────────
app.get('/auth/status', auth(['admin']), async (req, res) => {
  try {
    const { rows } = await db.query(
      "SELECT provider, updated_at FROM rh_oauth_tokens WHERE user_id=$1", [req.user.id]);
    const connected = {};
    rows.forEach(r => { connected[r.provider] = r.updated_at; });
    res.json({
      microsoft: { configured: !!process.env.MS_CLIENT_ID, connected: !!connected.microsoft, connectedAt: connected.microsoft },
      google: { configured: !!process.env.GOOGLE_CLIENT_ID, connected: !!connected.google, connectedAt: connected.google },
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Disconnect OAuth ────────────────────────────────────────────────────────────
app.delete('/auth/:provider', auth(['admin']), async (req, res) => {
  await db.query('DELETE FROM rh_oauth_tokens WHERE user_id=$1 AND provider=$2', [req.user.id, req.params.provider]);
  res.json({ ok: true });
});

// ────────────────────────────────────────────────────────────────────────────────
// ── FILE FETCH (with OAuth or public fallback) ──────────────────────────────────
// ────────────────────────────────────────────────────────────────────────────────

async function downloadWithMicrosoftGraph(userId, shareUrl) {
  const token = await getValidAccessToken(userId, 'microsoft');
  if (!token) throw new Error('NEEDS_AUTH:microsoft');

  // Use the Graph Shares API — works for any OneDrive/SharePoint share URL
  const encoded = Buffer.from(shareUrl).toString('base64')
    .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const apiUrl = `https://graph.microsoft.com/v1.0/shares/u!${encoded}/driveItem/content`;

  const resp = await fetch(apiUrl, {
    headers: { Authorization: `Bearer ${token}` },
    redirect: 'follow',
  });
  if (resp.status === 401) throw new Error('NEEDS_AUTH:microsoft');
  if (!resp.ok) throw new Error(`Microsoft Graph error: HTTP ${resp.status}`);
  return await resp.arrayBuffer();
}

async function downloadWithGoogleDrive(userId, shareUrl) {
  const token = await getValidAccessToken(userId, 'google');
  if (!token) throw new Error('NEEDS_AUTH:google');

  // Extract file ID from share URL
  const idMatch = shareUrl.match(/[-\w]{25,}/);
  if (!idMatch) throw new Error('Could not extract Google Drive file ID from URL');
  const fileId = idMatch[0];

  // Get file metadata first to check MIME type
  const metaResp = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?fields=id,name,mimeType`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (metaResp.status === 401) throw new Error('NEEDS_AUTH:google');
  if (!metaResp.ok) throw new Error(`Google Drive error: HTTP ${metaResp.status}`);
  const meta = await metaResp.json();

  let downloadUrl;
  // Native Google Sheets → export as XLSX
  if (meta.mimeType === 'application/vnd.google-apps.spreadsheet') {
    downloadUrl = `https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`;
  } else {
    downloadUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;
  }

  const resp = await fetch(downloadUrl, { headers: { Authorization: `Bearer ${token}` } });
  if (!resp.ok) throw new Error(`Google Drive download error: HTTP ${resp.status}`);
  return await resp.arrayBuffer();
}

function parseXlsxBuffer(buf, sheetName) {
  let wb;
  try { wb = XLSX.read(buf, { type: 'buffer', cellDates: true }); }
  catch(e) { throw new Error('Could not parse file as Excel: ' + e.message); }
  const sheetNames = wb.SheetNames;
  const wsName = sheetName && wb.SheetNames.includes(sheetName) ? sheetName : wb.SheetNames[0];
  const ws = wb.Sheets[wsName];
  if (!ws) throw new Error(`Sheet "${wsName}" not found. Available: ${sheetNames.join(', ')}`);
  if (ws['!ref']) {
    const r = XLSX.utils.decode_range(ws['!ref']);
    if (r.e.r > 100000) { r.e.r = 100000; ws['!ref'] = XLSX.utils.encode_range(r); }
  }
  return { rows: XLSX.utils.sheet_to_json(ws, { defval: null, cellDates: true }), sheetNames };
}

// ── Main fetch-url endpoint ─────────────────────────────────────────────────────
app.post('/api/fetch-url', auth(['admin','user']), async (req, res) => {
  const { url, sheetName } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });
  // For viewer role, use the admin's stored OAuth tokens
  let userId = req.user.id;
  if (req.user.role !== 'admin') {
    const adminRow = await db.query("SELECT id FROM rh_users WHERE role='admin' LIMIT 1");
    if (adminRow.rows[0]) userId = adminRow.rows[0].id;
  }
  const isMicrosoft = url.includes('sharepoint.com') || url.includes('onedrive.live.com') || url.includes('1drv.ms') || url.includes('office.com');
  const isGoogle = url.includes('drive.google.com') || url.includes('docs.google.com');

  try {
    // ── Strategy 1: Microsoft Graph API (if connected) ──────────────────────────
    if (isMicrosoft) {
      try {
        const buf = await downloadWithMicrosoftGraph(userId, url);
        const result = parseXlsxBuffer(buf, sheetName);
        return res.json({ ok: true, ...result, rowCount: result.rows.length });
      } catch(e) {
        if (e.message.startsWith('NEEDS_AUTH:')) {
          return res.status(401).json({ error: 'needs_auth', provider: 'microsoft',
            message: 'Connect your Microsoft account in the Upload tab to access OneDrive/SharePoint files.' });
        }
        console.log('Graph API failed, trying public fallback:', e.message);
      }
    }

    // ── Strategy 2: Google Drive API (if connected) ─────────────────────────────
    if (isGoogle) {
      try {
        const buf = await downloadWithGoogleDrive(userId, url);
        const result = parseXlsxBuffer(buf, sheetName);
        return res.json({ ok: true, ...result, rowCount: result.rows.length });
      } catch(e) {
        if (e.message.startsWith('NEEDS_AUTH:')) {
          return res.status(401).json({ error: 'needs_auth', provider: 'google',
            message: 'Connect your Google account in the Upload tab to access Google Drive files.' });
        }
        console.log('Google Drive API failed, trying public fallback:', e.message);
      }
    }

    // ── Strategy 3: Public download fallback (for publicly shared files) ────────
    let downloadUrl = url;
    if (isMicrosoft) {
      try {
        const encoded = Buffer.from(url).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
        const apiResp = await fetch(`https://api.onedrive.com/v1.0/shares/u!${encoded}/root/content`, {
          headers: { 'User-Agent': 'Mozilla/5.0' }, redirect: 'follow' });
        if (apiResp.ok) {
          const buf = await apiResp.arrayBuffer();
          const result = parseXlsxBuffer(buf, sheetName);
          return res.json({ ok: true, ...result, rowCount: result.rows.length });
        }
      } catch(e) { console.log('OneDrive public API failed:', e.message); }
    }
    if (isGoogle) {
      const idMatch = url.match(/\/d\/([a-zA-Z0-9_-]+)/);
      if (idMatch) downloadUrl = `https://drive.google.com/uc?export=download&id=${idMatch[1]}&confirm=t`;
    }
    if (url.includes('dropbox.com')) {
      const u = new URL(url); u.searchParams.set('dl','1'); downloadUrl = u.toString();
    }

    const resp = await fetch(downloadUrl, { headers: { 'User-Agent': 'Mozilla/5.0' }, redirect: 'follow' });
    if (!resp.ok) {
      // Give specific guidance for auth errors
      if (resp.status === 401 || resp.status === 403) {
        const provider = isMicrosoft ? 'microsoft' : isGoogle ? 'google' : null;
        if (provider) return res.status(401).json({ error: 'needs_auth', provider,
          message: `Connect your ${provider === 'microsoft' ? 'Microsoft' : 'Google'} account to access this file.` });
      }
      return res.status(400).json({ error: `Download failed: HTTP ${resp.status}` });
    }
    const ct = resp.headers.get('content-type') || '';
    const buf = await resp.arrayBuffer();
    if (ct.includes('text/html')) {
      const preview = Buffer.from(buf).toString('utf-8', 0, 500);
      if (preview.includes('<html') || preview.includes('<!DOCTYPE')) {
        const provider = isMicrosoft ? 'microsoft' : isGoogle ? 'google' : null;
        if (provider) return res.status(401).json({ error: 'needs_auth', provider,
          message: `File requires sign-in. Connect your ${provider === 'microsoft' ? 'Microsoft' : 'Google'} account in the Upload tab.` });
        return res.status(400).json({ error: 'Got a login page instead of the file. Share the file publicly or connect an account.' });
      }
    }
    const result = parseXlsxBuffer(buf, sheetName);
    return res.json({ ok: true, ...result, rowCount: result.rows.length });
  } catch(e) {
    console.error('fetch-url error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


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
app.get('/api/users', auth(['admin','subadmin']), async (req, res) => {
  const { rows } = await db.query("SELECT id, username, role FROM rh_users ORDER BY username");
  res.json(rows);
});

app.post('/api/users', auth(['admin','subadmin']), async (req, res) => {
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

app.patch('/api/users/:id/role', auth(['admin']), async (req, res) => {
  try {
    const { role } = req.body;
    if (!['admin','subadmin','user'].includes(role))
      return res.status(400).json({ error: 'Invalid role' });
    // Never demote the last admin
    if (role !== 'admin') {
      const { rows: admins } = await db.query("SELECT id FROM rh_users WHERE role='admin'");
      if (admins.length === 1 && admins[0].id === req.params.id)
        return res.status(400).json({ error: 'Cannot demote the last super admin' });
    }
    const { rows } = await db.query(
      'UPDATE rh_users SET role=$1 WHERE id=$2 RETURNING id,username,role',
      [role, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
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
// ── Public: published reports list (no auth — for mobile/shared link access) ────
app.get('/api/public/reports', async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT id, name, config, card_fields,
         (SELECT COUNT(*) FROM rh_rows WHERE report_id=r.id) AS row_count
       FROM rh_reports r WHERE is_published=true ORDER BY updated_at DESC`
    );
    res.json(rows.map(r => ({
      id: r.id, name: r.name, isPublished: true,
      rows: parseInt(r.row_count) || 0,
      config: typeof r.config === 'string' ? JSON.parse(r.config) : (r.config || {}),
      cardFields: r.card_fields ? (typeof r.card_fields === 'string' ? JSON.parse(r.card_fields) : r.card_fields) : [],
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Public: rows for a published report (no auth) ───────────────────────────────
app.get('/api/public/reports/:id/data', async (req, res) => {
  try {
    const { rows: rpts } = await db.query(
      'SELECT is_published FROM rh_reports WHERE id=$1', [req.params.id]);
    if (!rpts[0] || !rpts[0].is_published)
      return res.status(403).json({ error: 'Report not found or not published' });
    const { rows } = await db.query(
      'SELECT data FROM rh_rows WHERE report_id=$1 ORDER BY id', [req.params.id]);
    const allRows = rows.map(r => typeof r.data === 'string' ? JSON.parse(r.data) : r.data);
    const fields = allRows.length ? Object.keys(allRows[0]) : [];
    const numFields = fields.filter(f => typeof allRows[0]?.[f] === 'number');
    res.json({ rows: allRows, fields, numFields });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reports', auth([]), async (req, res) => {
  try {
    const role = req.user.role;
    const userId = req.user.id;
    let q, params = [];

    if (role === 'admin') {
      // Super admin: see ALL reports
      q = `SELECT r.id, r.name, r.config, r.card_fields, r.is_published,
             r.row_count, r.field_count, r.created_at, r.created_by
           FROM rh_reports r ORDER BY r.created_at DESC`;
    } else if (role === 'subadmin') {
      // Sub-admin: see only their own reports
      q = `SELECT r.id, r.name, r.config, r.card_fields, r.is_published,
             r.row_count, r.field_count, r.created_at, r.created_by
           FROM rh_reports r WHERE r.created_by=$1 ORDER BY r.created_at DESC`;
      params = [userId];
    } else {
      // User: see only published reports explicitly assigned to them
      // (if a report has NO access rows, it is NOT visible to regular users unless assigned)
      q = `SELECT r.id, r.name, r.config, r.card_fields, r.is_published,
             r.row_count, r.field_count, r.created_at
           FROM rh_reports r
           INNER JOIN rh_report_access ra ON ra.report_id = r.id
           WHERE r.is_published = true AND ra.user_id = $1
           ORDER BY r.created_at DESC`;
      params = [userId];
    }

    const { rows } = await db.query(q, params);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Report access management ───────────────────────────────────────────────────
// Get users who have access to a specific report
app.get('/api/reports/:id/access', auth(['admin','subadmin']), async (req, res) => {
  try {
    // Subadmin can only manage their own reports
    if (req.user.role === 'subadmin') {
      const { rows: rpt } = await db.query(
        'SELECT created_by FROM rh_reports WHERE id=$1', [req.params.id]);
      if (!rpt[0] || rpt[0].created_by !== req.user.id)
        return res.status(403).json({ error: 'Access denied' });
    }
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.role,
         CASE WHEN ra.user_id IS NOT NULL THEN true ELSE false END as has_access
       FROM rh_users u
       LEFT JOIN rh_report_access ra ON ra.report_id=$1 AND ra.user_id=u.id
       WHERE u.role='user'
       ORDER BY u.username`, [req.params.id]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Set report access (replace all users for this report)
app.put('/api/reports/:id/access', auth(['admin','subadmin']), async (req, res) => {
  const client = await db.connect();
  try {
    if (req.user.role === 'subadmin') {
      const { rows: rpt } = await db.query(
        'SELECT created_by FROM rh_reports WHERE id=$1', [req.params.id]);
      if (!rpt[0] || rpt[0].created_by !== req.user.id)
        return res.status(403).json({ error: 'Access denied' });
    }
    const { userIds } = req.body; // array of user UUIDs
    await client.query('BEGIN');
    await client.query('DELETE FROM rh_report_access WHERE report_id=$1', [req.params.id]);
    for (const uid of (userIds || [])) {
      await client.query(
        'INSERT INTO rh_report_access(report_id, user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',
        [req.params.id, uid]);
    }
    await client.query('COMMIT');
    res.json({ ok: true, count: userIds?.length || 0 });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally { client.release(); }
});

app.post('/api/reports', auth(['admin','subadmin']), async (req, res) => {
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

// Helper: ensure requester owns this report or is super admin
async function assertReportOwner(req, res) {
  if (req.user.role === 'admin') return true;
  const { rows } = await db.query('SELECT created_by FROM rh_reports WHERE id=$1', [req.params.id]);
  if (!rows[0]) { res.status(404).json({ error: 'Report not found' }); return false; }
  if (rows[0].created_by !== req.user.id) { res.status(403).json({ error: 'Not your report' }); return false; }
  return true;
}

// Update report in-place (preserves is_published and rh_report_access)
app.put('/api/reports/:id', auth(['admin','subadmin']), async (req, res) => {
  if (!await assertReportOwner(req, res)) return;
  const client = await db.connect();
  try {
    const { name, config, cardFields, rows, fields, numFields } = req.body;
    await client.query('BEGIN');
    // Update metadata
    await client.query(
      `UPDATE rh_reports SET name=$1, config=$2, card_fields=$3, num_fields=$4,
       row_count=$5, field_count=$6 WHERE id=$7`,
      [name, JSON.stringify(config), JSON.stringify(cardFields||[]),
       JSON.stringify(numFields||[]), rows.length, fields.length, req.params.id]
    );
    // Replace dataset fields
    await client.query('DELETE FROM rh_datasets WHERE report_id=$1', [req.params.id]);
    await client.query('INSERT INTO rh_datasets(report_id, fields) VALUES($1,$2)',
      [req.params.id, JSON.stringify(fields)]);
    // Replace rows
    await client.query('DELETE FROM rh_rows WHERE report_id=$1', [req.params.id]);
    for (let i = 0; i < rows.length; i += 500) {
      const batch = rows.slice(i, i + 500);
      const values = batch.map((_, j) => `($1, $${j + 2})`).join(',');
      await client.query(
        `INSERT INTO rh_rows(report_id, row_data) VALUES ${values}`,
        [req.params.id, ...batch.map(r => JSON.stringify(r))]
      );
    }
    await client.query('COMMIT');
    res.json({ id: req.params.id });
  } catch(e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally { client.release(); }
});

app.delete('/api/reports/:id', auth(['admin','subadmin']), async (req, res) => {
  if (!await assertReportOwner(req, res)) return;
  try {
    await db.query('DELETE FROM rh_reports WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Report access management ─────────────────────────────────────────────────────
app.get('/api/reports/:id/access', auth(['admin','subadmin']), async (req, res) => {
  if (!await assertReportOwner(req, res)) return;
  try {
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.role,
         EXISTS(SELECT 1 FROM rh_report_access ra WHERE ra.report_id=$1 AND ra.user_id=u.id) AS has_access
       FROM rh_users u WHERE u.role='user' ORDER BY u.username`,
      [req.params.id]
    );
    const { rows: acRows } = await db.query(
      'SELECT COUNT(*) FROM rh_report_access WHERE report_id=$1', [req.params.id]);
    res.json({ users: rows, isRestricted: parseInt(acRows[0].count) > 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/reports/:id/access', auth(['admin','subadmin']), async (req, res) => {
  if (!await assertReportOwner(req, res)) return;
  try {
    const { userIds } = req.body;
    await db.query('DELETE FROM rh_report_access WHERE report_id=$1', [req.params.id]);
    if (userIds && userIds.length > 0) {
      const vals = userIds.map((uid, i) => `($1,$${i+2})`).join(',');
      await db.query(`INSERT INTO rh_report_access(report_id,user_id) VALUES ${vals}`,
        [req.params.id, ...userIds]);
    }
    res.json({ ok: true, restricted: !!(userIds && userIds.length > 0) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Publish — always sets published=true, never touches other reports
app.patch('/api/reports/:id/publish', auth(['admin','subadmin']), async (req, res) => {
  if (!await assertReportOwner(req, res)) return;
  try {
    await db.query('UPDATE rh_reports SET is_published=true WHERE id=$1', [req.params.id]);
    res.json({ ok: true, is_published: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Unpublish — always sets published=false
app.patch('/api/reports/:id/unpublish', auth(['admin','subadmin']), async (req, res) => {
  if (!await assertReportOwner(req, res)) return;
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
app.post('/api/fetch-url', auth(['admin','user']), async (req, res) => {
  try {
    const { url, sheetName } = req.body;
    if (!url) return res.status(400).json({ error: 'url is required' });

    let downloadUrl = url.trim();

    // ── OneDrive / SharePoint — use the Sharing API for reliable download ───────
    // Works for personal OneDrive (1drv.ms), OneDrive for Business, SharePoint
    // Even "anyone can edit/view" links work without sign-in via this method
    if (downloadUrl.includes('1drv.ms') || downloadUrl.includes('onedrive.live.com') ||
        downloadUrl.includes('sharepoint.com') || downloadUrl.includes('my.sharepoint.com')) {
      try {
        // Encode share URL as base64url (OneDrive Sharing API spec)
        const encoded = Buffer.from(downloadUrl).toString('base64')
          .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const apiUrl = `https://api.onedrive.com/v1.0/shares/u!${encoded}/root/content`;
        console.log('Using OneDrive API:', apiUrl);
        const r0 = await fetch(apiUrl, {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ReportHub/2.0)' },
          redirect: 'follow',
        });
        if (r0.ok) {
          // Success — use this response directly
          const ct = r0.headers.get('content-type') || '';
          const buf0 = await r0.arrayBuffer();
          let wb;
          try { wb = XLSX.read(buf0, { type: 'buffer', cellDates: true }); }
          catch(e) { return res.status(400).json({ error: 'Could not parse file: '+e.message }); }
          const sheetNames0 = wb.SheetNames;
          const wsName0 = sheetName && wb.SheetNames.includes(sheetName) ? sheetName : wb.SheetNames[0];
          const ws0 = wb.Sheets[wsName0];
          if (!ws0) return res.status(400).json({ error: `Sheet not found. Available: ${sheetNames0.join(', ')}` });
          if (ws0['!ref']) {
            const rr = XLSX.utils.decode_range(ws0['!ref']);
            if (rr.e.r > 100000) { rr.e.r = 100000; ws0['!ref'] = XLSX.utils.encode_range(rr); }
          }
          const rows0 = XLSX.utils.sheet_to_json(ws0, { defval: null, cellDates: true });
          return res.json({ ok: true, rows: rows0, sheetNames: sheetNames0, rowCount: rows0.length });
        }
        // If API fails, fall through to direct download attempt
        console.log('OneDrive API returned', r0.status, '— trying direct download');
      } catch(e) {
        console.log('OneDrive API error:', e.message, '— trying direct download');
      }
      // Fallback: try appending download=1
      try {
        const u = new URL(downloadUrl);
        u.searchParams.set('download', '1');
        downloadUrl = u.toString();
      } catch(e) { /* url parse failed, use as-is */ }
    }

    // ── Dropbox ───────────────────────────────────────────────────────────────
    if (downloadUrl.includes('dropbox.com')) {
      const u = new URL(downloadUrl);
      u.searchParams.set('dl', '1');
      downloadUrl = u.toString();
    }

    // ── Google Drive share link ───────────────────────────────────────────────
    if (downloadUrl.includes('drive.google.com')) {
      const idMatch = downloadUrl.match(/\/d\/([a-zA-Z0-9_-]+)/);
      if (idMatch) {
        downloadUrl = `https://drive.google.com/uc?export=download&id=${idMatch[1]}&confirm=t`;
      }
    }

    console.log('Fetching:', downloadUrl);

    const resp = await fetch(downloadUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; ReportHub/2.0)',
        'Accept': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/octet-stream,*/*',
      },
      redirect: 'follow',
    });

    if (!resp.ok) {
      return res.status(400).json({
        error: `Download failed: HTTP ${resp.status}. Make sure the file is shared as "Anyone with the link can view".`,
        tip: resp.status === 401 || resp.status === 403
          ? 'The file requires authentication. Share it publicly (Anyone with the link → View).'
          : `HTTP ${resp.status} — check that the link is correct and the file is publicly shared.`
      });
    }

    const contentType = resp.headers.get('content-type') || '';
    const buf = await resp.arrayBuffer();

    // Detect if we got an HTML page instead of a file (common with auth redirects)
    if (contentType.includes('text/html')) {
      const preview = Buffer.from(buf).toString('utf-8', 0, 500);
      if (preview.includes('<html') || preview.includes('<!DOCTYPE')) {
        return res.status(400).json({
          error: 'Got a login/preview page instead of the file. The file needs to be shared as "Anyone with the link can view" without requiring sign-in.',
          tip: 'OneDrive: open file → Share → Change to "Anyone with the link can view" → Copy link. Make sure it says "No sign-in required".'
        });
      }
    }

    let rows, sheetNames;

    if (contentType.includes('csv') || url.endsWith('.csv') || url.endsWith('.txt')) {
      const text = Buffer.from(buf).toString('utf-8');
      const csvLines = text.split(/\r?\n/).filter(l => l.trim());
      if (!csvLines.length) return res.status(400).json({ error: 'File appears to be empty.' });
      // Simple CSV parse
      const parseCSVLine = l => l.split(',').map(v => v.replace(/^"|"$/g, '').trim());
      const headers = parseCSVLine(csvLines[0]);
      rows = csvLines.slice(1).map(line => {
        const vals = parseCSVLine(line);
        const obj = {};
        headers.forEach((h, i) => { if (h) obj[h] = vals[i] || ''; });
        return obj;
      });
      sheetNames = ['CSV'];
    } else {
      let wb;
      try {
        wb = XLSX.read(buf, { type: 'buffer', cellDates: true });
      } catch (xlsxErr) {
        return res.status(400).json({
          error: 'Could not parse the downloaded file as Excel. ' + xlsxErr.message,
          tip: 'Make sure the link points to an .xlsx, .xls, or .csv file, not a preview page.'
        });
      }
      sheetNames = wb.SheetNames;
      const wsName = sheetName && wb.SheetNames.includes(sheetName) ? sheetName : wb.SheetNames[0];
      const ws = wb.Sheets[wsName];
      if (!ws) return res.status(400).json({ error: `Sheet "${wsName}" not found. Available: ${sheetNames.join(', ')}` });
      if (ws['!ref']) {
        const r = XLSX.utils.decode_range(ws['!ref']);
        if (r.e.r > 100000) { r.e.r = 100000; ws['!ref'] = XLSX.utils.encode_range(r); }
      }
      rows = XLSX.utils.sheet_to_json(ws, { defval: null, cellDates: true });
    }

    res.json({ ok: true, rows, sheetNames, rowCount: rows.length });
  } catch (e) {
    console.error('fetch-url error:', e);
    res.status(500).json({ error: e.message });
  }
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`ReportHub API running on port ${PORT}`));
