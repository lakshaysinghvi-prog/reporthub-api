require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const Cursor = require('pg-cursor');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const XLSX = require('xlsx');
const cors = require('cors');

const app = express();
app.use(cors({ origin: true, credentials: true, methods: ['GET','POST','PATCH','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.options('*', cors());
app.use(express.json({ limit: '100mb' }));

const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ── Startup migrations (idempotent) ────────────────────────────────────────────
(async()=>{
  try{
    await db.query(`ALTER TABLE rh_reports ADD COLUMN IF NOT EXISTS collab_enabled BOOLEAN DEFAULT FALSE`);
    await db.query(`CREATE TABLE IF NOT EXISTS rh_collab_columns (
      id SERIAL PRIMARY KEY, report_id TEXT NOT NULL, label TEXT NOT NULL,
      col_type TEXT NOT NULL DEFAULT 'input', inputter_ids JSONB DEFAULT '[]',
      reviewer_ids JSONB DEFAULT '[]', ref_column TEXT, col_order INT DEFAULT 0,
      validation_config JSONB DEFAULT NULL, created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now())`);
    await db.query(`CREATE TABLE IF NOT EXISTS rh_collab_cycles (
      id SERIAL PRIMARY KEY, report_id TEXT NOT NULL, period_label TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open', opened_by INT,
      history_viewer_ids JSONB DEFAULT '[]', closed_at TIMESTAMPTZ, closed_by INT,
      created_at TIMESTAMPTZ DEFAULT now())`);
    await db.query(`CREATE TABLE IF NOT EXISTS rh_collab_values (
      id SERIAL PRIMARY KEY, cycle_id INT NOT NULL, report_id TEXT NOT NULL,
      row_key TEXT NOT NULL, col_id INT NOT NULL, value NUMERIC, remarks TEXT,
      status TEXT NOT NULL DEFAULT 'pending', inputter_id INT, reviewer_id INT,
      reviewer_remarks TEXT, reviewer_value NUMERIC DEFAULT NULL,
      reviewed_at TIMESTAMPTZ, updated_at TIMESTAMPTZ DEFAULT now(),
      UNIQUE(cycle_id, row_key, col_id))`);
    await db.query(`CREATE TABLE IF NOT EXISTS rh_collab_audit (
      id SERIAL PRIMARY KEY, cycle_id INT NOT NULL, report_id TEXT NOT NULL,
      row_key TEXT NOT NULL, col_id INT NOT NULL, actor_id INT, action TEXT NOT NULL,
      value NUMERIC, remarks TEXT, created_at TIMESTAMPTZ DEFAULT now())`);
    await db.query(`ALTER TABLE rh_collab_values DROP CONSTRAINT IF EXISTS rh_collab_values_status_check`);
    await db.query(`ALTER TABLE rh_collab_values ADD CONSTRAINT rh_collab_values_status_check
      CHECK (status IN ('pending','submitted','approved','rejected','hold','modified'))`);
    await db.query(`ALTER TABLE rh_collab_columns ADD COLUMN IF NOT EXISTS validation_config JSONB DEFAULT NULL`);
    await db.query(`ALTER TABLE rh_collab_values ADD COLUMN IF NOT EXISTS reviewer_value NUMERIC DEFAULT NULL`);
    console.log('Migrations OK');
  }catch(e){console.error('Migration error:',e.message);}
})();

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

// ── Custom credentials helpers ────────────────────────────────────────────────
async function getEffectiveCreds(provider) {
  try {
    const { rows } = await db.query(
      'SELECT client_id, client_secret, tenant_id FROM rh_custom_credentials WHERE provider=$1',
      [provider]
    );
    if (rows[0] && rows[0].client_id) {
      return { clientId:rows[0].client_id, clientSecret:rows[0].client_secret,
               tenantId:rows[0].tenant_id||'common', isCustom:true };
    }
  } catch(e) {}
  if (provider==='microsoft') return {
    clientId:process.env.MS_CLIENT_ID, clientSecret:process.env.MS_CLIENT_SECRET,
    tenantId:process.env.MS_TENANT_ID||'common', isCustom:false };
  if (provider==='google') return {
    clientId:process.env.GOOGLE_CLIENT_ID, clientSecret:process.env.GOOGLE_CLIENT_SECRET, isCustom:false };
  return {};
}

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
  const creds = await getEffectiveCreds('microsoft');
  const body = new URLSearchParams({
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    grant_type: 'refresh_token',
    refresh_token: stored.refresh_token,
    scope: 'Files.Read Files.Read.All offline_access',
  });
  const r = await fetch(`https://login.microsoftonline.com/${creds.tenantId}/oauth2/v2.0/token`, {
    method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body
  });
  if (!r.ok) throw new Error('Token refresh failed: ' + await r.text());
  const data = await r.json();
  await saveToken(stored.user_id, 'microsoft', data);
  return data.access_token;
}

async function refreshGoogleToken(stored) {
  const creds = await getEffectiveCreds('google');
  const body = new URLSearchParams({
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
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
app.get('/auth/microsoft/start', auth(['admin']), async (req, res) => {
  const creds = await getEffectiveCreds('microsoft');
  if (!creds.clientId) return res.status(400).json({ error: 'Microsoft credentials not configured. Add them in Settings.' });
  const state = Math.random().toString(36).slice(2) + Date.now();
  oauthStates.set(state, { provider: 'microsoft', userId: req.user.id, ts: Date.now() });
  const params = new URLSearchParams({
    client_id: creds.clientId,
    response_type: 'code',
    redirect_uri: BACKEND_URL + '/auth/microsoft/callback',
    scope: 'Files.Read Files.Read.All offline_access User.Read',
    state,
    prompt: 'select_account',
  });
  res.json({ url: `https://login.microsoftonline.com/${creds.tenantId}/oauth2/v2.0/authorize?` + params });
});

app.get('/auth/microsoft/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.send(`<script>window.opener&&window.opener.postMessage({type:'oauth-error',error:'${error}'},'*');window.close();</script>`);
  const saved = oauthStates.get(state);
  if (!saved) return res.send('<script>window.close();</script>');
  oauthStates.delete(state);
  try {
    const creds = await getEffectiveCreds('microsoft');
    const body = new URLSearchParams({
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      code,
      grant_type: 'authorization_code',
      redirect_uri: BACKEND_URL + '/auth/microsoft/callback',
    });
    const r = await fetch(`https://login.microsoftonline.com/${creds.tenantId}/oauth2/v2.0/token`, {
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
app.get('/auth/google/start', auth(['admin']), async (req, res) => {
  const creds = await getEffectiveCreds('google');
  if (!creds.clientId) return res.status(400).json({ error: 'Google credentials not configured. Add them in Settings.' });
  const state = Math.random().toString(36).slice(2) + Date.now();
  oauthStates.set(state, { provider: 'google', userId: req.user.id, ts: Date.now() });
  const params = new URLSearchParams({
    client_id: creds.clientId,
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
    const creds = await getEffectiveCreds('google');
    const body = new URLSearchParams({
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
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


// ── Custom credentials management ─────────────────────────────────────────────
app.get('/api/custom-credentials', auth(['admin','subadmin']), async (req, res) => {
  try {
    const { rows } = await db.query('SELECT provider, client_id, tenant_id, updated_at FROM rh_custom_credentials');
    const result = {};
    rows.forEach(r => {
      result[r.provider] = {
        clientIdMasked: r.client_id ? r.client_id.slice(0,8)+'...'+r.client_id.slice(-4) : null,
        tenantId: r.tenant_id, updatedAt: r.updated_at,
      };
    });
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/custom-credentials/:provider', auth(['admin']), async (req, res) => {
  const { provider } = req.params;
  if (!['microsoft','google'].includes(provider)) return res.status(400).json({ error: 'Invalid provider' });
  const { clientId, clientSecret, tenantId } = req.body;
  if (!clientId || !clientSecret) return res.status(400).json({ error: 'clientId and clientSecret required' });
  try {
    await db.query(`
      INSERT INTO rh_custom_credentials (provider, client_id, client_secret, tenant_id, updated_by)
      VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (provider) DO UPDATE SET
        client_id=$2, client_secret=$3, tenant_id=$4, updated_by=$5, updated_at=now()
    `, [provider, clientId.trim(), clientSecret.trim(), (tenantId||'').trim()||null, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/custom-credentials/:provider/test', auth(['admin']), async (req, res) => {
  const { provider } = req.params;
  const { clientId, clientSecret, tenantId } = req.body;
  try {
    if (provider === 'microsoft') {
      const tid = (tenantId||'').trim() || 'common';
      const body = new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'client_credentials', scope: 'https://graph.microsoft.com/.default',
      });
      const r = await fetch('https://login.microsoftonline.com/'+tid+'/oauth2/v2.0/token', {
        method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body
      });
      const data = await r.json();
      if (data.error) return res.json({ ok: false, error: data.error_description || data.error });
      // Quick check: call Graph /me to verify token works
      const testR = await fetch('https://graph.microsoft.com/v1.0/sites?search=*&$top=1', {
        headers: { Authorization: 'Bearer ' + data.access_token }
      });
      if (!testR.ok) {
        const err = await testR.json().catch(()=>({}));
        return res.json({ ok: false, error: 'Token obtained but Graph API failed: ' + (err.error?.message||testR.status) + '. Check Sites.Read.All permission is granted.' });
      }
      return res.json({ ok: true, message: 'Microsoft credentials verified — Graph API access confirmed ✓' });
    }
    if (provider === 'google') {
      if (!clientId.includes('.apps.googleusercontent.com'))
        return res.json({ ok: false, error: 'Client ID should end with .apps.googleusercontent.com' });
      return res.json({ ok: true, message: 'Google credentials format valid. Connect account to fully verify.' });
    }
    res.status(400).json({ error: 'Unknown provider' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/custom-credentials/:provider', auth(['admin']), async (req, res) => {
  await db.query('DELETE FROM rh_custom_credentials WHERE provider=$1', [req.params.provider]);
  res.json({ ok: true });
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

// Get an app-level access token using client_credentials (no user login needed)
// Works when custom credentials with Sites.Read.All application permission are configured
async function getMsAppToken(creds) {
  const body = new URLSearchParams({
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    grant_type: 'client_credentials',
    scope: 'https://graph.microsoft.com/.default',
  });
  const r = await fetch(`https://login.microsoftonline.com/${creds.tenantId}/oauth2/v2.0/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
  });
  const data = await r.json();
  if (data.error) throw new Error(`App token failed: ${data.error_description || data.error}`);
  return data.access_token;
}

async function downloadWithMicrosoftGraph(userId, shareUrl) {
  // Strategy 1: try custom app credentials (client_credentials, no user login needed)
  // This works for SharePoint when Sites.Read.All application permission is granted
  const creds = await getEffectiveCreds('microsoft');
  if (creds.isCustom && creds.tenantId && creds.tenantId !== 'common') {
    try {
      const appToken = await getMsAppToken(creds);
      const encoded = Buffer.from(shareUrl).toString('base64')
        .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
      const apiUrl = `https://graph.microsoft.com/v1.0/shares/u!${encoded}/driveItem/content`;
      const resp = await fetch(apiUrl, {
        headers: { Authorization: `Bearer ${appToken}` },
        redirect: 'follow',
      });
      if (resp.ok) return await resp.arrayBuffer();
      console.log('App token fetch returned', resp.status, '— trying user token');
    } catch(e) {
      console.log('App token strategy failed:', e.message, '— falling back to user token');
    }
  }

  // Strategy 2: user OAuth token (from Connect flow)
  const token = await getValidAccessToken(userId, 'microsoft');
  if (!token) throw new Error('NEEDS_AUTH:microsoft');

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

function parseXlsxBuffer(buf, sheetName, rangeOverride) {
  let wb;
  try { wb = XLSX.read(buf, { type: 'buffer', cellDates: true }); }
  catch(e) { throw new Error('Could not parse file as Excel: ' + e.message); }
  const sheetNames = wb.SheetNames;
  const wsName = sheetName && wb.SheetNames.includes(sheetName) ? sheetName : wb.SheetNames[0];
  const ws = wb.Sheets[wsName];
  if (!ws) throw new Error(`Sheet "${wsName}" not found. Available: ${sheetNames.join(', ')}`);
  if (rangeOverride && rangeOverride.trim()) {
    try { XLSX.utils.decode_range(rangeOverride.trim()); ws['!ref'] = rangeOverride.trim().toUpperCase(); }
    catch(e) { /* invalid range — use sheet default */ }
  } else if (ws['!ref']) {
    const r = XLSX.utils.decode_range(ws['!ref']);
    if (r.e.r > 100000) { r.e.r = 100000; ws['!ref'] = XLSX.utils.encode_range(r); }
  }
  const rawRows = XLSX.utils.sheet_to_json(ws, { defval: null, cellDates: true, raw: true });

  // Normalize column header names — trim whitespace to match how frontend upload parses
  // This ensures SharePoint-fetched data has the same field names as the original upload
  const fields = rawRows.length > 0
    ? Object.keys(rawRows[0]).map(k => String(k).trim())
    : [];
  const fieldMap = rawRows.length > 0
    ? Object.fromEntries(Object.keys(rawRows[0]).map(k => [k, String(k).trim()]))
    : {};
  const needsRemap = Object.entries(fieldMap).some(([k,v]) => k !== v);
  const rows = needsRemap
    ? rawRows.map(r => {
        const n = {};
        for (const k of Object.keys(r)) n[fieldMap[k] || k] = r[k];
        return n;
      })
    : rawRows;

  // Detect numeric fields (>50% numeric values in sample)
  // Strip currency symbols and thousand-separators before testing so that
  // Indian-formatted values like "₹84,00,00,000" or "1,40,00,000" are detected.
  const sample = rows.slice(0, 50);
  const numFields = fields.filter(f => {
    const vals = sample.map(r => r[f]).filter(v => v !== null && v !== undefined && v !== '');
    if (!vals.length) return false;
    const numCount = vals.filter(v => {
      if (typeof v === 'number') return true;
      if (typeof v !== 'string') return false;
      const stripped = v.trim().replace(/[$,₹₹\s]/g, '');
      return stripped !== '' && !isNaN(parseFloat(stripped)) && isFinite(stripped);
    }).length;
    return numCount / vals.length > 0.5;
  });

  return { rows, fields, numFields, sheetNames };
}

// ── Main fetch-url endpoint ─────────────────────────────────────────────────────
app.post('/api/fetch-url', auth(['admin','user']), async (req, res) => {
  const { url, sheetName, rangeOverride } = req.body;
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
        const result = parseXlsxBuffer(buf, sheetName, rangeOverride);
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
        const result = parseXlsxBuffer(buf, sheetName, rangeOverride);
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
          const result = parseXlsxBuffer(buf, sheetName, rangeOverride);
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
    const result = parseXlsxBuffer(buf, sheetName, rangeOverride);
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
  const client = await db.connect();
  try {
    const { rows: rpts } = await client.query(
      'SELECT is_published FROM rh_reports WHERE id=$1', [req.params.id]);
    if (!rpts[0] || !rpts[0].is_published) {
      client.release();
      return res.status(403).json({ error: 'Report not found or not published' });
    }
    res.setHeader('Content-Type', 'application/json');
    res.write('{"rows":[');
    const cursor = client.query(new Cursor(
      'SELECT row_data FROM rh_rows WHERE report_id=$1 ORDER BY id', [req.params.id]
    ));
    let first = true;
    let firstRow = null;
    try {
      while (true) {
        const batch = await new Promise((resolve, reject) =>
          cursor.read(500, (err, rows) => err ? reject(err) : resolve(rows))
        );
        if (batch.length === 0) break;
        for (const row of batch) {
          const rd = typeof row.row_data === 'string' ? JSON.parse(row.row_data) : row.row_data;
          if (!first) res.write(',');
          if (first) { firstRow = rd; first = false; }
          res.write(JSON.stringify(rd));
        }
      }
    } finally {
      await new Promise(r => cursor.close(r));
      client.release();
    }
    const fields = firstRow ? Object.keys(firstRow) : [];
    const numFields = fields.filter(f => typeof firstRow?.[f] === 'number');
    res.write('],"fields":' + JSON.stringify(fields) + ',"numFields":' + JSON.stringify(numFields) + '}');
    res.end();
  } catch(e) {
    try { client.release(); } catch {}
    if (!res.headersSent) res.status(500).json({ error: e.message });
    else res.end();
  }
});

app.get('/api/reports', auth([]), async (req, res) => {
  try {
    const role = req.user.role;
    const userId = req.user.id;
    let q, params = [];

    if (role === 'admin') {
      // Super admin: see ALL reports
      q = `SELECT r.id, r.name, r.config, r.card_fields, r.is_published, r.collab_enabled,
             r.row_count, r.field_count, r.created_at, r.created_by,
             u.username AS created_by_username
           FROM rh_reports r LEFT JOIN rh_users u ON u.id=r.created_by
           ORDER BY r.created_at DESC`;
    } else if (role === 'subadmin') {
      // Sub-admin: see only their own reports
      q = `SELECT r.id, r.name, r.config, r.card_fields, r.is_published, r.collab_enabled,
             r.row_count, r.field_count, r.created_at, r.created_by,
             u.username AS created_by_username
           FROM rh_reports r LEFT JOIN rh_users u ON u.id=r.created_by
           WHERE r.created_by=$1 ORDER BY r.created_at DESC`;
      params = [userId];
    } else {
      // User: see only published reports explicitly assigned to them
      q = `SELECT r.id, r.name, r.config, r.card_fields, r.is_published, r.collab_enabled,
             r.row_count, r.field_count, r.created_at
           FROM rh_reports r
           INNER JOIN rh_report_access ra ON ra.report_id = r.id
           WHERE r.is_published = true AND ra.user_id = $1
           ORDER BY r.created_at DESC`;
      params = [userId];
    }

    const { rows } = await db.query(q, params);
    // Guard against null config — ensures frontend never receives config=null
    res.json(rows.map(r => ({...r, config: r.config || {}})));
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

// Update report config only (no row replacement) — used for filter/layout saves
app.patch('/api/reports/:id/config', auth(['admin','subadmin']), async (req, res) => {
  if (!await assertReportOwner(req, res)) return;
  try {
    const { config, name, numFields } = req.body;
    // Extract numeric fields from config.values if not explicitly provided
    let nfArr = Array.isArray(numFields) ? numFields : null;
    if (!nfArr && config) {
      const allValues = [];
      if (Array.isArray(config.values)) allValues.push(...config.values.map(v=>v.field).filter(Boolean));
      if (Array.isArray(config.tabs)) {
        config.tabs.forEach(t=>(t.config?.values||[]).forEach(v=>v.field&&allValues.push(v.field)));
      }
      if (allValues.length) nfArr = [...new Set(allValues)];
    }
    const cols = ['config=$1'];
    const vals = [JSON.stringify(config)];
    if (nfArr) { cols.push(`num_fields=$${vals.length+1}`); vals.push(JSON.stringify(nfArr)); }
    if (name) { cols.push(`name=$${vals.length+1}`); vals.push(name); }
    // WHERE clause must NOT be in the SET cols array — add it separately
    vals.push(req.params.id);
    await db.query(`UPDATE rh_reports SET ${cols.join(', ')} WHERE id=$${vals.length}`, vals);
    res.json({ id: req.params.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

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

// ── Update report rows only (preserves config/name/etc) ─────────────────────────
app.patch('/api/reports/:id/rows', auth(['admin','subadmin']), async (req, res) => {
  if (!await assertReportOwner(req, res)) return;
  const client = await db.connect();
  try {
    const { rows, fields, numFields } = req.body;
    if (!rows || !Array.isArray(rows)) return res.status(400).json({ error: 'rows required' });
    await client.query('BEGIN');
    // Update metadata
    const nfArr = Array.isArray(numFields) ? numFields : [...(numFields||[])];
    await client.query(
      'UPDATE rh_reports SET num_fields=$1, row_count=$2, field_count=$3 WHERE id=$4',
      [JSON.stringify(nfArr), rows.length, (fields||[]).length, req.params.id]
    );
    // Update dataset fields
    await client.query(
      'INSERT INTO rh_datasets (report_id, fields) VALUES ($1,$2) ON CONFLICT (report_id) DO UPDATE SET fields=$2',
      [req.params.id, JSON.stringify(fields||[])]
    );
    // Replace rows
    await client.query('DELETE FROM rh_rows WHERE report_id=$1', [req.params.id]);
    if (rows.length > 0) {
      const BATCH = 200;
      for (let i = 0; i < rows.length; i += BATCH) {
        const batch = rows.slice(i, i + BATCH);
        const vals = batch.map((r,j) => `($1, $${j+2})`).join(',');
        await client.query(
          `INSERT INTO rh_rows (report_id, row_data) VALUES ${vals}`,
          [req.params.id, ...batch.map(r => JSON.stringify(r))]
        );
      }
    }
    await client.query('COMMIT');
    res.json({ ok: true, rowCount: rows.length });
  } catch(e) {
    await client.query('ROLLBACK').catch(()=>{});
    res.status(500).json({ error: e.message });
  } finally { client.release(); }
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
  const client = await db.connect();
  try {
    const { rows: rpt } = await client.query(
      'SELECT is_published, num_fields FROM rh_reports WHERE id=$1', [req.params.id]
    );
    if (!rpt[0]) { client.release(); return res.status(404).json({ error: 'Not found' }); }
    if (!rpt[0].is_published && req.user.role !== 'admin' && req.user.role !== 'subadmin') {
      client.release();
      return res.status(403).json({ error: 'Not published' });
    }
    const { rows: ds } = await client.query('SELECT fields FROM rh_datasets WHERE report_id=$1', [req.params.id]);
    const fields = ds[0]?.fields || [];
    const numFields = rpt[0].num_fields || [];
    res.setHeader('Content-Type', 'application/json');
    res.write('{"fields":' + JSON.stringify(fields) + ',"config":{},"numFields":' + JSON.stringify(numFields) + ',"rows":[');
    const cursor = client.query(new Cursor(
      'SELECT row_data FROM rh_rows WHERE report_id=$1 ORDER BY id', [req.params.id]
    ));
    let first = true;
    try {
      while (true) {
        const batch = await new Promise((resolve, reject) =>
          cursor.read(500, (err, rows) => err ? reject(err) : resolve(rows))
        );
        if (batch.length === 0) break;
        for (const row of batch) {
          if (!first) res.write(',');
          first = false;
          res.write(typeof row.row_data === 'string' ? row.row_data : JSON.stringify(row.row_data));
        }
      }
    } finally {
      await new Promise(r => cursor.close(r));
      client.release();
    }
    res.write(']}');
    res.end();
  } catch(e) {
    try { client.release(); } catch {}
    if (!res.headersSent) res.status(500).json({ error: e.message });
    else res.end();
  }
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
    const rows = XLSX.utils.sheet_to_json(ws, { defval: null, cellDates: true, raw: true });
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
          const rows0 = XLSX.utils.sheet_to_json(ws0, { defval: null, cellDates: true, raw: true });
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
      rows = XLSX.utils.sheet_to_json(ws, { defval: null, cellDates: true, raw: true });
    }

    res.json({ ok: true, rows, sheetNames, rowCount: rows.length });
  } catch (e) {
    console.error('fetch-url error:', e);
    res.status(500).json({ error: e.message });
  }
});


// ── Phase 3: Collaborative Workflow ──────────────────────────────────────────────

// Lightweight field-name list (for collab setup dropdowns)
app.get('/api/reports/:id/fields', auth([]), async (req, res) => {
  try {
    const { rows: ds } = await db.query('SELECT fields FROM rh_datasets WHERE report_id=$1', [req.params.id]);
    if (ds[0]?.fields) {
      const f = Array.isArray(ds[0].fields) ? ds[0].fields : (typeof ds[0].fields==='string'?JSON.parse(ds[0].fields):[]);
      if (f.length>0) return res.json(f);
    }
    const { rows: sample } = await db.query('SELECT row_data FROM rh_rows WHERE report_id=$1 LIMIT 1', [req.params.id]);
    if (sample[0]) {
      const rd = typeof sample[0].row_data==='string'?JSON.parse(sample[0].row_data):sample[0].row_data;
      return res.json(Object.keys(rd||{}));
    }
    const { rows: rpt } = await db.query('SELECT config FROM rh_reports WHERE id=$1', [req.params.id]);
    if (rpt[0]) {
      const cfg = typeof rpt[0].config==='string'?JSON.parse(rpt[0].config):(rpt[0].config||{});
      const fields = new Set();
      const extract = c => ['rows','columns','values','filters'].forEach(k=>(c[k]||[]).forEach(x=>x.field&&fields.add(x.field)));
      if (cfg.tabs) cfg.tabs.forEach(t=>extract(t.config||{}));
      extract(cfg);
      return res.json([...fields]);
    }
    res.json([]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Toggle collab mode
app.patch('/api/reports/:id/collab-toggle', auth(['admin','subadmin','subadmin_user']), async (req, res) => {
  try {
    const { enabled } = req.body;
    await db.query('UPDATE rh_reports SET collab_enabled=$1 WHERE id=$2', [!!enabled, req.params.id]);
    res.json({ ok: true, collab_enabled: !!enabled });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Collab columns
app.get('/api/reports/:id/collab-columns', auth(['admin','subadmin','subadmin_user','user']), async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM rh_collab_columns WHERE report_id=$1 ORDER BY col_order ASC, id ASC', [req.params.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/reports/:id/collab-columns', auth(['admin','subadmin','subadmin_user']), async (req, res) => {
  try {
    const { label, col_type, inputter_ids, reviewer_ids, ref_column, col_order, validation_config } = req.body;
    const { rows } = await db.query(`INSERT INTO rh_collab_columns (report_id,label,col_type,inputter_ids,reviewer_ids,ref_column,col_order,validation_config) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.params.id,label,col_type||'input',JSON.stringify(inputter_ids||[]),JSON.stringify(reviewer_ids||[]),ref_column||null,col_order||0,validation_config?JSON.stringify(validation_config):null]);
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/reports/:id/collab-columns/:colId', auth(['admin','subadmin','subadmin_user']), async (req, res) => {
  try {
    const { label, col_type, inputter_ids, reviewer_ids, ref_column, col_order, validation_config } = req.body;
    const { rows } = await db.query(`UPDATE rh_collab_columns SET label=$1,col_type=$2,inputter_ids=$3,reviewer_ids=$4,ref_column=$5,col_order=$6,validation_config=$7,updated_at=now() WHERE id=$8 AND report_id=$9 RETURNING *`,
      [label,col_type||'input',JSON.stringify(inputter_ids||[]),JSON.stringify(reviewer_ids||[]),ref_column||null,col_order||0,validation_config?JSON.stringify(validation_config):null,req.params.colId,req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Column not found' });
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/reports/:id/collab-columns/:colId', auth(['admin','subadmin','subadmin_user']), async (req, res) => {
  try {
    await db.query('DELETE FROM rh_collab_columns WHERE id=$1 AND report_id=$2', [req.params.colId, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Collab cycles
app.get('/api/reports/:id/collab-cycles', auth(['admin','subadmin','subadmin_user','user']), async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM rh_collab_cycles WHERE report_id=$1 ORDER BY created_at DESC', [req.params.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/reports/:id/collab-cycles', auth(['admin','subadmin','subadmin_user']), async (req, res) => {
  try {
    const { period_label, history_viewer_ids } = req.body;
    if (!period_label) return res.status(400).json({ error: 'period_label required' });
    const { rows } = await db.query(`INSERT INTO rh_collab_cycles (report_id,period_label,status,history_viewer_ids,opened_by) VALUES ($1,$2,'open',$3,$4) RETURNING *`,
      [req.params.id, period_label, JSON.stringify(history_viewer_ids||[]), req.user.id]);
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/reports/:id/collab-cycles/:cycleId/close', auth(['admin','subadmin','subadmin_user']), async (req, res) => {
  try {
    const { rows } = await db.query(`UPDATE rh_collab_cycles SET status='closed',closed_at=now(),closed_by=$1 WHERE id=$2 AND report_id=$3 AND status='open' RETURNING *`, [req.user.id, req.params.cycleId, req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Open cycle not found' });
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/reports/:id/collab-cycles/:cycleId/rename', auth(['admin','subadmin','subadmin_user']), async (req, res) => {
  try {
    const { label } = req.body;
    if (!label?.trim()) return res.status(400).json({ error: 'Label required' });
    const { rows } = await db.query(`UPDATE rh_collab_cycles SET period_label=$1 WHERE id=$2 AND report_id=$3 RETURNING *`, [label.trim(), req.params.cycleId, req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Cycle not found' });
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/reports/:id/collab-cycles/:cycleId', auth(['admin']), async (req, res) => {
  try {
    const { rows } = await db.query(`DELETE FROM rh_collab_cycles WHERE id=$1 AND report_id=$2 RETURNING id,period_label`, [req.params.cycleId, req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Cycle not found' });
    res.json({ deleted: true, ...rows[0] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/reports/:id/collab-cycles/:cycleId/reopen', auth(['admin','subadmin','subadmin_user']), async (req, res) => {
  try {
    const { rows } = await db.query(`UPDATE rh_collab_cycles SET status='open',closed_at=null,closed_by=null WHERE id=$1 AND report_id=$2 AND status='closed' RETURNING *`, [req.params.cycleId, req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Closed cycle not found' });
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/reports/:id/collab-cycles/:cycleId/export', auth(['admin','subadmin','subadmin_user','user']), async (req, res) => {
  try {
    const [cols, vals, dataRows] = await Promise.all([
      db.query('SELECT * FROM rh_collab_columns WHERE report_id=$1 ORDER BY col_order ASC, id ASC', [req.params.id]),
      db.query(`SELECT v.*,u1.username as inputter_name,u2.username as reviewer_name FROM rh_collab_values v LEFT JOIN rh_users u1 ON u1.id=v.inputter_id LEFT JOIN rh_users u2 ON u2.id=v.reviewer_id WHERE v.cycle_id=$1`, [req.params.cycleId]),
      db.query('SELECT row_data FROM rh_rows WHERE report_id=$1 ORDER BY id', [req.params.id])
    ]);
    res.json({ columns: cols.rows, values: vals.rows, dataRows: dataRows.rows.map(r=>typeof r.row_data==='string'?JSON.parse(r.row_data):r.row_data) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Collab values
app.get('/api/reports/:id/collab-cycles/:cycleId/values', auth(['admin','subadmin','subadmin_user','user']), async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM rh_collab_values WHERE cycle_id=$1 ORDER BY row_key, col_id', [req.params.cycleId]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/reports/:id/collab-cycles/:cycleId/values', auth(['admin','subadmin','subadmin_user','user']), async (req, res) => {
  try {
    const { row_key, col_id, value, remarks } = req.body;
    if (row_key===undefined||col_id===undefined) return res.status(400).json({ error: 'row_key and col_id required' });
    const { rows: cyc } = await db.query("SELECT status FROM rh_collab_cycles WHERE id=$1", [req.params.cycleId]);
    if (!cyc[0]||cyc[0].status!=='open') return res.status(409).json({ error: 'Cycle is closed' });
    const { rows: col } = await db.query('SELECT col_type,inputter_ids FROM rh_collab_columns WHERE id=$1', [col_id]);
    if (!col[0]) return res.status(404).json({ error: 'Column not found' });
    const isBuilder = ['admin','subadmin','subadmin_user'].includes(req.user.role);
    const inputterIds = Array.isArray(col[0].inputter_ids)?col[0].inputter_ids:JSON.parse(col[0].inputter_ids||'[]');
    if (!isBuilder&&!inputterIds.includes(req.user.id)) return res.status(403).json({ error: 'Not assigned as inputter' });
    const newStatus = col[0].col_type==='input'?'approved':'pending';
    const { rows } = await db.query(`INSERT INTO rh_collab_values (cycle_id,report_id,row_key,col_id,value,remarks,status,inputter_id,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now()) ON CONFLICT (cycle_id,row_key,col_id) DO UPDATE SET value=$5,remarks=$6,status=CASE WHEN rh_collab_values.status IN ('approved','rejected') THEN 'pending' ELSE $7 END,inputter_id=$8,updated_at=now() RETURNING *`,
      [req.params.cycleId,req.params.id,String(row_key),col_id,value,remarks||null,newStatus,req.user.id]);
    await db.query(`INSERT INTO rh_collab_audit (cycle_id,report_id,row_key,col_id,actor_id,action,value,remarks) VALUES ($1,$2,$3,$4,$5,'save',$6,$7)`,
      [req.params.cycleId,req.params.id,String(row_key),col_id,req.user.id,value,remarks||null]);
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/reports/:id/collab-cycles/:cycleId/values/submit', auth(['admin','subadmin','subadmin_user','user']), async (req, res) => {
  try {
    const { row_key, col_id } = req.body;
    const { rows: cyc } = await db.query("SELECT status FROM rh_collab_cycles WHERE id=$1", [req.params.cycleId]);
    if (!cyc[0]||cyc[0].status!=='open') return res.status(409).json({ error: 'Cycle is closed' });
    const { rows } = await db.query(`UPDATE rh_collab_values SET status='submitted',updated_at=now() WHERE cycle_id=$1 AND row_key=$2 AND col_id=$3 AND inputter_id=$4 AND status='pending' RETURNING *`,
      [req.params.cycleId,String(row_key),col_id,req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Value not found or not pending' });
    await db.query(`INSERT INTO rh_collab_audit (cycle_id,report_id,row_key,col_id,actor_id,action,value,remarks) VALUES ($1,$2,$3,$4,$5,'submit',$6,null)`,
      [req.params.cycleId,req.params.id,String(row_key),col_id,req.user.id,rows[0].value]);
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/reports/:id/collab-cycles/:cycleId/values/review', auth(['admin','subadmin','subadmin_user','user']), async (req, res) => {
  try {
    const { row_key, col_id, action, remarks, modified_value } = req.body;
    if (!['approved','rejected','hold','modified'].includes(action)) return res.status(400).json({ error: 'action must be approved/rejected/hold/modified' });
    const { rows: cyc } = await db.query("SELECT status FROM rh_collab_cycles WHERE id=$1", [req.params.cycleId]);
    if (!cyc[0]||cyc[0].status!=='open') return res.status(409).json({ error: 'Cycle is closed' });
    const { rows: col } = await db.query('SELECT reviewer_ids FROM rh_collab_columns WHERE id=$1', [col_id]);
    if (!col[0]) return res.status(404).json({ error: 'Column not found' });
    const isBuilder = ['admin','subadmin'].includes(req.user.role);
    const reviewerIds = Array.isArray(col[0].reviewer_ids)?col[0].reviewer_ids:JSON.parse(col[0].reviewer_ids||'[]');
    if (!isBuilder&&!reviewerIds.includes(req.user.id)) return res.status(403).json({ error: 'Not assigned as reviewer' });
    let finalAction=action, finalValue=null;
    if (action==='modified'&&modified_value!==undefined&&modified_value!==null) {
      finalValue=parseFloat(modified_value)||0;
      if (finalValue===0) finalAction='rejected';
    }
    let updateResult;
    if (finalValue!==null&&finalAction==='modified') {
      updateResult=await db.query(`UPDATE rh_collab_values SET status=$1,reviewer_id=$2,reviewer_remarks=$3,reviewed_at=now(),updated_at=now(),reviewer_value=$7 WHERE cycle_id=$4 AND row_key=$5 AND col_id=$6 AND status='submitted' RETURNING *`,
        [finalAction,req.user.id,remarks||null,req.params.cycleId,String(row_key),col_id,finalValue]);
    } else {
      updateResult=await db.query(`UPDATE rh_collab_values SET status=$1,reviewer_id=$2,reviewer_remarks=$3,reviewed_at=now(),updated_at=now() WHERE cycle_id=$4 AND row_key=$5 AND col_id=$6 AND status='submitted' RETURNING *`,
        [finalAction,req.user.id,remarks||null,req.params.cycleId,String(row_key),col_id]);
    }
    if (!updateResult.rows[0]) return res.status(404).json({ error: 'Value not found or not submitted' });
    await db.query(`INSERT INTO rh_collab_audit (cycle_id,report_id,row_key,col_id,actor_id,action,value,remarks) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [req.params.cycleId,req.params.id,String(row_key),col_id,req.user.id,finalAction,updateResult.rows[0].value,remarks||null]);
    res.json(updateResult.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Audit trail
app.get('/api/reports/:id/collab-cycles/:cycleId/audit', auth(['admin','subadmin','subadmin_user','user']), async (req, res) => {
  try {
    const { row_key } = req.query;
    let q='SELECT a.*,u.username FROM rh_collab_audit a LEFT JOIN rh_users u ON u.id=a.actor_id WHERE a.cycle_id=$1';
    const params=[req.params.cycleId];
    if (row_key) { q+=' AND a.row_key=$2'; params.push(String(row_key)); }
    q+=' ORDER BY a.created_at ASC';
    const { rows } = await db.query(q, params);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// History
app.get('/api/reports/:id/collab-history', auth(['admin','subadmin','subadmin_user','user']), async (req, res) => {
  try {
    const { rows: cycles } = await db.query("SELECT * FROM rh_collab_cycles WHERE report_id=$1 AND status='closed' ORDER BY closed_at DESC", [req.params.id]);
    const filtered = cycles.filter(c => {
      if (['admin','subadmin'].includes(req.user.role)) return true;
      const ids = Array.isArray(c.history_viewer_ids)?c.history_viewer_ids:JSON.parse(c.history_viewer_ids||'[]');
      return ids.includes(req.user.id);
    });
    res.json(filtered);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`ReportHub API running on port ${PORT}`));
