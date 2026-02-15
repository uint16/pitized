const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const dgram = require('dgram');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1100,
    minHeight: 750,
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#08080e',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, '../preload.js')
    }
  });
  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  // Open DevTools for debugging (remove this line in production)
  // mainWindow.webContents.openDevTools();
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });

/* ── Mock Data ────────────────────────────────────────────────────────────── */
const MOCK_DATA = {
  info: { model: 'Simulated PTZ', serial: 'SIM-001', firmware: 'v9.9.9-mock' },
  config: {
    wb_mode: 0, rgaintuning: 10, bgaintuning: 10,
    exposure_mode: 0, gain: 0, gainLimit: 15, backlight: 3, iris: 0, shutter: 1,
    focus_mode: 2, drc: 0,
    saturation: 4, bright: 7, contrast: 7, hue: 7, sharpness: 6,
    nr2d: 0, anti_flicker: 0
  }
};

// Mock PTZ State (World Coordinates of the camera center)
let mockPtz = { pan: 0, tilt: 0, zoom: 0 };
// The "Subject" is at (0,0). Camera sees subject relative to its pan/tilt.
// Range: Pan -100 to 100, Tilt -50 to 50.

/* ── HTTP Authentication ──────────────────────────────────────────────────── */
function md5(str) {
  return crypto.createHash('md5').update(str).digest('hex');
}

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function parseAuthParams(header) {
  const params = {};
  const re = /(\w+)=(?:"([^"]*?)"|([^\s,]+))/g;
  let m;
  while ((m = re.exec(header)) !== null) {
    params[m[1]] = m[2] !== undefined ? m[2] : m[3];
  }
  return params;
}

// Cache auth state per camera IP to avoid 401 round-trips on every request
const authCache = new Map();

function buildDigestAuth(method, uri, username, password, challenge) {
  const nc = '00000001';
  const cnonce = crypto.randomBytes(8).toString('hex');
  const algo = (challenge.algorithm || 'MD5').toUpperCase();
  const hash = algo.startsWith('SHA-256') ? sha256 : md5;
  let ha1 = hash(`${username}:${challenge.realm}:${password}`);
  if (algo === 'MD5-SESS' || algo === 'SHA-256-SESS') {
    ha1 = hash(`${ha1}:${challenge.nonce}:${cnonce}`);
  }
  const ha2 = hash(`${method}:${uri}`);
  const qop = challenge.qop ? challenge.qop.split(',')[0].trim() : null;
  const response = qop
    ? hash(`${ha1}:${challenge.nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
    : hash(`${ha1}:${challenge.nonce}:${ha2}`);
  let header = `Digest username="${username}", realm="${challenge.realm}", nonce="${challenge.nonce}", uri="${uri}", algorithm=${algo}, response="${response}"`;
  if (qop) header += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
  if (challenge.opaque) header += `, opaque="${challenge.opaque}"`;
  return { headerName: 'Authorization', headerValue: header };
}

function buildAuthnAuth(uri, username, password, challenge) {
  const cnonce = crypto.randomBytes(8).toString('hex');
  // SHA-256 Digest-like auth used by PTZOptics cameras
  const ha1 = sha256(`${username}:${challenge.realm || ''}:${password}`);
  const ha2 = sha256(`GET:${uri}`);
  const response = sha256(`${ha1}:${challenge.nonce}:${cnonce}:${ha2}`);
  const header = `Authn username="${username}", nonce="${challenge.nonce}", uri="${uri}", response="${response}", cnonce="${cnonce}"`;
  return { headerName: 'auth_tkt', headerValue: header };
}

function buildBasicAuth(username, password) {
  return { headerName: 'Authorization', headerValue: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}` };
}

function buildRetryHeaders(scheme, uri, auth, challenge, cookie) {
  const headers = { 'Connection': 'close' };

  if (scheme === 'digest') {
    const a = buildDigestAuth('GET', uri, auth.username, auth.password, challenge);
    headers[a.headerName] = a.headerValue;
  } else if (scheme === 'authn') {
    const a = buildAuthnAuth(uri, auth.username, auth.password, challenge);
    headers[a.headerName] = a.headerValue;
    headers['User-From'] = 'www';
    if (cookie) headers['Cookie'] = cookie;
  } else if (scheme === 'basic') {
    const a = buildBasicAuth(auth.username, auth.password);
    headers[a.headerName] = a.headerValue;
  }

  return headers;
}

/**
 * Performs HTTP GET with automatic auth negotiation.
 * Supports: Digest, Basic, and PTZOptics auth_tkt (Authn) with SHA-256.
 * Caches auth params per camera IP to avoid 401 round-trips.
 */
function authGet(ip, urlPath, timeout, auth, onResponse, onError) {
  const url = `http://${ip}${urlPath}`;

  // Try cached auth first to avoid double round-trip
  const cached = authCache.get(ip);
  if (cached && auth && auth.username && auth.password) {
    const headers = buildRetryHeaders(cached.scheme, urlPath, auth, cached.challenge, cached.cookie);
    const req = http.get(url, { timeout, headers }, res => {
      if (res.statusCode === 401) {
        // Cache stale — clear and retry fresh
        console.log(`[auth] Cached ${cached.scheme} auth expired for ${ip}, re-authenticating`);
        authCache.delete(ip);
        res.resume();
        authGetFresh(ip, urlPath, timeout, auth, onResponse, onError);
        return;
      }
      onResponse(res);
    });
    req.on('error', (err) => { req.destroy(); onError(err); });
    req.on('timeout', () => { req.destroy(); onError(new Error('Request timed out')); });
    return;
  }

  authGetFresh(ip, urlPath, timeout, auth, onResponse, onError);
}

function authGetFresh(ip, urlPath, timeout, auth, onResponse, onError) {
  const url = `http://${ip}${urlPath}`;
  const req = http.get(url, { timeout, headers: { 'Connection': 'close' } }, res => {
    if (res.statusCode !== 401 || !auth || !auth.username || !auth.password) {
      return onResponse(res);
    }

    // 401 — negotiate auth scheme
    const wwwAuth = res.headers['www-authenticate'] || '';
    const setCookies = res.headers['set-cookie'] || [];
    console.log(`[auth] 401 on ${urlPath} — WWW-Authenticate: ${wwwAuth || '(empty)'}`);
    if (setCookies.length) console.log(`[auth] Set-Cookie: ${JSON.stringify(setCookies)}`);
    res.resume();

    // Detect scheme
    let scheme, challenge, cookie;
    const wwwLower = wwwAuth.toLowerCase();

    if (wwwLower.startsWith('digest')) {
      scheme = 'digest';
      challenge = parseAuthParams(wwwAuth);
    } else if (wwwLower.startsWith('authn') || wwwLower.startsWith('auth_tkt')) {
      scheme = 'authn';
      challenge = parseAuthParams(wwwAuth);
      const tktCookie = setCookies.find(c => c.startsWith('auth_tkt='));
      if (tktCookie) cookie = tktCookie.split(';')[0];
    } else if (wwwLower.startsWith('basic')) {
      scheme = 'basic';
      challenge = {};
    } else {
      // No standard WWW-Authenticate — check for auth_tkt cookie as fallback
      const tktCookie = setCookies.find(c => c.startsWith('auth_tkt='));
      if (tktCookie) {
        cookie = tktCookie.split(';')[0];
        // Parse nonce from cookie: base64(nonce!username!token)
        try {
          const decoded = Buffer.from(tktCookie.split('=').slice(1).join('=').split(';')[0], 'base64').toString();
          const nonce = decoded.split('!')[0];
          scheme = 'authn';
          challenge = { nonce };
          console.log(`[auth] Extracted nonce from auth_tkt cookie: ${nonce}`);
        } catch (e) {
          console.error(`[auth] Failed to parse auth_tkt cookie:`, e.message);
        }
      }

      if (!scheme) {
        console.error(`[auth] Unknown auth scheme: "${wwwAuth}"`);
        return onError(new Error(`401 Unauthorized — unknown auth scheme`));
      }
    }

    console.log(`[auth] Using ${scheme} auth for ${urlPath}`);
    const headers = buildRetryHeaders(scheme, urlPath, auth, challenge, cookie);

    const req2 = http.get(url, { timeout, headers }, res2 => {
      if (res2.statusCode === 401) {
        const retryWww = res2.headers['www-authenticate'] || '';
        console.error(`[auth] Still 401 after ${scheme} auth on ${urlPath}${retryWww ? ' — WWW-Auth: ' + retryWww : ''}`);
        res2.resume();
        return onError(new Error('401 Unauthorized - check credentials'));
      }
      // Cache successful auth params
      console.log(`[auth] ${scheme} auth successful for ${ip}, cached`);
      authCache.set(ip, { scheme, challenge, cookie });
      onResponse(res2);
    });
    req2.on('error', (err) => { req2.destroy(); onError(err); });
    req2.on('timeout', () => { req2.destroy(); onError(new Error('Request timed out')); });
  });
  req.on('error', (err) => { req.destroy(); onError(err); });
  req.on('timeout', () => { req.destroy(); onError(new Error('Request timed out')); });
}

/* ── HTTP helpers ─────────────────────────────────────────────────────────── */
function httpGet(ip, urlPath, timeout = 4000, auth = null) {
  return new Promise((resolve, reject) => {
    function onError(err) {
      if (err.code === 'ECONNREFUSED') reject(new Error('Connection refused - camera may be offline or IP is incorrect'));
      else if (err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH') reject(new Error('Network unreachable - check network connection'));
      else if (err.code === 'ETIMEDOUT') reject(new Error('Connection timed out - camera not responding'));
      else reject(err);
    }

    authGet(ip, urlPath, timeout, auth, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve(d));
      res.on('error', reject);
    }, onError);
  });
}

function httpGetBinary(ip, urlPath, timeout = 5000, auth = null) {
  return new Promise((resolve, reject) => {
    function onError(err) {
      if (err.code === 'ECONNREFUSED') reject(new Error('Connection refused - camera may be offline'));
      else if (err.code === 'ETIMEDOUT') reject(new Error('Connection timed out'));
      else reject(err);
    }

    authGet(ip, urlPath, timeout, auth, res => {
      if (res.statusCode === 404) { res.resume(); return reject(new Error('404 Not Found - endpoint not supported')); }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }, onError);
  });
}

function httpPost(ip, urlPath, timeout = 4000, auth = null) {
  return new Promise((resolve, reject) => {
    function onError(err) {
      if (err.code === 'ECONNREFUSED') reject(new Error('Connection refused - camera may be offline'));
      else if (err.code === 'ETIMEDOUT') reject(new Error('Connection timed out'));
      else reject(err);
    }
    // POST with Content-Length: 0 (required by PTZOptics G3 API for query-param POSTs)
    const url = `http://${ip}${urlPath}`;
    const cached = authCache.get(ip);
    const headers = { 'Connection': 'close', 'Content-Length': '0' };
    if (cached && auth && auth.username && auth.password) {
      const retryH = buildRetryHeaders(cached.scheme, urlPath, auth, cached.challenge, cached.cookie);
      Object.assign(headers, retryH);
    }
    const urlObj = new (require('url').URL)(url);
    const opts = { hostname: urlObj.hostname, port: urlObj.port || 80, path: urlObj.pathname + urlObj.search, method: 'POST', timeout, headers };
    const req = http.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve(d));
      res.on('error', reject);
    });
    req.on('error', (err) => { req.destroy(); onError(err); });
    req.on('timeout', () => { req.destroy(); onError(new Error('Request timed out')); });
    req.end();
  });
}

function parse(raw) {
  const r = {};
  for (const line of raw.split(/[\r\n]+/)) {
    const eq = line.indexOf('=');
    if (eq > 0) { const k = line.substring(0, eq).trim(), v = line.substring(eq+1).trim(); r[k] = isNaN(v) ? v : Number(v); }
  }
  return r;
}

/* ── Connect & fetch all config ───────────────────────────────────────────── */
ipcMain.handle('camera:connect', async (_, ip, auth = null) => {
  console.log('[camera:connect] Attempting to connect to:', ip, auth ? '(with auth)' : '(no auth)');
  if (ip === 'mock') {
    console.log('[camera:connect] Using MOCK mode');
    return { success: true, info: MOCK_DATA.info, config: { ...MOCK_DATA.config } };
  }
  try {
    let info = {};
    let hadAnyResponse = false;
    let errors = [];

    // Try to get device info first
    try {
      console.log('[camera:connect] Fetching device config...');
      const deviceConf = await httpGet(ip, '/cgi-bin/param.cgi?get_device_conf', 4000, auth);
      info = parse(deviceConf);
      hadAnyResponse = true;
      console.log('[camera:connect] Device config retrieved successfully');
    } catch (e) {
      console.log('[camera:connect] Device config failed:', e.message);
      errors.push(`Device config: ${e.message}`);
      // Device conf might not be available on all models, continue
    }

    // Fetch camera settings
    const [img, exp, foc] = await Promise.all([
      httpGet(ip, '/cgi-bin/param.cgi?get_image_conf', 4000, auth).then(r => { hadAnyResponse = true; return r; }).catch(e => { errors.push(`Image conf: ${e.message}`); return ''; }),
      httpGet(ip, '/cgi-bin/param.cgi?get_exposure_conf', 4000, auth).then(r => { hadAnyResponse = true; return r; }).catch(e => { errors.push(`Exposure conf: ${e.message}`); return ''; }),
      httpGet(ip, '/cgi-bin/param.cgi?get_focus_conf', 4000, auth).then(r => { hadAnyResponse = true; return r; }).catch(e => { errors.push(`Focus conf: ${e.message}`); return ''; })
    ]);

    // If we got no response at all, the camera is unreachable
    if (!hadAnyResponse) {
      console.log('[camera:connect] No responses received. Errors:', errors);
      const firstError = errors[0] || 'Camera unreachable - check IP address and network connection';
      return { success: false, error: firstError };
    }

    console.log('[camera:connect] Successfully connected to:', ip);
    return { success: true,
      info: { model: info.device_model || info.model || 'PTZOptics Move SE', serial: info.serial_number || info.sn || 'N/A', firmware: info.firmware_version || info.fw || 'N/A' },
      config: { ...parse(img), ...parse(exp), ...parse(foc) }
    };
  } catch (err) {
    return { success: false, error: err.message || 'Connection failed' };
  }
});

ipcMain.handle('camera:getSettings', async (_, ip, auth = null) => {
  if (ip === 'mock') return { success: true, config: { ...MOCK_DATA.config } };
  try {
    const [img, exp, foc] = await Promise.all([
      httpGet(ip, '/cgi-bin/param.cgi?get_image_conf', 4000, auth).catch(() => ''),
      httpGet(ip, '/cgi-bin/param.cgi?get_exposure_conf', 4000, auth).catch(() => ''),
      httpGet(ip, '/cgi-bin/param.cgi?get_focus_conf', 4000, auth).catch(() => '')
    ]);
    return { success: true, config: { ...parse(img), ...parse(exp), ...parse(foc) } };
  } catch (err) { return { success: false, error: err.message }; }
});

/* ── Set parameters via post_image_value (G3 API) ─────────────────────────── */
// All image/exposure/color/focus settings use: GET /cgi-bin/ptzctrl.cgi?post_image_value&param&value
ipcMain.handle('camera:setImageParam', async (_, ip, params, auth = null) => {
  if (ip === 'mock') { Object.assign(MOCK_DATA.config, params); return { success: true }; }
  try {
    for (const [k, v] of Object.entries(params)) {
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&${k}&${v}`, 4000, auth);
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('camera:setExposureParam', async (_, ip, params, auth = null) => {
  if (ip === 'mock') { Object.assign(MOCK_DATA.config, params); return { success: true }; }
  try {
    for (const [k, v] of Object.entries(params)) {
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&${k}&${v}`, 4000, auth);
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('camera:setFocusParam', async (_, ip, params, auth = null) => {
  if (ip === 'mock') { Object.assign(MOCK_DATA.config, params); return { success: true }; }
  try {
    for (const [k, v] of Object.entries(params)) {
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&${k}&${v}`, 4000, auth);
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/* ── PTZ movement ─────────────────────────────────────────────────────────── */
ipcMain.handle('camera:ptz', async (_, ip, cmd, s1 = 5, s2 = 5, auth = null) => {
  try {
    if (ip === 'mock') {
      const speed = (parseInt(s1) || 5) * 2;
      if (cmd === 'up') mockPtz.tilt = Math.min(50, mockPtz.tilt + speed);
      if (cmd === 'down') mockPtz.tilt = Math.max(-50, mockPtz.tilt - speed);
      if (cmd === 'left') mockPtz.pan = Math.max(-100, mockPtz.pan - speed);
      if (cmd === 'right') mockPtz.pan = Math.min(100, mockPtz.pan + speed);
      if (cmd === 'upleft') { mockPtz.tilt += speed; mockPtz.pan -= speed; }
      if (cmd === 'upright') { mockPtz.tilt += speed; mockPtz.pan += speed; }
      if (cmd === 'downleft') { mockPtz.tilt -= speed; mockPtz.pan -= speed; }
      if (cmd === 'downright') { mockPtz.tilt -= speed; mockPtz.pan += speed; }
      if (cmd === 'home') { mockPtz.pan = 0; mockPtz.tilt = 0; }
      if (cmd === 'ptzstop') { /* stop momentum */ }
      return { success: true };
    }
    
    let urlPath = `/cgi-bin/ptzctrl.cgi?ptzcmd&${cmd}`;
    if (cmd.toLowerCase() === 'home') {
      // Home command takes no arguments
    } else if (cmd.toLowerCase().startsWith('pos')) {
      // Presets (posset/poscall) take only one argument (position number)
      urlPath += `&${s1}`;
    } else {
      // Pan/Tilt commands take pan speed and tilt speed
      urlPath += `&${s1}&${s2}`;
    }

    const response = await httpGet(ip, urlPath, 4000, auth);

    // Check for error responses
    if (response.includes('401') || response.includes('Unauthorized')) {
      return { success: false, error: 'Authentication required for PTZ control' };
    }

    return { success: true };
  }
  catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('camera:zoom', async (_, ip, dir, spd = 3, auth = null) => {
  try {
    if (ip === 'mock') { return { success: true }; }
    await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&${dir}&${spd}`, 4000, auth);
    return { success: true };
  }
  catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('camera:focus', async (_, ip, cmd, auth = null) => {
  try {
    if (ip === 'mock') { return { success: true }; }
    // Focus commands require a speed (1-7). Defaulting to 3.
    await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&${cmd}&3`, 4000, auth);
    return { success: true };
  }
  catch (err) {
    return { success: false, error: err.message };
  }
});

/* ── Snapshot ─────────────────────────────────────────────────────────────── */
ipcMain.handle('camera:snapshot', async (_, ip, auth = null) => {
  try {
    if (ip === 'mock') {
      // Generate dynamic SVG based on mockPtz state
      // Subject is a red circle at world (0,0). Camera view is offset by mockPtz.
      // Viewport is 320x240. Center is (160, 120).
      // If pan=0, tilt=0, circle is at 160,120.
      const cx = 160 - mockPtz.pan * 2;
      const cy = 120 + mockPtz.tilt * 2; // Tilt up means camera moves up, subject moves down
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="240" viewBox="0 0 320 240"><rect width="320" height="240" fill="#222"/><circle cx="${cx}" cy="${cy}" r="30" fill="#ff4444"/><text x="10" y="20" fill="#666" font-family="monospace">MOCK FEED</text><text x="10" y="230" fill="#666" font-family="monospace">Pos: ${mockPtz.pan},${mockPtz.tilt}</text></svg>`;
      return { success: true, data: Buffer.from(svg).toString('base64'), mime: 'image/svg+xml' };
    }
    // Try /cgi-bin/snapshot.cgi (most models), fall back to /snapshot.jpg (G3)
    let buf;
    try {
      buf = await httpGetBinary(ip, '/cgi-bin/snapshot.cgi', 5000, auth);
    } catch (e) {
      buf = await httpGetBinary(ip, '/snapshot.jpg', 5000, auth);
    }

    // Check if response is too small to be a real image (likely an error page)
    if (buf.length < 1000) {
      const textResponse = buf.toString('utf8');

      // Check if it's an HTML error page (401, 404, etc.)
      if (textResponse.includes('<!DOCTYPE') || textResponse.includes('<html')) {
        if (textResponse.includes('401') || textResponse.includes('Unauthorized')) {
          return { success: false, error: 'Authentication required for snapshots' };
        }
        return { success: false, error: 'Camera returned error page instead of image' };
      }
    }

    return { success: true, data: buf.toString('base64') };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/* ── Bulk sync (sends each param via post_image_value) ─────────────────── */
ipcMain.handle('camera:syncAll', async (_, ip, imgP, expP, focP, auth = null) => {
  try {
    if (ip === 'mock') { Object.assign(MOCK_DATA.config, imgP, expP, focP); return { success: true }; }
    const allParams = { ...imgP, ...expP, ...focP };
    for (const [k, v] of Object.entries(allParams)) {
      if (v === undefined || v === null) continue;
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&${k}&${v}`, 4000, auth).catch(() => null);
    }
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

/* ── Extended Features (G3) ───────────────────────────────────────────────── */
ipcMain.handle('camera:setFocusLock', async (_, ip, lock, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    const cmd = lock ? 'lock_mfocus' : 'unlock_mfocus';
    await httpGet(ip, `/cgi-bin/param.cgi?ptzcmd&${cmd}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:ptzReset', async (_, ip, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    await httpGet(ip, '/cgi-bin/param.cgi?pan_tiltdrive_reset', 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:zoomTo', async (_, ip, position, speed = 7, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    // position expected as decimal 0-16384, converted to 4-digit hex
    const posHex = Math.max(0, Math.min(16384, Number(position))).toString(16).padStart(4, '0');
    await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&zoomto&${speed}&${posHex}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:setOsdState', async (_, ip, open, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    const mode = open ? 'OSD' : 'PTZ';
    await httpGet(ip, `/cgi-bin/param.cgi?navigate_mode&${mode}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:osdNavigate', async (_, ip, cmd, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    // cmd: up, down, left, right, confirm, osd_back
    await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&${cmd}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:setAutoTracking', async (_, ip, enabled, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    // Try G3 endpoint first, fall back to G2
    const g3Val = enabled ? 'on' : 'off';
    try {
      await httpGet(ip, `/cgi-bin/param.cgi?set_overlay&autotracking&${g3Val}`, 4000, auth);
      return { success: true };
    } catch (e) {
      const g2Val = enabled ? 2 : 3;
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&autotrack&${g2Val}`, 4000, auth);
      return { success: true };
    }
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:saveSnapshot', async (_, ip, auth = null) => {
  try {
    if (ip === 'mock') return { success: false, error: 'Snapshots not available in mock mode' };
    let buf;
    try {
      buf = await httpGetBinary(ip, '/cgi-bin/snapshot.cgi', 5000, auth);
    } catch (e) {
      buf = await httpGetBinary(ip, '/snapshot.jpg', 5000, auth);
    }
    if (buf.length < 1000) {
      const text = buf.toString('utf8');
      if (text.includes('<!DOCTYPE') || text.includes('<html')) {
        return { success: false, error: 'Authentication required or endpoint not supported' };
      }
    }
    return { success: true, data: buf.toString('base64'), mime: 'image/jpeg' };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:getSystemConfig', async (_, ip, auth = null) => {
  try {
    if (ip === 'mock') return { success: true, config: {} };
    const [net, srv, usr, trans] = await Promise.all([
      httpGet(ip, '/cgi-bin/param.cgi?get_network_conf', 4000, auth).catch(() => ''),
      httpGet(ip, '/cgi-bin/param.cgi?get_server_conf', 4000, auth).catch(() => ''),
      httpGet(ip, '/cgi-bin/param.cgi?get_user_conf', 4000, auth).catch(() => ''),
      httpGet(ip, '/cgi-bin/param.cgi?get_trans_conf', 4000, auth).catch(() => '')
    ]);
    return { success: true, config: { network: parse(net), server: parse(srv), user: parse(usr), trans: parse(trans) } };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:getVideoUrl', (_, ip, index = 1) => {
  return `http://${ip}/video${index}.mp4`;
});

/* ── Video / Stream Configuration (SE-focused) ───────────────────────────── */
ipcMain.handle('camera:getVideoConfig', async (_, ip, auth = null) => {
  try {
    if (ip === 'mock') return { success: true, config: {} };
    const [video, audio] = await Promise.all([
      httpGet(ip, '/cgi-bin/param.cgi?get_media_video', 4000, auth).catch(() => ''),
      httpGet(ip, '/cgi-bin/param.cgi?get_media_audio', 4000, auth).catch(() => '')
    ]);
    return { success: true, config: { ...parse(video), ...parse(audio) } };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:setVideoParam', async (_, ip, params, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    const q = Object.entries(params).map(([k, v]) => `${k}=${v}`).join('&');
    await httpPost(ip, `/cgi-bin/param.cgi?post_media_video&${q}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:setAudioParam', async (_, ip, params, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    const q = Object.entries(params).map(([k, v]) => `${k}=${v}`).join('&');
    await httpPost(ip, `/cgi-bin/param.cgi?post_media_audio&${q}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:setImageValue', async (_, ip, param, value, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&${param}&${value}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:setOverlay', async (_, ip, param, value, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    await httpGet(ip, `/cgi-bin/param.cgi?set_overlay&${param}&${value}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:setTrackPreset', async (_, ip, value, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&trackpreset&${value}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:setNetworkParam', async (_, ip, params, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    const q = Object.entries(params).map(([k, v]) => `${k}=${v}`).join('&');
    await httpPost(ip, `/cgi-bin/param.cgi?post_network_other_conf&${q}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:setIRChannel', async (_, ip, channel, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    await httpGet(ip, `/cgi-bin/param.cgi?post_ir_info=&ir_id=${channel}`, 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('camera:reboot', async (_, ip, auth = null) => {
  try {
    if (ip === 'mock') return { success: true };
    await httpPost(ip, '/cgi-bin/param.cgi?post_reboot', 4000, auth);
    return { success: true };
  } catch (err) { return { success: false, error: err.message }; }
});

/* ── VISCA ────────────────────────────────────────────────────────────────── */
ipcMain.handle('camera:visca', async (_, ip, hexCmd, port = 1259) => {
  return new Promise(resolve => {
    try {
      const client = dgram.createSocket('udp4');
      const buf = Buffer.from(hexCmd, 'hex');
      const t = setTimeout(() => { client.close(); resolve({ success: false, error: 'timeout' }); }, 2000);
      client.on('message', msg => { clearTimeout(t); client.close(); resolve({ success: true, response: msg.toString('hex') }); });
      client.send(buf, port, ip, err => { if (err) { clearTimeout(t); client.close(); resolve({ success: false, error: err.message }); } });
    } catch (err) { resolve({ success: false, error: err.message }); }
  });
});

/* ── Discovery ────────────────────────────────────────────────────────────── */
ipcMain.handle('camera:discover', async () => {
  return new Promise(resolve => {
    const found = [];
    const client = dgram.createSocket('udp4');
    client.on('message', (_, r) => { if (!found.find(f => f.ip === r.address)) found.push({ ip: r.address }); });
    client.on('error', () => { client.close(); resolve(found); });
    client.bind(() => { client.setBroadcast(true); const c = Buffer.from('81090002ff','hex'); [1259,5678].forEach(p => client.send(c, p, '255.255.255.255')); });
    setTimeout(() => { client.close(); resolve(found); }, 3000);
  });
});
