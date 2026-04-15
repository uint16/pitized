import http from 'http';
import { URL } from 'url';
import { Auth, AuthCacheEntry } from '../types/camera';
import { buildRetryHeaders, parseAuthParams } from './auth';

// Cache auth state per camera IP to avoid 401 round-trips on every request
const authCache = new Map<string, AuthCacheEntry>();

export function authGet(
  ip: string,
  urlPath: string,
  timeout: number,
  auth: Auth | null,
  onResponse: (res: http.IncomingMessage) => void,
  onError: (err: Error) => void
) {
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

function authGetFresh(
  ip: string,
  urlPath: string,
  timeout: number,
  auth: Auth | null,
  onResponse: (res: http.IncomingMessage) => void,
  onError: (err: Error) => void
) {
  const url = `http://${ip}${urlPath}`;
  const req = http.get(url, { timeout, headers: { 'Connection': 'close' } }, res => {
    if (res.statusCode !== 401 || !auth || !auth.username || !auth.password) {
      return onResponse(res);
    }

    // 401 — negotiate auth scheme
    const wwwAuth = res.headers['www-authenticate'] || '';
    const setCookies = (res.headers['set-cookie'] || []) as string[];
    console.log(`[auth] 401 on ${urlPath} — WWW-Authenticate: ${wwwAuth || '(empty)'}`);
    res.resume();

    // Detect scheme
    let scheme: string | undefined;
    let challenge: any;
    let cookie: string | undefined;
    const wwwLower = (Array.isArray(wwwAuth) ? wwwAuth[0] : wwwAuth).toLowerCase();

    if (wwwLower.startsWith('digest')) {
      scheme = 'digest';
      challenge = parseAuthParams(wwwAuth as string);
    } else if (wwwLower.startsWith('authn') || wwwLower.startsWith('auth_tkt')) {
      scheme = 'authn';
      challenge = parseAuthParams(wwwAuth as string);
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
        try {
          const decoded = Buffer.from(tktCookie.split('=').slice(1).join('=').split(';')[0], 'base64').toString();
          const nonce = decoded.split('!')[0];
          scheme = 'authn';
          challenge = { nonce };
          console.log(`[auth] Extracted nonce from auth_tkt cookie: ${nonce}`);
        } catch (e: any) {
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

export function httpGet(ip: string, urlPath: string, timeout = 4000, auth: Auth | null = null): Promise<string> {
  return new Promise((resolve, reject) => {
    function onError(err: any) {
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

export function httpGetBinary(ip: string, urlPath: string, timeout = 5000, auth: Auth | null = null): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    function onError(err: any) {
      if (err.code === 'ECONNREFUSED') reject(new Error('Connection refused - camera may be offline'));
      else if (err.code === 'ETIMEDOUT') reject(new Error('Connection timed out'));
      else reject(err);
    }

    authGet(ip, urlPath, timeout, auth, res => {
      if (res.statusCode === 404) { res.resume(); return reject(new Error('404 Not Found - endpoint not supported')); }
      const chunks: Buffer[] = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }, onError);
  });
}

export function httpPost(ip: string, urlPath: string, timeout = 4000, auth: Auth | null = null): Promise<string> {
  return new Promise((resolve, reject) => {
    function onError(err: any) {
      if (err.code === 'ECONNREFUSED') reject(new Error('Connection refused - camera may be offline'));
      else if (err.code === 'ETIMEDOUT') reject(new Error('Connection timed out'));
      else reject(err);
    }
    const url = `http://${ip}${urlPath}`;
    const cached = authCache.get(ip);
    const headers: Record<string, string> = { 'Connection': 'close', 'Content-Length': '0' };
    if (cached && auth && auth.username && auth.password) {
      const retryH = buildRetryHeaders(cached.scheme, urlPath, auth, cached.challenge, cached.cookie);
      Object.assign(headers, retryH);
    }
    const urlObj = new URL(url);
    const opts = { 
      hostname: urlObj.hostname, 
      port: urlObj.port || 80, 
      path: urlObj.pathname + urlObj.search, 
      method: 'POST', 
      timeout, 
      headers 
    };
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
