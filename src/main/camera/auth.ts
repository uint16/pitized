import crypto from 'crypto';
import { Auth, AuthChallenge } from '../types/camera';

export function md5(str: string): string {
  return crypto.createHash('md5').update(str).digest('hex');
}

export function sha256(str: string): string {
  return crypto.createHash('sha256').update(str).digest('hex');
}

export function parseAuthParams(header: string): AuthChallenge {
  const params: AuthChallenge = {};
  const re = /(\w+)=(?:"([^"]*?)"|([^\s,]+))/g;
  let m;
  while ((m = re.exec(header)) !== null) {
    const key = m[1] as keyof AuthChallenge;
    const val = m[2] !== undefined ? m[2] : m[3];
    (params as any)[key] = val;
  }
  return params;
}

export function buildDigestAuth(method: string, uri: string, auth: Auth, challenge: AuthChallenge) {
  const nc = '00000001';
  const cnonce = crypto.randomBytes(8).toString('hex');
  const algo = (challenge.algorithm || 'MD5').toUpperCase();
  const hash = algo.startsWith('SHA-256') ? sha256 : md5;
  
  let ha1 = hash(`${auth.username}:${challenge.realm}:${auth.password}`);
  if (algo === 'MD5-SESS' || algo === 'SHA-256-SESS') {
    ha1 = hash(`${ha1}:${challenge.nonce}:${cnonce}`);
  }
  
  const ha2 = hash(`${method}:${uri}`);
  const qop = challenge.qop ? challenge.qop.split(',')[0].trim() : null;
  const response = qop
    ? hash(`${ha1}:${challenge.nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
    : hash(`${ha1}:${challenge.nonce}:${ha2}`);
    
  let header = `Digest username="${auth.username}", realm="${challenge.realm}", nonce="${challenge.nonce}", uri="${uri}", algorithm=${algo}, response="${response}"`;
  if (qop) header += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
  if (challenge.opaque) header += `, opaque="${challenge.opaque}"`;
  
  return { headerName: 'Authorization', headerValue: header };
}

export function buildAuthnAuth(uri: string, auth: Auth, challenge: AuthChallenge) {
  const cnonce = crypto.randomBytes(8).toString('hex');
  const ha1 = sha256(`${auth.username}:${challenge.realm || ''}:${auth.password}`);
  const ha2 = sha256(`GET:${uri}`);
  const response = sha256(`${ha1}:${challenge.nonce}:${cnonce}:${ha2}`);
  const header = `Authn username="${auth.username}", nonce="${challenge.nonce}", uri="${uri}", response="${response}", cnonce="${cnonce}"`;
  return { headerName: 'auth_tkt', headerValue: header };
}

export function buildBasicAuth(auth: Auth) {
  return { 
    headerName: 'Authorization', 
    headerValue: `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}` 
  };
}

export function buildRetryHeaders(scheme: string, uri: string, auth: Auth, challenge: AuthChallenge, cookie?: string) {
  const headers: Record<string, string> = { 'Connection': 'close' };

  if (scheme === 'digest') {
    const a = buildDigestAuth('GET', uri, auth, challenge);
    headers[a.headerName] = a.headerValue;
  } else if (scheme === 'authn') {
    const a = buildAuthnAuth(uri, auth, challenge);
    headers[a.headerName] = a.headerValue;
    headers['User-From'] = 'www';
    if (cookie) headers['Cookie'] = cookie;
  } else if (scheme === 'basic') {
    const a = buildBasicAuth(auth);
    headers[a.headerName] = a.headerValue;
  }

  return headers;
}
