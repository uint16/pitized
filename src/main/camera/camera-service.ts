import { Auth, CameraConfig, CameraInfo } from '../types/camera';
import { httpGet, httpGetBinary, httpPost } from './http-client';
import { parse, normalizeConfig, WRITE_TO_READ_KEY } from '../utils/parsing';
import { MOCK_DATA, mockPtz } from '../mock/mock-data';

export class CameraService {
  async connect(ip: string, auth: Auth | null = null): Promise<{ success: boolean; info?: CameraInfo; config?: CameraConfig; error?: string }> {
    console.log('[camera:connect] Attempting to connect to:', ip, auth ? '(with auth)' : '(no auth)');
    
    if (ip === 'mock') {
      console.log('[camera:connect] Using MOCK mode');
      return { success: true, info: MOCK_DATA.info, config: { ...MOCK_DATA.config } };
    }

    try {
      let info: any = {};
      let hadAnyResponse = false;
      const errors: string[] = [];

      // Try to get device info first
      try {
        console.log('[camera:connect] Fetching device config...');
        const deviceConf = await httpGet(ip, '/cgi-bin/param.cgi?get_device_conf', 4000, auth);
        info = parse(deviceConf);
        hadAnyResponse = true;
        console.log('[camera:connect] Device config retrieved successfully');
      } catch (e: any) {
        console.log('[camera:connect] Device config failed:', e.message);
        errors.push(`Device config: ${e.message}`);
      }

      // Fetch camera settings
      const [img, exp, foc] = await Promise.all([
        httpGet(ip, '/cgi-bin/param.cgi?get_image_conf', 4000, auth).then(r => { hadAnyResponse = true; return r; }).catch(e => { errors.push(`Image conf: ${e.message}`); return ''; }),
        httpGet(ip, '/cgi-bin/param.cgi?get_exposure_conf', 4000, auth).then(r => { hadAnyResponse = true; return r; }).catch(e => { errors.push(`Exposure conf: ${e.message}`); return ''; }),
        httpGet(ip, '/cgi-bin/param.cgi?get_focus_conf', 4000, auth).then(r => { hadAnyResponse = true; return r; }).catch(e => { errors.push(`Focus conf: ${e.message}`); return ''; })
      ]);

      if (!hadAnyResponse) {
        console.log('[camera:connect] No responses received. Errors:', errors);
        const firstError = errors[0] || 'Camera unreachable - check IP address and network connection';
        return { success: false, error: firstError };
      }

      console.log('[camera:connect] Successfully connected to:', ip);
      const rawConfig = { ...parse(img), ...parse(exp), ...parse(foc) };
      console.log('[camera:connect] Raw config keys:', Object.keys(rawConfig).join(', '));
      return {
        success: true,
        info: { 
          model: info.device_model || info.model || 'PTZOptics Move SE', 
          serial: info.serial_number || info.sn || 'N/A', 
          firmware: info.firmware_version || info.fw || 'N/A' 
        },
        config: normalizeConfig(rawConfig)
      };
    } catch (err: any) {
      return { success: false, error: err.message || 'Connection failed' };
    }
  }

  async getSettings(ip: string, auth: Auth | null = null): Promise<{ success: boolean; config?: CameraConfig; error?: string }> {
    if (ip === 'mock') return { success: true, config: { ...MOCK_DATA.config } };
    try {
      const [img, exp, foc] = await Promise.all([
        httpGet(ip, '/cgi-bin/param.cgi?get_image_conf', 4000, auth).catch(() => ''),
        httpGet(ip, '/cgi-bin/param.cgi?get_exposure_conf', 4000, auth).catch(() => ''),
        httpGet(ip, '/cgi-bin/param.cgi?get_focus_conf', 4000, auth).catch(() => '')
      ]);
      return { success: true, config: normalizeConfig({ ...parse(img), ...parse(exp), ...parse(foc) }) };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setImageParam(ip: string, params: CameraConfig, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    if (ip === 'mock') { Object.assign(MOCK_DATA.config, params); return { success: true }; }
    try {
      for (const [k, v] of Object.entries(params)) {
        await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&${k}&${v}`, 4000, auth);
      }
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setExposureParam(ip: string, params: CameraConfig, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    return this.setImageParam(ip, params, auth);
  }

  async setFocusParam(ip: string, params: CameraConfig, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    return this.setImageParam(ip, params, auth);
  }

  async ptz(ip: string, cmd: string, s1: any = 5, s2: any = 5, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
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
        return { success: true };
      }
      
      let urlPath = `/cgi-bin/ptzctrl.cgi?ptzcmd&${cmd}`;
      if (cmd.toLowerCase() === 'home') {
        // no args
      } else if (cmd.toLowerCase().startsWith('pos')) {
        urlPath += `&${s1}`;
      } else {
        urlPath += `&${s1}&${s2}`;
      }

      const response = await httpGet(ip, urlPath, 4000, auth);
      if (response.includes('401') || response.includes('Unauthorized')) {
        return { success: false, error: 'Authentication required for PTZ control' };
      }
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async zoom(ip: string, dir: string, spd: any = 3, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&${dir}&${spd}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async focus(ip: string, cmd: string, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&${cmd}&3`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async snapshot(ip: string, auth: Auth | null = null, forSave: boolean = false): Promise<{ success: boolean; data?: string; mime?: string; error?: string }> {
    try {
      if (ip === 'mock') {
        if (forSave) return { success: false, error: 'Snapshots not available in mock mode' };
        const cx = 160 - mockPtz.pan * 2;
        const cy = 120 + mockPtz.tilt * 2;
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="240" viewBox="0 0 320 240"><rect width="320" height="240" fill="#222"/><circle cx="${cx}" cy="${cy}" r="30" fill="#ff4444"/><text x="10" y="20" fill="#666" font-family="monospace">MOCK FEED</text><text x="10" y="230" fill="#666" font-family="monospace">Pos: ${mockPtz.pan},${mockPtz.tilt}</text></svg>`;
        return { success: true, data: Buffer.from(svg).toString('base64'), mime: 'image/svg+xml' };
      }
      let buf;
      try {
        buf = await httpGetBinary(ip, '/cgi-bin/snapshot.cgi', 5000, auth);
      } catch (e) {
        buf = await httpGetBinary(ip, '/snapshot.jpg', 5000, auth);
      }

      if (buf.length < 1000) {
        const textResponse = buf.toString('utf8');
        if (textResponse.includes('<!DOCTYPE') || textResponse.includes('<html')) {
          if (textResponse.includes('401') || textResponse.includes('Unauthorized')) {
            return { success: false, error: 'Authentication required for snapshots' };
          }
          return { success: false, error: 'Camera returned error page instead of image' };
        }
      }
      return { success: true, data: buf.toString('base64'), mime: 'image/jpeg' };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async syncAll(ip: string, imgP: CameraConfig, expP: CameraConfig, focP: CameraConfig, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') { Object.assign(MOCK_DATA.config, imgP, expP, focP); return { success: true }; }
      const allParams = { ...imgP, ...expP, ...focP };
      for (const [k, v] of Object.entries(allParams)) {
        if (v === undefined || v === null) continue;
        await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&${k}&${v}`, 4000, auth).catch(() => null);
      }
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setFocusLock(ip: string, lock: boolean, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      const cmd = lock ? 'lock_mfocus' : 'unlock_mfocus';
      await httpGet(ip, `/cgi-bin/param.cgi?ptzcmd&${cmd}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async ptzReset(ip: string, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpGet(ip, '/cgi-bin/param.cgi?pan_tiltdrive_reset', 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async zoomTo(ip: string, position: number, speed: number = 7, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      const posHex = Math.max(0, Math.min(16384, Number(position))).toString(16).padStart(4, '0');
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&zoomto&${speed}&${posHex}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setOsdState(ip: string, open: boolean, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      const mode = open ? 'OSD' : 'PTZ';
      await httpGet(ip, `/cgi-bin/param.cgi?navigate_mode&${mode}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async osdNavigate(ip: string, cmd: string, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&${cmd}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setAutoTracking(ip: string, enabled: boolean, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      const g3Val = enabled ? 'on' : 'off';
      try {
        await httpGet(ip, `/cgi-bin/param.cgi?set_overlay&autotracking&${g3Val}`, 4000, auth);
        return { success: true };
      } catch (e) {
        const g2Val = enabled ? 2 : 3;
        await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&autotrack&${g2Val}`, 4000, auth);
        return { success: true };
      }
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async getSystemConfig(ip: string, auth: Auth | null = null): Promise<{ success: boolean; config?: any; error?: string }> {
    try {
      if (ip === 'mock') return { success: true, config: {} };
      const [net, srv, usr, trans] = await Promise.all([
        httpGet(ip, '/cgi-bin/param.cgi?get_network_conf', 4000, auth).catch(() => ''),
        httpGet(ip, '/cgi-bin/param.cgi?get_server_conf', 4000, auth).catch(() => ''),
        httpGet(ip, '/cgi-bin/param.cgi?get_user_conf', 4000, auth).catch(() => ''),
        httpGet(ip, '/cgi-bin/param.cgi?get_trans_conf', 4000, auth).catch(() => '')
      ]);
      return { success: true, config: { network: parse(net), server: parse(srv), user: parse(usr), trans: parse(trans) } };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async getVideoConfig(ip: string, auth: Auth | null = null): Promise<{ success: boolean; config?: any; error?: string }> {
    try {
      if (ip === 'mock') return { success: true, config: {} };
      const [video, audio] = await Promise.all([
        httpGet(ip, '/cgi-bin/param.cgi?get_media_video', 4000, auth).catch(() => ''),
        httpGet(ip, '/cgi-bin/param.cgi?get_media_audio', 4000, auth).catch(() => '')
      ]);
      return { success: true, config: { ...parse(video), ...parse(audio) } };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setVideoParam(ip: string, params: any, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      const q = Object.entries(params).map(([k, v]) => `${k}=${v}`).join('&');
      await httpPost(ip, `/cgi-bin/param.cgi?post_media_video&${q}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setAudioParam(ip: string, params: any, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      const q = Object.entries(params).map(([k, v]) => `${k}=${v}`).join('&');
      await httpPost(ip, `/cgi-bin/param.cgi?post_media_audio&${q}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setImageValue(ip: string, param: string, value: any, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') {
        const readKey = WRITE_TO_READ_KEY[param] || param;
        MOCK_DATA.config[readKey] = Number(value);
        return { success: true };
      }
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&${param}&${value}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setOverlay(ip: string, param: string, value: any, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpGet(ip, `/cgi-bin/param.cgi?set_overlay&${param}&${value}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setTrackPreset(ip: string, value: any, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?post_image_value&trackpreset&${value}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setNetworkParam(ip: string, params: any, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      const q = Object.entries(params).map(([k, v]) => `${k}=${v}`).join('&');
      await httpPost(ip, `/cgi-bin/param.cgi?post_network_other_conf&${q}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async setIRChannel(ip: string, channel: any, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpGet(ip, `/cgi-bin/param.cgi?post_ir_info=&ir_id=${channel}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async reboot(ip: string, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpPost(ip, '/cgi-bin/param.cgi?post_reboot', 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async presetCall(ip: string, preset: any, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&poscall&${preset}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }

  async presetSet(ip: string, preset: any, auth: Auth | null = null): Promise<{ success: boolean; error?: string }> {
    try {
      if (ip === 'mock') return { success: true };
      await httpGet(ip, `/cgi-bin/ptzctrl.cgi?ptzcmd&posset&${preset}`, 4000, auth);
      return { success: true };
    } catch (err: any) { return { success: false, error: err.message }; }
  }
}

export const cameraService = new CameraService();
