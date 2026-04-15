import { CameraConfig } from '../types/camera';

export function parse(raw: string): CameraConfig {
  const r: CameraConfig = {};
  for (const line of raw.split(/[\r\n]+/)) {
    const eq = line.indexOf('=');
    if (eq > 0) { 
      const k = line.substring(0, eq).trim();
      const v = line.substring(eq + 1).trim(); 
      r[k] = isNaN(v as any) || v === '' ? v : Number(v); 
    }
  }
  return r;
}

// Cameras may return write-side key names (wbmode, aemode, etc.) from their read
// endpoints, or use underscore variants — normalize everything to the UI-expected names.
const CAMERA_KEY_NORMALIZE: Record<string, string> = {
  wbmode:       'wb_mode',
  aemode:       'exposure_mode',
  luminance:    'bright',
  antiflicker:  'anti_flicker',
  noise2d:      'nr2d',
  focusmode:    'focus_mode',
  rgain:        'red_gain',
  bgain:        'blue_gain',
};

export function normalizeConfig(cfg: CameraConfig): CameraConfig {
  const out = { ...cfg };
  for (const [from, to] of Object.entries(CAMERA_KEY_NORMALIZE)) {
    if (from in out && !(to in out)) {
      out[to] = out[from];
      delete out[from];
    }
  }
  return out;
}

// Maps G3 write-key names → read-key names returned by get_image_conf / get_exposure_conf / get_focus_conf
export const WRITE_TO_READ_KEY: Record<string, string> = {
  wbmode: 'wb_mode', 
  aemode: 'exposure_mode', 
  luminance: 'bright',
  antiflicker: 'anti_flicker', 
  noise2d: 'nr2d', 
  focusmode: 'focus_mode',
  rgain: 'red_gain', 
  bgain: 'blue_gain'
};
