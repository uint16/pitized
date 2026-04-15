export interface CameraInfo {
  model: string;
  serial: string;
  firmware: string;
}

export interface CameraConfig {
  [key: string]: string | number;
}

export interface Auth {
  username: string;
  password?: string;
}

export interface AuthChallenge {
  realm?: string;
  nonce?: string;
  qop?: string;
  algorithm?: string;
  opaque?: string;
}

export interface AuthCacheEntry {
  scheme: string;
  challenge: AuthChallenge;
  cookie?: string;
}

export interface MockPtz {
  pan: number;
  tilt: number;
  zoom: number;
}
