import { MockPtz } from '../types/camera';

export const MOCK_DATA = {
  info: { model: 'Simulated PTZ', serial: 'SIM-001', firmware: 'v9.9.9-mock' },
  config: {
    wb_mode: 0, rgaintuning: 10, bgaintuning: 10,
    exposure_mode: 0, gain: 0, gainLimit: 15, backlight: 3, iris: 0, shutter: 1,
    focus_mode: 2, drc: 0,
    saturation: 4, bright: 7, contrast: 7, hue: 7, sharpness: 6,
    nr2d: 0, anti_flicker: 0
  } as Record<string, number>
};

// Mock PTZ State (World Coordinates of the camera center)
export const mockPtz: MockPtz = { pan: 0, tilt: 0, zoom: 0 };
// The "Subject" is at (0,0). Camera sees subject relative to its pan/tilt.
// Range: Pan -100 to 100, Tilt -50 to 50.
