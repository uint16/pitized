import { ipcMain } from 'electron';
import { cameraService } from './camera/camera-service';
import { udpService } from './discovery/udp-service';

export function registerIpcHandlers() {
  ipcMain.handle('camera:connect', (_, ip, auth) => cameraService.connect(ip, auth));
  ipcMain.handle('camera:getSettings', (_, ip, auth) => cameraService.getSettings(ip, auth));
  ipcMain.handle('camera:setImageParam', (_, ip, params, auth) => cameraService.setImageParam(ip, params, auth));
  ipcMain.handle('camera:setExposureParam', (_, ip, params, auth) => cameraService.setExposureParam(ip, params, auth));
  ipcMain.handle('camera:setFocusParam', (_, ip, params, auth) => cameraService.setFocusParam(ip, params, auth));
  ipcMain.handle('camera:ptz', (_, ip, cmd, s1, s2, auth) => cameraService.ptz(ip, cmd, s1, s2, auth));
  ipcMain.handle('camera:zoom', (_, ip, dir, spd, auth) => cameraService.zoom(ip, dir, spd, auth));
  ipcMain.handle('camera:focus', (_, ip, cmd, auth) => cameraService.focus(ip, cmd, auth));
  ipcMain.handle('camera:snapshot', (_, ip, auth) => cameraService.snapshot(ip, auth));
  ipcMain.handle('camera:syncAll', (_, ip, imgP, expP, focP, auth) => cameraService.syncAll(ip, imgP, expP, focP, auth));
  ipcMain.handle('camera:setFocusLock', (_, ip, lock, auth) => cameraService.setFocusLock(ip, lock, auth));
  ipcMain.handle('camera:ptzReset', (_, ip, auth) => cameraService.ptzReset(ip, auth));
  ipcMain.handle('camera:zoomTo', (_, ip, pos, spd, auth) => cameraService.zoomTo(ip, pos, spd, auth));
  ipcMain.handle('camera:setOsdState', (_, ip, open, auth) => cameraService.setOsdState(ip, open, auth));
  ipcMain.handle('camera:osdNavigate', (_, ip, cmd, auth) => cameraService.osdNavigate(ip, cmd, auth));
  ipcMain.handle('camera:setAutoTracking', (_, ip, enabled, auth) => cameraService.setAutoTracking(ip, enabled, auth));
  ipcMain.handle('camera:saveSnapshot', (_, ip, auth) => cameraService.snapshot(ip, auth, true));
  ipcMain.handle('camera:getSystemConfig', (_, ip, auth) => cameraService.getSystemConfig(ip, auth));
  ipcMain.handle('camera:getVideoUrl', (_, ip, index = 1) => `http://${ip}/video${index}.mp4`);
  ipcMain.handle('camera:getVideoConfig', (_, ip, auth) => cameraService.getVideoConfig(ip, auth));
  ipcMain.handle('camera:setVideoParam', (_, ip, params, auth) => cameraService.setVideoParam(ip, params, auth));
  ipcMain.handle('camera:setAudioParam', (_, ip, params, auth) => cameraService.setAudioParam(ip, params, auth));
  ipcMain.handle('camera:setImageValue', (_, ip, param, value, auth) => cameraService.setImageValue(ip, param, value, auth));
  ipcMain.handle('camera:setOverlay', (_, ip, param, value, auth) => cameraService.setOverlay(ip, param, value, auth));
  ipcMain.handle('camera:setTrackPreset', (_, ip, value, auth) => cameraService.setTrackPreset(ip, value, auth));
  ipcMain.handle('camera:setNetworkParam', (_, ip, params, auth) => cameraService.setNetworkParam(ip, params, auth));
  ipcMain.handle('camera:setIRChannel', (_, ip, channel, auth) => cameraService.setIRChannel(ip, channel, auth));
  ipcMain.handle('camera:reboot', (_, ip, auth) => cameraService.reboot(ip, auth));
  ipcMain.handle('camera:presetCall', (_, ip, preset, auth) => cameraService.presetCall(ip, preset, auth));
  ipcMain.handle('camera:presetSet', (_, ip, preset, auth) => cameraService.presetSet(ip, preset, auth));
  ipcMain.handle('camera:visca', (_, ip, hexCmd, port) => udpService.visca(ip, hexCmd, port));
  ipcMain.handle('camera:discover', () => udpService.discover());
}
