import { contextBridge, ipcRenderer } from 'electron';
import { Auth, CameraConfig } from './types/camera';

contextBridge.exposeInMainWorld('ptz', {
  connect:          (ip: string, auth: Auth | null) => ipcRenderer.invoke('camera:connect', ip, auth),
  getSettings:      (ip: string, auth: Auth | null) => ipcRenderer.invoke('camera:getSettings', ip, auth),
  setImageParam:    (ip: string, p: CameraConfig, auth: Auth | null) => ipcRenderer.invoke('camera:setImageParam', ip, p, auth),
  setExposureParam: (ip: string, p: CameraConfig, auth: Auth | null) => ipcRenderer.invoke('camera:setExposureParam', ip, p, auth),
  setFocusParam:    (ip: string, p: CameraConfig, auth: Auth | null) => ipcRenderer.invoke('camera:setFocusParam', ip, p, auth),
  ptz:              (ip: string, cmd: string, s1: any, s2: any, auth: Auth | null) => ipcRenderer.invoke('camera:ptz', ip, cmd, s1, s2, auth),
  zoom:             (ip: string, dir: string, spd: any, auth: Auth | null) => ipcRenderer.invoke('camera:zoom', ip, dir, spd, auth),
  focus:            (ip: string, cmd: string, auth: Auth | null) => ipcRenderer.invoke('camera:focus', ip, cmd, auth),
  snapshot:         (ip: string, auth: Auth | null) => ipcRenderer.invoke('camera:snapshot', ip, auth),
  syncAll:          (ip: string, img: CameraConfig, exp: CameraConfig, foc: CameraConfig, auth: Auth | null) => ipcRenderer.invoke('camera:syncAll', ip, img, exp, foc, auth),
  setAutoTracking:  (ip: string, enabled: boolean, auth: Auth | null) => ipcRenderer.invoke('camera:setAutoTracking', ip, enabled, auth),
  saveSnapshot:     (ip: string, auth: Auth | null) => ipcRenderer.invoke('camera:saveSnapshot', ip, auth),
  getVideoConfig:   (ip: string, auth: Auth | null) => ipcRenderer.invoke('camera:getVideoConfig', ip, auth),
  setVideoParam:    (ip: string, p: any, auth: Auth | null) => ipcRenderer.invoke('camera:setVideoParam', ip, p, auth),
  setAudioParam:    (ip: string, p: any, auth: Auth | null) => ipcRenderer.invoke('camera:setAudioParam', ip, p, auth),
  setImageValue:    (ip: string, param: string, val: any, auth: Auth | null) => ipcRenderer.invoke('camera:setImageValue', ip, param, val, auth),
  setOverlay:       (ip: string, param: string, val: any, auth: Auth | null) => ipcRenderer.invoke('camera:setOverlay', ip, param, val, auth),
  setTrackPreset:   (ip: string, val: any, auth: Auth | null) => ipcRenderer.invoke('camera:setTrackPreset', ip, val, auth),
  setNetworkParam:  (ip: string, p: any, auth: Auth | null) => ipcRenderer.invoke('camera:setNetworkParam', ip, p, auth),
  setIRChannel:     (ip: string, ch: any, auth: Auth | null) => ipcRenderer.invoke('camera:setIRChannel', ip, ch, auth),
  reboot:           (ip: string, auth: Auth | null) => ipcRenderer.invoke('camera:reboot', ip, auth),
  presetCall:       (ip: string, preset: any, auth: Auth | null) => ipcRenderer.invoke('camera:presetCall', ip, preset, auth),
  presetSet:        (ip: string, preset: any, auth: Auth | null) => ipcRenderer.invoke('camera:presetSet', ip, preset, auth),
  visca:            (ip: string, cmd: string, port: number) => ipcRenderer.invoke('camera:visca', ip, cmd, port),
  discover:         () => ipcRenderer.invoke('camera:discover')
});
