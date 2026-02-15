const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('ptz', {
  connect:          (ip, auth) => ipcRenderer.invoke('camera:connect', ip, auth),
  getSettings:      (ip, auth) => ipcRenderer.invoke('camera:getSettings', ip, auth),
  setImageParam:    (ip, p, auth) => ipcRenderer.invoke('camera:setImageParam', ip, p, auth),
  setExposureParam: (ip, p, auth) => ipcRenderer.invoke('camera:setExposureParam', ip, p, auth),
  setFocusParam:    (ip, p, auth) => ipcRenderer.invoke('camera:setFocusParam', ip, p, auth),
  ptz:              (ip, cmd, s1, s2, auth) => ipcRenderer.invoke('camera:ptz', ip, cmd, s1, s2, auth),
  zoom:             (ip, dir, spd, auth) => ipcRenderer.invoke('camera:zoom', ip, dir, spd, auth),
  focus:            (ip, cmd, auth) => ipcRenderer.invoke('camera:focus', ip, cmd, auth),
  snapshot:         (ip, auth) => ipcRenderer.invoke('camera:snapshot', ip, auth),
  syncAll:          (ip, img, exp, foc, auth) => ipcRenderer.invoke('camera:syncAll', ip, img, exp, foc, auth),
  setAutoTracking:  (ip, enabled, auth) => ipcRenderer.invoke('camera:setAutoTracking', ip, enabled, auth),
  saveSnapshot:     (ip, auth) => ipcRenderer.invoke('camera:saveSnapshot', ip, auth),
  getVideoConfig:   (ip, auth) => ipcRenderer.invoke('camera:getVideoConfig', ip, auth),
  setVideoParam:    (ip, p, auth) => ipcRenderer.invoke('camera:setVideoParam', ip, p, auth),
  setAudioParam:    (ip, p, auth) => ipcRenderer.invoke('camera:setAudioParam', ip, p, auth),
  setImageValue:    (ip, param, val, auth) => ipcRenderer.invoke('camera:setImageValue', ip, param, val, auth),
  setOverlay:       (ip, param, val, auth) => ipcRenderer.invoke('camera:setOverlay', ip, param, val, auth),
  setTrackPreset:   (ip, val, auth) => ipcRenderer.invoke('camera:setTrackPreset', ip, val, auth),
  setNetworkParam:  (ip, p, auth) => ipcRenderer.invoke('camera:setNetworkParam', ip, p, auth),
  setIRChannel:     (ip, ch, auth) => ipcRenderer.invoke('camera:setIRChannel', ip, ch, auth),
  reboot:           (ip, auth) => ipcRenderer.invoke('camera:reboot', ip, auth),
  visca:            (ip, cmd, port) => ipcRenderer.invoke('camera:visca', ip, cmd, port),
  discover:         () => ipcRenderer.invoke('camera:discover')
});
