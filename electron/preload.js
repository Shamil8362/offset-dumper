const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  sendCommand: (cmd) => ipcRenderer.invoke('backend:command', cmd),
  ping:        ()    => ipcRenderer.invoke('backend:ping'),
  minimize:    ()    => ipcRenderer.send('window:minimize'),
  maximize:    ()    => ipcRenderer.send('window:maximize'),
  close:       ()    => ipcRenderer.send('window:close'),

  // Listen for backend status / log events pushed from main process
  onBackendStatus: (cb) => {
    const handler = (e, data) => cb(data)
    ipcRenderer.on('backend:status', handler)
    return () => ipcRenderer.removeListener('backend:status', handler)
  },
  onBackendLog: (cb) => {
    const handler = (e, msg) => cb(msg)
    ipcRenderer.on('backend:log', handler)
    return () => ipcRenderer.removeListener('backend:log', handler)
  },
  onNoAdmin: (cb) => {
    const handler = () => cb()
    ipcRenderer.once('app:no-admin', handler)
    return () => ipcRenderer.removeListener('app:no-admin', handler)
  },
})
