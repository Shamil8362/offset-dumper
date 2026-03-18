const { app, BrowserWindow, ipcMain, dialog } = require('electron')
const path  = require('path')
const { spawn, exec } = require('child_process')
const readline = require('readline')

let mainWindow
let backend
let rl
let pendingResolvers = new Map()
let msgId = 0
let backendRestartCount = 0
let backendRestarting = false
const MAX_RESTARTS = 5
const CMD_TIMEOUT_MS  = 30000   // 30s default
const SCAN_TIMEOUT_MS = 120000  // 2 min for heavy ops

// ── Admin check (Windows only) ───────────────────────────────────────────────
function checkAdminRights() {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve(true)
    const { exec } = require('child_process')
    exec('net session', (err) => resolve(!err))
  })
}

// ── Backend path ─────────────────────────────────────────────────────────────
function getBackendPath() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'offset_backend.exe')
  }
  return path.join(__dirname, '..', 'backend', 'offset_backend.exe')
}

// ── Kill all pending resolvers ────────────────────────────────────────────────
function rejectAllPending(reason) {
  for (const [, { reject }] of pendingResolvers) {
    reject(new Error(reason))
  }
  pendingResolvers.clear()
}

// ── Spawn C++ backend ─────────────────────────────────────────────────────────
function spawnBackend() {
  const exePath = getBackendPath()
  try {
    backend = spawn(exePath, [], { stdio: ['pipe', 'pipe', 'pipe'] })

    rl = readline.createInterface({ input: backend.stdout })
    rl.on('line', (line) => {
      if (!line.trim()) return
      try {
        const msg = JSON.parse(line)
        const id  = msg._id
        if (id !== undefined && pendingResolvers.has(id)) {
          const { resolve } = pendingResolvers.get(id)
          pendingResolvers.delete(id)
          resolve(msg)
        }
      } catch (e) {
        // Non-JSON output from backend (crash info etc.) — log separately
        console.error('[backend non-json]', line)
      }
    })

    // Dedicated stderr channel — never pollutes IPC JSON stream
    backend.stderr.on('data', (d) => {
      const msg = d.toString().trim()
      if (msg) {
        console.error('[backend]', msg)
        mainWindow?.webContents?.send('backend:log', msg)
      }
    })

    backend.on('exit', (code, signal) => {
      console.warn(`Backend exited: code=${code} signal=${signal}`)
      rejectAllPending('Backend process terminated unexpectedly')

      // Watchdog: auto-restart unless app is quitting
      if (!app.isQuitting && backendRestartCount < MAX_RESTARTS) {
        backendRestartCount++
        backendRestarting = true
        mainWindow?.webContents?.send('backend:status', {
          running: false, restarting: true, attempt: backendRestartCount,
        })
        setTimeout(() => {
          spawnBackend()
          backendRestarting = false
          mainWindow?.webContents?.send('backend:status', { running: true })
        }, 1500)
      } else if (backendRestartCount >= MAX_RESTARTS) {
        mainWindow?.webContents?.send('backend:status', {
          running: false, restarting: false, fatal: true,
        })
      }
    })

    backend.on('error', (err) => {
      console.error('Backend spawn error:', err)
      mainWindow?.webContents?.send('backend:status', {
        running: false, error: err.message,
      })
    })

    backendRestartCount = 0
    console.log('Backend spawned:', exePath)
  } catch (e) {
    console.error('Failed to spawn backend:', e)
  }
}

// ── Send command to backend ───────────────────────────────────────────────────
function sendCommand(cmd) {
  return new Promise((resolve, reject) => {
    if (!backend || backend.exitCode !== null) {
      return reject(new Error('Backend not running'))
    }
    if (backendRestarting) {
      return reject(new Error('Backend is restarting, please wait…'))
    }

    const id = ++msgId

    // Longer timeout for heavy commands
    const heavyCmds = ['batch_scan','netvar_dump','ue4_dump','il2cpp_dump','goldsrc_dump']
    const timeout = heavyCmds.includes(cmd.cmd) ? SCAN_TIMEOUT_MS : CMD_TIMEOUT_MS

    const timer = setTimeout(() => {
      if (pendingResolvers.has(id)) {
        pendingResolvers.delete(id)
        reject(new Error(`Command '${cmd.cmd}' timed out after ${timeout/1000}s`))
      }
    }, timeout)

    pendingResolvers.set(id, {
      resolve: (val) => { clearTimeout(timer); resolve(val) },
      reject:  (err) => { clearTimeout(timer); reject(err)  },
    })

    const payload = JSON.stringify({ ...cmd, _id: id }) + '\n'
    try {
      backend.stdin.write(payload)
    } catch (e) {
      pendingResolvers.delete(id)
      clearTimeout(timer)
      reject(new Error('Failed to write to backend stdin: ' + e.message))
    }
  })
}

// ── IPC handlers ─────────────────────────────────────────────────────────────
ipcMain.handle('backend:command', async (event, cmd) => {
  try {
    return await sendCommand(cmd)
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

ipcMain.handle('backend:ping', async () => {
  try {
    return await sendCommand({ cmd: 'ping' })
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

// ── Window ────────────────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    backgroundColor: '#0a0a0f',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    icon: path.join(__dirname, '..', 'public', 'icon.ico'),
  })

  const isDev = !app.isPackaged
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173')
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
  }
}

// ── Window controls via IPC ───────────────────────────────────────────────────
ipcMain.on('window:minimize', () => mainWindow?.minimize())
ipcMain.on('window:maximize', () => {
  if (mainWindow?.isMaximized()) mainWindow.unmaximize()
  else mainWindow?.maximize()
})
ipcMain.on('window:close', () => mainWindow?.close())

// ── App lifecycle ─────────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  const isAdmin = await checkAdminRights()
  if (!isAdmin && process.platform === 'win32') {
    app.once('browser-window-created', (e, win) => {
      win.webContents.once('did-finish-load', () => {
        win.webContents.send('app:no-admin')
      })
    })
  }

  spawnBackend()
  createWindow()
})

app.on('before-quit', () => { app.isQuitting = true })

app.on('window-all-closed', () => {
  app.isQuitting = true
  rejectAllPending('App is closing')
  if (backend) backend.kill()
  if (process.platform !== 'darwin') app.quit()
})
