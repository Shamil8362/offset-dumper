import React, {
  useState, useCallback, useRef, useEffect,
  createContext, useContext, useMemo
} from 'react'
import './App.css'
import { LANGS, useLang } from './i18n.js'

// ── API ───────────────────────────────────────────────────────────────────────
const api = window.electronAPI || {
  sendCommand: async () => ({ ok: false, error: 'Not in Electron' }),
  minimize: () => {}, maximize: () => {}, close: () => {},
}

// ── Contexts ──────────────────────────────────────────────────────────────────
const LangCtx    = createContext('ru')
const ProcCtx    = createContext(null)
const SetProcCtx = createContext(null)
const AddLogCtx  = createContext(null)
const SetTabCtx  = createContext(null)

const useTr      = () => useLang(useContext(LangCtx))
const useProc    = () => useContext(ProcCtx)
const useSetProc = () => useContext(SetProcCtx)
const useAddLog  = () => useContext(AddLogCtx)
const useSetTab  = () => useContext(SetTabCtx)

// ── Backend status banner ─────────────────────────────────────────────────────
function BackendStatusBanner() {
  const [status, setStatus] = useState(null) // null | {restarting, attempt, fatal, error}
  const [noAdmin, setNoAdmin] = useState(false)

  useEffect(() => {
    const unsubStatus = window.electronAPI?.onBackendStatus?.(s => setStatus(s))
    const unsubAdmin  = window.electronAPI?.onNoAdmin?.(() => setNoAdmin(true))
    return () => { unsubStatus?.(); unsubAdmin?.() }
  }, [])

  if (!status && !noAdmin) return null

  return (
    <div className="status-banners">
      {noAdmin && (
        <div className="sys-banner warn">
          ⚠ Запущено без прав администратора — чтение памяти процессов может не работать.
          Перезапустите приложение от имени администратора.
          <button className="banner-close" onClick={() => setNoAdmin(false)}>✕</button>
        </div>
      )}
      {status?.restarting && (
        <div className="sys-banner info">
          <span className="spinner" /> Бэкенд перезапускается... (попытка {status.attempt}/5)
        </div>
      )}
      {status?.fatal && (
        <div className="sys-banner err">
          ✗ Бэкенд не запустился после 5 попыток. Проверьте backend/offset_backend.exe.
        </div>
      )}
      {status?.error && !status?.fatal && (
        <div className="sys-banner err">
          ✗ Ошибка бэкенда: {status.error}
        </div>
      )}
    </div>
  )
}

// ── TitleBar ──────────────────────────────────────────────────────────────────
function TitleBar({ lang, setLang }) {
  return (
    <div className="titlebar">
      <div className="tb-left">
        <span className="tb-icon">⬡</span>
        <span className="tb-title">OffsetDumper</span>
      </div>
      <div className="tb-drag" />
      <div className="lang-switcher">
        {Object.keys(LANGS).map(l => (
          <button key={l} className={`lang-btn${lang===l?' active':''}`} onClick={() => setLang(l)}>
            {LANGS[l]}
          </button>
        ))}
      </div>
      <div className="tb-controls">
        <button onClick={() => api.minimize()}>─</button>
        <button onClick={() => api.maximize()}>□</button>
        <button className="tb-close" onClick={() => api.close()}>✕</button>
      </div>
    </div>
  )
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
function Sidebar({ active, setActive }) {
  const proc = useProc()
  const tabs = [
    { id: 'processes', icon: '⊞', tip: 'PROC' },
    { id: 'file',      icon: '◈', tip: 'FILE' },
    { id: 'memory',    icon: '◎', tip: 'MEM'  },
    { id: 'chain',     icon: '⟡', tip: 'PTR'  },
    { id: 'log',       icon: '≡', tip: 'LOG'  },
    { id: 'sigs',      icon: '⚡', tip: 'SIGS' },
    { id: 'netvars',   icon: '◬', tip: 'NET'  },
    { id: 'readme',    icon: '?', tip: 'HELP' },
  ]
  return (
    <nav className="sidebar">
      {tabs.map(t => (
        <button key={t.id}
          className={`sidebar-item${active===t.id?' active':''}`}
          onClick={() => setActive(t.id)} title={t.tip}>
          <span className="si-icon">{t.icon}</span>
          <span className="si-tip">{t.tip}</span>
          {/* dot on MEM/PTR if process selected */}
          {proc && (t.id==='memory'||t.id==='chain') && (
            <span className="si-proc-dot" />
          )}
        </button>
      ))}
      <div className="sidebar-spacer" />
      {proc && (
        <div className="sidebar-proc-chip" title={proc.name}>
          <span className={`proc-dot${proc.active?' active':' bg'}`} />
          <span className="chip-name">{proc.name.replace('.exe','')}</span>
        </div>
      )}
    </nav>
  )
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function CopyBtn({ text }) {
  const [c, setC] = useState(false)
  return (
    <button className="copy-btn" onClick={e => {
      e.stopPropagation()
      navigator.clipboard?.writeText(text)
      setC(true); setTimeout(() => setC(false), 1000)
    }}>{c ? '✓' : '⎘'}</button>
  )
}

function Btn({ primary, sm, onClick, disabled, loading, children }) {
  const t = useTr()
  return (
    <button
      className={`btn${primary?' btn-primary':' btn-secondary'}${sm?' btn-sm':''}`}
      onClick={onClick} disabled={disabled || loading}>
      {loading && <span className="spinner" />}
      {loading ? t('scanning') : children}
    </button>
  )
}

function Pill({ color, children }) {
  return <span className={`pill pill-${color}`}>{children}</span>
}

const HEX_KEYS = ['address','rva','base','offset','rawoffset','va','riptarget','mainbase']
const isHex = col => HEX_KEYS.some(h => col.toLowerCase().replace(/[^a-z]/g,'').includes(h))

function DataTable({ columns, rows, emptyMsg, onRowClick }) {
  const t = useTr()
  if (!rows?.length)
    return <div className="empty"><div className="ei">○</div>{emptyMsg || t('noResults')}</div>
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{columns.map(c => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} onClick={() => onRowClick?.(row)} className={onRowClick?'clickable':''}>
              {columns.map(c => {
                const val = row[c] ?? '—'
                const h = isHex(c)
                return (
                  <td key={c}>
                    {h ? <span className="hex">{val}</span> : val}
                    {h && val !== '—' && <CopyBtn text={val} />}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SectionHeading({ children, badge, badgeColor }) {
  return (
    <div className="sec-heading">
      {children}
      {badge != null && (
        <span className={`badge${badgeColor?' badge-'+badgeColor:''}`}>{badge}</span>
      )}
    </div>
  )
}

function InfoRow({ children }) {
  return <div className="info-row">{children}</div>
}

function SelectedBanner() {
  const t    = useTr()
  const proc = useProc()
  const set  = useSetProc()
  if (!proc) return null
  return (
    <div className="sel-banner">
      <span className={`proc-dot${proc.active?' active':' bg'}`} />
      <span className="sel-name">{proc.name}</span>
      <span className="sel-pid">PID {proc.pid}</span>
      <button className="sel-clear" onClick={() => set(null)} title={t('clear')}>×</button>
    </div>
  )
}

// ── Export HPP modal ──────────────────────────────────────────────────────────
function ExportModal({ content, onClose }) {
  const t = useTr()
  const addLog = useAddLog()
  const [path, setPath] = useState('offsets.hpp')
  const [done, setDone] = useState(false)

  const doExport = async () => {
    const res = await api.sendCommand({ cmd: 'export_hpp', path, content })
    if (res?.ok) { addLog(`✓ Exported: ${path}`); setDone(true); setTimeout(onClose, 1200) }
    else addLog(`ERROR export: ${res?.error}`)
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span>{t('exportHpp')}</span>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <label className="field-label">{t('outputPath')}</label>
          <input className="field-input mono" value={path} onChange={e => setPath(e.target.value)}
            style={{marginTop:6,marginBottom:12}} />
          <pre className="hpp-preview">{content.slice(0, 600)}{content.length>600?'\n// ...':''}</pre>
        </div>
        <div className="modal-footer">
          <Btn onClick={onClose}>{t('cancel')}</Btn>
          <Btn primary onClick={doExport}>{done ? '✓ '+t('done') : t('export')}</Btn>
        </div>
      </div>
    </div>
  )
}

// ── Context menu ──────────────────────────────────────────────────────────────
function CtxMenu({ proc, pos, onClose }) {
  const t       = useTr()
  const setProc = useSetProc()
  const setTab  = useSetTab()
  const addLog  = useAddLog()

  useEffect(() => {
    const h = e => { if(e.key==='Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  const go = tab => { setProc(proc); setTab(tab); onClose() }

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="ctx-menu" style={{ left: pos.x, top: pos.y }}>
        <div className="ctx-head">
          <div className="ctx-name">{proc.name}</div>
          <div className="ctx-pid">PID {proc.pid}</div>
        </div>
        <button className="ctx-item" onClick={() => go('memory')}>
          <span className="ctx-icon">◎</span>{t('ctxMemScan')}
        </button>
        <button className="ctx-item" onClick={() => go('chain')}>
          <span className="ctx-icon">⟡</span>{t('ctxChain')}
        </button>
        <div className="ctx-sep" />
        <button className="ctx-item" onClick={() => { setProc(proc); addLog(`Selected: ${proc.name} (${proc.pid})`); onClose() }}>
          <span className="ctx-icon">✓</span>{t('ctxSelect')}
        </button>
      </div>
    </>
  )
}

// ── PROCESSES PAGE ────────────────────────────────────────────────────────────
function ProcessesPage({ visible }) {
  const t      = useTr()
  const addLog = useAddLog()
  const setProc = useSetProc()
  const setTab  = useSetTab()

  const [loading, setLoading]   = useState(false)
  const [procs, setProcs]       = useState([])
  const [filter, setFilter]     = useState('')
  const [subtab, setSubtab]     = useState('active')
  const [ctx, setCtx]           = useState(null)
  const [sortBy, setSortBy]     = useState('name') // 'name' | 'pid'
  const [sortAsc, setSortAsc]   = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const filterRef = useRef(null)
  const timerRef  = useRef(null)

  const load = useCallback(async (silent=false) => {
    if (!silent) setLoading(true)
    if (!silent) addLog(t('logListProc'))
    try {
      const res = await api.sendCommand({ cmd: 'list_processes' })
      if (!res?.ok) { if(!silent) addLog(`ERROR: ${res?.error ?? 'no response'}`); return }
      const list = Array.isArray(res.data) ? res.data : []
      setProcs(list)
      if (!silent) {
        const act = list.filter(p => p.active).length
        addLog(`${t('logFound')} ${list.length} (${act} ${t('logActive')})`)
      }
    } catch(e) { if(!silent) addLog(`ERROR: ${e.message}`) }
    finally { if (!silent) setLoading(false) }
  }, [t, addLog])

  // Auto-refresh
  useEffect(() => {
    if (autoRefresh) {
      timerRef.current = setInterval(() => load(true), 3000)
    } else {
      clearInterval(timerRef.current)
    }
    return () => clearInterval(timerRef.current)
  }, [autoRefresh, load])

  // Hotkey: '/' focuses filter when page is visible
  useEffect(() => {
    if (!visible) return
    const h = e => {
      if (e.key === '/' && document.activeElement !== filterRef.current) {
        e.preventDefault()
        filterRef.current?.focus()
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [visible])

  const sorted = useMemo(() => {
    let list = procs.filter(p => !filter || p.name?.toLowerCase().includes(filter.toLowerCase()))
    list = [...list].sort((a,b) => {
      const va = sortBy==='pid' ? a.pid : a.name.toLowerCase()
      const vb = sortBy==='pid' ? b.pid : b.name.toLowerCase()
      return sortAsc ? (va>vb?1:-1) : (va<vb?1:-1)
    })
    return list
  }, [procs, filter, sortBy, sortAsc])

  const active = sorted.filter(p => p.active)
  const bg     = sorted.filter(p => !p.active)
  const shown  = subtab === 'active' ? active : bg

  const toggleSort = field => {
    if (sortBy === field) setSortAsc(a => !a)
    else { setSortBy(field); setSortAsc(true) }
  }

  const openCtx = (e, proc) => {
    e.preventDefault()
    const x = Math.min(e.clientX, window.innerWidth - 230)
    const y = Math.min(e.clientY, window.innerHeight - 160)
    setCtx({ proc, x, y })
  }

  const onDblClick = proc => {
    setProc(proc)
    setTab('memory')
  }

  return (
    <div className="page" style={{ display: visible ? '' : 'none' }}>
      {ctx && <CtxMenu proc={ctx.proc} pos={{x:ctx.x,y:ctx.y}} onClose={() => setCtx(null)} />}

      <div className="page-header">
        <span className="page-title">{t('tabProcesses')}</span>
        <div style={{display:'flex',gap:8,alignItems:'center'}}>
          {/* Auto-refresh toggle */}
          <button
            className={`btn btn-secondary btn-sm${autoRefresh?' active-toggle':''}`}
            onClick={() => setAutoRefresh(a => !a)}
            title={t('autoRefresh')}
          >
            {autoRefresh ? '⏸ Auto' : '⏵ Auto'}
          </button>
          <Btn primary loading={loading} onClick={() => load(false)}>{t('refresh')}</Btn>
        </div>
      </div>

      {/* Search + sort */}
      <div className="search-row">
        <input ref={filterRef} className="search-input"
          placeholder={`${t('filterByName')} ( / )`}
          value={filter} onChange={e => setFilter(e.target.value)} />
        <button className={`sort-btn${sortBy==='name'?' active':''}`} onClick={() => toggleSort('name')}>
          {t('colName')} {sortBy==='name' ? (sortAsc?'↑':'↓') : ''}
        </button>
        <button className={`sort-btn${sortBy==='pid'?' active':''}`} onClick={() => toggleSort('pid')}>
          PID {sortBy==='pid' ? (sortAsc?'↑':'↓') : ''}
        </button>
        <span className="count-badge">{active.length} / {bg.length}</span>
      </div>

      {/* Sub-tabs */}
      <div className="tabs">
        <button className={`tab-btn${subtab==='active'?' active':''}`} onClick={() => setSubtab('active')}>
          {t('tabActive')}
          <span className="tab-count tab-count-green">{active.length}</span>
        </button>
        <button className={`tab-btn${subtab==='bg'?' active':''}`} onClick={() => setSubtab('bg')}>
          {t('tabBackground')}
          <span className="tab-count">{bg.length}</span>
        </button>
      </div>

      {/* List */}
      <div className="proc-list">
        {shown.length === 0 && (
          <div className="empty">
            <div className="ei">{procs.length===0 ? '○' : '⊘'}</div>
            {procs.length===0 ? t('clickRefresh') : t('noResults')}
          </div>
        )}
        {shown.map(p => (
          <div key={p.pid} className="proc-item"
            onClick={e => openCtx(e, p)}
            onContextMenu={e => openCtx(e, p)}
            onDoubleClick={() => onDblClick(p)}
            title={t('dblClickMem')}>
            <span className={`proc-dot${p.active?' active':' bg'}`} />
            <span className="proc-name">{p.name}</span>
            <span className="proc-pid">{p.pid}</span>
          </div>
        ))}
      </div>

      {procs.length > 0 && (
        <div className="proc-hint">
          {t('clickToAction')} · {t('dblClickMem')}
          {autoRefresh && <span className="auto-badge"> · ⏵ {t('autoRefresh')}</span>}
        </div>
      )}
    </div>
  )
}

// ── FILE PAGE ─────────────────────────────────────────────────────────────────
function FilePage({ visible }) {
  const t      = useTr()
  const addLog = useAddLog()
  const [file, setFile]         = useState('')
  const [pattern, setPattern]   = useState('')
  const [loading, setLoading]   = useState(false)
  const [result, setResult]     = useState(null)
  const [showExport, setExport] = useState(false)

  const run = async () => {
    if (!file) return
    setLoading(true); setResult(null)
    addLog(`${t('logScanFile')}: ${file}`)
    try {
      const res = await api.sendCommand({ cmd: 'scan_file', file, pattern })
      if (!res?.ok) { addLog(`ERROR: ${res?.error}`); return }
      setResult(res.data)
      addLog(`${t('logDone')}: ${res.data.sections?.length??0} sec, ${res.data.matches?.length??0} matches`)
    } catch(e) { addLog(`ERROR: ${e.message}`) }
    finally { setLoading(false) }
  }

  const buildHpp = () => {
    if (!result) return ''
    const lines = [
      '#pragma once',
      '#include <cstdint>',
      '',
      `// Auto-generated by OffsetDumper`,
      `// Target: ${file}`,
      `// Arch: ${result.arch} | ImageBase: ${result.imageBase}`,
      `// EntryPoint: ${result.entryPoint}`,
      '',
      'namespace Offsets {',
    ]
    if (result.matches?.length) {
      lines.push('    // AOB Pattern matches')
      result.matches.forEach((m,i) => {
        lines.push(`    constexpr uintptr_t match_${i} = ${m.rva}; // ${m.section}${m.ripTarget?` -> RIP: ${m.ripTarget}`:''}`)
      })
    }
    lines.push('')
    lines.push('    // Sections')
    result.sections?.forEach(s => {
      lines.push(`    // ${s.name}: VA=${s.va} Size=${s.size}`)
    })
    lines.push('}')
    return lines.join('\n')
  }

  return (
    <div className="page" style={{ display: visible ? '' : 'none' }}>
      {showExport && <ExportModal content={buildHpp()} onClose={() => setExport(false)} />}
      <div className="page-header">
        <span className="page-title">{t('tabFile')}</span>
        <div style={{display:'flex',gap:8}}>
          {result && <Btn sm onClick={() => setExport(true)}>⬇ {t('exportHpp')}</Btn>}
          <Btn primary loading={loading} onClick={run}>{t('scan')}</Btn>
        </div>
      </div>
      <div className="fields">
        <div className="field-group">
          <label className="field-label">{t('peFilePath')}</label>
          <input className="field-input" placeholder="C:\game.exe"
            value={file} onChange={e => setFile(e.target.value)}
            onKeyDown={e => e.key==='Enter' && run()} />
        </div>
        <div className="field-group">
          <label className="field-label">{t('aobPattern')} <span className="opt">({t('optional')})</span></label>
          <input className="field-input mono" placeholder='48 8B 05 ? ? ? ?'
            value={pattern} onChange={e => setPattern(e.target.value)}
            onKeyDown={e => e.key==='Enter' && run()} />
        </div>
      </div>

      {result && <>
        <InfoRow>
          <Pill color="green">✓ {t('loaded')}</Pill>
          <Pill color="blue">{result.arch}</Pill>
          <span className="info-kv">ImageBase<span className="hex">{result.imageBase}</span></span>
          <span className="info-kv">EntryPoint<span className="hex">{result.entryPoint}</span></span>
        </InfoRow>
        <SectionHeading badge={result.sections?.length}>{t('sections')}</SectionHeading>
        <DataTable
          columns={[t('colName'), t('colVa'), t('colSize'), t('colRawOffset')]}
          rows={(result.sections||[]).map(s=>({[t('colName')]:s.name,[t('colVa')]:s.va,[t('colSize')]:s.size,[t('colRawOffset')]:s.rawOffset}))}
          emptyMsg={t('noSections')}
        />
        {result.matches && <>
          <SectionHeading badge={result.matches.length} badgeColor={result.matches.length?'green':'dim'}>
            {t('patternMatches')}
          </SectionHeading>
          <DataTable
            columns={[t('colRva'), t('colSection'), t('colRipTarget')]}
            rows={(result.matches||[]).map(m=>({[t('colRva')]:m.rva,[t('colSection')]:m.section,[t('colRipTarget')]:m.ripTarget||'—'}))}
            emptyMsg={t('noMatches')}
          />
        </>}
      </>}
    </div>
  )
}

// ── MEMORY PAGE ───────────────────────────────────────────────────────────────
function MemoryPage({ visible }) {
  const t       = useTr()
  const addLog  = useAddLog()
  const selProc = useProc()
  const [proc, setProc]         = useState('')
  const [pattern, setPattern]   = useState('')
  const [loading, setLoading]   = useState(false)
  const [result, setResult]     = useState(null)
  const [showExport, setExport] = useState(false)

  // Sync when selProc changes from outside
  useEffect(() => { if (selProc) setProc(selProc.name) }, [selProc])

  const run = async () => {
    if (!proc) return
    setLoading(true); setResult(null)
    addLog(`${t('logAttach')}: ${proc}`)
    try {
      const res = await api.sendCommand({ cmd: 'scan_process', process: proc, pattern })
      if (!res?.ok) { addLog(`ERROR: ${res?.error}`); return }
      setResult(res.data)
      addLog(`${t('logDone')}: ${res.data.modules?.length??0} ${t('logModules')}, ${res.data.matches?.length??0} matches`)
    } catch(e) { addLog(`ERROR: ${e.message}`) }
    finally { setLoading(false) }
  }

  const buildHpp = () => {
    if (!result) return ''
    const lines = [
      '#pragma once', '#include <cstdint>', '',
      `// Auto-generated by OffsetDumper`,
      `// Process: ${proc} | Module: ${result.mainModule}`,
      `// Base: ${result.mainBase}`, '',
      'namespace Offsets {',
    ]
    if (result.matches?.length) {
      lines.push('    // Memory scan matches')
      result.matches.forEach((m,i) => {
        lines.push(`    constexpr uintptr_t match_${i} = ${m.rva || m.address};`)
      })
    }
    lines.push('}')
    return lines.join('\n')
  }

  return (
    <div className="page" style={{ display: visible ? '' : 'none' }}>
      {showExport && <ExportModal content={buildHpp()} onClose={() => setExport(false)} />}
      <div className="page-header">
        <span className="page-title">{t('tabMemory')}</span>
        <div style={{display:'flex',gap:8}}>
          {result && <Btn sm onClick={() => setExport(true)}>⬇ {t('exportHpp')}</Btn>}
          <Btn primary loading={loading} onClick={run}>{t('attachScan')}</Btn>
        </div>
      </div>
      <SelectedBanner />
      <div className="fields">
        <div className="field-group">
          <label className="field-label">{t('processName')}</label>
          <input className="field-input" placeholder="game.exe"
            value={proc} onChange={e => setProc(e.target.value)}
            onKeyDown={e => e.key==='Enter' && run()} />
        </div>
        <div className="field-group">
          <label className="field-label">{t('aobPattern')} <span className="opt">({t('optional')})</span></label>
          <input className="field-input mono" placeholder='48 8B 05 ? ? ? ?'
            value={pattern} onChange={e => setPattern(e.target.value)}
            onKeyDown={e => e.key==='Enter' && run()} />
        </div>
      </div>

      {result && <>
        <InfoRow>
          <Pill color="green">✓ {t('attached')}</Pill>
          <span className="info-kv">{t('module')}<span className="hex">{result.mainModule}</span></span>
          <span className="info-kv">{t('colBase')}<span className="hex">{result.mainBase}</span></span>
        </InfoRow>
        <SectionHeading badge={result.modules?.length}>{t('loadedModules')}</SectionHeading>
        <DataTable
          columns={[t('colName'), t('colBase'), t('colSize')]}
          rows={(result.modules||[]).map(m=>({[t('colName')]:m.name,[t('colBase')]:m.base,[t('colSize')]:m.size}))}
          emptyMsg={t('noModules')}
        />
        {result.matches && <>
          <SectionHeading badge={result.matches.length} badgeColor={result.matches.length?'green':'dim'}>
            {t('patternMatches')}
          </SectionHeading>
          <DataTable
            columns={[t('colAddress'), t('colRva')]}
            rows={(result.matches||[]).map(m=>({[t('colAddress')]:m.address,[t('colRva')]:m.rva||'—'}))}
            emptyMsg={t('noMatches')}
          />
        </>}
      </>}
    </div>
  )
}

// ── Visual PTR Chain Builder ───────────────────────────────────────────────────
function ChainBuilder({ value, onChange }) {
  const parts = value ? value.split(':') : ['']

  const update = (idx, val) => {
    const next = [...parts]
    next[idx] = val
    onChange(next.join(':'))
  }
  const addLink = () => onChange([...parts, '0x0'].join(':'))
  const removeLink = (idx) => {
    if (parts.length <= 1) return
    const next = parts.filter((_, i) => i !== idx)
    onChange(next.join(':'))
  }

  return (
    <div className="chain-builder">
      {parts.map((p, i) => (
        <div key={i} className="cb-link">
          {i > 0 && <span className="cb-arrow">→</span>}
          <div className="cb-field-wrap">
            <span className="cb-label">{i === 0 ? 'base' : `+${i}`}</span>
            <input
              className="field-input mono cb-input"
              placeholder={i === 0 ? '0x1A2B00' : '0x10'}
              value={p}
              onChange={e => update(i, e.target.value)}
            />
          </div>
          {parts.length > 1 && (
            <button className="cb-del" onClick={() => removeLink(i)} title="Remove">×</button>
          )}
        </div>
      ))}
      <button className="cb-add" onClick={addLink} title="Add offset">+ offset</button>
      <div className="cb-raw">
        <span className="cb-raw-label">Raw:</span>
        <code className="cb-raw-val">{value || '—'}</code>
      </div>
    </div>
  )
}

// ── CHAIN PAGE ────────────────────────────────────────────────────────────────
function ChainPage({ visible }) {
  const t       = useTr()
  const addLog  = useAddLog()
  const selProc = useProc()
  const [proc, setProc]         = useState('')
  const [chain, setChain]       = useState('')
  const [chainLabel, setLabel]  = useState('')   // optional name for this chain
  const [loading, setLoading]   = useState(false)
  const [result, setResult]     = useState(null)

  // Persistent history in localStorage (up to 20 entries)
  const [history, setHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('offsetdumper_chains') || '[]') } catch { return [] }
  })
  const saveHistory = (newH) => {
    setHistory(newH)
    localStorage.setItem('offsetdumper_chains', JSON.stringify(newH))
  }

  useEffect(() => { if (selProc) setProc(selProc.name) }, [selProc])

  const run = async () => {
    if (!proc || !chain) return
    setLoading(true); setResult(null)
    addLog(`${t('logResolve')}: ${proc} | ${chain}`)
    try {
      const res = await api.sendCommand({ cmd: 'resolve_chain', process: proc, chain })
      if (!res?.ok) { addLog(`ERROR: ${res?.error}`); return }
      setResult(res.data)
      if (res.data.valid) {
        addLog(`✓ ${res.data.finalAddress}`)
        const entry = {
          proc, chain,
          label: chainLabel || chain.split(':')[0],
          addr: res.data.finalAddress,
          time: new Date().toTimeString().slice(0,8),
        }
        saveHistory([entry, ...history.filter(h => h.chain !== chain || h.proc !== proc)].slice(0, 20))
      } else {
        addLog(t('logChainInvalid'))
      }
    } catch(e) { addLog(`ERROR: ${e.message}`) }
    finally { setLoading(false) }
  }

  return (
    <div className="page" style={{ display: visible ? '' : 'none' }}>
      <div className="page-header">
        <span className="page-title">{t('tabChain')}</span>
        <Btn primary loading={loading} onClick={run}>{t('resolve')}</Btn>
      </div>
      <SelectedBanner />
      <div className="fields">
        <div className="field-group">
          <label className="field-label">{t('processName')}</label>
          <input className="field-input" placeholder="game.exe"
            value={proc} onChange={e => setProc(e.target.value)} />
        </div>
        <div className="field-group">
          <label className="field-label">
            {t('pointerChain')}
            <span className="opt" style={{marginLeft:8}}>({t('hexColon')})</span>
          </label>
          <ChainBuilder value={chain} onChange={setChain} />
        </div>
        <div className="field-group">
          <label className="field-label">Label <span className="opt">(optional name for history)</span></label>
          <input className="field-input" placeholder="e.g. localPlayer health"
            value={chainLabel} onChange={e => setLabel(e.target.value)} />
        </div>
      </div>

      {result && (
        <div className={`chain-card${result.valid?' ok':' fail'}`}>
          <div className="chain-head">
            <Pill color={result.valid?'green':'red'}>{result.valid ? `✓ ${t('resolved')}` : `✗ ${t('invalid')}`}</Pill>
          </div>
          {result.valid && (
            <div className="chain-body">
              <div className="chain-row"><span className="ck">{t('finalAddress')}</span>
                <span className="cv big">{result.finalAddress}</span><CopyBtn text={result.finalAddress} /></div>
              <div className="chain-row"><span className="ck">{t('module')}</span>
                <span className="cv">{result.module}</span></div>
              <div className="chain-row"><span className="ck">{t('baseOffset')}</span>
                <span className="cv">{result.baseOffset}</span></div>
            </div>
          )}
        </div>
      )}

      {/* History */}
      {history.length > 0 && <>
        <SectionHeading badge={history.length}>
          {t('chainHistory')}
          <button className="clear-hist-btn" onClick={() => saveHistory([])} title="Clear history">✕</button>
        </SectionHeading>
        <div className="chain-history">
          {history.map((h,i) => (
            <div key={i} className="hist-item" onClick={() => { setProc(h.proc); setChain(h.chain); setLabel(h.label||'') }}>
              <span className="hist-label">{h.label || h.chain.split(':')[0]}</span>
              <span className="hist-chain mono">{h.chain}</span>
              <span className="hist-addr hex">{h.addr}</span>
              <span className="hist-proc">{h.proc}</span>
              {h.time && <span className="hist-time">{h.time}</span>}
            </div>
          ))}
        </div>
      </>}

      <div className="help-box">
        <div className="help-title">{t('howToUse')}</div>
        <p>{t('chainHelp1')}</p>
        <p style={{marginTop:4}}>{t('chainHelp2')}</p>
        <p style={{marginTop:4}}><code>0x1A2B00:0x10:0x20:0x5C</code></p>
        <p style={{marginTop:4}}>{t('chainHelp3')} <code>module+0x1A2B00 → read → +0x10 → +0x5C</code></p>
      </div>
    </div>
  )
}

// ── LOG PAGE ──────────────────────────────────────────────────────────────────
function LogPage({ visible, logs, clearLogs }) {
  const t = useTr()
  const bottomRef = useRef(null)
  useEffect(() => {
    if (visible) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs, visible])

  return (
    <div className="page" style={{ display: visible ? '' : 'none' }}>
      <div className="page-header">
        <span className="page-title">{t('opLog')}</span>
        <Btn onClick={clearLogs}>{t('clear')}</Btn>
      </div>
      <div className="log-wrap">
        {!logs.length && <div className="empty"><div className="ei">≡</div>{t('noActivity')}</div>}
        {logs.map((e,i) => (
          <div key={i} className={`log-line${e.type?' '+e.type:''}`}>
            <span className="log-time">{e.time}</span>
            <span className="log-msg">{e.msg}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}




// ── NETVARS PAGE ──────────────────────────────────────────────────────────────
function NetVarsPage({ visible }) {
  const t      = useTr()
  const addLog = useAddLog()

  const [proc,    setProc]    = useState('')
  const [filter,  setFilter]  = useState('')
  const [loading, setLoading] = useState(false)
  const [data,    setData]    = useState(null)   // { total, classes, filtered, vars[] }
  const [exportFmt, setExFmt] = useState('hpp')
  const [selTable, setSelTable] = useState('')   // selected class filter

  const selProc = useProc()
  useEffect(() => { if (selProc) setProc(selProc.name) }, [selProc])

  // ── Run dump ────────────────────────────────────────────────────────────────
  const run = async () => {
    if (!proc) return
    setLoading(true); setData(null); setSelTable('')
    addLog(`NetVar dump: ${proc}`)
    try {
      const res = await api.sendCommand({ cmd: 'netvar_dump', process: proc, filter: '' })
      if (!res?.ok) { addLog(`ERROR: ${res?.error}`); return }
      setData(res.data)
      addLog(`✓ Dumped ${res.data.total} netvars from ${res.data.classes} classes`)
    } catch(e) { addLog(`ERROR: ${e.message}`) }
    finally { setLoading(false) }
  }

  // ── Derived data ────────────────────────────────────────────────────────────
  const vars = data?.vars || []

  // Unique tables
  const tables = useMemo(() => {
    const s = new Set(vars.map(v => v.table))
    return ['', ...Array.from(s).sort()]
  }, [vars])

  // Filtered vars
  const shown = useMemo(() => {
    return vars.filter(v => {
      const matchTable  = !selTable || v.table === selTable
      const matchFilter = !filter   || v.full.toLowerCase().includes(filter.toLowerCase())
      return matchTable && matchFilter
    })
  }, [vars, selTable, filter])

  // ── Build export ─────────────────────────────────────────────────────────────
  const buildExport = (fmt, source) => {
    const items = source || shown

    if (fmt === 'hpp') {
      const byTable = {}
      items.forEach(v => {
        if (!byTable[v.table]) byTable[v.table] = []
        byTable[v.table].push(v)
      })
      const lines = [
        '#pragma once', '#include <cstdint>', '',
        '// Auto-generated by OffsetDumper — NetVar Dump',
        `// Process: ${proc}`,
        `// Total: ${items.length} netvars`, '',
      ]
      Object.entries(byTable).forEach(([table, tvars]) => {
        lines.push(`// ${table}`)
        tvars.forEach(v => {
          lines.push(`constexpr uintptr_t ${v.name.padEnd(32)} = ${v.offset}; // ${v.table}`)
        })
        lines.push('')
      })
      return lines.join('\n')
    }

    if (fmt === 'hpp_ns') {
      const byTable = {}
      items.forEach(v => {
        if (!byTable[v.table]) byTable[v.table] = []
        byTable[v.table].push(v)
      })
      const lines = [
        '#pragma once', '#include <cstdint>', '',
        '// Auto-generated by OffsetDumper — NetVar Dump',
        `// Process: ${proc}`, '',
        'namespace netvars {',
      ]
      Object.entries(byTable).forEach(([table, tvars]) => {
        lines.push(`  namespace ${table} {`)
        tvars.forEach(v => {
          lines.push(`    constexpr uintptr_t ${v.name.padEnd(30)} = ${v.offset};`)
        })
        lines.push('  }')
      })
      lines.push('}')
      return lines.join('\n')
    }

    if (fmt === 'json') {
      const obj = {}
      items.forEach(v => {
        if (!obj[v.table]) obj[v.table] = {}
        obj[v.table][v.name] = v.offset
      })
      return JSON.stringify(obj, null, 2)
    }

    if (fmt === 'cs') {
      const lines = ['public static class NetVars {']
      items.forEach(v => {
        lines.push(`    public const uint ${v.name} = ${v.offset}; // ${v.table}`)
      })
      lines.push('}')
      return lines.join('\n')
    }

    if (fmt === 'py') {
      const lines = ['# NetVar dump — auto-generated by OffsetDumper', '']
      const byTable = {}
      items.forEach(v => {
        if (!byTable[v.table]) byTable[v.table] = []
        byTable[v.table].push(v)
      })
      Object.entries(byTable).forEach(([table, tvars]) => {
        lines.push(`# ${table}`)
        tvars.forEach(v => lines.push(`${v.name} = ${v.offset}`))
        lines.push('')
      })
      return lines.join('\n')
    }

    if (fmt === 'rs') {
      const lines = ['pub mod netvars {']
      items.forEach(v => {
        lines.push(`    pub const ${v.name.toUpperCase()}: usize = ${v.offset}; // ${v.table}`)
      })
      lines.push('}')
      return lines.join('\n')
    }

    return ''
  }

  const downloadExport = () => {
    const exts = { hpp:'hpp', hpp_ns:'hpp', json:'json', cs:'cs', py:'py', rs:'rs' }
    const content = buildExport(exportFmt, shown)
    const blob = new Blob([content], {type:'text/plain'})
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = `netvars.${exts[exportFmt]}`; a.click()
    URL.revokeObjectURL(url)
    addLog(`✓ Exported netvars.${exts[exportFmt]} (${shown.length} entries)`)
  }

  const copyExport = () => {
    navigator.clipboard?.writeText(buildExport(exportFmt, shown))
    addLog(`✓ Copied ${shown.length} netvars as ${exportFmt}`)
  }

  return (
    <div className="page" style={{ display: visible ? '' : 'none' }}>

      {/* Header */}
      <div className="page-header">
        <span className="page-title">NetVar Dump</span>
        <div style={{display:'flex',gap:8,alignItems:'center'}}>
          {data && <>
            <select className="fmt-select" value={exportFmt} onChange={e => setExFmt(e.target.value)}>
              <option value="hpp">C++ flat .hpp</option>
              <option value="hpp_ns">C++ namespace .hpp</option>
              <option value="json">JSON</option>
              <option value="cs">C# .cs</option>
              <option value="py">Python .py</option>
              <option value="rs">Rust .rs</option>
            </select>
            <Btn sm onClick={copyExport}>⎘ {t('copy')}</Btn>
            <Btn sm primary onClick={downloadExport}>⬇ {t('download')}</Btn>
          </>}
          <Btn primary loading={loading} onClick={run}>◬ Dump NetVars</Btn>
        </div>
      </div>

      {/* Info banner */}
      <div className="nv-info-box">
        <span className="nv-info-icon">ℹ</span>
        <span>{t('netvarInfo')}</span>
      </div>

      {/* Selected process banner */}
      <SelectedBanner />

      {/* Target input */}
      <div style={{display:'flex',gap:8,marginBottom:14}}>
        <input className="field-input" style={{maxWidth:300}}
          placeholder="game.exe / csgo.exe / tf2.exe"
          value={proc} onChange={e => setProc(e.target.value)}
          onKeyDown={e => e.key==='Enter' && run()} />
        {data && (
          <div className="nv-stats">
            <span className="nv-stat"><strong>{data.classes}</strong> classes</span>
            <span className="nv-stat"><strong>{data.total}</strong> netvars</span>
            <span className="nv-stat"><strong>{shown.length}</strong> shown</span>
          </div>
        )}
      </div>

      {data && (
        <div className="nv-layout">

          {/* Left: class list */}
          <div className="nv-left">
            <div className="nv-left-header">{t('classes')}</div>
            <input className="search-input" style={{margin:'6px 8px',width:'calc(100% - 16px)'}}
              placeholder={t('filterByName')}
              value={filter} onChange={e => setFilter(e.target.value)} />
            <div className="nv-class-list">
              {tables.map(tbl => {
                const count = tbl ? vars.filter(v => v.table===tbl).length : vars.length
                return (
                  <button key={tbl||'__all'}
                    className={`nv-class-item${selTable===tbl?' active':''}`}
                    onClick={() => setSelTable(tbl)}>
                    <span className="nv-class-name">{tbl || t('allClasses')}</span>
                    <span className="nv-class-count">{count}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Right: var list */}
          <div className="nv-right">
            <div className="nv-vars-header">
              <span>{selTable || t('allClasses')} · {shown.length}</span>
            </div>
            <div className="nv-vars-list">
              {shown.length === 0 && (
                <div className="empty"><div className="ei">◬</div>{t('noResults')}</div>
              )}
              {shown.map((v, i) => (
                <div key={i} className="nv-var-row">
                  <span className="nv-var-name">{v.name}</span>
                  <span className="nv-var-offset hex">{v.offset}</span>
                  {!selTable && <span className="nv-var-table">{v.table}</span>}
                  <CopyBtn text={v.offset} />
                </div>
              ))}
            </div>
          </div>

        </div>
      )}

      {!data && !loading && (
        <div className="nv-empty-state">
          <div className="nes-icon">◬</div>
          <div className="nes-title">NetVar Dumper</div>
          <div className="nes-desc">{t('netvarEmptyDesc')}</div>
          <div className="nes-steps">
            <div className="nes-step"><span>1</span>{t('netvarStep1')}</div>
            <div className="nes-step"><span>2</span>{t('netvarStep2')}</div>
            <div className="nes-step"><span>3</span>{t('netvarStep3')}</div>
            <div className="nes-step"><span>4</span>{t('netvarStep4')}</div>
          </div>
        </div>
      )}

    </div>
  )
}

// ── SIGNATURES PAGE ────────────────────────────────────────────────────────
const INITIAL_SIGS = [
  { id:1, name:'dwLocalPlayer', module:'client.dll', pattern:'8D 34 85 ? ? ? ? 89 15 ? ? ? ?', offset:3, extra:0, relative:true },
  { id:2, name:'dwEntityList',  module:'client.dll', pattern:'BB ? ? ? ? 83 FF 01 0F 8C ? ? ? ?', offset:1, extra:0, relative:false },
  { id:3, name:'dwViewMatrix',  module:'client.dll', pattern:'0F 10 05 ? ? ? ? 8D 85 ? ? ? ? B9', offset:3, extra:0, relative:true },
]

let sigIdCounter = 10

  function SigsPage({ visible }) {
  const t      = useTr()
  const addLog = useAddLog()

  // Загружаем из localStorage, или используем примеры при первом запуске
  const [sigs, setSigs] = useState(() => {
    const saved = localStorage.getItem('offsetdumper_sigs')
    if (saved) {
      try {
        return JSON.parse(saved)
      } catch {
        return INITIAL_SIGS
      }
    }
    return INITIAL_SIGS
  })

  // Сохраняем в localStorage при изменении
  useEffect(() => {
    localStorage.setItem('offsetdumper_sigs', JSON.stringify(sigs))
  }, [sigs])

  const [target, setTarget]     = useState('')
  const [mode, setMode]         = useState('process') // 'process' | 'file'
  const [loading, setLoading]   = useState(false)
  const [results, setResults]   = useState(null)
  const [editing, setEditing]   = useState(null)   // sig being edited
  const [showExport, setExport] = useState(false)
  const [exportFmt, setExFmt]   = useState('hpp')
  // ── Add / remove / edit ───────────────────────────────────────────────────
  const addSig = () => {
    const id = ++sigIdCounter
    const newSig = { id, name:`sig_${id}`, module:'', pattern:'', offset:3, extra:0, relative:true }
    setSigs(s => [...s, newSig])
    setEditing(newSig)
  }

  const removeSig = id => {
    setSigs(s => s.filter(x => x.id !== id))
    if (editing?.id === id) setEditing(null)
  }

  const saveSig = (updated) => {
    setSigs(s => s.map(x => x.id === updated.id ? updated : x))
    setEditing(null)
  }

  // ── Import / Export config ────────────────────────────────────────────────
  const importConfig = e => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => {
      try {
        const data = JSON.parse(ev.target.result)
        const arr = Array.isArray(data) ? data : data.signatures || []
        let id = ++sigIdCounter
        setSigs(arr.map(s => ({ ...s, id: id++,
          offset: s.offset ?? 3, extra: s.extra ?? 0, relative: s.relative ?? true
        })))
        addLog(`Imported ${arr.length} signatures`)
      } catch { addLog('ERROR: Invalid JSON config') }
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  const exportConfig = () => {
    const json = JSON.stringify({ signatures: sigs.map(({id,...s}) => s) }, null, 2)
    const blob = new Blob([json], {type:'application/json'})
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = 'signatures.json'; a.click()
    URL.revokeObjectURL(url)
  }

  // ── Batch scan ────────────────────────────────────────────────────────────
  const runScan = async () => {
    if (!target) return
    const activeSigs = sigs.filter(s => s.pattern.trim())
    if (!activeSigs.length) { addLog('ERROR: No signatures with patterns'); return }

    setLoading(true); setResults(null)
    addLog(`Batch scan: ${activeSigs.length} sigs on ${target}`)

    const sigsJson = JSON.stringify(activeSigs.map(s => ({
      name:     s.name,
      module:   s.module,
      pattern:  s.pattern,
      offset:   s.offset,
      extra:    s.extra,
      relative: s.relative,
    })))

    try {
      const cmd = mode === 'file'
        ? { cmd:'batch_scan', file: target, sigs: sigsJson }
        : { cmd:'batch_scan', process: target, sigs: sigsJson }
      const res = await api.sendCommand(cmd)
      if (!res?.ok) { addLog(`ERROR: ${res?.error}`); return }
      const list = Array.isArray(res.data) ? res.data : []
      setResults(list)
      const ok_  = list.filter(r => r.ok).length
      addLog(`✓ Scan done: ${ok_}/${list.length} found`)
    } catch(e) { addLog(`ERROR: ${e.message}`) }
    finally { setLoading(false) }
  }

  // ── Generate export content ────────────────────────────────────────────────
  const buildExport = fmt => {
    if (!results) return ''
    const pairs = results.filter(r => r.ok).map(r => ({ name: r.name, val: r.offset || '0x0' }))

    if (fmt === 'hpp') {
      const lines = [
        '#pragma once', '#include <cstdint>', '',
        '// Auto-generated by OffsetDumper',
        `// Target: ${target}`, '',
        'namespace Offsets {'
      ]
      pairs.forEach(p => lines.push(`    constexpr uintptr_t ${p.name.padEnd(30)} = ${p.val};`))
      lines.push('}')
      return lines.join('\n')
    }
    if (fmt === 'json') {
      const obj = {}
      pairs.forEach(p => { obj[p.name] = p.val })
      return JSON.stringify(obj, null, 2)
    }
    if (fmt === 'cs') {
      const lines = ['public static class Offsets {']
      pairs.forEach(p => lines.push(`    public const ulong ${p.name} = ${p.val};`))
      lines.push('}')
      return lines.join('\n')
    }
    if (fmt === 'py') {
      const lines = ['# Auto-generated by OffsetDumper', `# Target: ${target}`, '']
      pairs.forEach(p => lines.push(`${p.name} = ${p.val}`))
      return lines.join('\n')
    }
    if (fmt === 'rs') {
      const lines = ['// Auto-generated by OffsetDumper', 'pub mod offsets {']
      pairs.forEach(p => lines.push(`    pub const ${p.name.toUpperCase()}: usize = ${p.val};`))
      lines.push('}')
      return lines.join('\n')
    }
    return ''
  }

  const downloadExport = fmt => {
    const content = buildExport(fmt)
    const exts = { hpp:'hpp', json:'json', cs:'cs', py:'py', rs:'rs' }
    const blob = new Blob([content], {type:'text/plain'})
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = `offsets.${exts[fmt]}`; a.click()
    URL.revokeObjectURL(url)
    addLog(`✓ Exported offsets.${exts[fmt]}`)
  }

  const copyAll = () => {
    navigator.clipboard?.writeText(buildExport(exportFmt))
    addLog(`✓ Copied as ${exportFmt}`)
  }

  return (
    <div className="page" style={{ display: visible ? '' : 'none' }}>

      {/* Header */}
      <div className="page-header">
        <span className="page-title">{t('tabSigs')}</span>
        <div style={{display:'flex',gap:6}}>
          <label className="btn btn-secondary btn-sm" style={{cursor:'pointer'}}>
            ⬆ {t('importCfg')}
            <input type="file" accept=".json" style={{display:'none'}} onChange={importConfig} />
          </label>
          <Btn sm onClick={exportConfig}>⬇ {t('exportCfg')}</Btn>
          <Btn sm onClick={addSig}>+ {t('addSig')}</Btn>
        </div>
      </div>

      <div className="sigs-layout">

        {/* LEFT: signature list */}
        <div className="sigs-left">
          <div className="sigs-list">
            {sigs.map(sig => (
              <div key={sig.id}
                className={`sig-item${editing?.id===sig.id?' selected':''}`}
                onClick={() => setEditing(sig)}>
                <div className="sig-item-top">
                  <span className={`sig-dot${sig.pattern?'':' empty'}`} />
                  <span className="sig-name">{sig.name}</span>
                  <button className="sig-del" onClick={e=>{e.stopPropagation();removeSig(sig.id)}}>×</button>
                </div>
                {sig.module && <div className="sig-module">{sig.module}</div>}
                {sig.pattern && <div className="sig-pattern">{sig.pattern}</div>}
              </div>
            ))}
            {sigs.length === 0 && (
              <div className="empty"><div className="ei">⚡</div>{t('noSigs')}</div>
            )}
          </div>
        </div>

        {/* RIGHT: editor + scan */}
        <div className="sigs-right">

          {/* Sig editor */}
          {editing && (
            <SigEditor sig={editing} onSave={saveSig} onCancel={() => setEditing(null)} />
          )}

          {/* Scan target */}
          <div className="scan-box">
            <div className="scan-box-header">{t('scanTarget')}</div>
            <div className="scan-mode-row">
              <button className={`mode-btn${mode==='process'?' active':''}`} onClick={() => setMode('process')}>
                {t('liveProcess')}
              </button>
              <button className={`mode-btn${mode==='file'?' active':''}`} onClick={() => setMode('file')}>
                {t('staticFile')}
              </button>
            </div>
            <div style={{display:'flex',gap:8,marginTop:10}}>
              <input className="field-input" style={{flex:1}}
                placeholder={mode==='file' ? 'C:\\game.exe' : 'game.exe'}
                value={target} onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key==='Enter' && runScan()} />
              <Btn primary loading={loading} onClick={runScan}>
                ⚡ {t('batchScan')}
              </Btn>
            </div>
            <div className="scan-stats">
              {sigs.filter(s=>s.pattern).length} / {sigs.length} {t('sigsReady')}
            </div>
          </div>

          {/* Results */}
          {results && (
            <div className="results-box">
              <div className="results-header">
                <span>{t('results')} · {results.filter(r=>r.ok).length}/{results.length} {t('found')}</span>
                <div style={{display:'flex',gap:6,alignItems:'center'}}>
                  <select className="fmt-select" value={exportFmt} onChange={e => setExFmt(e.target.value)}>
                    <option value="hpp">C++ .hpp</option>
                    <option value="json">JSON</option>
                    <option value="cs">C# .cs</option>
                    <option value="py">Python .py</option>
                    <option value="rs">Rust .rs</option>
                  </select>
                  <Btn sm onClick={copyAll}>⎘ {t('copy')}</Btn>
                  <Btn sm primary onClick={() => downloadExport(exportFmt)}>⬇ {t('download')}</Btn>
                </div>
              </div>
              <div className="results-list">
                {results.map((r,i) => (
                  <div key={i} className={`result-row${r.ok?'':' fail'}`}>
                    <span className={`res-dot${r.ok?'':' fail'}`} />
                    <span className="res-name">{r.name}</span>
                    {r.ok
                      ? <>
                          <span className="res-offset hex">{r.offset}</span>
                          {r.module && <span className="res-mod">{r.module}</span>}
                          <span className="res-hits">{r.hits} hit{r.hits!==1?'s':''}</span>
                          <CopyBtn text={r.offset} />
                        </>
                      : <span className="res-err">{r.error}</span>
                    }
                  </div>
                ))}
              </div>

              {/* Export preview */}
              <pre className="export-preview">{buildExport(exportFmt)}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── AOB pattern validator (client-side, mirrors C++ logic) ────────────────────
function validateAobPattern(pattern) {
  if (!pattern || !pattern.trim()) return null // empty = no error
  const tokens = pattern.trim().split(/\s+/)
  if (tokens.length === 0) return 'Empty pattern'
  for (const tok of tokens) {
    if (/^(\?{1,2}|\*)$/.test(tok)) continue              // wildcard
    if (/^[0-9A-Fa-f]{2}$/.test(tok)) continue            // hex byte
    return `Invalid token: "${tok}" — use hex bytes (48, 8B) or wildcards (?, ??)`
  }
  if (tokens.length < 2) return 'Pattern too short (min 2 bytes)'
  return null // valid
}

// ── Sig Editor ─────────────────────────────────────────────────────────────────
function SigEditor({ sig, onSave, onCancel }) {
  const t = useTr()
  const [form, setForm] = useState({...sig})
  const set = (k, v) => setForm(f => ({...f, [k]: v}))
  const patternError = validateAobPattern(form.pattern)

  return (
    <div className="sig-editor">
      <div className="sig-editor-header">
        <span>{t('editSig')}: <strong>{sig.name}</strong></span>
        <button className="modal-close" onClick={onCancel}>✕</button>
      </div>
      <div className="sig-editor-body">
        <div className="se-row">
          <label className="field-label">{t('sigName')}</label>
          <input className="field-input" value={form.name} onChange={e => set('name', e.target.value)} />
        </div>
        <div className="se-row">
          <label className="field-label">{t('sigModule')} <span className="opt">({t('optional')})</span></label>
          <input className="field-input" placeholder="client.dll" value={form.module} onChange={e => set('module', e.target.value)} />
        </div>
        <div className="se-row">
          <label className="field-label">{t('sigPattern')}</label>
          <input
            className={`field-input mono${patternError ? ' input-error' : form.pattern && !patternError ? ' input-ok' : ''}`}
            placeholder="48 8B 05 ? ? ? ? 48 89"
            value={form.pattern}
            onChange={e => set('pattern', e.target.value)} />
          {patternError && <div className="field-error">⚠ {patternError}</div>}
          {form.pattern && !patternError && (
            <div className="field-ok">✓ {form.pattern.trim().split(/\s+/).length} bytes</div>
          )}
        </div>
        <div className="se-row-3">
          <div>
            <label className="field-label">{t('sigOffset')}</label>
            <input className="field-input" type="number" value={form.offset}
              onChange={e => set('offset', parseInt(e.target.value)||0)} />
          </div>
          <div>
            <label className="field-label">{t('sigExtra')}</label>
            <input className="field-input mono" placeholder="0"
              value={form.extra === 0 ? '0' : form.extra}
              onChange={e => {
                const v = e.target.value
                set('extra', v.startsWith('0x') ? parseInt(v,16)||0 : parseInt(v)||0)
              }} />
          </div>
          <div>
            <label className="field-label">{t('sigRelative')}</label>
            <button
              className={`toggle-btn${form.relative?' on':''}`}
              onClick={() => set('relative', !form.relative)}>
              {form.relative ? 'RIP-relative' : 'Absolute'}
            </button>
          </div>
        </div>
        <div className="se-help">
          <strong>{t('sigOffset')}:</strong> {t('sigOffsetHelp')}<br/>
          <strong>{t('sigExtra')}:</strong> {t('sigExtraHelp')}<br/>
          <strong>RIP-relative:</strong> {t('sigRelativeHelp')}
        </div>
      </div>
      <div className="sig-editor-footer">
        <Btn onClick={onCancel}>{t('cancel')}</Btn>
        <Btn primary onClick={() => onSave(form)} disabled={!!patternError}>{t('saveSig')}</Btn>
      </div>
    </div>
  )
}

// ── README PAGE ───────────────────────────────────────────────────────────────
function ReadmePage({ visible }) {
  const lang = useContext(LangCtx)
  const [active, setActive] = useState(0)

  const data = {
    ru: {
      title: 'Справка',
      sections: [
        { h: 'Что такое оффсет?', b: `Оффсет — смещение от базового адреса модуля до нужной переменной/функции в памяти.

Пример: game.exe грузится по 0x140000000, переменная health по 0x1401A2B00 → оффсет = 0x1A2B00.

Виды:
• Статический (RVA) — стабилен между запусками
• Динамический — меняется каждый запуск из-за ASLR, нужна цепь указателей` },
        { h: 'PROC — Процессы', b: `Список всех процессов Windows.

Активные — с видимым окном (игры, приложения).
Фоновые — системные службы.

Горячие клавиши:
  /  →  фокус на поиске
  клик  →  меню (Memory Scan, PTR Chain)
  двойной клик  →  сразу Memory Scan

Авто-обновление — список каждые 3 сек.` },
        { h: 'FILE — Статический анализ', b: `Анализирует PE файл (.exe/.dll) без его запуска.

Показывает:
• ImageBase, EntryPoint
• Секции — .text (код), .data, .rdata
• Совпадения AOB паттерна с RVA

AOB паттерн:  48 8B 05 ? ? ? ? 48 89
? — wildcard, любой байт.

Найденный RVA стабилен, не зависит от ASLR.
RIP Target — адрес на который ссылается инструкция.` },
        { h: 'MEM — Сканирование памяти', b: `Подключается к живому процессу через ReadProcessMemory.

Показывает:
• Загруженные модули (.exe + .dll) с базами
• Совпадения AOB с абсолютным адресом и RVA

Важно:
  Address — абсолютный, меняется при перезапуске!
  RVA = Address − ModuleBase — стабилен, используй его.` },
        { h: 'PTR — Цепь указателей', b: `Резолвит цепь указателей для динамических объектов.

Формат:  базовый_оффсет:оффсет1:оффсет2:оффсет3
Пример:  0x1A2B00:0x10:0x20:0x5C

Как работает:
1. module_base + 0x1A2B00 → читаем qword → адрес объекта
2. + 0x10 → читаем qword → следующий указатель
3. + 0x20 → читаем qword
4. + 0x5C → финальный адрес (поле структуры)

Используется когда объект создаётся динамически и его адрес меняется. Цепь через статический корневой указатель — постоянна.

История — последние 5 цепей, клик для повтора.` },
        { h: 'Экспорт .hpp', b: `После скана появляется кнопка "Экспорт .hpp".

Генерирует C++ заголовок:

namespace Offsets {
    constexpr uintptr_t match_0 = 0x1A2B00; // .text
}

Подключи в свой проект и используй оффсеты как константы.` },
        { h: '⚡ Сигнатуры (SIGS)', b: `Вкладка SIGS — автоматический дампер оффсетов по именованным паттернам.

Как найти паттерн:
1. Запусти игру и открой Cheat Engine
2. Найди нужное значение (здоровье, позиция и т.д.)
3. Клик правой кнопкой → "Find out what writes to this address"
4. В Memory Viewer берёшь байты вокруг инструкции
5. Изменяющиеся байты (адреса) заменяешь на ?

Пример:  48 89 88 ? ? ? ?

Поля сигнатуры:
  Name    — имя оффсета (dwLocalPlayer, m_iHealth)
  Module  — в каком .dll искать (client.dll, engine.dll)
  Pattern — AOB паттерн в IDA стиле
  Offset  — байт от начала совпадения до 4-байтного displacement
  Extra   — константа прибавляемая к результату
  Type    — RIP-relative (читать 4-байт displacement) или Absolute (RVA + offset)

Как использовать результат:
  dwLocalPlayer = 0x1A2B00  →  module_base + 0x1A2B00 = указатель на игрока
  m_iHealth     = 0x100     →  player_ptr + 0x100 = здоровье

В коде:
  uintptr_t player = read<uintptr_t>(base + Offsets::dwLocalPlayer);
  int health = read<int>(player + Offsets::m_iHealth);

Импорт конфига — загружаешь готовый config.json (совместим с hazedumper).
Batch Scan — один клик сканирует все сигнатуры сразу.
Экспорт — получаешь .hpp / .json / .cs / .py / .rs` },
        { h: 'Статический vs Динамический', b: `RVA (статический):
✓ Не меняется между запусками
✓ Работает после обновлений (если структура не изменилась)
✓ Используй как константу

Absolute Address (динамический):
✗ Меняется каждый запуск (ASLR)
✓ Полезен для отладки здесь и сейчас

AOB паттерн — самый надёжный:
✓ Работает после обновлений игры
✓ Ищет по сигнатуре, не по адресу
✓ RIP Target даёт финальный RVA автоматически` },
      ]
    },
    en: {
      title: 'Help',
      sections: [
        { h: 'What is an offset?', b: `An offset is the displacement from a module base address to a variable or function in memory.

Example: game.exe loads at 0x140000000, health is at 0x1401A2B00 → offset = 0x1A2B00.

Types:
• Static (RVA) — stable across runs
• Dynamic — changes every run due to ASLR, needs a pointer chain` },
        { h: 'PROC — Processes', b: `Lists all Windows processes.

Active — with a visible window (games, apps).
Background — system services.

Shortcuts:
  /  →  focus search
  click  →  action menu (Memory Scan, PTR Chain)
  double-click  →  go straight to Memory Scan

Auto-refresh updates every 3 seconds.` },
        { h: 'FILE — Static Analysis', b: `Analyzes a PE file (.exe/.dll) without running it.

Shows:
• ImageBase, EntryPoint
• Sections — .text (code), .data, .rdata
• AOB pattern matches with RVA

AOB pattern:  48 8B 05 ? ? ? ? 48 89
? — wildcard, any byte.

Found RVA is stable, independent of ASLR.
RIP Target — address referenced by the instruction.` },
        { h: 'MEM — Memory Scan', b: `Attaches to a live process via ReadProcessMemory.

Shows:
• Loaded modules (.exe + .dll) with bases
• AOB matches with absolute address and RVA

Note:
  Address — absolute, changes on restart!
  RVA = Address − ModuleBase — stable, use this.` },
        { h: 'PTR — Pointer Chain', b: `Resolves a pointer chain for dynamic objects.

Format:  base_offset:offset1:offset2:offset3
Example:  0x1A2B00:0x10:0x20:0x5C

How it works:
1. module_base + 0x1A2B00 → read qword → object address
2. + 0x10 → read qword → next pointer
3. + 0x20 → read qword
4. + 0x5C → final address (struct field)

Used when an object is heap-allocated and its address changes. The chain through a static root pointer is constant.

History — last 5 chains, click to reuse.` },
        { h: 'Export .hpp', b: `After scanning an "Export .hpp" button appears.

Generates a C++ header:

namespace Offsets {
    constexpr uintptr_t match_0 = 0x1A2B00; // .text
}

Include in your project and use offsets as constants.` },
        { h: '⚡ Signatures (SIGS)', b: `The SIGS tab is an automated offset dumper using named AOB patterns.

How to find a pattern:
1. Run the game and open Cheat Engine
2. Find the value you need (health, position, etc.)
3. Right-click → "Find out what writes to this address"
4. In Memory Viewer grab bytes around that instruction
5. Replace changing bytes (addresses) with ?

Example:  48 89 88 ? ? ? ?

Signature fields:
  Name    — offset label (dwLocalPlayer, m_iHealth)
  Module  — which .dll to scan (client.dll, engine.dll)
  Pattern — IDA-style AOB pattern
  Offset  — byte position from match start to the 4-byte displacement field
  Extra   — constant added to the final result
  Type    — RIP-relative (read 4-byte displacement) or Absolute (RVA + offset)

How to use results:
  dwLocalPlayer = 0x1A2B00  →  module_base + 0x1A2B00 = pointer to player object
  m_iHealth     = 0x100     →  player_ptr + 0x100 = health value

In code:
  uintptr_t player = read<uintptr_t>(base + Offsets::dwLocalPlayer);
  int health = read<int>(player + Offsets::m_iHealth);

Import config — load a ready-made config.json (hazedumper compatible).
Batch Scan — one click scans all signatures at once.
Export — get .hpp / .json / .cs / .py / .rs` },
        { h: 'Static vs Dynamic', b: `RVA (static):
✓ Doesn't change between runs
✓ Survives game updates (if structure unchanged)
✓ Use as a constant

Absolute Address (dynamic):
✗ Changes every run (ASLR)
✓ Useful for right-now debugging

AOB pattern — most reliable:
✓ Survives game updates
✓ Searches by signature, not address
✓ RIP Target gives the final RVA automatically` },
      ]
    },
    pt: {
      title: 'Ajuda',
      sections: [
        { h: 'O que e um offset?', b: `Deslocamento do endereco base de um modulo ate uma variavel na memoria.

Estatico (RVA): estavel entre execucoes.
Dinamico: muda por ASLR, precisa de cadeia de ponteiros.` },
        { h: 'PROC', b: `Lista processos. Ativos = janela visivel.
Atalho: / para busca, clique duplo = Memory Scan.
Auto-refresh atualiza a cada 3 segundos.` },
        { h: 'FILE — Analise Estatica', b: `Analisa PE sem executar. Mostra secoes, ImageBase e correspondencias AOB.
RVA encontrado e estavel independente do ASLR.
RIP Target: endereco referenciado pela instrucao.` },
        { h: 'MEM — Varredura de Memoria', b: `Conecta ao processo via ReadProcessMemory.
Mostra modulos carregados e correspondencias AOB.

Atencao: Address muda a cada reinicio!
Use RVA = Address menos ModuleBase.` },
        { h: 'PTR — Cadeia de Ponteiros', b: `Formato: base:off1:off2
Exemplo: 0x1A2B00:0x10:0x5C

Resolve cadeia de ponteiros para objetos dinamicos.
A cadeia via ponteiro raiz estatico e constante.
Historico: ultimas 5 cadeias, clique para reutilizar.` },
        { h: 'Exportar .hpp', b: `Gera arquivo C++ com offsets encontrados:

namespace Offsets {
    constexpr uintptr_t match_0 = 0x1A2B00;
}

Inclua no projeto e use como constantes.` },
        { h: '⚡ Assinaturas (SIGS)', b: `A aba SIGS e um dumper automatico de offsets usando padroes AOB nomeados.

Como encontrar um padrao:
1. Execute o jogo e abra o Cheat Engine
2. Encontre o valor desejado (vida, posicao, etc.)
3. Clique com botao direito → "Find out what writes to this address"
4. No Memory Viewer pegue os bytes ao redor da instrucao
5. Substitua bytes que mudam (enderecos) por ?

Exemplo:  48 89 88 ? ? ? ?

Campos da assinatura:
  Name    — nome do offset (dwLocalPlayer, m_iHealth)
  Module  — qual .dll escanear (client.dll, engine.dll)
  Pattern — padrao AOB no estilo IDA
  Offset  — posicao em bytes do inicio da correspondencia ao displacement
  Extra   — constante adicionada ao resultado final
  Type    — RIP-relativo ou Absoluto

Como usar os resultados:
  dwLocalPlayer = 0x1A2B00  →  module_base + 0x1A2B00 = ponteiro para o jogador
  m_iHealth     = 0x100     →  player_ptr + 0x100 = vida

Importar — carregue um config.json pronto (compativel com hazedumper).
Batch Scan — um clique escaneia todas as assinaturas de uma vez.
Exportar — obtenha .hpp / .json / .cs / .py / .rs` },
        { h: 'Estatico vs Dinamico', b: `RVA (estatico):
+  Nao muda entre execucoes
+  Sobrevive a atualizacoes do jogo
+  Use como constante

Endereco absoluto (dinamico):
-  Muda por ASLR
+  Util para depuracao imediata

Padrao AOB: mais confiavel, sobrevive a atualizacoes.` },
      ]
    },
    tr: {
      title: 'Yardim',
      sections: [
        { h: 'Offset nedir?', b: `Modul taban adresinden bellekteki degiskene mesafe.

Statik (RVA): calistirmalar arasinda sabit.
Dinamik: ASLR nedeniyle degisir, isaretci zinciri gerektirir.` },
        { h: 'PROC', b: `Islemleri listeler. Aktif = gorunen pencere.
Kisayol: / arama, cift tiklama = Memory Scan.
Otomatik yenileme her 3 saniyede bir.` },
        { h: 'FILE — Statik Analiz', b: `PE dosyasini calistirmadan analiz eder.
Bolumler, ImageBase ve AOB eslesmeleri gosterir.
Bulunan RVA ASLR'den bagimsiz olarak stabildir.` },
        { h: 'MEM — Bellek Taramasi', b: `ReadProcessMemory ile baglanir.
Yuklenen moduller ve AOB eslesmeleri gosterir.

Dikkat: Address her yeniden baslatmada degisir!
RVA = Address eksi ModulBase kullanin.` },
        { h: 'PTR — Isaretci Zinciri', b: `Format: taban:off1:off2
Ornek: 0x1A2B00:0x10:0x5C

Dinamik nesneler icin isaretci zincirini cozer.
Statik kok isaretci uzerinden zincir sabittir.
Gecmis: son 5 zincir, tekrarlamak icin tiklayin.` },
        { h: 'Disa Aktarma .hpp', b: `Bulunan offsetlerle C++ baslik dosyasi olusturur:

namespace Offsets {
    constexpr uintptr_t match_0 = 0x1A2B00;
}

Projenize dahil edin ve sabit deger olarak kullanin.` },
        { h: '⚡ Imzalar (SIGS)', b: `SIGS sekmesi, adlandirilmis AOB desenleri kullanan otomatik bir offset dumper'dir.

Desen nasil bulunur:
1. Oyunu ac ve Cheat Engine'i baslat
2. Ihtiyacin olan degeri bul (can, konum vb.)
3. Sag tik → "Find out what writes to this address"
4. Memory Viewer'da talimat etrafindaki baytlari al
5. Degisen baytlari (adresler) ? ile degistir

Ornek:  48 89 88 ? ? ? ?

Imza alanlari:
  Name    — offset adi (dwLocalPlayer, m_iHealth)
  Module  — hangi .dll taranacak (client.dll, engine.dll)
  Pattern — IDA stilinde AOB deseni
  Offset  — eslesme basindan 4 baytlik displacement'a bayt konumu
  Extra   — sonuca eklenen sabit
  Type    — RIP-goreceli veya Mutlak

Sonuclari nasil kullanirsiniz:
  dwLocalPlayer = 0x1A2B00  →  module_base + 0x1A2B00 = oyuncu isaretcisi
  m_iHealth     = 0x100     →  player_ptr + 0x100 = can degeri

Konfig ice aktar — hazedumper uyumlu config.json yukle.
Batch Scan — tek tiklama ile tum imzalari tara.
Disa aktar — .hpp / .json / .cs / .py / .rs al` },
        { h: 'Statik ve Dinamik', b: `RVA (statik):
+  Calistirmalar arasinda degismez
+  Oyun guncellemelerinden sonra da calisir
+  Sabit deger olarak kullanin

Mutlak adres (dinamik):
-  ASLR nedeniyle degisir
+  Anlik hata ayiklama icin yararli

AOB deseni: en guvenilir yontem.` },
      ]
    },
  }

  const d = data[lang] || data.en
  const sec = d.sections[active]

  return (
    <div className="page" style={{ display: visible ? '' : 'none' }}>
      <div className="page-header">
        <span className="page-title">{d.title}</span>
        <span style={{fontSize:11,color:'var(--text3)'}}>OffsetDumper v1.3</span>
      </div>
      <div className="readme-layout">
        {/* Nav */}
        <div className="readme-nav">
          {d.sections.map((s, i) => (
            <button key={i}
              className={`readme-nav-item${active===i?' active':''}`}
              onClick={() => setActive(i)}>
              {s.h}
            </button>
          ))}
        </div>
        {/* Content */}
        <div className="readme-content">
          <h3 className="readme-heading">{sec.h}</h3>
          <pre className="readme-body">{sec.b}</pre>
        </div>
      </div>
    </div>
  )
}

// ── Status bar ────────────────────────────────────────────────────────────────
function StatusBar({ proc }) {
  const t = useTr()
  return (
    <div className="statusbar">
      <span className="sb-left">
        {proc
          ? <><span className={`proc-dot${proc.active?' active':' bg'}`} style={{width:6,height:6}} />
              <span style={{marginLeft:5}}>{proc.name} · PID {proc.pid}</span></>
          : <span style={{color:'var(--text3)'}}>{t('noProcessSelected')}</span>
        }
      </span>
      <span className="sb-right">OffsetDumper v1.3</span>
    </div>
  )
}

// ── ROOT ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [lang, setLang] = useState('ru')
  const [tab, setTab]   = useState('processes')
  const [proc, setProc] = useState(null)
  const [logs, setLogs] = useState([])

  const addLog = useCallback((msg) => {
    const time = new Date().toTimeString().slice(0,8)
    const type = msg.startsWith('ERROR') ? 'err' : msg.startsWith('✓') ? 'ok' : 'info'
    setLogs(prev => [...prev.slice(-499), { msg, time, type }])
  }, [])

  return (
    <LangCtx.Provider value={lang}>
    <ProcCtx.Provider value={proc}>
    <SetProcCtx.Provider value={setProc}>
    <AddLogCtx.Provider value={addLog}>
    <SetTabCtx.Provider value={setTab}>
      <div className="app">
        <TitleBar lang={lang} setLang={setLang} />
        <BackendStatusBanner />
        <div className="app-body">
          <Sidebar active={tab} setActive={setTab} />
          <main className="main">
            {/* All pages always mounted — visibility via display:none */}
            <ProcessesPage visible={tab==='processes'} />
            <FilePage      visible={tab==='file'} />
            <MemoryPage    visible={tab==='memory'} />
            <ChainPage     visible={tab==='chain'} />
            <LogPage       visible={tab==='log'} logs={logs} clearLogs={() => setLogs([])} />
            <SigsPage      visible={tab==='sigs'} />
            <NetVarsPage   visible={tab==='netvars'} />
            <ReadmePage    visible={tab==='readme'} />
          </main>
        </div>
        <StatusBar proc={proc} />
      </div>
    </SetTabCtx.Provider>
    </AddLogCtx.Provider>
    </SetProcCtx.Provider>
    </ProcCtx.Provider>
    </LangCtx.Provider>
  )
}


// ── README PAGE ───────────────────────────────────────────────────────────────
// (appended after root export — imported via module re-evaluation)
