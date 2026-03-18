# Changelog

All notable changes to OffsetDumper are documented here.

## [v1.3.0] — 2026-03-18

### Added
- **Watchdog**: backend auto-restarts on crash (up to 5 attempts), UI shows restart status
- **Admin rights check**: warning banner if app runs without admin privileges
- **Separate stderr channel**: backend crash messages no longer corrupt the IPC JSON stream
- **Smart timeouts**: regular commands 30s, heavy scans (batch_scan, netvar_dump, ue4_dump) 2 min
- **Visual PTR Chain Builder**: add/remove chain links with buttons instead of raw text input
- **Named chain history**: chains now have optional labels; history persists across sessions via localStorage (up to 20 entries) with clear button
- **AOB pattern live validation**: SigEditor validates pattern tokens in real-time; Save button disabled on invalid input; byte count shown
- **GitHub Actions CI**: automatic C++ backend build + Electron installer on every push; auto-release on `v*` tags with SHA256 checksum
- **`backend:log` IPC channel**: backend stderr forwarded to renderer log panel

### Changed
- `electron/preload.js`: new events `onBackendStatus`, `onBackendLog`, `onNoAdmin`
- `.gitignore`: `offset_backend.exe` excluded from repo (built via CI or locally)
- Command timeouts now per-command-type instead of flat 15s

### Fixed
- Non-JSON output from backend (crash text) no longer breaks the IPC line parser
- App no longer hangs indefinitely on heavy scan commands

---

## [v1.2.0] — (original release)

### Added
- PROC, FILE, MEM, PTR, SIGS, NET tabs
- Source Engine x64/x86 netvar dumper
- Unreal Engine 4/5 and Unity IL2CPP dumpers
- Batch AOB scanner (hazedumper-compatible)
- Export to C++, JSON, C#, Python, Rust
- RU / EN / PT / TR localization
- Signature persistence via localStorage
