# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**spowerwk** is a decentralized LAN keep-alive system targeting school computer labs. It intercepts Windows shutdown commands and coordinates with peer nodes via UDP broadcast to ensure at least `min_nodes` machines remain active. Blocked shutdowns enter "Ghost Mode" — the machine appears off to the user but keeps running.

The system has two compiled components:
1. A **Python Windows service** (compiled via Nuitka) running as SYSTEM
2. A **C++ Hook DLL** (compiled via MSVC + MinHook) injected into `winlogon.exe`

## Commands

### Tests (Linux/dev environment)
```bash
# Run all tests
pytest tests/

# Run a single test file
pytest tests/test_crypto.py

# Run a single test case
pytest tests/test_crypto.py::test_encryption_decryption
```

Tests mock Windows-specific modules (`pywin32`), so they run on Linux. The `pythonpath` in `pytest.ini` adds both `.` and `src/service` so imports resolve correctly.

### Build (Windows only, via GitHub Actions)
The full build pipeline runs in CI. Three parallel jobs then merge:
1. **build-rva-db**: `python pdb/pdb_download.py winlogon.exe` → `python pdb/pdb2json.py` → LZMA compress
2. **build-dll**: `cl /LD ... src\hook\dllmain.cpp /I include /link lib\libMinHook.x64.lib ...`
3. **build-service**: Nuitka standalone on `src/service/main.py`
4. **build-installer**: Packs all artifacts into `payload.tar.xz`, then Nuitka onefile on `src/installer/install.py`

### RVA Database (Windows, requires LLVM)
```bash
python pdb/pdb_download.py winlogon.exe   # downloads PDBs from msdl.microsoft.com
python pdb/pdb2json.py                    # parses PDBs → unified_rva_db.json
```

## Architecture

### Component Interaction

```
winlogon.exe
  └── spowerwkHook.dll (injected by service via NtCreateThreadEx)
        └── Named Pipe \\.\pipe\spowerwk_ipc  (SYSTEM-only ACL)
              └── SpowerwkService (Python, SYSTEM)
                    ├── P2PManager   (UDP broadcast, port 45678)
                    └── HTTP log server (port 45679, serves log file)
```

### Shutdown Flow

1. `ShutdownWindowsWorkerThread` in `winlogon.exe` is hooked via MinHook
2. Hook sends `QUERY_SHUTDOWN\0` over named pipe and blocks
3. Python service calls `P2PManager.negotiate_shutdown()`:
   - Broadcasts `SHUTDOWN_INTENT` with a random weight via UDP
   - Waits `wait_window` seconds to collect peer intents
   - Sorts all intents descending; if this node's rank < `total_active - min_nodes`, allow
4. Service replies `ALLOW\0` or `BLOCK\0` on the pipe
5. If BLOCK: hook converts the call to `EWX_REBOOT | EWX_FORCE`

### IPC Protocol (Named Pipe)

On each connection the service immediately sends `RVA:<Shutdown>:<Display>:<SAS>\0` (hex RVAs). Then:
- DLL → Service: `LOG:<text>\0`, `QUERY_SHUTDOWN\0`, `PING\0`
- Service → DLL: `ALLOW\0`, `BLOCK\0`

### RVA Lookup

`winlogon.exe`'s PDB GUID+Age is extracted at runtime by parsing the PE Debug Directory (not byte-scanning — see `get_pdb_id()` in `main.py`). This is matched against `unified_rva_db.json.xz` to find the correct `ShutdownWindowsWorkerThread` RVA for this exact Windows build.

### DLL Injection

`injector.py` uses `NtCreateThreadEx` instead of `CreateRemoteThread` to bypass Win32 security callbacks (`PsSetCreateThreadNotifyRoutine`) that silently block injection into system processes. The DLL is **never unloaded** after injection — unloading while hook trampolines may be executing would BSOD.

### P2P & Encryption

All UDP packets are AES-256-GCM encrypted (PSK → SHA-256 → key). The PSK is configured in `spowerwk_config.json` at `C:\Program Files\spowerwk\spowerwk_config.json`. Ping interval is adaptive: `power` mode (default, concave/bowl-shaped) or `exp` mode scales from `ping_min_interval` to `ping_max_interval` based on active node count.

### CFG Compatibility

After installing hooks, the DLL registers all hook stub and trampoline pages as valid CFG call targets via `SetProcessValidCallTargets` (marking all 16-byte slots in each page as `CFG_CALL_TARGET_VALID`).

## Key Files

| File | Role |
|------|------|
| `src/service/main.py` | Service entry, IPC server loop, RVA lookup, injector loop |
| `src/service/p2p.py` | UDP broadcast, PING/WoL loop, shutdown negotiation |
| `src/service/crypto.py` | AES-GCM encrypt/decrypt for P2P messages |
| `src/service/injector.py` | DLL injection via NtCreateThreadEx |
| `src/hook/dllmain.cpp` | MinHook setup, pipe IPC, hooked shutdown function |
| `src/installer/install.py` | Unpacks payload.tar.xz, registers Windows service |
| `pdb/pdb_download.py` | Async batch PDB downloader from msdl.microsoft.com |
| `pdb/pdb2json.py` | Parses PDBs with llvm-pdbutil, builds RVA database |
| `include/MinHook.h` / `lib/libMinHook.*.lib` | MinHook static libs (x64 and x86) |

## Configuration (`spowerwk_config.json`)

```json
{
  "psk": "...",              // Pre-shared key — must match across all nodes
  "min_nodes": 1,            // Minimum alive nodes; below this all shutdowns are blocked
  "wait_window": 1.0,        // Seconds to collect peer SHUTDOWN_INTENT packets
  "port": 45678,             // UDP broadcast port
  "nodes": [{"ip":"...", "mac":"..."}],  // Full LAN node list for WoL
  "ping_interval_mode": "power",         // "fixed", "power", or "exp"
  "ping_min_interval": 1.0,
  "ping_max_interval": 5.0,
  "ping_interval_nodes": 10,
  "log_server_port": 45679,
  "log_level": "INFO",
  "log_max_size_mb": 1024
}
```
