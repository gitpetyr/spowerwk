import ctypes
import ctypes.wintypes
import subprocess
import time
import threading
import logging

user32   = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
ntdll    = ctypes.windll.ntdll
advapi32 = ctypes.windll.advapi32

# ---------------------------------------------------------------------------
# NT-level hard reboot via NtShutdownSystem(ShutdownReboot=1)
# This is the same call used by the DLL; it bypasses shutdown.exe entirely
# and issues an immediate reset without waiting for any process to respond.
# ---------------------------------------------------------------------------
_SE_SHUTDOWN_NAME = "SeShutdownPrivilege"
_TOKEN_ADJUST_PRIVILEGES = 0x0020
_TOKEN_QUERY             = 0x0008
_SE_PRIVILEGE_ENABLED    = 0x00000002

class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.wintypes.DWORD),
                ("HighPart", ctypes.c_long)]

class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID),
                ("Attributes", ctypes.wintypes.DWORD)]

class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD),
                ("Privileges",    _LUID_AND_ATTRIBUTES * 1)]

def _acquire_shutdown_privilege():
    """Elevate the current token with SeShutdownPrivilege."""
    hToken = ctypes.wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            _TOKEN_ADJUST_PRIVILEGES | _TOKEN_QUERY,
            ctypes.byref(hToken)):
        return
    luid = _LUID()
    advapi32.LookupPrivilegeValueW(None, _SE_SHUTDOWN_NAME, ctypes.byref(luid))
    tp = _TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = _SE_PRIVILEGE_ENABLED
    advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp),
                                   ctypes.sizeof(tp), None, None)
    kernel32.CloseHandle(hToken)

def hard_reboot():
    """
    Immediately reboot via NtShutdownSystem(ShutdownReboot=1).
    No graceful teardown, no shutdown.exe — equivalent to a hard reset.
    """
    logging.warning("[HardReboot] Acquiring SeShutdownPrivilege...")
    _acquire_shutdown_privilege()
    logging.warning("[HardReboot] Calling NtShutdownSystem(ShutdownReboot). System will reset NOW.")
    # ShutdownNoReboot=0, ShutdownReboot=1, ShutdownPowerOff=2
    ntdll.NtShutdownSystem(1)

def enter_ghost_mode():
    """
    Enters ghost mode:
    1. Block standard input
    2. Uninstall/Disable physical input and output devices via pnputil
    3. Mute volume
    NOTE: Monitor power-off is handled by the DLL (dllmain.cpp TurnOffDisplay)
          because it must run in Session 1 (winlogon context). Calling
          PostMessageW(HWND_BROADCAST, ...) from Session 0 (service) has no effect.
    """
    # 1. Block Input
    user32.BlockInput(True)
    
    # 2. Disable devices (Keyboard, Mouse, Monitor)
    disable_devices_by_class("Keyboard")
    disable_devices_by_class("Mouse")
    disable_devices_by_class("Monitor")
    
    # 3. Mute volume
    # VK_VOLUME_MUTE = 0xAD
    user32.keybd_event(0xAD, 0, 0, 0)
    user32.keybd_event(0xAD, 0, 2, 0)

def disable_devices_by_class(class_name):
    """
    Uses pnputil to disable all devices of a certain class.
    Available on Windows 10 and above.
    """
    try:
        # Get list of devices
        output = subprocess.check_output(["pnputil", "/enum-devices", "/class", class_name], text=True)
        instance_ids = []
        for line in output.splitlines():
            if "Instance ID:" in line or "实例 ID:" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    instance_ids.append(parts[1].strip())
        
        for iid in instance_ids:
            subprocess.run(["pnputil", "/disable-device", iid], capture_output=True)
    except Exception as e:
        pass


_ghost_watchdog_started = False
_ghost_watchdog_lock = threading.Lock()

def _ghost_power_watchdog():
    """
    Fallback watchdog for Ghost Mode:
    Monitors WMI Win32_PowerManagementEvent for power-button events.
    If detected while in ghost mode, triggers an immediate hard reboot.

    Win32_PowerManagementEvent.EventType values:
        4  = Entering suspend
        7  = Resume from suspend
        10 = Power status change (battery <-> AC)
        11 = OEM event
        18 = Resume (critical)
    We treat type 4 (suspend) and power-status changes as power-button signals.
    """
    logging.info("[GhostWatchdog] Power watchdog thread started.")
    try:
        import wmi
        c = wmi.WMI()
        watcher = c.Win32_PowerManagementEvent.watch_for()
        while True:
            try:
                event = watcher(timeout_ms=5000)
                if event is not None:
                    etype = getattr(event, 'EventType', -1)
                    logging.info(f"[GhostWatchdog] WMI PowerManagementEvent type={etype}")
                    # EventType 4 = Entering suspend (triggered by power button if set to sleep)
                    # EventType 10 = Power status change (AC disconnect = impending shutdown)
                    if etype in (4, 10, 11):
                        logging.warning("[GhostWatchdog] Power event during Ghost Mode! Forcing hard reboot.")
                        hard_reboot()
                        return
            except Exception:
                # Timeout or transient error, keep watching
                pass
    except ImportError:
        # wmi module not available; fall back to a basic shutdown.exe event log poll
        logging.warning("[GhostWatchdog] wmi module unavailable. Using shutdown event fallback.")
        _ghost_event_log_watchdog()
    except Exception as e:
        logging.error(f"[GhostWatchdog] WMI watcher error: {e}")


def _ghost_event_log_watchdog():
    """
    Ultra-simple fallback: poll every 3 seconds for System EventID 41
    (unexpected power loss) or EventID 1074 (shutdown initiated).
    If either appears with a timestamp newer than our ghost mode start, reboot.
    """
    import subprocess, re, datetime
    start_time = time.time()
    logging.info("[GhostWatchdog] Event log watchdog started.")
    while True:
        time.sleep(3)
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "System",
                 "/q:*[System[(EventID=41 or EventID=1074)]]",
                 "/c:1", "/rd:true", "/f:text"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                logging.warning("[GhostWatchdog] Detected power/shutdown event in System log. Rebooting.")
                hard_reboot()
                return
        except Exception:
            pass


def start_ghost_power_watchdog():
    """Start the ghost-mode power watchdog thread (idempotent)."""
    global _ghost_watchdog_started
    with _ghost_watchdog_lock:
        if _ghost_watchdog_started:
            return
        _ghost_watchdog_started = True
    t = threading.Thread(target=_ghost_power_watchdog, daemon=True, name="GhostPowerWatchdog")
    t.start()
    logging.info("[GhostWatchdog] Watchdog thread launched.")
