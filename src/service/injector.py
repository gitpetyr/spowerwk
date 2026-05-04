import ctypes
import ctypes.wintypes
import psutil
import os
import time
import logging

kernel32 = ctypes.windll.kernel32

# Bug #6 fix: set correct restype for functions that return pointers/handles.
# Without this, on 64-bit Windows ctypes defaults to c_int (32-bit), truncating
# any address above 4 GB and causing crashes or writes to wrong memory locations.
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]

kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                     ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]

kernel32.WriteProcessMemory.restype = ctypes.wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

kernel32.GetModuleHandleW.restype = ctypes.c_void_p
kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]

kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

kernel32.CreateRemoteThread.restype = ctypes.c_void_p
kernel32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                         ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]

kernel32.WaitForSingleObject.restype = ctypes.wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD]

kernel32.GetExitCodeThread.restype = ctypes.wintypes.BOOL
kernel32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.DWORD)]

kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

kernel32.VirtualFreeEx.restype = ctypes.wintypes.BOOL
kernel32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.wintypes.DWORD]

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000
PAGE_READWRITE = 0x04

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

    # Use UTF-16LE + LoadLibraryW so paths with non-ASCII characters work.
    dll_path_bytes = (dll_path + '\0').encode('utf-16-le')
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        err = ctypes.get_last_error()
        logging.error(f"inject_dll: OpenProcess(pid={pid}) failed. LastError={err}")
        return False

    arg_address = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes),
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not arg_address:
        err = ctypes.get_last_error()
        logging.error(f"inject_dll: VirtualAllocEx failed. LastError={err}")
        kernel32.CloseHandle(h_process)
        return False

    written = ctypes.c_size_t(0)
    ok = kernel32.WriteProcessMemory(h_process, arg_address, dll_path_bytes,
                                     len(dll_path_bytes), ctypes.byref(written))
    if not ok or written.value != len(dll_path_bytes):
        err = ctypes.get_last_error()
        logging.error(f"inject_dll: WriteProcessMemory failed (wrote {written.value}/{len(dll_path_bytes)} bytes). LastError={err}")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
    # Use LoadLibraryW to match the UTF-16LE path encoding
    h_loadlib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
    if not h_loadlib:
        logging.error("inject_dll: GetProcAddress(LoadLibraryW) returned NULL")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    thread_id = ctypes.wintypes.DWORD(0)
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib,
                                            arg_address, 0, ctypes.byref(thread_id))
    if not h_thread:
        err = ctypes.get_last_error()
        logging.error(f"inject_dll: CreateRemoteThread failed. LastError={err}")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    wait_result = kernel32.WaitForSingleObject(h_thread, 5000)
    if wait_result != 0:  # WAIT_OBJECT_0 == 0
        logging.warning(f"inject_dll: WaitForSingleObject returned {wait_result:#x} (timeout or error)")

    # LoadLibraryW returns the HMODULE as the thread exit code; 0 means it failed.
    exit_code = ctypes.wintypes.DWORD(0)
    kernel32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
    if exit_code.value == 0:
        logging.error("inject_dll: LoadLibraryW returned NULL in remote process — DLL failed to load (bad path, blocked by policy, missing dependency, etc.)")
        kernel32.CloseHandle(h_thread)
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False
    else:
        logging.info(f"inject_dll: LoadLibraryW returned HMODULE={exit_code.value:#x} — DLL loaded OK.")

    kernel32.CloseHandle(h_thread)
    kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
    kernel32.CloseHandle(h_process)
    return True

def ensure_injected(dll_path):
    pid = get_pid("winlogon.exe")
    if not pid:
        logging.warning("ensure_injected: winlogon.exe not found, skipping injection.")
        return

    # Bug #7 fix: check whether the DLL is already loaded before injecting again.
    # Without this check, every call would inject a second copy, causing multiple
    # MH_Initialize() calls and undefined hook behavior that can crash winlogon.exe.
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
