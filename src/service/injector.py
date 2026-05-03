import ctypes
import ctypes.wintypes
import psutil
import os
import time

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
        return False

    # Use UTF-16LE + LoadLibraryW so paths with non-ASCII characters work.
    dll_path_bytes = (dll_path + '\0').encode('utf-16-le')
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        return False

    arg_address = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes),
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not arg_address:
        kernel32.CloseHandle(h_process)
        return False

    written = ctypes.c_size_t(0)
    kernel32.WriteProcessMemory(h_process, arg_address, dll_path_bytes,
                                 len(dll_path_bytes), ctypes.byref(written))

    h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
    # Use LoadLibraryW to match the UTF-16LE path encoding
    h_loadlib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")

    thread_id = ctypes.wintypes.DWORD(0)
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib,
                                            arg_address, 0, ctypes.byref(thread_id))

    if h_thread:
        kernel32.WaitForSingleObject(h_thread, 5000)
        kernel32.CloseHandle(h_thread)

    kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
    kernel32.CloseHandle(h_process)
    return True

def ensure_injected(dll_path):
    pid = get_pid("winlogon.exe")
    if not pid:
        return

    # Bug #7 fix: check whether the DLL is already loaded before injecting again.
    # Without this check, every call would inject a second copy, causing multiple
    # MH_Initialize() calls and undefined hook behavior that can crash winlogon.exe.
    dll_basename = os.path.basename(dll_path).lower()
    if is_dll_injected(pid, dll_basename):
        return

    inject_dll(pid, dll_path)
