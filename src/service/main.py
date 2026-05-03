import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os
import json
import lzma
import threading
import logging
import time
import sys

log_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(
    filename=os.path.join(log_dir, 'spowerwk_service.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

from crypto import SecureChannel
from p2p import P2PManager
from hardware import enter_ghost_mode
from injector import ensure_injected

import win32file
import win32pipe

class SpowerwkService(win32serviceutil.ServiceFramework):
    _svc_name_ = "spowerwk"
    _svc_display_name_ = "Windows 电源管理服务"
    _svc_description_ = "Windows 高级电源状态管理服务。"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
        self.config = {}
        self.rva_db = {}
        self.p2p = None
        self.pipe_connected = False

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        logging.info("Spowerwk Service Starting...")
        self.main()

    def load_config(self):
        config_path = os.path.join(os.path.dirname(sys.executable), 'spowerwk_config.json')
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    self.config = json.load(f)
            except Exception:
                pass
        
        # Defaults
        if 'psk' not in self.config:
            self.config['psk'] = 'default_secure_password_please_change'
        if 'min_nodes' not in self.config:
            self.config['min_nodes'] = 1
        if 'wait_window' not in self.config:
            self.config['wait_window'] = 1.0
        if 'port' not in self.config:
            self.config['port'] = 45678

    def load_rva_db(self):
        xz_path = os.path.join(os.path.dirname(sys.executable), 'unified_rva_db.json.xz')
        
        if not os.path.exists(xz_path):
            xz_path = 'unified_rva_db.json.xz' # Fallback for dev
            
        if os.path.exists(xz_path):
            try:
                with lzma.open(xz_path, 'rt', encoding='utf-8') as f:
                    self.rva_db = json.load(f)
            except Exception:
                pass

    def get_pdb_id(self, file_path):
        import struct
        try:
            with open(file_path, 'rb') as f:
                pe_data = f.read()
            rsds_idx = pe_data.find(b'RSDS')
            if rsds_idx == -1:
                return None

            guid_bytes = pe_data[rsds_idx+4 : rsds_idx+20]
            age = struct.unpack("<I", pe_data[rsds_idx+20 : rsds_idx+24])[0]

            data1 = struct.unpack("<I", guid_bytes[0:4])[0]
            data2 = struct.unpack("<H", guid_bytes[4:6])[0]
            data3 = struct.unpack("<H", guid_bytes[6:8])[0]
            
            guid_str = f"{data1:08X}{data2:04X}{data3:04X}"
            for b in guid_bytes[8:16]:
                guid_str += f"{b:02X}"
            
            return f"{guid_str}{age:X}"
        except Exception as e:
            logging.error(f"Failed to get PDB ID from {file_path}: {e}")
            return None

    def get_current_winlogon_rvas(self):
        import os
        shutdown_rva = "0"
        display_rva = "0"
        
        winlogon_path = r"C:\Windows\System32\winlogon.exe"
        if os.path.exists(r"C:\Windows\sysnative\winlogon.exe"):
            winlogon_path = r"C:\Windows\sysnative\winlogon.exe"
            
        pdb_id = self.get_pdb_id(winlogon_path)
        
        if pdb_id and "winlogon.pdb" in self.rva_db:
            if pdb_id in self.rva_db["winlogon.pdb"]:
                pdb_info = self.rva_db["winlogon.pdb"][pdb_id]
                
                # 使用用户提供的正确的 Mangled 符号名
                shutdown_mangled = "?ShutdownWindowsWorkerThread@@YAXPEAU_TP_CALLBACK_INSTANCE@@PEAX@Z"
                display_mangled = "?WlDisplayStatusByResourceId@@YAKIW4_WLUI_STATE@@KPEAVCUser@@@Z"
                
                shutdown_rva = pdb_info.get(shutdown_mangled, "0")
                display_rva = pdb_info.get(display_mangled, "0")
                
                logging.info(f"Matched winlogon.exe PDB {pdb_id}. RVAs -> Shutdown: {shutdown_rva}, Display: {display_rva}")
            else:
                logging.warning(f"Winlogon PDB ID {pdb_id} not found in database. Hooking disabled to prevent crash.")
        else:
            logging.warning("Failed to extract PDB ID or missing database. Hooking disabled.")
        
        return shutdown_rva, display_rva

    def ipc_server_loop(self):
        pipe_name = r'\\.\pipe\spowerwk_ipc'
        
        while self.running:
            try:
                pipe = win32pipe.CreateNamedPipe(
                    pipe_name,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, 65536, 65536, 0, None)
                
                win32pipe.ConnectNamedPipe(pipe, None)
                self.pipe_connected = True
                
                # Send RVAs
                s_rva, d_rva = self.get_current_winlogon_rvas()
                # Format "RVA:<Shutdown>:<Display>"
                # remove 0x prefix if present
                s_rva = s_rva.replace('0x', '')
                d_rva = d_rva.replace('0x', '')
                msg = f"RVA:{s_rva}:{d_rva}".encode('utf-8')
                win32file.WriteFile(pipe, msg)
                
                while self.running:
                    try:
                        hr, data = win32file.ReadFile(pipe, 1024)
                        req = data.decode('utf-8').strip('\x00')
                        
                        if req == "QUERY_SHUTDOWN":
                            logging.info("Received QUERY_SHUTDOWN from DLL")
                            allow = self.p2p.negotiate_shutdown()
                            if allow:
                                logging.info("Decision: ALLOW. Sending ALLOW to DLL.")
                                win32file.WriteFile(pipe, b"ALLOW")
                            else:
                                logging.info("Decision: BLOCK. Sending BLOCK to DLL and entering Ghost Mode.")
                                win32file.WriteFile(pipe, b"BLOCK")
                                enter_ghost_mode()
                                
                        elif req == "PING":
                            pass # Heartbeat
                            
                    except Exception:
                        break # Pipe broken
                        
            except Exception:
                pass
            finally:
                self.pipe_connected = False
                try:
                    win32file.CloseHandle(pipe)
                except Exception:
                    pass
            
            time.sleep(1)

    def injector_loop(self):
        dll_path = os.path.join(os.path.dirname(sys.executable), 'spowerwkHook.dll')
        
        if not os.path.exists(dll_path):
            dll_path = os.path.abspath('build/Release/spowerwkHook.dll')
            
        while self.running:
            if not self.pipe_connected:
                # Give it a chance to connect first, otherwise inject
                time.sleep(2)
                if not self.pipe_connected:
                    ensure_injected(dll_path)
            time.sleep(10)

    def main(self):
        self.load_config()
        self.load_rva_db()
        
        crypto = SecureChannel(self.config['psk'])
        self.p2p = P2PManager(self.config, crypto)
        
        t_ipc = threading.Thread(target=self.ipc_server_loop, daemon=True)
        t_ipc.start()
        
        t_inj = threading.Thread(target=self.injector_loop, daemon=True)
        t_inj.start()
        
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SpowerwkService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SpowerwkService)
