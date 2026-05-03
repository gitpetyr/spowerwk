import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os
import json
import lzma
import struct
import threading
import logging
import time

log_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(
    filename=os.path.join(log_dir, 'spowerwk_service.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

import http.server
import socketserver

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def start_log_server(port, log_file_path):
    class LogHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.end_headers()
            try:
                with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.wfile.write(f.read().encode('utf-8'))
            except Exception as e:
                self.wfile.write(f"Error reading log: {e}".encode('utf-8'))
        def log_message(self, format, *args):
            pass

    def run_server():
        try:
            with ReusableTCPServer(("", port), LogHandler) as httpd:
                logging.info(f"Log HTTP server started on port {port}")
                httpd.serve_forever()
        except Exception as e:
            logging.error(f"Failed to start log HTTP server on port {port}: {e}")

    t = threading.Thread(target=run_server, daemon=True)
    t.start()

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

        if 'log_server_port' not in self.config:
            self.config['log_server_port'] = 45679

        try:
            port = int(self.config['log_server_port'])
            log_file_path = os.path.join(log_dir, 'spowerwk_service.log')
            start_log_server(port, log_file_path)
        except Exception as e:
            logging.error(f"Failed to setup log server: {e}")

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
        """
        Bug #13 fix: parse the PE Debug Directory properly instead of scanning
        for the first 'RSDS' byte sequence, which can false-match section data.
        Walks Optional Header -> Data Directory[6] (Debug) -> finds the
        IMAGE_DEBUG_TYPE_CODEVIEW (type=2) entry -> reads CV_INFO_PDB70.
        """
        try:
            with open(file_path, 'rb') as f:
                pe_data = f.read()

            # --- DOS header ---
            if len(pe_data) < 0x40 or pe_data[:2] != b'MZ':
                return None
            e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]

            # --- PE signature ---
            if pe_data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
                return None

            # Machine: 0x8664 = AMD64, 0x014C = x86
            machine = struct.unpack_from('<H', pe_data, e_lfanew + 4)[0]
            is_64bit = (machine == 0x8664)

            num_sections   = struct.unpack_from('<H', pe_data, e_lfanew + 6)[0]
            opt_hdr_size   = struct.unpack_from('<H', pe_data, e_lfanew + 20)[0]
            opt_hdr_offset = e_lfanew + 24

            # Data directories start at different offsets for PE32 vs PE32+
            dd_start = opt_hdr_offset + (112 if is_64bit else 96)
            # Debug directory is entry index 6
            debug_dd_offset = dd_start + 6 * 8
            debug_dir_rva  = struct.unpack_from('<I', pe_data, debug_dd_offset)[0]
            debug_dir_size = struct.unpack_from('<I', pe_data, debug_dd_offset + 4)[0]

            if debug_dir_rva == 0 or debug_dir_size == 0:
                return None

            # --- Section headers ---
            sections_offset = opt_hdr_offset + opt_hdr_size

            def rva_to_file_offset(rva):
                for i in range(num_sections):
                    base = sections_offset + i * 40
                    sec_rva      = struct.unpack_from('<I', pe_data, base + 12)[0]
                    sec_raw_size = struct.unpack_from('<I', pe_data, base + 16)[0]
                    sec_raw_off  = struct.unpack_from('<I', pe_data, base + 20)[0]
                    if sec_rva <= rva < sec_rva + sec_raw_size:
                        return sec_raw_off + (rva - sec_rva)
                return None

            debug_dir_file_off = rva_to_file_offset(debug_dir_rva)
            if debug_dir_file_off is None:
                return None

            # --- Walk IMAGE_DEBUG_DIRECTORY entries (each 28 bytes) ---
            num_entries = debug_dir_size // 28
            for i in range(num_entries):
                entry = debug_dir_file_off + i * 28
                debug_type  = struct.unpack_from('<I', pe_data, entry + 12)[0]
                # IMAGE_DEBUG_TYPE_CODEVIEW == 2
                if debug_type != 2:
                    continue
                # PointerToRawData (file offset, not RVA)
                data_off = struct.unpack_from('<I', pe_data, entry + 24)[0]

                if pe_data[data_off:data_off + 4] != b'RSDS':
                    continue

                guid_bytes = pe_data[data_off + 4: data_off + 20]
                age = struct.unpack_from('<I', pe_data, data_off + 20)[0]

                data1 = struct.unpack('<I', guid_bytes[0:4])[0]
                data2 = struct.unpack('<H', guid_bytes[4:6])[0]
                data3 = struct.unpack('<H', guid_bytes[6:8])[0]

                guid_str = f"{data1:08X}{data2:04X}{data3:04X}"
                for b in guid_bytes[8:16]:
                    guid_str += f"{b:02X}"

                return f"{guid_str}{age:X}"

            return None
        except Exception as e:
            logging.error(f"Failed to get PDB ID from {file_path}: {e}")
            return None

    def get_current_winlogon_rvas(self):
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
                msg = f"RVA:{s_rva}:{d_rva}\x00".encode('utf-8')
                win32file.WriteFile(pipe, msg)
                try:
                    win32file.FlushFileBuffers(pipe)
                except Exception:
                    pass
                
                while self.running:
                    try:
                        hr, data = win32file.ReadFile(pipe, 1024)
                        req = data.decode('utf-8').strip('\x00')
                        
                        if req == "QUERY_SHUTDOWN":
                            logging.info("Received QUERY_SHUTDOWN from DLL")
                            allow = self.p2p.negotiate_shutdown()
                            if allow:
                                logging.info("Decision: ALLOW. Sending ALLOW to DLL.")
                                win32file.WriteFile(pipe, b"ALLOW\x00")
                                try: win32file.FlushFileBuffers(pipe)
                                except: pass
                            else:
                                logging.info("Decision: BLOCK. Sending BLOCK to DLL and entering Ghost Mode.")
                                win32file.WriteFile(pipe, b"BLOCK\x00")
                                try: win32file.FlushFileBuffers(pipe)
                                except: pass
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
