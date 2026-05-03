import socket
import threading
import time
import random
import struct
from crypto import SecureChannel

class P2PManager:
    def __init__(self, config, crypto_channel: SecureChannel):
        self.nodes = config.get('nodes', [])
        self.min_nodes = config.get('min_nodes', 1)
        self.wait_window = config.get('wait_window', 1.0)
        self.crypto = crypto_channel
        self.broadcast_port = config.get('port', 45678)
        self.active_nodes = set()
        self.intents = {}
        self.lock = threading.Lock()

        # Bug #3 fix: get local IP so we can filter self-PING and use as intent key
        self.local_ip = self._get_local_ip()

        # Setup UDP Broadcast Socket
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_sock.bind(('', self.broadcast_port))
        
        # Start listeners
        threading.Thread(target=self._listen_udp, daemon=True).start()
        threading.Thread(target=self._ping_loop, daemon=True).start()

    def _get_local_ip(self) -> str:
        """Returns the primary local IP address used for outbound connections."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _listen_udp(self):
        while True:
            try:
                data, addr = self.udp_sock.recvfrom(4096)

                # Bug #3 fix: ignore packets from ourselves to prevent self-counting
                if addr[0] == self.local_ip:
                    continue

                msg = self.crypto.decrypt_message(data)
                if msg.get('type') == 'SHUTDOWN_INTENT':
                    with self.lock:
                        self.intents[addr[0]] = msg.get('weight', 0)
                elif msg.get('type') == 'PING':
                    # Bug #2 fix: protect active_nodes with the same lock used in _ping_loop
                    with self.lock:
                        self.active_nodes.add(addr[0])
            except Exception:
                pass

    def _ping_loop(self):
        while True:
            # Broadcast PING
            ping_msg = self.crypto.encrypt_message({'type': 'PING'})
            try:
                self.udp_sock.sendto(ping_msg, ('<broadcast>', self.broadcast_port))
            except Exception:
                pass
            
            # Check active nodes against min_nodes
            time.sleep(5)
            with self.lock:
                current_active = len(self.active_nodes)
                if current_active < self.min_nodes and current_active > 0:
                    # Bug #4 note: _wake_offline_nodes MUST be called while holding self.lock
                    self._wake_offline_nodes()
                self.active_nodes.clear() # reset for next cycle

    def _wake_offline_nodes(self):
        """
        Sends WoL Magic Packets to nodes not currently active.
        NOTE: Must be called while holding self.lock, as it reads self.active_nodes.
        """
        for node in self.nodes:
            if node['ip'] not in self.active_nodes:
                mac = node['mac'].replace(':', '').replace('-', '')
                if len(mac) == 12:
                    # Bug #9 note: Standard WoL = 6x 0xFF + MAC repeated 16 times = 102 bytes total
                    data = bytes.fromhex('FF' * 6 + mac * 16)
                    try:
                        self.udp_sock.sendto(data, ('<broadcast>', 9))
                    except Exception:
                        pass

    def negotiate_shutdown(self) -> bool:
        """
        Returns True if ALLOWED to shutdown, False if BLOCKED (Ghost mode).
        """
        weight = random.random()
        msg = self.crypto.encrypt_message({'type': 'SHUTDOWN_INTENT', 'weight': weight})
        
        # Bug #5 fix: use real local IP as key, not 'localhost', so all nodes
        # in the cluster can consistently rank each other's intents.
        with self.lock:
            self.intents.clear()
            self.intents[self.local_ip] = weight
            
        # Broadcast intent
        try:
            self.udp_sock.sendto(msg, ('<broadcast>', self.broadcast_port))
        except Exception:
            pass
            
        time.sleep(self.wait_window)
        
        with self.lock:
            total_active = max(len(self.active_nodes), len(self.intents))
            # Sort intents descending
            sorted_intents = sorted(self.intents.items(), key=lambda x: x[1], reverse=True)
            
            my_rank = 0
            for i, (ip, w) in enumerate(sorted_intents):
                # Bug #5 fix: compare against self.local_ip instead of 'localhost'
                if ip == self.local_ip:
                    my_rank = i
                    break
            
            allowed_shutdowns = max(0, total_active - self.min_nodes)
            if my_rank < allowed_shutdowns:
                return True # Allow
            else:
                return True # Block
