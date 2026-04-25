import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureChannel:
    def __init__(self, psk_str: str):
        if not psk_str:
            psk_str = 'default_spowerwk_key'
        
        # Hash the plain string to get a 32-byte (256-bit) key for AESGCM
        self.key = hashlib.sha256(psk_str.encode('utf-8')).digest()
        self.aesgcm = AESGCM(self.key)

    def encrypt_message(self, data: dict) -> bytes:
        nonce = os.urandom(12)
        payload = json.dumps(data).encode('utf-8')
        ciphertext = self.aesgcm.encrypt(nonce, payload, None)
        return nonce + ciphertext

    def decrypt_message(self, data: bytes) -> dict:
        if len(data) < 12:
            return {}
        nonce = data[:12]
        ciphertext = data[12:]
        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode('utf-8'))
        except Exception:
            return {}
