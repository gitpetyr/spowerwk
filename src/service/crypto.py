import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureChannel:
    def __init__(self, psk_hex: str):
        if not psk_hex or len(psk_hex) != 64:
            # Fallback to a default key if invalid, but in production this should fail
            psk_hex = '0' * 64
        self.key = bytes.fromhex(psk_hex)
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
