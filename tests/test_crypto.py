import pytest
from src.service.crypto import SecureChannel

def test_encryption_decryption():
    channel = SecureChannel("test_key")
    data = {"type": "PING", "weight": 0.5}
    
    encrypted = channel.encrypt_message(data)
    assert isinstance(encrypted, bytes)
    
    decrypted = channel.decrypt_message(encrypted)
    assert decrypted == data

def test_decryption_invalid_data():
    channel = SecureChannel("test_key")
    
    # Too short
    assert channel.decrypt_message(b"short") == {}
    
    # Invalid data
    assert channel.decrypt_message(b"123456789012invalid_data") == {}

def test_default_key():
    channel1 = SecureChannel("")
    channel2 = SecureChannel("default_spowerwk_key")
    
    data = {"test": 123}
    encrypted = channel1.encrypt_message(data)
    decrypted = channel2.decrypt_message(encrypted)
    
    assert decrypted == data
