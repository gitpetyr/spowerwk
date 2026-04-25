import pytest
from unittest.mock import patch, MagicMock
from src.service.p2p import P2PManager
from src.service.crypto import SecureChannel

@pytest.fixture
def mock_crypto():
    crypto = MagicMock(spec=SecureChannel)
    crypto.encrypt_message.side_effect = lambda x: b"enc_" + str(x).encode()
    crypto.decrypt_message.side_effect = lambda x: {} # Default empty dict
    return crypto

@pytest.fixture
def mock_socket():
    with patch('src.service.p2p.socket.socket') as mock_sock:
        yield mock_sock

def test_p2p_initialization(mock_crypto, mock_socket):
    config = {
        'nodes': [{'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55'}],
        'min_nodes': 2,
        'wait_window': 0.1,
        'port': 12345
    }
    
    manager = P2PManager(config, mock_crypto)
    
    assert manager.min_nodes == 2
    assert manager.broadcast_port == 12345
    assert len(manager.nodes) == 1
    
    # Check socket initialization
    mock_socket.return_value.bind.assert_called_once_with(('', 12345))

@patch('src.service.p2p.time.sleep', return_value=None)
def test_negotiate_shutdown_allow(mock_sleep, mock_crypto, mock_socket):
    config = {'min_nodes': 1, 'wait_window': 0.1}
    manager = P2PManager(config, mock_crypto)
    
    # Setup state: 2 active nodes, min_nodes=1, my_rank=0 (highest weight)
    manager.active_nodes = {'192.168.1.100', '192.168.1.101'}
    manager.intents = {'localhost': 0.9, '192.168.1.100': 0.5}
    
    # Force the intents to be used during negotiate_shutdown
    def add_mock_intents(*args):
        manager.intents['192.168.1.100'] = 0.5 # lower weight
    mock_sleep.side_effect = add_mock_intents
    
    # 2 total active, min_nodes 1 -> allowed_shutdowns = 1.
    with patch('src.service.p2p.random.random', return_value=0.9):
        result = manager.negotiate_shutdown()
        
    assert result is True

@patch('src.service.p2p.time.sleep', return_value=None)
def test_negotiate_shutdown_block(mock_sleep, mock_crypto, mock_socket):
    config = {'min_nodes': 2, 'wait_window': 0.1}
    manager = P2PManager(config, mock_crypto)
    
    def add_mock_intents(*args):
        manager.intents['192.168.1.100'] = 0.9 # higher weight
    mock_sleep.side_effect = add_mock_intents
    
    manager.active_nodes = {'192.168.1.100'} # only 2 total active including us
    
    with patch('src.service.p2p.random.random', return_value=0.5):
        result = manager.negotiate_shutdown()
        
    assert result is False
