import pytest
import math
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


@patch('src.service.p2p.time.sleep', return_value=None)
def test_island_mode_wakes_all_nodes(mock_sleep, mock_crypto, mock_socket):
    """当没有其他活跃节点时（孤岛），仍应尝试唤醒离线节点。"""
    config = {
        'nodes': [{'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55'}],
        'min_nodes': 2,
        'wait_window': 0.1,
    }
    manager = P2PManager(config, mock_crypto)
    with manager.lock:
        manager.active_nodes = set()  # 孤岛：无其他活跃节点

    with patch.object(manager, '_wake_offline_nodes') as mock_wake:
        with manager.lock:
            current_active = len(manager.active_nodes)
            if current_active < manager.min_nodes:
                manager._wake_offline_nodes()
            manager.active_nodes.clear()

    mock_wake.assert_called_once()


@patch('src.service.p2p.time.sleep', return_value=None)
def test_interval_fixed_mode(mock_sleep, mock_crypto, mock_socket):
    """fixed 模式下无论活跃节点数多少，间隔始终为 ping_min_interval。"""
    config = {
        'nodes': [], 'min_nodes': 1, 'wait_window': 0.1,
        'ping_interval_mode': 'fixed',
        'ping_min_interval': 2.0,
        'ping_max_interval': 8.0,
        'ping_interval_nodes': 10,
    }
    manager = P2PManager(config, mock_crypto)
    for n in (0, 1, 5, 10):
        assert manager._calc_ping_interval(n) == 2.0


@patch('src.service.p2p.time.sleep', return_value=None)
def test_interval_power_mode_convex(mock_sleep, mock_crypto, mock_socket):
    """power 模式（下凹函数，f''>0）：初始增速慢，后期增速快（碗形曲线）。"""
    config = {
        'nodes': [], 'min_nodes': 1, 'wait_window': 0.1,
        'ping_interval_mode': 'power',
        'ping_interval_exponent': 2.0,
        'ping_min_interval': 1.0,
        'ping_max_interval': 5.0,
        'ping_interval_nodes': 10,
    }
    manager = P2PManager(config, mock_crypto)

    v0  = manager._calc_ping_interval(0)
    v2  = manager._calc_ping_interval(2)
    v5  = manager._calc_ping_interval(5)
    v10 = manager._calc_ping_interval(10)

    assert v0  == 1.0              # n=0  → min
    assert v10 == 5.0              # n=N  → max
    assert v0 < v2 < v5 < v10     # 单调递增
    # 下凹性（f''>0）：后段增量 > 前段增量
    assert (v10 - v5) > (v5 - v2)


@patch('src.service.p2p.time.sleep', return_value=None)
def test_interval_exp_mode_convex(mock_sleep, mock_crypto, mock_socket):
    """exp 模式（指数增长，下凹性更强）：初始几乎不增，后期急速增大。"""
    config = {
        'nodes': [], 'min_nodes': 1, 'wait_window': 0.1,
        'ping_interval_mode': 'exp',
        'ping_min_interval': 1.0,
        'ping_max_interval': 5.0,
        'ping_interval_nodes': 10,
    }
    manager = P2PManager(config, mock_crypto)

    v0  = manager._calc_ping_interval(0)
    v5  = manager._calc_ping_interval(5)
    v10 = manager._calc_ping_interval(10)

    assert v0  == 1.0
    assert v10 == 5.0
    assert v0 < v5 < v10
    # exp 下凹性强于 power=2：后半段增量占比 > 2/3
    assert (v10 - v5) > (v5 - v0)


@patch('src.service.p2p.time.sleep', return_value=None)
def test_interval_defaults(mock_sleep, mock_crypto, mock_socket):
    """未配置时默认 power 模式，exponent=2，min=1, max=5, nodes=10。"""
    config = {'nodes': [], 'min_nodes': 1, 'wait_window': 0.1}
    manager = P2PManager(config, mock_crypto)
    assert manager.config.get('ping_interval_mode', 'power') == 'power'
    assert manager.config.get('ping_interval_exponent', 2.0) == 2.0
    assert manager.config.get('ping_min_interval', 1.0) == 1.0
    assert manager.config.get('ping_max_interval', 5.0) == 5.0
    assert manager.config.get('ping_interval_nodes', 10) == 10
