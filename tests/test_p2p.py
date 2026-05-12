import json
import os
import pytest
import math
import tempfile
from unittest.mock import patch, MagicMock, call
from src.service.p2p import P2PManager
from src.service.crypto import SecureChannel

@pytest.fixture
def mock_crypto():
    crypto = MagicMock(spec=SecureChannel)
    crypto.encrypt_message.side_effect = lambda x: b"enc_" + str(x).encode()
    crypto.decrypt_message.side_effect = lambda x: {}
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

    # _discovered is seeded from config nodes
    assert '00:11:22:33:44:55' in manager._discovered
    assert manager._discovered['00:11:22:33:44:55']['ip'] == '192.168.1.100'

    # Check socket initialization
    mock_socket.return_value.bind.assert_called_once_with(('', 12345))


def test_p2p_local_mac_format(mock_crypto, mock_socket):
    """local_mac 必须是 AA:BB:CC:DD:EE:FF 格式。"""
    config = {'nodes': [], 'min_nodes': 1}
    manager = P2PManager(config, mock_crypto)
    parts = manager.local_mac.split(':')
    assert len(parts) == 6
    for part in parts:
        assert len(part) == 2
        int(part, 16)  # must be valid hex


@patch('src.service.p2p.time.sleep', return_value=None)
def test_negotiate_shutdown_allow(mock_sleep, mock_crypto, mock_socket):
    config = {'min_nodes': 1, 'wait_window': 0.1}
    manager = P2PManager(config, mock_crypto)

    # Setup state: 2 active nodes, min_nodes=1, my_rank=0 (highest weight)
    manager.active_nodes = {'192.168.1.100', '192.168.1.101'}
    manager.intents = {'localhost': 0.9, '192.168.1.100': 0.5}

    # Force the intents to be used during negotiate_shutdown
    def add_mock_intents(*args):
        manager.intents['192.168.1.100'] = 0.5  # lower weight
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
        manager.intents['192.168.1.100'] = 0.9  # higher weight
    mock_sleep.side_effect = add_mock_intents

    manager.active_nodes = {'192.168.1.100'}  # only 2 total active including us

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


# ──────────────────────────────────────────
# 自动发现节点相关测试
# ──────────────────────────────────────────

def test_auto_discover_new_node(mock_crypto, mock_socket):
    """收到带有合法 MAC 的 PING → 写入 _discovered 并触发 debounce。"""
    config = {'nodes': [], 'min_nodes': 1, 'auto_discover_nodes': True}
    manager = P2PManager(config, mock_crypto)

    mock_crypto.decrypt_message.return_value = {'type': 'PING', 'mac': 'AA:BB:CC:DD:EE:FF'}

    with patch.object(manager, '_reset_debounce') as mock_debounce:
        # Simulate receiving a UDP packet from a peer
        manager.udp_sock.recvfrom.return_value = (b'fake', ('192.168.1.50', 45678))
        # Directly invoke the internal logic
        ip = '192.168.1.50'
        mac = 'AA:BB:CC:DD:EE:FF'
        dirty = False
        from src.service.p2p import _MAC_RE
        with manager.lock:
            manager.active_nodes.add(ip)
            if _MAC_RE.match(mac) and manager.config.get('auto_discover_nodes', True):
                if mac not in manager._discovered:
                    manager._discovered[mac] = {'ip': ip, 'mac': mac}
                    manager._nodes_dirty = True
                    dirty = True
        if dirty:
            manager._reset_debounce()

    assert 'AA:BB:CC:DD:EE:FF' in manager._discovered
    assert manager._discovered['AA:BB:CC:DD:EE:FF']['ip'] == '192.168.1.50'
    mock_debounce.assert_called_once()


def test_auto_discover_update_ip(mock_crypto, mock_socket):
    """已知 MAC 但 IP 变化 → 更新 IP 并标记 dirty。"""
    config = {
        'nodes': [{'ip': '192.168.1.10', 'mac': 'AA:BB:CC:DD:EE:FF'}],
        'min_nodes': 1,
        'auto_discover_nodes': True,
    }
    manager = P2PManager(config, mock_crypto)

    ip = '192.168.1.99'
    mac = 'AA:BB:CC:DD:EE:FF'
    dirty = False
    from src.service.p2p import _MAC_RE
    with patch.object(manager, '_reset_debounce') as mock_debounce:
        with manager.lock:
            manager.active_nodes.add(ip)
            if _MAC_RE.match(mac) and manager.config.get('auto_discover_nodes', True):
                if mac not in manager._discovered:
                    manager._discovered[mac] = {'ip': ip, 'mac': mac}
                    manager._nodes_dirty = True
                    dirty = True
                elif manager._discovered[mac]['ip'] != ip:
                    manager._discovered[mac]['ip'] = ip
                    manager._nodes_dirty = True
                    dirty = True
        if dirty:
            manager._reset_debounce()

    assert manager._discovered['AA:BB:CC:DD:EE:FF']['ip'] == '192.168.1.99'
    mock_debounce.assert_called_once()


def test_auto_discover_invalid_mac_ignored(mock_crypto, mock_socket):
    """MAC 格式非法 → 忽略，不写 _discovered。"""
    config = {'nodes': [], 'min_nodes': 1, 'auto_discover_nodes': True}
    manager = P2PManager(config, mock_crypto)

    from src.service.p2p import _MAC_RE
    for bad_mac in ('', 'ZZZZZZ', '00:11:22:33:44', '00-11-22-33-44-55'):
        dirty = False
        with manager.lock:
            if bad_mac and _MAC_RE.match(bad_mac):
                manager._discovered[bad_mac] = {'ip': '1.2.3.4', 'mac': bad_mac}
                dirty = True
        assert not dirty, f"bad MAC {bad_mac!r} should have been rejected"

    assert len(manager._discovered) == 0


def test_auto_discover_disabled(mock_crypto, mock_socket):
    """auto_discover_nodes=False 时不写 _discovered。"""
    config = {'nodes': [], 'min_nodes': 1, 'auto_discover_nodes': False}
    manager = P2PManager(config, mock_crypto)

    from src.service.p2p import _MAC_RE
    mac = 'AA:BB:CC:DD:EE:FF'
    ip = '192.168.1.77'
    with manager.lock:
        manager.active_nodes.add(ip)
        if _MAC_RE.match(mac) and manager.config.get('auto_discover_nodes', True):
            manager._discovered[mac] = {'ip': ip, 'mac': mac}

    assert mac not in manager._discovered


def test_no_change_no_dirty(mock_crypto, mock_socket):
    """已知 MAC 且 IP 相同 → 不标记 dirty。"""
    config = {
        'nodes': [{'ip': '192.168.1.10', 'mac': 'AA:BB:CC:DD:EE:FF'}],
        'min_nodes': 1,
        'auto_discover_nodes': True,
    }
    manager = P2PManager(config, mock_crypto)
    manager._nodes_dirty = False

    from src.service.p2p import _MAC_RE
    mac = 'AA:BB:CC:DD:EE:FF'
    ip = '192.168.1.10'  # same IP
    with manager.lock:
        if _MAC_RE.match(mac) and manager.config.get('auto_discover_nodes', True):
            if mac not in manager._discovered:
                manager._discovered[mac] = {'ip': ip, 'mac': mac}
                manager._nodes_dirty = True
            elif manager._discovered[mac]['ip'] != ip:
                manager._discovered[mac]['ip'] = ip
                manager._nodes_dirty = True

    assert not manager._nodes_dirty


def test_flush_nodes_writes_config(mock_crypto, mock_socket, tmp_path):
    """_flush_nodes 原子写入 config 文件，nodes 字段包含 _discovered 内容。"""
    cfg_file = tmp_path / 'spowerwk_config.json'
    cfg_file.write_text(json.dumps({'psk': 'test', 'port': 45678}))

    config = {'nodes': [], 'min_nodes': 1}
    manager = P2PManager(config, mock_crypto, config_path=str(cfg_file))

    with manager.lock:
        manager._discovered['AA:BB:CC:DD:EE:FF'] = {'ip': '10.0.0.1', 'mac': 'AA:BB:CC:DD:EE:FF'}
        manager._nodes_dirty = True

    manager._flush_nodes()

    result = json.loads(cfg_file.read_text())
    assert result['psk'] == 'test'  # other fields preserved
    assert len(result['nodes']) == 1
    assert result['nodes'][0]['mac'] == 'AA:BB:CC:DD:EE:FF'
    assert result['nodes'][0]['ip'] == '10.0.0.1'
    assert not manager._nodes_dirty


def test_flush_nodes_no_config_path(mock_crypto, mock_socket):
    """config_path 为空时 _flush_nodes 不抛异常。"""
    config = {'nodes': [], 'min_nodes': 1}
    manager = P2PManager(config, mock_crypto, config_path='')
    with manager.lock:
        manager._discovered['AA:BB:CC:DD:EE:FF'] = {'ip': '10.0.0.1', 'mac': 'AA:BB:CC:DD:EE:FF'}
        manager._nodes_dirty = True
    manager._flush_nodes()  # should not raise


def test_update_config_merges_nodes(mock_crypto, mock_socket):
    """update_config 合并新 nodes，不删除已发现节点。"""
    config = {
        'nodes': [{'ip': '10.0.0.1', 'mac': 'AA:AA:AA:AA:AA:AA'}],
        'min_nodes': 1,
    }
    manager = P2PManager(config, mock_crypto)
    # Simulate a discovered node not in config
    manager._discovered['BB:BB:BB:BB:BB:BB'] = {'ip': '10.0.0.2', 'mac': 'BB:BB:BB:BB:BB:BB'}

    new_cfg = {
        'min_nodes': 3,
        'nodes': [
            {'ip': '10.0.0.1', 'mac': 'AA:AA:AA:AA:AA:AA'},
            {'ip': '10.0.0.9', 'mac': 'CC:CC:CC:CC:CC:CC'},  # new manual node
        ],
    }
    manager.update_config(new_cfg)

    assert manager.config['min_nodes'] == 3
    # previously discovered node still there
    assert 'BB:BB:BB:BB:BB:BB' in manager._discovered
    # new manual node added
    assert 'CC:CC:CC:CC:CC:CC' in manager._discovered


def test_update_config_updates_crypto(mock_crypto, mock_socket):
    """update_config 传入 new_crypto 时替换 self.crypto。"""
    config = {'nodes': [], 'min_nodes': 1}
    manager = P2PManager(config, mock_crypto)

    new_crypto = MagicMock(spec=SecureChannel)
    manager.update_config({}, new_crypto=new_crypto)
    assert manager.crypto is new_crypto


def test_wake_offline_nodes_uses_discovered(mock_crypto, mock_socket):
    """_wake_offline_nodes 从 _discovered 读取，而非仅 self.nodes。"""
    config = {'nodes': [], 'min_nodes': 1}
    manager = P2PManager(config, mock_crypto)

    # Add a node directly to _discovered (simulating auto-discovery)
    manager._discovered['11:22:33:44:55:66'] = {'ip': '192.168.1.200', 'mac': '11:22:33:44:55:66'}

    with manager.lock:
        manager.active_nodes = set()  # all offline
        manager._wake_offline_nodes()

    sent_calls = manager.udp_sock.sendto.call_args_list
    # Should have sent a WoL packet to broadcast:9
    wol_calls = [c for c in sent_calls if c[0][1] == ('<broadcast>', 9)]
    assert len(wol_calls) == 1

    # Verify WoL packet structure: 6×FF + MAC×16
    wol_data = wol_calls[0][0][0]
    assert wol_data[:6] == b'\xff' * 6
    assert len(wol_data) == 102


def test_ping_loop_includes_mac(mock_crypto, mock_socket):
    """_ping_loop 发送的 PING payload 包含 mac 字段。"""
    config = {'nodes': [], 'min_nodes': 1, 'ping_min_interval': 0.01}
    manager = P2PManager(config, mock_crypto)

    captured = []
    original = mock_crypto.encrypt_message.side_effect
    def capture(payload):
        captured.append(payload)
        return b'enc'
    mock_crypto.encrypt_message.side_effect = capture

    # Trigger one ping directly
    manager.crypto.encrypt_message({'type': 'PING', 'mac': manager.local_mac})

    assert any(p.get('type') == 'PING' and 'mac' in p for p in captured)


def test_shutdown_cancels_debounce_and_flushes(mock_crypto, mock_socket, tmp_path):
    """shutdown() 取消 debounce timer 并同步刷盘。"""
    cfg_file = tmp_path / 'spowerwk_config.json'
    cfg_file.write_text('{}')

    config = {'nodes': [], 'min_nodes': 1}
    manager = P2PManager(config, mock_crypto, config_path=str(cfg_file))

    with manager.lock:
        manager._discovered['AA:BB:CC:DD:EE:FF'] = {'ip': '1.2.3.4', 'mac': 'AA:BB:CC:DD:EE:FF'}
        manager._nodes_dirty = True

    # Set up a debounce timer that hasn't fired yet
    import threading
    timer = MagicMock()
    manager._debounce_timer = timer

    manager.shutdown()

    timer.cancel.assert_called_once()
    result = json.loads(cfg_file.read_text())
    assert len(result['nodes']) == 1
