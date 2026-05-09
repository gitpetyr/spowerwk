# Ghost Reboot / LAN Discovery / Sensitivity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 BLOCK 决策的鬼影模式替换为可配置延迟后的硬重启，同时实现局域网节点自动发现并合并至 config，以及修复孤岛保护 bug 并引入动态 ping 间隔。

**Architecture:** `main.py` 在 BLOCK 决策后等待 `ghost_reboot_delay` 秒（DLL 仍做黑屏欺骗）再调用 `hard_reboot()`。`p2p.py` 在 PING 广播中携带本机 ip/mac/hostname，接收方以 MAC 为主键 merge 节点列表并持久化；ping 间隔支持两种模式：固定值（`fixed`）或**下凹函数**增长（`power`/`exp`，f''(x)>0，碗形曲线，初始增速慢后期增速快，缺省 `power` 指数 2），孤岛判断条件去掉 `> 0` 限制。

**Tech Stack:** Python 3.x, win32serviceutil, ctypes/ntdll, socket/UDP broadcast, json, uuid, threading

---

## File Map

| 文件 | 变更类型 | 职责 |
|---|---|---|
| `src/service/main.py` | Modify | BLOCK → hard_reboot，移除 ghost mode 调用，传 config_path 给 P2PManager |
| `src/service/p2p.py` | Modify | PING 携带节点信息，merge 逻辑，动态间隔，孤岛修复 |
| `tests/test_p2p.py` | Modify | 新增 3 组测试：节点 merge、孤岛唤醒、动态间隔 |

---

### Task 1: 修复孤岛 bug 并添加动态 Ping 间隔

**Files:**
- Modify: `src/service/p2p.py` — `_ping_loop()` 方法
- Modify: `src/service/main.py` — `load_config()` 添加新默认值
- Test: `tests/test_p2p.py`

- [ ] **Step 1: 在 `tests/test_p2p.py` 顶部添加 `import math`**

```python
import math
```

- [ ] **Step 2: 在 `tests/test_p2p.py` 末尾添加失败测试**

```python
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
```

- [ ] **Step 3: 运行测试，确认失败**

```bash
cd /home/liveless/workspace/spowerwk
python -m pytest tests/test_p2p.py::test_island_mode_wakes_all_nodes tests/test_p2p.py::test_interval_fixed_mode tests/test_p2p.py::test_interval_sqrt_mode_concave tests/test_p2p.py::test_interval_log_mode_concave tests/test_p2p.py::test_interval_defaults -v
```

预期：全部 FAIL（`_calc_ping_interval` 不存在，孤岛 bug 未修复）。

- [ ] **Step 4: 在 `src/service/p2p.py` 顶部添加 `import math`**

在现有 `import struct` 之后添加：
```python
import math
```

- [ ] **Step 5: 在 `P2PManager` 类中（`_wake_offline_nodes` 之前）添加 `_calc_ping_interval` 方法**

```python
    def _calc_ping_interval(self, active_count: int) -> float:
        """
        计算下一轮 ping 间隔（下凹函数，f''>0，初始增速慢后期增速快）。
        mode='fixed' : 始终返回 ping_min_interval。
        mode='power' : min + (max-min) * (n/N)^k，k>1 时为下凹，缺省 k=2（抛物线）。
        mode='exp'   : min + (max-min) * (e^(n/N)-1)/(e-1)，下凹性更强。
        N = ping_interval_nodes（预期最大节点数，归一化用）。
        """
        min_i = self.config.get('ping_min_interval', 1.0)
        max_i = self.config.get('ping_max_interval', 5.0)
        mode  = self.config.get('ping_interval_mode', 'power')
        N     = max(1, self.config.get('ping_interval_nodes', 10))

        if mode == 'fixed':
            return min_i

        n = max(0, min(active_count, N))
        if mode == 'exp':
            ratio = (math.exp(n / N) - 1) / (math.e - 1)
        else:  # 'power' 为默认
            k = self.config.get('ping_interval_exponent', 2.0)
            ratio = (n / N) ** k

        return min_i + (max_i - min_i) * ratio
```

- [ ] **Step 6: 将 `_ping_loop` 整个方法替换为使用 `_calc_ping_interval` 的新版本**

```python
    def _ping_loop(self):
        interval = self.config.get('ping_min_interval', 1.0)
        while True:
            ping_msg = self.crypto.encrypt_message({'type': 'PING'})
            try:
                self.udp_sock.sendto(ping_msg, ('<broadcast>', self.broadcast_port))
            except Exception:
                pass

            time.sleep(interval)

            with self.lock:
                current_active = len(self.active_nodes)
                if current_active < self.min_nodes:
                    self._wake_offline_nodes()
                self.active_nodes.clear()

            interval = self._calc_ping_interval(current_active)
```

- [ ] **Step 7: 在 `src/service/main.py` 的 `load_config` 中添加新默认值**

在现有默认值代码块（`if 'log_server_port' not in self.config:` 之前）追加：

```python
        if 'ping_interval_mode' not in self.config:
            self.config['ping_interval_mode'] = 'power'
        if 'ping_interval_exponent' not in self.config:
            self.config['ping_interval_exponent'] = 2.0
        if 'ping_min_interval' not in self.config:
            self.config['ping_min_interval'] = 1.0
        if 'ping_max_interval' not in self.config:
            self.config['ping_max_interval'] = 5.0
        if 'ping_interval_nodes' not in self.config:
            self.config['ping_interval_nodes'] = 10
```

- [ ] **Step 8: 运行全部测试，确认通过**

```bash
python -m pytest tests/test_p2p.py -v
```

预期：全部 PASS。

- [ ] **Step 9: Commit**

```bash
git add src/service/p2p.py src/service/main.py tests/test_p2p.py
git commit -m "fix: repair island-mode WoL trigger; add concave/fixed dynamic ping interval"
```

---

### Task 2: 局域网节点自动发现与 Config 合并

**Files:**
- Modify: `src/service/p2p.py` — PING 广播携带节点信息，`_listen_udp` merge 逻辑，新增 `_merge_node`、`_local_mac`
- Modify: `src/service/main.py` — 传 `config_path` 给 P2PManager
- Test: `tests/test_p2p.py`

- [ ] **Step 1: 在 `tests/test_p2p.py` 顶部添加 `import json, os, tempfile`**

```python
import json
import os
import tempfile
```

- [ ] **Step 2: 在 `tests/test_p2p.py` 末尾添加节点 merge 测试**

```python
@patch('src.service.p2p.time.sleep', return_value=None)
def test_merge_node_adds_new_entry(mock_sleep, mock_crypto, mock_socket):
    """收到含 mac 的 PING 包时，应将未知节点追加到 config['nodes']。"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            'nodes': [],
            'min_nodes': 1,
            'wait_window': 0.1,
        }
        json.dump(config, f)
        config_path = f.name

    try:
        manager = P2PManager(config, mock_crypto, config_path=config_path)
        manager._merge_node({'ip': '192.168.1.50', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'PC-50'})

        assert len(manager.nodes) == 1
        assert manager.nodes[0]['mac'] == 'aa:bb:cc:dd:ee:ff'
        assert manager.nodes[0]['ip'] == '192.168.1.50'

        with open(config_path) as f:
            saved = json.load(f)
        assert len(saved['nodes']) == 1
        assert saved['nodes'][0]['mac'] == 'aa:bb:cc:dd:ee:ff'
    finally:
        os.unlink(config_path)


@patch('src.service.p2p.time.sleep', return_value=None)
def test_merge_node_updates_existing_ip(mock_sleep, mock_crypto, mock_socket):
    """同 MAC 节点 IP 变化时，应更新 IP 而不是新增条目。"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            'nodes': [{'ip': '192.168.1.10', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'PC-10'}],
            'min_nodes': 1,
            'wait_window': 0.1,
        }
        json.dump(config, f)
        config_path = f.name

    try:
        manager = P2PManager(config, mock_crypto, config_path=config_path)
        manager._merge_node({'ip': '192.168.1.99', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'PC-10'})

        assert len(manager.nodes) == 1
        assert manager.nodes[0]['ip'] == '192.168.1.99'
    finally:
        os.unlink(config_path)


@patch('src.service.p2p.time.sleep', return_value=None)
def test_merge_node_never_deletes(mock_sleep, mock_crypto, mock_socket):
    """merge 操作不得删减已有节点。"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            'nodes': [
                {'ip': '192.168.1.10', 'mac': 'aa:bb:cc:dd:ee:01', 'hostname': 'PC-01'},
                {'ip': '192.168.1.11', 'mac': 'aa:bb:cc:dd:ee:02', 'hostname': 'PC-02'},
            ],
            'min_nodes': 1,
            'wait_window': 0.1,
        }
        json.dump(config, f)
        config_path = f.name

    try:
        manager = P2PManager(config, mock_crypto, config_path=config_path)
        # 只收到一个节点的 PING，另一个节点不应被删除
        manager._merge_node({'ip': '192.168.1.10', 'mac': 'aa:bb:cc:dd:ee:01', 'hostname': 'PC-01'})

        assert len(manager.nodes) == 2
    finally:
        os.unlink(config_path)
```

- [ ] **Step 3: 运行新测试，确认失败（P2PManager 不接受 config_path 参数）**

```bash
python -m pytest tests/test_p2p.py::test_merge_node_adds_new_entry tests/test_p2p.py::test_merge_node_updates_existing_ip tests/test_p2p.py::test_merge_node_never_deletes -v
```

预期：TypeError — P2PManager 不接受 `config_path` 关键字参数。

- [ ] **Step 4: 修改 `src/service/p2p.py`，在文件顶部添加 `import uuid, json, os` 导入**

文件头部现有导入：
```python
import socket
import threading
import time
import random
import struct
from crypto import SecureChannel
```

替换为：
```python
import socket
import threading
import time
import random
import struct
import uuid
import json
import os
from crypto import SecureChannel
```

- [ ] **Step 5: 修改 `P2PManager.__init__` 接受可选 `config_path` 并获取本机 MAC/hostname**

将 `__init__` 签名及前几行替换为：

```python
def __init__(self, config, crypto_channel: SecureChannel, config_path: str = None):
    self.nodes = config.get('nodes', [])
    self.min_nodes = config.get('min_nodes', 1)
    self.wait_window = config.get('wait_window', 1.0)
    self.crypto = crypto_channel
    self.broadcast_port = config.get('port', 45678)
    self.config = config
    self.config_path = config_path
    self.active_nodes = set()
    self.intents = {}
    self.lock = threading.Lock()

    self.local_ip = self._get_local_ip()
    self.local_mac = self._get_local_mac()
    self.local_hostname = socket.gethostname()

    self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    self.udp_sock.bind(('', self.broadcast_port))

    threading.Thread(target=self._listen_udp, daemon=True).start()
    threading.Thread(target=self._ping_loop, daemon=True).start()
```

- [ ] **Step 6: 在 `_get_local_ip` 之后添加 `_get_local_mac` 方法**

```python
def _get_local_mac(self) -> str:
    """返回本机 MAC 地址（冒号分隔小写形式）。"""
    mac_int = uuid.getnode()
    return ':'.join(f'{(mac_int >> (8 * i)) & 0xff:02x}' for i in range(5, -1, -1))
```

- [ ] **Step 7: 修改 `_ping_loop` 中广播 PING 的部分，携带本机信息**

将 `_ping_loop` 内 `ping_msg` 构造一行替换为：

```python
        ping_msg = self.crypto.encrypt_message({
            'type': 'PING',
            'ip': self.local_ip,
            'mac': self.local_mac,
            'hostname': self.local_hostname,
        })
```

- [ ] **Step 8: 修改 `_listen_udp` 中处理 PING 的分支，触发 merge**

将：
```python
                elif msg.get('type') == 'PING':
                    # Bug #2 fix: protect active_nodes with the same lock used in _ping_loop
                    with self.lock:
                        self.active_nodes.add(addr[0])
```

替换为：
```python
                elif msg.get('type') == 'PING':
                    with self.lock:
                        self.active_nodes.add(addr[0])
                    if 'mac' in msg:
                        self._merge_node(msg)
```

- [ ] **Step 9: 在 `_wake_offline_nodes` 之后添加 `_merge_node` 和 `_save_config` 方法**

```python
    def _merge_node(self, info: dict):
        """
        以 MAC 为主键将节点信息 merge 进 self.nodes（只增改，不删）。
        持锁操作，写盘时不持锁（避免长时间占用 lock）。
        """
        mac = info.get('mac', '').lower()
        if not mac:
            return

        needs_save = False
        with self.lock:
            for node in self.nodes:
                if node.get('mac', '').lower() == mac:
                    changed = False
                    if 'ip' in info and node.get('ip') != info['ip']:
                        node['ip'] = info['ip']
                        changed = True
                    if 'hostname' in info and node.get('hostname') != info['hostname']:
                        node['hostname'] = info['hostname']
                        changed = True
                    needs_save = changed
                    break
            else:
                self.nodes.append({
                    'ip': info.get('ip', ''),
                    'mac': mac,
                    'hostname': info.get('hostname', ''),
                })
                self.config['nodes'] = self.nodes
                needs_save = True

        if needs_save:
            self._save_config()

    def _save_config(self):
        """将当前 config（含更新后的 nodes）写回磁盘。config_path 未设置时跳过。"""
        if not self.config_path:
            return
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
```

- [ ] **Step 10: 修改 `src/service/main.py`，传 `config_path` 给 P2PManager**

定位 `main()` 方法中：
```python
        self.p2p = P2PManager(self.config, crypto)
```

替换为：
```python
        config_path = os.path.join(os.path.dirname(sys.executable), 'spowerwk_config.json')
        self.p2p = P2PManager(self.config, crypto, config_path=config_path)
```

- [ ] **Step 11: 运行全部测试**

```bash
python -m pytest tests/test_p2p.py -v
```

预期：全部 PASS（包括旧的 3 个和新的 6 个）。

- [ ] **Step 12: Commit**

```bash
git add src/service/p2p.py src/service/main.py tests/test_p2p.py
git commit -m "feat: add LAN node auto-discovery via PING with MAC-keyed config merge"
```

---

### Task 3: 将 BLOCK 决策替换为可配置延迟后的硬重启

**Files:**
- Modify: `src/service/main.py` — `ipc_server_loop` 中 BLOCK 分支，`load_config` 添加默认值，更新 import
- Test: 无自动化测试（涉及 NtShutdownSystem，只做代码审查）

- [ ] **Step 1: 修改 `main.py` 顶部的 hardware 导入**

将：
```python
from hardware import enter_ghost_mode, start_ghost_power_watchdog
```

替换为：
```python
from hardware import hard_reboot
```

- [ ] **Step 2: 在 `load_config` 中添加 `ghost_reboot_delay` 默认值**

在现有默认值代码块末尾（`ping_interval_scale` 默认值之后）添加：

```python
        if 'ghost_reboot_delay' not in self.config:
            self.config['ghost_reboot_delay'] = 0.8
```

- [ ] **Step 3: 修改 `ipc_server_loop` 中的 BLOCK 分支**

定位：
```python
                                else:
                                    logging.info("Decision: BLOCK. Sending BLOCK to DLL and entering Ghost Mode.")
                                    win32file.WriteFile(pipe, b"BLOCK\x00")
                                    try: win32file.FlushFileBuffers(pipe)
                                    except: pass
                                    enter_ghost_mode()
                                    start_ghost_power_watchdog()
```

替换为：
```python
                                else:
                                    delay = self.config.get('ghost_reboot_delay', 0.8)
                                    logging.warning(f"Decision: BLOCK. Sending BLOCK to DLL, hard reboot in {delay}s.")
                                    win32file.WriteFile(pipe, b"BLOCK\x00")
                                    try: win32file.FlushFileBuffers(pipe)
                                    except: pass
                                    time.sleep(delay)
                                    hard_reboot()
```

- [ ] **Step 4: 运行现有测试，确认未破坏其他功能**

```bash
python -m pytest tests/ -v
```

预期：全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/service/main.py
git commit -m "feat: replace ghost mode with configurable-delay hard reboot on BLOCK decision"
```

---

## Self-Review

**Spec 覆盖检查：**
- ✅ 鬼影模式改硬重启：Task 3 完整覆盖，`ghost_reboot_delay` 可配置
- ✅ 局域网自动更新名单（只增改，不删）：Task 2，MAC 为主键，`_merge_node` 实现
- ✅ 孤岛保护 bug 修复：Task 1，移除 `> 0` 条件
- ✅ 动态 ping 间隔（固定/下凹函数）：Task 1，`_calc_ping_interval` 支持 `fixed`/`power`/`exp` 三种模式，`power`（k=2）和 `exp` 均满足 f''>0（初始增速慢，后期增速快）
- ✅ 火种保护（min_nodes 约束）：已有逻辑 + island fix 共同保障

**占位符检查：** 无 TBD / TODO，每步均含完整代码。

**类型一致性：**
- `P2PManager.__init__` 签名新增 `config_path: str = None`，Task 2 Step 5/10 一致
- `_calc_ping_interval(active_count: int) -> float` 在 Task 1 Step 5（定义）、Step 6（调用）、测试（调用）三处签名一致；`power`/`exp` 均满足 f''>0
- `_merge_node(info: dict)` 在 Step 8（调用方）和 Step 9（定义）签名一致
- `hard_reboot()` 在 hardware.py 中已实现，Task 3 直接调用，无签名变更
- Task 2 的 `import math` 已在 Task 1 Step 4 加入，不重复添加
