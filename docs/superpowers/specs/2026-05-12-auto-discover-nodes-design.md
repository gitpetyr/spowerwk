# Auto-Discover Nodes Design

**Date:** 2026-05-12  
**Feature:** 自动发现局域网节点并持久化到 nodes 名单（只增修不删）+ 配置热重载

---

## 背景

`nodes` 列表目前需手动维护，机房快速部署时繁琐。本功能让每台机器通过 PING 广播自报 MAC，邻居节点收到后自动将其写入 `spowerwk_config.json`，无需人工干预即可建立完整 WoL 名单。

---

## 配置项

在 `spowerwk_config.json` 新增一项，默认开启：

```json
"auto_discover_nodes": true
```

`load_config` 补充默认值 `True`。

---

## 第一节：协议变更 — PING 携带 MAC

**发送侧：**

`P2PManager.__init__` 时调用 `uuid.getnode()` 获取本机 MAC，格式化为 `AA:BB:CC:DD:EE:FF`，缓存为 `self.local_mac`。

PING payload 从 `{'type': 'PING'}` 改为：

```json
{"type": "PING", "mac": "AA:BB:CC:DD:EE:FF"}
```

**接收侧（`_listen_udp`）：**

1. 提取 `addr[0]`（IP）和 `msg.get('mac')`
2. MAC 缺失或不匹配 `^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$` → 忽略（兼容旧版节点）
3. `auto_discover_nodes` 为 False → 跳过写盘逻辑，但仍加入 `active_nodes`
4. 以 MAC 为主键查 `_discovered`：
   - 不存在 → 新增，标记 dirty
   - IP 不同 → 更新 IP，标记 dirty
   - 无变化 → 跳过
5. dirty 时重置 debounce 计时器（1 秒后触发写盘）

---

## 第二节：内存状态

`P2PManager` 新增字段：

```python
self.local_mac: str                 # 本机 MAC，AA:BB:CC:DD:EE:FF
self._discovered: dict[str, dict]   # mac → {"ip": ..., "mac": ...}
self._nodes_dirty: bool
self._debounce_timer: threading.Timer | None
self._config_path: str              # 由 main.py 传入，用于写盘
```

初始化时把现有 `config['nodes']` 按 MAC 键导入 `_discovered`，保留手动条目。

`_wake_offline_nodes` 改为从 `_discovered` 迭代，替代原来的 `self.nodes`。

---

## 第三节：Debounce 写盘（1 秒）

每次标记 dirty 时：

```python
if self._debounce_timer:
    self._debounce_timer.cancel()
self._debounce_timer = threading.Timer(1.0, self._flush_nodes)
self._debounce_timer.start()
```

`_flush_nodes` 流程：
1. 持 `self.lock` 快照 `_discovered`
2. 读取当前 JSON（防止热重载期间的并发写覆盖其他字段）
3. 将 `_discovered.values()` 写入 `nodes` 字段
4. 原子写盘：写临时文件 → `os.replace`（防止文件损坏）
5. 清除 `_nodes_dirty`

服务停止时（`SvcStop`）需调用 `p2p.shutdown()`，取消未触发的 debounce timer 并同步刷盘一次，防止丢失最后一批发现。

---

## 第四节：热重载（main.py，轮询 10 秒）

独立守护线程，检查 `os.path.getmtime(config_path)` 变化，变化时重新解析 JSON。

| 字段 | 热重载行为 |
|---|---|
| `min_nodes`、`wait_window`、`ping_interval_*`、`log_level`、`auto_discover_nodes` | 直接更新，立即生效 |
| `nodes`（手动增删） | 合并进 `_discovered`（只增修，不删远端已发现节点） |
| `psk` | 重建 `SecureChannel`，通过 `update_config` 注入 P2PManager |
| `port` | **不热重载**，需重启服务（重建 socket 代价过高） |

`P2PManager` 暴露 `update_config(new_config, new_crypto=None)` 方法，加锁更新运行时参数。

---

## 数据流总览

```
[本机 uuid.getnode()]
        │ local_mac
        ▼
_ping_loop → broadcast PING{type, mac}
        │
        │  UDP 广播
        ▼
邻居 _listen_udp → 提取 (IP, MAC)
        │
        ▼
_discovered[mac] = {ip, mac}  ──dirty──▶  debounce 1s  ──▶  _flush_nodes
        │                                                          │
        │                                                    os.replace(tmp→json)
        ▼
_wake_offline_nodes 读 _discovered
```

---

## 接口变更汇总

| 位置 | 变更 |
|---|---|
| `p2p.py` `__init__` | 新增 `config_path` 参数；初始化 `local_mac`、`_discovered`、debounce 状态 |
| `p2p.py` `_ping_loop` | PING payload 加 `mac` 字段 |
| `p2p.py` `_listen_udp` | 解析 MAC，调用 `_maybe_register_node` |
| `p2p.py` | 新增 `_maybe_register_node`、`_flush_nodes`、`update_config` |
| `p2p.py` `_wake_offline_nodes` | 改从 `_discovered` 读取 |
| `main.py` `load_config` | 新增 `auto_discover_nodes` 默认值 |
| `main.py` `main` | 传 `config_path` 给 `P2PManager`；启动热重载线程 |

---

## 不在本次范围内

- `port` 热重载
- 节点自动**删除**（设计上不做）
- 跨子网发现
