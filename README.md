# spowerwk (Decentralized LAN Keep-Alive System)

`spowerwk` 是一个专为特定局域网（如机房环境）设计的去中心化保活系统。它通过在底层拦截操作系统的关机指令，配合 P2P 网络协商机制，强制维持局域网内至少有 $N$ 台机器处于存活状态。

## 核心特性

- **去中心化 P2P 协商：** 没有中心服务器，所有节点平等。节点间使用 AES-GCM 加密 UDP 广播进行意图协商，动态决定哪台机器被允许关机。
- **底层 API Hook 拦截：** 通过提取不同版本 `winlogon.exe` 的 PDB 符号 (RVA)，使用 MinHook 动态拦截底层的 `ShutdownWindowsWorkerThread` 与 `WlDisplayStatusByResourceId`，在物理层面上阻止系统关机。
- **鬼影模式 (Ghost Mode)：** 当系统拒绝关机时，将平滑进入“鬼影模式”。在此模式下，系统会修改 UI 界面欺骗用户正在关机，同时物理卸载键盘/鼠标，关闭显示器，静音系统。
- **ACPI 硬件保护：** 在鬼影模式下，如果用户试图通过机箱电源键进行物理硬关机/开机，系统将拦截二次关机调用，并直接调用内核级接口执行断电重启。
- **Wake-on-LAN (WoL) 自动补位：** 系统节点会定期进行心跳检测。若发现存活机器数低于设定阈值，存活的机器将发送魔术包唤醒已死机或离线的设备。

## 系统架构

本项目包含两个主要组件：

1. **`spowerwk Service` (Python 守护进程)**
   - 部署位置：`C:\Windows\System32\main.exe`（或重命名为 `spowerwk.exe`）
   - 基于 `win32serviceutil` 运行在 SYSTEM 权限的 Session 0 下。
   - 负责：LZMA 解压 RVA 数据库、P2P 权重广播及决策、外设卸载、将 DLL 注入宿主进程，以及通过 IPC 通信将决策结果传递给 DLL。

2. **`spowerwkHook.dll` (C++ MinHook)**
   - 部署位置：`C:\Windows\System32\spowerwkHook.dll`
   - 由守护进程动态注入到 `winlogon.exe`。
   - 负责：拦截 `winlogon.exe` 内部隐藏的关机 API 和 UI 刷新函数，向服务发送关机拦截查询，篡改关机参数，并对 ACPI 唤醒做出惩罚式重启。

---

## 部署说明

### 1. 准备文件
通过本仓库的 GitHub Actions 流水线，获取构建产物：
- `main.exe` (主服务，使用 Nuitka 编译并自带了压缩的 RVA 数据库)
- `spowerwkHook.dll` (C++ Hook 模块)

### 2. 放置目录
将以上两个文件放入目标机器的 `System32` 目录下：
```text
C:\Windows\System32\main.exe
C:\Windows\System32\spowerwkHook.dll
```

### 3. 配置文件准备
在相同的 `System32` 目录下创建配置文件 `spowerwk_config.json`：
```json
{
    "psk": "您的64位十六进制预共享密钥（推荐64个字符）",
    "min_nodes": 2,
    "wait_window": 1.0,
    "nodes": [
        {
            "ip": "192.168.1.10",
            "mac": "00-11-22-33-44-55",
            "hostname": "PC-01"
        },
        {
            "ip": "192.168.1.11",
            "mac": "00-11-22-33-44-56",
            "hostname": "PC-02"
        }
    ]
}
```
*注意：`psk` 必须为有效的 hex 字符串。`min_nodes` 代表网络中强制存活的最低机器数。`wait_window` 为协商等待时间（秒）。*

### 4. 安装与启动服务
在目标机器上以**管理员权限**打开 CMD 或 PowerShell：
```cmd
cd C:\Windows\System32
main.exe install
main.exe start
```

---

## 开发与构建 (CI/CD)

本系统采用 GitHub Actions 自动化编译环境：
1. **PDB 抓取**：自动从微软符号服务器下载所有 `winlogon.pdb` 版本。
2. **RVA 解析**：使用 `llvm-pdbutil` 将其解析并构建庞大的符号表 `unified_rva_db.json`。
3. **数据压缩**：使用 Python `lzma` 模块将 66MB 的 RVA 表压缩。
4. **源码编译**：使用 CMake 构建 C++ DLL，使用 Nuitka 将 Python 服务代码及压缩的 `.xz` 数据库打包为单文件 `main.exe`。

## 日志排查
所有日志会自动写入 `System32` 目录。
- 服务级日志：`C:\Windows\System32\spowerwk_service.log`
- Hook 及底层拦截日志：`C:\Windows\System32\spowerwk_dll.log`

---
**安全声明与免责：**  
*本项目通过注入系统关键进程 (winlogon.exe) 并调用系统底层的未公开 API 来控制系统电源操作和劫持硬件外设。这种极其底层的侵入式行为几乎必然会被 Windows Defender 以及各大 EDR / 杀毒软件标记为高危病毒或勒索软件。必须在受控的安全测试环境中验证，并在相关安全软件中将服务和 DLL 文件加入白名单豁免列表。*
