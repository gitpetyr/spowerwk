import os
import sys
import shutil
import ctypes
import subprocess
import json
import socket
import uuid
import secrets
import lzma
import tarfile
import tempfile

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_local_mac():
    mac_num = uuid.getnode()
    mac_hex = f'{mac_num:012x}'.upper()
    return '-'.join(mac_hex[i:i+2] for i in range(0, 12, 2))

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    if not is_admin():
        print("需要管理员权限才能安装 spowerwk 服务。正在尝试提权...")
        if getattr(sys, 'frozen', False) or '__compiled__' in globals():
            params = " ".join(sys.argv[1:])
        else:
            params = " ".join(sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit()

    print("开始安装 spowerwk 服务...")

    svc_install_dir = r"C:\Program Files\spowerwk"
    sys32_dir       = r"C:\Windows\System32"

    # --standalone 模式下 sys.executable 指向真实的安装器 exe，
    # payload.tar.xz 就在同级目录。
    payload_path = os.path.join(os.path.dirname(sys.executable), "payload.tar.xz")
    if not os.path.exists(payload_path):
        print(f"错误: 未找到安装包 {payload_path}")
        os.system("pause")
        sys.exit(1)

    print(f"准备部署服务到: {svc_install_dir}")
    print(f"准备部署Hook到: {sys32_dir}")

    os.makedirs(svc_install_dir, exist_ok=True)

    print("正在解压安装包...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            with lzma.open(payload_path) as xz:
                with tarfile.open(fileobj=xz) as tar:
                    tar.extractall(tmpdir)

            # 1. 释放服务目录 (spowerwk_svc/ -> svc_install_dir)
            svc_src = os.path.join(tmpdir, "spowerwk_svc")
            if not os.path.exists(svc_src):
                print("错误: 安装包中未找到服务目录。")
                os.system("pause")
                sys.exit(1)
            try:
                print("正在释放服务运行环境...")
                shutil.copytree(svc_src, svc_install_dir, dirs_exist_ok=True)
            except Exception as e:
                print(f"释放服务运行环境失败: {e}")
                input("按回车键退出...")
                sys.exit(1)

            # 2. 拷贝 RVA 数据库到服务目录
            rva_src = os.path.join(tmpdir, "unified_rva_db.json.xz")
            if os.path.exists(rva_src):
                try:
                    shutil.copy2(rva_src, os.path.join(svc_install_dir, "unified_rva_db.json.xz"))
                except Exception as e:
                    print(f"拷贝 rva_db 失败: {e}")

            # 3. 拷贝 Hook DLL 到 System32
            dll_src = os.path.join(tmpdir, "spowerwkHook.dll")
            if os.path.exists(dll_src):
                try:
                    shutil.copy2(dll_src, os.path.join(sys32_dir, "spowerwkHook.dll"))
                except Exception as e:
                    print(f"拷贝 Hook DLL 失败: {e}")
                    input("按回车键退出...")
                    sys.exit(1)
    except Exception as e:
        print(f"解压安装包失败: {e}")
        os.system("pause")
        sys.exit(1)

    # 4. 生成默认配置文件
    config_path = os.path.join(svc_install_dir, "spowerwk_config.json")
    if not os.path.exists(config_path):
        default_config = {
            "psk": secrets.token_hex(32),
            "min_nodes": 1,
            "wait_window": 1.0,
            "port": 45678,
            "nodes": [
                {"ip": get_local_ip(), "mac": get_local_mac()}
            ]
        }
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=4, ensure_ascii=False)
            print(f"生成默认配置文件: {config_path}")
        except Exception as e:
            print(f"生成配置失败: {e}")

    # 5. 注册并启动服务
    # sc.exe 要求 key= 和 value 是两个独立参数。
    # binPath 值需含引号以保护路径中的空格。
    svc_exe = os.path.join(svc_install_dir, "spowerwk_svc.exe")
    if os.path.exists(svc_exe):
        print("正在注册服务...")
        subprocess.run(["sc", "stop",   "spowerwk"], capture_output=True)
        subprocess.run(["sc", "delete", "spowerwk"], capture_output=True)

        install_res = subprocess.run([
            "sc", "create", "spowerwk",
            "binPath=",     f'"{svc_exe}"',
            "start=",       "auto",
            "DisplayName=", "Windows 电源管理服务",
        ], capture_output=True, text=True, encoding="oem", errors="replace")

        if install_res.returncode == 0:
            print("服务注册成功。正在启动服务...")
            start_res = subprocess.run(
                ["sc", "start", "spowerwk"],
                capture_output=True, text=True, encoding="oem", errors="replace",
            )
            if start_res.returncode == 0:
                print("spowerwk 服务启动成功！")
            else:
                print(f"服务启动失败: {start_res.stderr}")
                print(f"你可以在 {config_path} 中修改节点和密码配置。")
                print("修改配置后，请在管理员终端执行 'sc stop spowerwk' 和 'sc start spowerwk' 重启服务。")
        else:
            print(f"服务注册失败: {install_res.stderr}\n{install_res.stdout}")

    print("\n安装流程结束。")
    os.system("pause")

if __name__ == "__main__":
    main()
