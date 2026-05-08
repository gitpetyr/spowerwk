import os
import sys
import shutil
import ctypes
import subprocess
import json
import socket
import uuid
import secrets

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
        # Re-run the program with admin rights
        if getattr(sys, 'frozen', False):
            # Frozen exe: sys.executable IS the installer, pass remaining args as-is
            params = " ".join(sys.argv[1:])
        else:
            # Running as a plain .py script: must include the script path (argv[0])
            # so Python knows which file to execute after elevation.
            params = " ".join(sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit()

    print("开始安装 spowerwk 服务...")
    
    # 目标目录
    svc_install_dir = r"C:\Program Files\spowerwk"
    sys32_dir = r"C:\Windows\System32"
    
    # 源文件目录 (PyInstaller onefile 释放的临时目录)
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base_dir = sys._MEIPASS
    elif not getattr(sys, 'frozen', False) and "__compiled__" not in globals():
        base_dir = os.path.dirname(os.path.abspath(__file__))
    else:
        base_dir = os.path.dirname(__file__)

    print(f"准备部署服务到: {svc_install_dir}")
    print(f"准备部署Hook到: {sys32_dir}")
    
    if not os.path.exists(svc_install_dir):
        os.makedirs(svc_install_dir, exist_ok=True)
    if not os.path.exists(sys32_dir):
        os.makedirs(sys32_dir, exist_ok=True)

    # 1. 拷贝 spowerwk_svc 服务目录
    svc_src_dir = os.path.join(base_dir, "spowerwk_svc")
    if os.path.exists(svc_src_dir):
        try:
            print(f"正在释放服务运行环境...")
            shutil.copytree(svc_src_dir, svc_install_dir, dirs_exist_ok=True)
        except Exception as e:
            print(f"释放服务运行环境失败: {e}")
            input("按回车键退出...")
            sys.exit(1)
    else:
        print(f"警告: 未找到内置服务目录 {svc_src_dir}")

    # 2. 拷贝 unified_rva_db.json.xz 到服务目录
    rva_db_src = os.path.join(base_dir, "unified_rva_db.json.xz")
    rva_db_dst = os.path.join(svc_install_dir, "unified_rva_db.json.xz")
    if os.path.exists(rva_db_src):
        try:
            shutil.copy2(rva_db_src, rva_db_dst)
        except Exception as e:
            print(f"拷贝 rva_db 失败: {e}")

    # 3. 拷贝 Hook DLL 到 System32
    dll_src = os.path.join(base_dir, "spowerwkHook.dll")
    dll_dst = os.path.join(sys32_dir, "spowerwkHook.dll")
    if os.path.exists(dll_src):
        try:
            shutil.copy2(dll_src, dll_dst)
        except Exception as e:
            print(f"拷贝 Hook DLL 失败: {e}")
            input("按回车键退出...")
            sys.exit(1)

    # 4. 生成默认配置到服务目录
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

    # 5. 安装并启动服务
    svc_exe = os.path.join(svc_install_dir, "spowerwk_svc.exe")
    if os.path.exists(svc_exe):
        print("正在注册服务...")
        subprocess.run(["sc", "stop", "spowerwk"], capture_output=True)
        subprocess.run(["sc", "delete", "spowerwk"], capture_output=True)
        
        install_res = subprocess.run([
            "sc", "create", "spowerwk",
            f"binPath= \"{svc_exe}\"",     # 空格在=后是sc的要求；引号保护含空格的路径
            "start= auto",
            "DisplayName= Windows 电源管理服务"  # 不加引号，避免sc将引号写入注册表
        ], capture_output=True, text=True)

        if install_res.returncode == 0:
            print("服务注册成功。正在启动服务...")
            start_res = subprocess.run(["sc", "start", "spowerwk"], capture_output=True, text=True)
            if start_res.returncode == 0:
                print("spowerwk 服务启动成功！")
            else:
                print(f"服务启动失败: {start_res.stderr}")
                print(f"你可以在 {config_path} 中修改节点和密码配置。")
                print("修改配置后，请在管理员终端执行 'sc stop spowerwk' 和 'sc start spowerwk' 重启服务。")
        else:
            print(f"服务注册失败: {install_res.stderr}\n{install_res.stdout}")
    
    print("\n安装流程结束。")
    
    # 等待用户确认
    os.system("pause")

if __name__ == "__main__":
    main()
