import os
import sys
import shutil
import ctypes
import subprocess
import json
import socket
import uuid

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
    target_dir = r"C:\Program Files\spowerwk"
    
    # 源文件目录 (PyInstaller onefile 释放的临时目录)
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base_dir = sys._MEIPASS
    elif not getattr(sys, 'frozen', False) and "__compiled__" not in globals():
        base_dir = os.path.dirname(os.path.abspath(__file__))
    else:
        base_dir = os.path.dirname(__file__)

    print(f"准备部署到: {target_dir}")
    
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)

    # 拷贝 spowerwk_svc 目录内容
    svc_src_dir = os.path.join(base_dir, "spowerwk_svc")
    if os.path.exists(svc_src_dir):
        try:
            print(f"正在释放服务运行环境...")
            # 拷贝目录下的所有文件和文件夹到 target_dir
            for item in os.listdir(svc_src_dir):
                s = os.path.join(svc_src_dir, item)
                d = os.path.join(target_dir, item)
                if os.path.isdir(s):
                    if not os.path.exists(d):
                        shutil.copytree(s, d)
                else:
                    shutil.copy2(s, d)
        except Exception as e:
            print(f"释放服务运行环境失败: {e}")
            input("按回车键退出...")
            sys.exit(1)
    else:
        print(f"警告: 未找到内置服务目录 {svc_src_dir}")

    # 要释放的其他文件列表
    files_to_copy = [
        "spowerwkHook.dll",
        "unified_rva_db.json.xz"
    ]

    for file_name in files_to_copy:
        src = os.path.join(base_dir, file_name)
        dst = os.path.join(target_dir, file_name)
        if os.path.exists(src):
            try:
                print(f"释放文件: {file_name} -> {dst}")
                shutil.copy2(src, dst)
            except Exception as e:
                print(f"拷贝 {file_name} 失败: {e}")
                input("按回车键退出...")
                sys.exit(1)
        else:
            print(f"警告: 未找到内置文件 {src}")

    # 生成默认配置
    config_path = os.path.join(target_dir, "spowerwk_config.json")
    if not os.path.exists(config_path):
        default_config = {
            "psk": "default_secure_password_please_change",
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

    # 安装并启动服务
    svc_exe = os.path.join(target_dir, "spowerwk_svc.exe")
    if os.path.exists(svc_exe):
        print("正在注册服务...")
        subprocess.run(["sc", "stop", "spowerwk"], capture_output=True)
        subprocess.run(["sc", "delete", "spowerwk"], capture_output=True)
        
        install_res = subprocess.run([
            "sc", "create", "spowerwk", 
            f'binPath="{svc_exe}"', 
            "start=auto", 
            'DisplayName="Windows 电源管理服务"'
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
