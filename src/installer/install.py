import os
import sys
import shutil
import ctypes
import subprocess
import json

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    if not is_admin():
        print("需要管理员权限才能安装 spowerwk 服务。正在尝试提权...")
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv[1:]), None, 1)
        sys.exit()

    print("开始安装 spowerwk 服务...")
    
    # 目标目录
    target_dir = r"C:\Windows\System32"
    
    # 源文件目录 (Nuitka onefile 释放的临时目录)
    base_dir = os.path.dirname(__file__)
    if not getattr(sys, 'frozen', False) and "__compiled__" not in globals():
        base_dir = os.path.dirname(os.path.abspath(__file__))

    # 要释放的文件列表
    files_to_copy = [
        "spowerwk_svc.exe",
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
                {"ip": "192.168.1.100", "mac": "00:11:22:33:44:55"}
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
        subprocess.run([svc_exe, "stop"], capture_output=True)
        subprocess.run([svc_exe, "remove"], capture_output=True)
        
        install_res = subprocess.run([svc_exe, "install"], capture_output=True, text=True)
        if install_res.returncode == 0:
            print("服务注册成功。正在启动服务...")
            start_res = subprocess.run([svc_exe, "start"], capture_output=True, text=True)
            if start_res.returncode == 0:
                print("spowerwk 服务启动成功！")
            else:
                print(f"服务启动失败: {start_res.stderr}")
        else:
            print(f"服务注册失败: {install_res.stderr}")
    
    print("\n安装流程结束。")
    print("你可以在 C:\\Windows\\System32\\spowerwk_config.json 中修改节点和密码配置。")
    print("修改配置后，请在管理员终端执行 'sc stop spowerwk' 和 'sc start spowerwk' 重启服务。")
    
    # 等待用户确认
    os.system("pause")

if __name__ == "__main__":
    main()
