import ctypes
import subprocess
import time

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

def enter_ghost_mode():
    """
    Enters ghost mode:
    1. Turn off monitor
    2. Block standard input
    3. Uninstall/Disable physical input and output devices via pnputil
    4. Mute volume
    """
    # 1. Turn off monitor (Might only work if called from an interactive session, but we try anyway)
    # HWND_BROADCAST = 0xFFFF, WM_SYSCOMMAND = 0x0112, SC_MONITORPOWER = 0xF170, 2 = Power off
    user32.SendMessageW(0xFFFF, 0x0112, 0xF170, 2)
    
    # 2. Block Input
    user32.BlockInput(True)
    
    # 3. Disable devices (Keyboard, Mouse, Monitor)
    disable_devices_by_class("Keyboard")
    disable_devices_by_class("Mouse")
    disable_devices_by_class("Monitor")
    
    # 4. Mute volume using endpoint volume API or just send volume mute keystrokes
    # VK_VOLUME_MUTE = 0xAD
    user32.keybd_event(0xAD, 0, 0, 0)
    user32.keybd_event(0xAD, 0, 2, 0)

def disable_devices_by_class(class_name):
    """
    Uses pnputil to disable all devices of a certain class.
    Available on Windows 10 and above.
    """
    try:
        # Get list of devices
        output = subprocess.check_output(["pnputil", "/enum-devices", "/class", class_name], text=True)
        instance_ids = []
        for line in output.splitlines():
            if "Instance ID:" in line or "实例 ID:" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    instance_ids.append(parts[1].strip())
        
        for iid in instance_ids:
            subprocess.run(["pnputil", "/disable-device", iid], capture_output=True)
    except Exception as e:
        pass
