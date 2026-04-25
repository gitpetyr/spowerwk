import os
import re
import json
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_llvm_pdbutil(args):
    """运行 llvm-pdbutil 并返回输出文本"""
    cmd = ["llvm-pdbutil", "dump"] + args
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, creationflags=creationflags
        )
        return result.stdout
    except Exception:
        return None

def parse_single_pdb(pdb_path_str):
    """执行底层 PDB 解析与 RVA 计算"""
    headers_out = run_llvm_pdbutil(["-section-headers", pdb_path_str])
    if not headers_out or "SECTION HEADER" not in headers_out:
        return None, "缺失节区表 (Section Headers)"

    section_vas = {}
    current_sec = None
    for line in headers_out.splitlines():
        line = line.strip()
        if line.startswith("SECTION HEADER #"):
            current_sec = int(line.split("#")[1])
        elif current_sec and "virtual address" in line:
            section_vas[current_sec] = int(line.split()[0], 16)
            current_sec = None

    publics_out = run_llvm_pdbutil(["-publics", pdb_path_str])
    if not publics_out or "S_PUB32" not in publics_out:
        return None, "没有公开符号 (Stripped)"

    rva_data = {}
    current_name = None
    for line in publics_out.splitlines():
        line = line.strip()
        if "S_PUB32" in line or "S_GDATA32" in line:
            match = re.search(r'`(.*?)`', line)
            if match:
                current_name = match.group(1)
        elif current_name and "addr = " in line:
            addr_match = re.search(r'addr = (\d+):([0-9A-Fa-f]+)', line)
            if addr_match:
                segment = int(addr_match.group(1))
                offset = int(addr_match.group(2), 16)
                if segment in section_vas:
                    rva_data[current_name] = f"0x{(section_vas[segment] + offset):X}"
            current_name = None

    if not rva_data:
        return None, "解析逻辑未能提取出任何 RVA"
    
    return rva_data, "成功"

def process_pdb_task(pdb_file):
    """线程池任务分配器"""
    try:
        parts = pdb_file.parts
        if len(parts) >= 3:
            category_name = parts[-3]
            pdb_id = parts[-2]
            pdb_path_str = str(pdb_file)
            
            if os.path.getsize(pdb_path_str) < 1024:
                return None, None, f"文件过小或损坏 ({os.path.getsize(pdb_path_str)} bytes)"

            rva_dict, error_msg = parse_single_pdb(pdb_path_str)
            
            if rva_dict:
                return category_name, pdb_id, rva_dict
            else:
                return None, None, error_msg
                
    except Exception as e:
        return None, None, f"运行异常: {e}"
    
    return None, None, "未知错误"

def build_unified_database(symbols_dir="symbols", output_file="unified_rva_db.json"):
    root_path = Path(symbols_dir)
    if not root_path.exists() or not root_path.is_dir():
        print(f"[-] 找不到指定的符号目录: {symbols_dir}")
        return

    pdb_files = list(root_path.rglob("*.pdb"))
    total_files = len(pdb_files)
    
    if total_files == 0:
        print("[-] 没有找到任何 PDB 文件。")
        return
        
    print(f"[*] 找到 {total_files} 个 PDB 文件，开始多线程深度解析...")

    unified_db = {}
    success_count = 0

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        future_to_pdb = {executor.submit(process_pdb_task, pdb): pdb for pdb in pdb_files}
        
        for future in as_completed(future_to_pdb):
            pdb_file = future_to_pdb[future]
            category, pdb_id, result = future.result()
            
            if isinstance(result, dict):
                if category not in unified_db:
                    unified_db[category] = {}
                unified_db[category][pdb_id] = result
                success_count += 1
                sys.stdout.write(f"\r[+] 进度: {success_count}/{total_files}...")
                sys.stdout.flush()
            elif isinstance(result, str):
                print(f"\n[-] 丢弃: {pdb_id} | 原因: {result}")

    print(f"\n[*] 解析结束。成功将 {success_count} 个版本的数据合并。")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(unified_db, f, indent=4, ensure_ascii=False)
        
    print(f"[+] 统一数据库已生成: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    # 确保 llvm-pdbutil 可用
    if subprocess.call("llvm-pdbutil --version", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print("[-] 严重错误: 找不到 llvm-pdbutil 环境！请先安装 LLVM。")
        sys.exit(1)
        
    build_unified_database()