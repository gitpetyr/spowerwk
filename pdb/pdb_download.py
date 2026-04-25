import asyncio
import httpx
import gzip
import json
import io
import os
import struct
import sys

def get_pdb_info_from_bytes(pe_data):
    """纯二进制特征匹配，提取 PDB GUID+Age，免疫文件截断"""
    rsds_idx = pe_data.find(b'RSDS')
    if rsds_idx == -1:
        return None, None

    try:
        guid_bytes = pe_data[rsds_idx+4 : rsds_idx+20]
        age = struct.unpack("<I", pe_data[rsds_idx+20 : rsds_idx+24])[0]
        
        path_start = rsds_idx + 24
        path_end = pe_data.find(b'\x00', path_start)
        pdb_path = pe_data[path_start:path_end].decode('utf-8', errors='ignore')
        pdb_filename = pdb_path.split('\\')[-1].split('/')[-1]

        data1 = struct.unpack("<I", guid_bytes[0:4])[0]
        data2 = struct.unpack("<H", guid_bytes[4:6])[0]
        data3 = struct.unpack("<H", guid_bytes[6:8])[0]
        
        guid_str = f"{data1:08X}{data2:04X}{data3:04X}"
        for b in guid_bytes[8:16]:
            guid_str += f"{b:02X}"
        
        pdb_id = f"{guid_str}{age:X}"
        return pdb_id, pdb_filename
    except Exception:
        return None, None

async def process_single_pe(client, target_filename, timestamp, virtual_size, semaphore, downloaded_pdbs):
    async with semaphore:
        pe_id = f"{timestamp:08X}{virtual_size:X}"
        pe_url = f"https://msdl.microsoft.com/download/symbols/{target_filename}/{pe_id}/{target_filename}"

        try:
            # Range 请求：只下载 PE 前 1MB
            headers = {"Range": "bytes=0-1048575"}
            pe_res = await client.get(pe_url, headers=headers, follow_redirects=True)
            
            if pe_res.status_code not in (200, 206):
                return

            pdb_id, pdb_filename = get_pdb_info_from_bytes(pe_res.content)
            if not pdb_id:
                return

            pdb_url = f"https://msdl.microsoft.com/download/symbols/{pdb_filename}/{pdb_id}/{pdb_filename}"

            if pdb_url in downloaded_pdbs:
                return
            downloaded_pdbs.add(pdb_url)

            save_dir = os.path.join("symbols", pdb_filename, pdb_id)
            save_path = os.path.join(save_dir, pdb_filename)

            if os.path.exists(save_path) and os.path.getsize(save_path) > 0:
                print(f"[*] [本地已存在] 跳过: {pdb_id}")
                return

            print(f"[+] 正在下载: {pdb_id}")
            pdb_res = await client.get(pdb_url, follow_redirects=True)
            
            if pdb_res.status_code == 200:
                os.makedirs(save_dir, exist_ok=True)
                with open(save_path, "wb") as f:
                    f.write(pdb_res.content)
            else:
                print(f"[-] PDB 下载失败 (HTTP {pdb_res.status_code}): {pdb_url}")

        except Exception as e:
            print(f"[-] 处理 ({pe_id}) 时发生网络异常: {e}")

async def main(target_filename):
    print(f"[*] 正在获取 {target_filename} 的元数据...")
    url = f"https://winbindex.m417z.com/data/by_filename_compressed/{target_filename}.json.gz"
    
    timeout = httpx.Timeout(30.0, connect=60.0)
    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    
    async with httpx.AsyncClient(headers={"User-Agent": "Mozilla/5.0"}, timeout=timeout, limits=limits) as client:
        res = await client.get(url, follow_redirects=True)
        if res.status_code != 200:
            print("[-] 元数据获取失败")
            return

        with gzip.GzipFile(fileobj=io.BytesIO(res.content)) as gz:
            data = json.loads(gz.read().decode('utf-8'))

        pe_identifiers = set()
        for _, file_info_dict in data.items():
            info = file_info_dict.get("fileInfo", {})
            ts = info.get("timestamp")
            vs = info.get("virtualSize")
            if ts and vs:
                pe_identifiers.add((ts, vs))
        
        print(f"[*] 找到 {len(pe_identifiers)} 个去重后的有效版本。开始高并发下载...")

        semaphore = asyncio.Semaphore(15) 
        downloaded_pdbs = set()

        tasks = [
            process_single_pe(client, target_filename, ts, vs, semaphore, downloaded_pdbs)
            for ts, vs in pe_identifiers
        ]

        await asyncio.gather(*tasks)
        print("[*] 全部下载任务处理完毕！")

if __name__ == "__main__":
    target = sys.argv[1]
    asyncio.run(main(target))