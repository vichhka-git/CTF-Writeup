#!/usr/bin/env python3
import os
import sys
import subprocess
import dissect.hypervisor
from dissect.util.stream import RangeStream
from dissect.target.filesystems.ntfs import NtfsFilesystem
import dissect.regf

BASE_VDI_EXTRACTED = "forensics/Kameosa/extracted_b1/Defcamp Machine/Defcamp Machine.vdi"
DIFF_VDI = "forensics/Kameosa/extracted_b3/Defcamp Machine/Snapshots/{ca7f590b-0b11-4bbf-a118-6710bd478948}.vdi"

def open_full_fs():
    print("[*] Opening base VDI and differencing VDI...")
    base_v = dissect.hypervisor.vdi.VDI(open(BASE_VDI_EXTRACTED, "rb"))
    diff_v = dissect.hypervisor.vdi.VDI(open(DIFF_VDI, "rb"))
    diff_v.parent = base_v.open()
    
    stream = RangeStream(diff_v.open(), 1048576, diff_v.size - 1048576)
    fs = NtfsFilesystem(stream)
    return fs, base_v, diff_v

def open_base_fs():
    print("[*] Opening base VDI alone...")
    base_v = dissect.hypervisor.vdi.VDI(open(BASE_VDI_EXTRACTED, "rb"))
    stream = RangeStream(base_v.open(), 1048576, base_v.size - 1048576)
    fs = NtfsFilesystem(stream)
    return fs

def dump_registry_disk_info(fs):
    print("\n=== SOLVING Q8 & Q9: DISK 0 METADATA ===")
    try:
        node = fs.open("Windows/System32/config/SYSTEM")
        reg = dissect.regf.RegistryHive(node.open())
        
        # Look for Enum/IDE and Enum/SCSI
        root = reg.root
        for cs_name in ["ControlSet001", "CurrentControlSet"]:
            try:
                enum_key = root.subkeys()[cs_name].subkeys()["Enum"]
                for bus in ["IDE", "SCSI"]:
                    if bus in [k.name for k in enum_key.subkeys().values()]:
                        bus_key = enum_key.subkeys()[bus]
                        print(f"--- {cs_name}\\Enum\\{bus} ---")
                        for dev in bus_key.subkeys().values():
                            print(f"  Device: {dev.name}")
                            for inst in dev.subkeys().values():
                                print(f"    Instance: {inst.name}")
                                for val in inst.values().values():
                                    print(f"      {val.name}: {val.value}")
                                # Check Device Parameters
                                if "Device Parameters" in [k.name for k in inst.subkeys().values()]:
                                    dp = inst.subkeys()["Device Parameters"]
                                    for val in dp.values().values():
                                        print(f"      [Device Parameters] {val.name}: {val.value}")
            except Exception as e:
                print(f"Error reading {cs_name}: {e}")
    except Exception as e:
        print(f"Error accessing SYSTEM hive: {e}")

def search_defender_and_setup_logs(fs):
    print("\n=== SOLVING Q2 & Q3: CD-ROM ACCESSED FILE & ENGINE VFZ ===")
    log_dirs = [
        "ProgramData/Microsoft/Windows Defender/Support",
        "Windows/Panther",
        "Windows/inf",
        ""
    ]
    for ld in log_dirs:
        try:
            d = fs.open(ld)
            for entry in d.iterdir():
                if entry.name.endswith(".log") or "mplog" in entry.name.lower():
                    print(f"Found log: {ld}/{entry.name} (size: {entry.stat().st_size})")
                    try:
                        content = entry.open().read().decode("latin1", errors="ignore")
                        for line in content.splitlines():
                            if "vfz" in line.lower() or "lowfi" in line.lower() or "cdrom" in line.lower():
                                print(f"  [{entry.name}] {line.strip()}")
                    except Exception as e:
                        print(f"  Error reading {entry.name}: {e}")
        except Exception as e:
            pass

def parse_security_evtx(fs):
    print("\n=== SOLVING Q6: SECURITY.EVTX RECORD TIMESTAMPS ===")
    try:
        sec_node = fs.open("Windows/System32/winevt/Logs/Security.evtx")
        data = sec_node.open().read()
        out_path = "forensics/Kameosa/Security_complete.evtx"
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"Saved complete Security.evtx: {len(data)} bytes")
        
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
        with evtx.Evtx(out_path) as log:
            header = log.get_file_header()
            print(f"Chunk count: {header.chunk_count()}, Next rec num: {header.next_record_number()}")
            first_rec = None
            last_rec = None
            for chunk in log.chunks():
                for rec in chunk.records():
                    if first_rec is None:
                        first_rec = rec
                    last_rec = rec
            
            if first_rec and last_rec:
                xml1 = ET.fromstring(first_rec.xml())
                t1 = xml1.find('.//{*}TimeCreated').get('SystemTime')
                xml2 = ET.fromstring(last_rec.xml())
                t2 = xml2.find('.//{*}TimeCreated').get('SystemTime')
                print(f"First record (rec #{first_rec.record_num()}): {t1}")
                print(f"Last record (rec #{last_rec.record_num()}): {t2}")
    except Exception as e:
        print(f"Error parsing Security.evtx: {e}")

def solve_ransomware_keys(base_fs):
    print("\n=== SOLVING Q14 & Q15: RECOVER KEYS VIA BKCRACK ===")
    desktop_path = "Users/vboxuser/Desktop"
    try:
        d = base_fs.open(desktop_path)
        desktop_files = {}
        for entry in d.iterdir():
            if entry.name not in [".", "..", "desktop.ini"]:
                desktop_files[entry.name] = entry.open().read()
                print(f"Base Desktop file: {entry.name} ({len(desktop_files[entry.name])} bytes)")
        
        # Test each file against encrypted_files/<name>.bart.zip
        bkcrack = "forensics/Kameosa/bin/bkcrack"
        enc_dir = "forensics/Kameosa/encrypted_files"
        helper_found = None
        recovered_keys = None
        
        for name, pt_data in desktop_files.items():
            enc_name = f"{name}.bart.zip"
            enc_path = os.path.join(enc_dir, enc_name)
            if not os.path.exists(enc_path):
                continue
            
            # Save plaintext to temp file
            pt_tmp = f"forensics/Kameosa/pt_{name}"
            with open(pt_tmp, "wb") as f:
                f.write(pt_data)
            
            print(f"[*] Testing {name} with bkcrack...")
            cmd = [
                bkcrack,
                "-C", enc_path,
                "-c", name,
                "-p", pt_tmp
            ]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                print(res.stdout)
                if "Keys:" in res.stdout:
                    print(f"[!] SUCCESS WITH HELPER FILE: {name}")
                    helper_found = name
                    for line in res.stdout.splitlines():
                        if "Keys:" in line:
                            recovered_keys = line.split("Keys:")[1].strip()
                            print(f"[!] Keys: {recovered_keys}")
                    break
            except subprocess.TimeoutExpired:
                print(f"Timeout on {name}")
            except Exception as e:
                print(f"Error running bkcrack on {name}: {e}")
        
        if recovered_keys:
            # Decrypt secret.txt
            secret_enc = os.path.join(enc_dir, "secret.txt.bart.zip")
            out_secret = "forensics/Kameosa/recovered_secret.txt"
            cmd = [
                bkcrack,
                "-C", secret_enc,
                "-c", "secret.txt",
                "-k", *recovered_keys.split(),
                "-d", out_secret
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            print(res.stdout)
            if os.path.exists(out_secret):
                with open(out_secret, "rb") as f:
                    flag_content = f.read().decode("latin1", errors="ignore")
                print(f"[★] FLAG: {flag_content}")
    except Exception as e:
        print(f"Error in solve_ransomware_keys: {e}")

if __name__ == "__main__":
    fs, base_v, diff_v = open_full_fs()
    base_fs = open_base_fs()
    
    dump_registry_disk_info(fs)
    search_defender_and_setup_logs(fs)
    parse_security_evtx(fs)
    solve_ransomware_keys(base_fs)
