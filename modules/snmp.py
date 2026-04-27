# modules/snmp.py
# WRAITH SNMP passive listener
import socket, os, json
from datetime import datetime
STACK_DIR = os.path.expanduser("~/.wraith/loot/stack")
SNMP_FILE = os.path.join(STACK_DIR, "snmp_inventory.json")
VERSIONS = {0: "v1", 1: "v2c", 3: "v3"}
def parse_snmp(data, src_ip):
    try:
        version = VERSIONS.get(data[1], "unknown")
        community_len = data[6]
        community = data[7:7+community_len].decode(errors="ignore")
        return {"ip": src_ip, "version": version, "community": community, "timestamp": datetime.now().isoformat()}
    except: return None
def save_snmp(inventory):
    os.makedirs(STACK_DIR, exist_ok=True)
    with open(SNMP_FILE, "w") as f:
        json.dump(inventory, f, indent=2)
    print("  [+] SNMP inventory saved")
def print_summary(inventory):
    devices = inventory.get("devices", {})
    print("  === SNMP SUMMARY ===")
    print(f"  Devices: {len(devices)}")
    for ip, info in devices.items():
        ver = info.get("version")
        com = info.get("community")
        ts = info.get("last_seen", "")[11:19]
        print(f"    {ip} SNMP {ver} community={com} last={ts}")
    if not devices:
        print("  no SNMP devices detected")
    print("  ===================")
def run_snmp(duration=60):
    print("  [WRAITH] SNMP Passive Listener — port 161")
    inventory = {"devices": {}, "frames": []}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.settimeout(1.0)
        print(f"  [*] listening for {duration}s — Ctrl+C to stop")
        import time
        deadline = time.time() + duration
        count = 0
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(4096)
                src_ip = addr[0]
                if len(data) > 28:
                    payload = data[28:]
                    dst_port = (data[22] << 8) | data[23]
                    if dst_port == 161:
                        parsed = parse_snmp(payload, src_ip)
                        if parsed:
                            count += 1
                            ip = parsed["ip"]
                            inventory["devices"][ip] = parsed
                            inventory["devices"][ip]["last_seen"] = parsed["timestamp"]
                            print(f"  [SNMP] {src_ip} v={parsed[chr(118)+chr(101)+chr(114)+chr(115)+chr(105)+chr(111)+chr(110)]} community={parsed[chr(99)+chr(111)+chr(109)+chr(109)+chr(117)+chr(110)+chr(105)+chr(116)+chr(121)]}")
            except socket.timeout: pass
            except KeyboardInterrupt: break
        s.close()
    except PermissionError:
        print("  [-] raw socket requires root")
        return
    print(f"  [+] captured {count} SNMP frames")
    print_summary(inventory)
    save_snmp(inventory)
