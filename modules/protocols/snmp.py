# modules/snmp.py
# WRAITH SNMP passive listener
import socket
from modules.core.asset_registry import upsert as reg_upsert, os, json
from datetime import datetime
STACK_DIR = os.path.expanduser("~/.wraith/loot/stack")
SNMP_FILE = os.path.join(STACK_DIR, "snmp_inventory.json")
GREEN  = '\033[32m'
CYAN   = '\033[36m'
YELLOW = '\033[33m'
RED    = '\033[31m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'
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
    print(f"\n{CYAN}{BOLD}  SNMP DEVICE SUMMARY{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
    print(f"  {DIM}devices found: {RESET}{YELLOW}{len(devices)}{RESET}")
    for ip, info in devices.items():
        ver = info.get("version")
        com = info.get("community")
        ts  = info.get("last_seen", "")[11:19]
        print(f"  {GREEN}{ip:<18}{RESET} {CYAN}{ver:<6}{RESET} {DIM}community={RESET}{YELLOW}{com}{RESET} {DIM}last={ts}{RESET}")
    if not devices:
        print(f"  {RED}no SNMP devices detected{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
def run_snmp(idle_timeout=30, max_duration=300):
    print("  [WRAITH] SNMP Passive Listener — port 161")
    inventory = {"devices": {}, "frames": []}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.settimeout(1.0)
        print(f"  [*] max {max_duration}s — stops after {idle_timeout}s idle")
        import time
        deadline = time.time() + max_duration
        last_seen = time.time()
        count = 0
        while time.time() < deadline:
            idle = int(time.time() - last_seen)
            if idle >= idle_timeout:
                print(f"  [*] no new devices for {idle_timeout}s — stopping")
                break
            if idle > 0 and idle % 10 == 0: print(f"  [*] idle {idle}s — listening...")
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
                            print(f"  {CYAN}[SNMP]{RESET} {GREEN}{src_ip}{RESET} v={YELLOW}{parsed['version']}{RESET} {DIM}community={RESET}{parsed['community']}")
            except socket.timeout: pass
            except KeyboardInterrupt: break
        s.close()
    except PermissionError:
        print("  [-] raw socket requires root")
        return
    print(f"  [+] captured {count} SNMP frames")
    print_summary(inventory)
    save_snmp(inventory)
