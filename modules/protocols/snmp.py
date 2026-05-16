# modules/snmp.py
# WRAITH SNMP passive listener
import socket
import os, json
from modules.core.asset_registry import upsert as reg_upsert
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
        rec = {"ip": src_ip, "version": version, "community": community, "timestamp": datetime.now().isoformat()}
        reg_upsert(ip=src_ip, mac="", source="snmp", **{"protocols":["SNMP"],"network.vendor":"","ot.device_description":community})
        return rec
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

def snmp_get(ip, community='public', oid='1.3.6.1.2.1.1.1.0'):
    import socket, struct
    try:
        def encode_oid(oid_str):
            parts = [int(x) for x in oid_str.split('.')]
            result = [40*parts[0]+parts[1]]
            for p in parts[2:]:
                if p < 128: result.append(p)
                else:
                    enc = []
                    while p:
                        enc.append((p & 0x7f) | (0x80 if enc else 0))
                        p >>= 7
                    result.extend(reversed(enc))
            return bytes(result)
        oid_enc = encode_oid(oid)
        oid_tlv = b'\x06' + bytes([len(oid_enc)]) + oid_enc
        null = b'\x05\x00'
        varbind = b'\x30' + bytes([len(oid_tlv)+len(null)]) + oid_tlv + null
        varbinds = b'\x30' + bytes([len(varbind)]) + varbind
        comm = community.encode()
        comm_tlv = b'\x04' + bytes([len(comm)]) + comm
        ver = b'\x02\x01\x00'
        req_id = b'\x02\x01\x01'
        err = b'\x02\x01\x00'
        erridx = b'\x02\x01\x00'
        pdu = req_id+err+erridx+varbinds
        getreq = b'\xa0' + bytes([len(pdu)]) + pdu
        msg = ver+comm_tlv+getreq
        packet = b'\x30' + bytes([len(msg)]) + msg
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(packet, (ip, 161))
        data, _ = s.recvfrom(4096)
        s.close()
        val = data[data.rfind(b'\x04')+2:]
        return val.split(b'\x00')[0].decode(errors='ignore').strip()
    except Exception as e:
        return None

COMMON_OIDS = {
    'sysDescr':    '1.3.6.1.2.1.1.1.0',
    'sysName':     '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
    'sysContact':  '1.3.6.1.2.1.1.4.0',
    'sysUptime':   '1.3.6.1.2.1.1.3.0',
}

def run_snmp_query():
    from modules.core.asset_registry import all_records, upsert as reg_upsert
    C='\033[36m';G='\033[32m';R='\033[31m';D='\033[2m';RS='\033[0m'
    print(f"\n{C}  [SNMP] active query{RS}")
    recs = all_records()
    ips = [r['network']['ip'] for r in recs]
    for i,ip in enumerate(ips):
        print(f"  {C}[{i+1}]{RS} {ip}")
    print(f"  {C}[m]{RS} enter manually")
    print(f"  {C}[0]{RS} cancel")
    sel = input("  select target > ").strip()
    if sel == '0': return
    if sel == 'm':
        target = input("  enter IP > ").strip()
    else:
        try: target = ips[int(sel)-1]
        except: print(f"  {R}invalid{RS}"); return
    community = input(f"  community string [public] > ").strip() or 'public'
    print(f"\n  {C}[SNMP]{RS} querying {target} community={community}")
    found = {}
    for name,oid in COMMON_OIDS.items():
        val = snmp_get(target, community, oid)
        if val:
            found[name] = val
            print(f"  {G}{name}{RS}: {val}")
        else:
            print(f"  {D}{name}: no response{RS}")
    if found:
        reg_upsert(ip=target, mac='', source='snmp_query',
            **{'ot.device_description': found.get('sysDescr',''),
               'network.hostname': found.get('sysName',''),
               'physical.location': found.get('sysLocation','')})
        print(f"\n  {G}[SNMP]{RS} registry enriched for {target}")
    return found
