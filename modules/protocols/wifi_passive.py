import os, json, socket, subprocess
from datetime import datetime
from modules.core.filestack import get_stack, write_json
from modules.core.asset_registry import upsert as reg_upsert

WIFI_FILE = 'wifi_clients.json'

def _now(): return datetime.utcnow().isoformat()+'Z'

def get_gateway_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return None

def scan_arp_table():
    clients = []
    try:
        result = subprocess.run(['cat','/proc/net/arp'],
            capture_output=True, text=True)
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3]
                flags = parts[2]
                if mac != '00:00:00:00:00:00' and flags != '0x0':
                    clients.append({'ip':ip,'mac':mac,'ts':_now()})
    except: pass
    return clients

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except: return ''

def infer_device_type(hostname, mac=''):
    hostname = hostname.lower()
    mac_prefix = mac[:8].lower() if mac else ''
    if any(x in hostname for x in ['iphone','apple','macbook','ipad']):
        return 'mobile', 'Apple'
    if any(x in hostname for x in ['android','samsung','pixel']):
        return 'mobile', 'Android'
    if any(x in hostname for x in ['router','gateway','dsl','modem','att']):
        return 'router', 'ISP'
    if any(x in hostname for x in ['chromecast','google','nest']):
        return 'iot', 'Google'
    if any(x in hostname for x in ['ring','camera','cam']):
        return 'camera', 'IoT'
    if any(x in hostname for x in ['jace','niagara','bacnet','tridium']):
        return 'controller', 'BAS'
    return 'unknown', 'unknown'

def run_wifi_passive():
    C='\033[36m';G='\033[32m';Y='\033[33m';R='\033[31m'
    D='\033[2m';RS='\033[0m'
    print(f"\n{C}  [WIFI] passive client discovery{RS}")
    print(f"  {D}reading ARP table + DNS inference{RS}")
    clients = scan_arp_table()
    enriched = []
    for c in clients:
        ip = c['ip']
        mac = c['mac']
        hostname = resolve_hostname(ip)
        dtype, vendor = infer_device_type(hostname, mac)
        entry = {
            'ip': ip, 'mac': mac,
            'hostname': hostname,
            'device_type': dtype,
            'vendor_inferred': vendor,
            'timestamp': _now()
        }
        enriched.append(entry)
        reg_upsert(ip=ip, mac=mac, source='wifi_passive',
            **{'type': dtype,
               'network.vendor': vendor,
               'network.hostname': hostname,
               'network.mac': mac,
               'protocols': ['WiFi']})
        auth_str = f"{D}known{RS}" if dtype != 'unknown' else f"{Y}unknown{RS}"
        print(f"  {C}{ip}{RS} {mac} {hostname or D+'no hostname'+RS} [{auth_str}]")
    write_json(WIFI_FILE, {
        'timestamp': _now(),
        'count': len(enriched),
        'clients': enriched
    })
    print(f"\n  {G}[WIFI]{RS} {len(enriched)} clients — {WIFI_FILE} written")
    return enriched
