import socket, struct, threading
from datetime import datetime
from modules.core.filestack import write_json
from modules.core.asset_registry import upsert as reg_upsert

MDNS_ADDR = '224.0.0.251'
MDNS_PORT = 5353
_now = lambda: datetime.utcnow().isoformat()+'Z'

def _parse_mdns(data, src_ip):
    try:
        name_parts = []
        i = 12
        while i < len(data) and data[i] != 0:
            length = data[i]
            if length & 0xC0 == 0xC0: break
            i += 1
            name_parts.append(data[i:i+length].decode(errors='ignore'))
            i += length
        return '.'.join(name_parts)
    except: return ''

def _infer_type(name):
    n = name.lower()
    if '_airplay' in n or '_raop' in n: return 'apple','Apple AirPlay'
    if '_googlecast' in n: return 'iot','Google Chromecast'
    if '_ipp' in n or '_printer' in n: return 'printer','Network Printer'
    if '_smb' in n or '_afpovertcp' in n: return 'server','File Server'
    if '_http' in n: return 'server','HTTP Service'
    if '_bacnet' in n: return 'controller','BACnet Device'
    if '_niagara' in n: return 'controller','Niagara BAS'
    return 'unknown','unknown'

def run_mdns(duration=30):
    C='\033[36m';G='\033[32m';Y='\033[33m'
    D='\033[2m';RS='\033[0m'
    print(f"\n{C}  [mDNS] passive listener — {duration}s{RS}")
    findings = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', MDNS_PORT))
        mreq = struct.pack('4sL', socket.inet_aton(MDNS_ADDR),
            socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(2)
        import time; end = time.time() + duration
        seen = set()
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                name = _parse_mdns(data, src_ip)
                if not name or src_ip in seen: continue
                seen.add(src_ip)
                dtype, vendor = _infer_type(name)
                findings.append({'ip':src_ip,'name':name,
                    'type':dtype,'vendor':vendor,'ts':_now()})
                reg_upsert(ip=src_ip, mac='', source='mdns',
                    **{'network.hostname':name.split('.')[0],
                       'type':dtype,'network.vendor':vendor,
                       'protocols':['mDNS']})
                print(f"  {C}{src_ip}{RS} {name[:50]} [{dtype}]")
            except socket.timeout: continue
        sock.close()
    except Exception as e:
        print(f"  {D}mDNS unavailable: {e}{RS}")
    write_json('mdns_findings.json',
        {'timestamp':_now(),'count':len(findings),
         'findings':findings})
    print(f"\n  {G}[mDNS]{RS} {len(findings)} devices — mdns_findings.json written")
    return findings
