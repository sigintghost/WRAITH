import socket, struct, time, re
from datetime import datetime
from modules.core.filestack import write_json
from modules.core.asset_registry import upsert as reg_upsert

SSDP_ADDR = '239.255.255.250'
SSDP_PORT = 1900
_now = lambda: datetime.utcnow().isoformat()+'Z'

SSDP_MSEARCH = (
    'M-SEARCH * HTTP/1.1\r\n'
    'HOST: 239.255.255.250:1900\r\n'
    'MAN: "ssdp:discover"\r\n'
    'MX: 3\r\n'
    'ST: ssdp:all\r\n\r\n'
).encode()

def _parse_ssdp(data):
    headers = {}
    for line in data.decode(errors='ignore').splitlines():
        if ':' in line:
            k,v = line.split(':',1)
            headers[k.strip().upper()] = v.strip()
    return headers

def _infer_type(headers):
    st = headers.get('ST','').lower()
    server = headers.get('SERVER','').lower()
    if 'samsung' in server or 'samsung' in st:
        return 'iot','Samsung'
    if 'google' in server or 'chromecast' in st:
        return 'iot','Google'
    if 'roku' in server: return 'iot','Roku'
    if 'ring' in server: return 'camera','Ring'
    if 'bacnet' in st: return 'controller','BACnet'
    if 'printer' in st: return 'printer','Printer'
    if 'mediaserver' in st: return 'server','Media Server'
    if 'router' in server or 'gateway' in server:
        return 'router','Router'
    return 'unknown','unknown'

def run_ssdp(duration=15):
    C='\033[36m';G='\033[32m';Y='\033[33m'
    D='\033[2m';RS='\033[0m'
    print(f"\n{C}  [SSDP] passive UPnP discovery — {duration}s{RS}")
    findings = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2)
        sock.sendto(SSDP_MSEARCH, (SSDP_ADDR, SSDP_PORT))
        end = time.time() + duration
        seen = set()
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                if src_ip in seen: continue
                seen.add(src_ip)
                headers = _parse_ssdp(data)
                dtype, vendor = _infer_type(headers)
                server = headers.get('SERVER','unknown')
                location = headers.get('LOCATION','')
                findings.append({'ip':src_ip,'server':server,
                    'type':dtype,'vendor':vendor,
                    'location':location,'ts':_now()})
                reg_upsert(ip=src_ip, mac='', source='ssdp',
                    **{'type':dtype,'network.vendor':vendor,
                       'network.http_banner':server[:80],
                       'protocols':['SSDP']})
                print(f"  {C}{src_ip}{RS} {server[:40]} [{dtype}]")
                if location:
                    print(f"  {D}  location: {location[:60]}{RS}")
            except socket.timeout: continue
        sock.close()
    except Exception as e:
        print(f"  {D}SSDP unavailable: {e}{RS}")
    write_json('ssdp_findings.json',
        {'timestamp':_now(),'count':len(findings),
         'findings':findings})
    print(f"\n  {G}[SSDP]{RS} {len(findings)} devices — ssdp_findings.json written")
    return findings
