import socket, os, json
from datetime import datetime
from modules.core.filestack import get_stack, write_json
from modules.core.asset_registry import upsert as reg_upsert

DNS_FILE = 'passive_dns.json'
def _now(): return datetime.utcnow().isoformat()+'Z'

def resolve_ip(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return None

def reverse_lookup(hostname):
    try: return socket.gethostbyname(hostname)
    except: return None

def fingerprint_hostname(hostname):
    if not hostname: return 'unknown','unknown'
    h = hostname.lower()
    if any(x in h for x in ['iphone','apple','macbook','ipad','airport']):
        return 'mobile','Apple'
    if any(x in h for x in ['android','samsung','pixel','google']):
        return 'mobile','Google'
    if any(x in h for x in ['dsl','modem','router','gateway','att','comcast']):
        return 'router','ISP'
    if any(x in h for x in ['jace','niagara','tridium','bacnet','alc','webctrl']):
        return 'controller','BAS'
    if any(x in h for x in ['camera','cam','nvr','dvr','ring','nest']):
        return 'camera','IoT'
    if any(x in h for x in ['printer','print','hp','xerox']):
        return 'printer','Office'
    if any(x in h for x in ['switch','ap','wap','wifi','wireless']):
        return 'ap','Network'
    return 'unknown','unknown'

def run_passive_dns():
    C='\033[36m';G='\033[32m';Y='\033[33m'
    D='\033[2m';RS='\033[0m'
    print(f"\n{C}  [DNS] passive hostname resolution{RS}")
    from modules.core.asset_registry import all_records
    recs = all_records()
    findings = []
    for r in recs:
        ip = r['network']['ip']
        existing = r['network']['hostname']
        hostname = resolve_ip(ip)
        dtype, vendor = fingerprint_hostname(hostname)
        entry = {'ip':ip,'hostname':hostname or '','type_inferred':dtype,'vendor_inferred':vendor,'ts':_now()}
        findings.append(entry)
        if hostname:
            reg_upsert(ip=ip, mac='', source='passive_dns',
                **{'network.hostname':hostname,'type':dtype if dtype!='unknown' else r['type'],'network.vendor':vendor if vendor!='unknown' else r['network']['vendor']})
            changed = hostname != existing
            marker = f"{Y}NEW{RS}" if changed else f"{D}same{RS}"
            print(f"  {C}{ip}{RS} -> {hostname} [{dtype}] {marker}")
        else:
            print(f"  {D}{ip} -> no hostname{RS}")
    write_json(DNS_FILE,{'timestamp':_now(),'count':len(findings),'findings':findings})
    print(f"\n  {G}[DNS]{RS} {len(findings)} hosts resolved — {DNS_FILE} written")
    return findings
