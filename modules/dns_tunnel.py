import socket, datetime, json, os, time
from modules.filestack import get_stack, write_json

THRESHOLD_QUERIES = 20
THRESHOLD_LEN = 40
WATCH_SECS = 60

def check_dns_length(hostname):
    parts = hostname.split('.')
    for p in parts:
        if len(p) > THRESHOLD_LEN:
            return True
    return len(hostname) > 100

def scan_dns_passive(hosts, duration=WATCH_SECS):
    from modules.alerts import add_alert
    print(f'\n  [DNS] passive monitor — {duration}s')
    findings = []
    query_counts = {}
    deadline = time.time() + duration
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
            socket.IPPROTO_UDP)
        sock.settimeout(2)
    except:
        print('  [DNS] raw socket requires root — skipping capture')
        findings = _check_filestack_dns(hosts)
        _save(findings)
        return
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
            ip = addr[0]
            if len(data) > 28:
                payload = data[28:]
                if len(payload) > 12:
                    query_counts[ip] = query_counts.get(ip,0) + 1
                    if query_counts[ip] > THRESHOLD_QUERIES:
                        msg = f'{ip} excessive DNS queries: {query_counts[ip]}'
                        findings.append({'ip':ip,'type':'HIGH_VOLUME',
                            'count':query_counts[ip],
                            'ts':datetime.datetime.now().isoformat()})
                        add_alert(f'DNS TUNNEL SUSPECT {msg}',severity='HIGH')
        except: pass
    sock.close()
    _save(findings)

def _check_filestack_dns(hosts):
    findings = []
    for h in hosts:
        ip = h.get('ip') if isinstance(h,dict) else h
        if not ip: continue
        try:
            name = socket.gethostbyaddr(ip)[0]
            if check_dns_length(name):
                findings.append({'ip':ip,'type':'LONG_HOSTNAME',
                    'hostname':name,
                    'ts':datetime.datetime.now().isoformat()})
        except: pass
    return findings

def _save(findings):
    write_json('dns_findings.json',{
        'timestamp':datetime.datetime.now().isoformat(),
        'findings':findings})
    print(f'  [DNS] {len(findings)} anomalies — dns_findings.json written')

def run_dns_tunnel(duration=WATCH_SECS):
    from modules.filestack import get_stack
    import json, os
    p = os.path.join(get_stack(),'hosts.json')
    hosts = []
    if os.path.exists(p):
        try:
            with open(p) as f: hosts = json.load(f).get('hosts',[])
        except: pass
    scan_dns_passive(hosts, duration)
