import os, json, datetime, time
from modules.filestack import get_stack, write_json

HOP_WINDOW_SECS = 60
HOP_THRESHOLD = 5
SUSPICIOUS_RANGES = [
    (1024, 1100), (4444, 4445), (6666, 6667),
    (8080, 8090), (9000, 9100), (49150, 49160),
]

def is_suspicious_port(port):
    for low, high in SUSPICIOUS_RANGES:
        if low <= port <= high:
            return True
    return False

def analyze_port_hops():
    from modules.alerts import fire as add_alert
    print('\n  [PORT HOP] analyzing portscan history')
    p = os.path.join(get_stack(), 'portscan.json')
    if not os.path.exists(p):
        print('  [PORT HOP] no portscan data — run SCAN first')
        return []
    with open(p) as f: ps = json.load(f)
    scans = ps.get('scans', [])
    findings = []
    ip_ports = {}
    for scan in scans:
        ip = scan.get('target','')
        ports = [x.get('port') for x in scan.get('ports',[])
            if isinstance(x,dict) and x.get('state')=='OPEN']
        if not ip or not ports: continue
        ip_ports[ip] = ports
    for ip, ports in ip_ports.items():
        suspicious = [p for p in ports if is_suspicious_port(p)]
        if len(ports) >= HOP_THRESHOLD:
            msg = f'{ip} port hopping — {len(ports)} ports open'
            print(f'  [!] {msg}')
            findings.append({'ip':ip,'ports':ports,
                'type':'PORT_HOP','count':len(ports),
                'ts':datetime.datetime.now().isoformat()})
            add_alert(msg, severity='HIGH',
                source='port_hop', ip=ip)
        if suspicious:
            msg = f'{ip} suspicious ports — {suspicious}'
            print(f'  [!] {msg}')
            findings.append({'ip':ip,'ports':suspicious,
                'type':'SUSPICIOUS_PORTS',
                'ts':datetime.datetime.now().isoformat()})
            add_alert(msg, severity='HIGH',
                source='port_hop', ip=ip)
    return findings

def run_port_hop():
    findings = analyze_port_hops()
    write_json('port_hop_findings.json', {
        'timestamp': datetime.datetime.now().isoformat(),
        'findings': findings
    })
    if not findings:
        print('  [PORT HOP] no anomalies detected')
    else:
        print(f'  [PORT HOP] {len(findings)} anomalies — port_hop_findings.json written')
