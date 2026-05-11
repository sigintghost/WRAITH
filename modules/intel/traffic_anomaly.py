import socket, os, time, datetime, json, struct
from modules.core.asset_registry import upsert as reg_upsert
from modules.core.filestack import get_stack, write_json

BYTE_THRESHOLD = 500000
CONN_THRESHOLD = 50
WATCH_SECS = 60
MICRO_EXFIL_BYTES = 100
MICRO_EXFIL_COUNT = 30

def run_traffic_anomaly(duration=WATCH_SECS):
    from modules.core.alerts import fire as add_alert
    print(f'\n  [TRAFFIC] anomaly monitor — {duration}s')
    findings = []
    byte_map = {}
    conn_map = {}
    micro_map = {}
    try:
        sock = socket.socket(socket.AF_INET,
            socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.settimeout(2)
    except:
        print('  [TRAFFIC] raw socket requires root — skipping')
        _save([])
        return
    deadline = time.time() + duration
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65535)
            ip = addr[0]
            plen = len(data)
            byte_map[ip] = byte_map.get(ip,0) + plen
            conn_map[ip] = conn_map.get(ip,0) + 1
            if plen < MICRO_EXFIL_BYTES:
                micro_map[ip] = micro_map.get(ip,0) + 1
            flags = []
            if byte_map[ip] > BYTE_THRESHOLD:
                flags.append(f'HIGH_VOLUME:{byte_map[ip]}b')
            if conn_map[ip] > CONN_THRESHOLD:
                flags.append(f'HIGH_CONN:{conn_map[ip]}')
            if micro_map.get(ip,0) > MICRO_EXFIL_COUNT:
                flags.append(f'MICRO_EXFIL:{micro_map[ip]}pkts')
            if flags:
                existing = [f for f in findings if f['ip']==ip]
                if not existing:
                    msg = f'{ip} traffic flags={flags}'
                    print(f'  [!] {msg}')
                    findings.append({'ip':ip,'flags':flags,
                        'bytes':byte_map[ip],
                        'conns':conn_map[ip],
                        'ts':datetime.datetime.now().isoformat()})
                    add_alert(f'TRAFFIC ANOMALY {msg}',
                        severity='HIGH')
        except: pass
    sock.close()
    _save(findings)

def _save(findings):
    write_json('traffic_findings.json',{
        'timestamp':datetime.datetime.now().isoformat(),
        'findings':findings})
    print(f'  [TRAFFIC] {len(findings)} anomalies — traffic_findings.json written')
