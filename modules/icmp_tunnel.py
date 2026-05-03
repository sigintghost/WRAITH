import socket, os, time, datetime, json, struct
from modules.filestack import get_stack, write_json

PAYLOAD_THRESHOLD = 64
RATE_THRESHOLD = 10
WATCH_SECS = 60

def parse_icmp(data):
    if len(data) < 28: return None
    ihl = (data[0] & 0x0F) * 4
    if len(data) < ihl + 8: return None
    icmp = data[ihl:]
    typ = icmp[0]
    code = icmp[1]
    payload_len = len(icmp) - 8
    return {'type':typ,'code':code,'payload_len':payload_len}

def run_icmp_tunnel(duration=WATCH_SECS):
    from modules.alerts import add_alert
    print(f'\n  [ICMP] tunnel monitor — {duration}s')
    findings = []
    rate_map = {}
    try:
        sock = socket.socket(socket.AF_INET,
            socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(2)
    except:
        print('  [ICMP] raw socket requires root — skipping')
        _save([])
        return
    deadline = time.time() + duration
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
            ip = addr[0]
            parsed = parse_icmp(data)
            if not parsed: continue
            rate_map[ip] = rate_map.get(ip, 0) + 1
            flags = []
            if parsed['payload_len'] > PAYLOAD_THRESHOLD:
                flags.append(f'OVERSIZED:{parsed["payload_len"]}b')
            if parsed['type'] not in (0,8):
                flags.append(f'NONSTANDARD_TYPE:{parsed["type"]}')
            if rate_map[ip] > RATE_THRESHOLD:
                flags.append(f'HIGH_RATE:{rate_map[ip]}')
            if flags:
                msg = f'{ip} ICMP flags={flags}'
                print(f'  [!] {msg}')
                findings.append({'ip':ip,'flags':flags,
                    'type':parsed['type'],
                    'payload_len':parsed['payload_len'],
                    'ts':datetime.datetime.now().isoformat()})
                add_alert(f'ICMP TUNNEL SUSPECT {msg}',
                    severity='HIGH')
        except: pass
    sock.close()
    _save(findings)

def _save(findings):
    write_json('icmp_findings.json',{
        'timestamp':datetime.datetime.now().isoformat(),
        'findings':findings})
    print(f'  [ICMP] {len(findings)} anomalies — icmp_findings.json written')
