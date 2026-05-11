import socket, os, time, datetime, json, struct
from modules.core.filestack import get_stack, write_json

ETHERTYPE_8021Q = 0x8100
ETHERTYPE_8021AD = 0x88A8
WATCH_SECS = 60

def parse_frame(data):
    if len(data) < 14: return None
    eth_type = struct.unpack('!H', data[12:14])[0]
    result = {'double_tagged':False,'vlan_ids':[]}
    if eth_type in (ETHERTYPE_8021Q, ETHERTYPE_8021AD):
        if len(data) < 18: return result
        vlan1 = struct.unpack('!H', data[14:16])[0] & 0x0FFF
        result['vlan_ids'].append(vlan1)
        inner_type = struct.unpack('!H', data[16:18])[0]
        if inner_type == ETHERTYPE_8021Q:
            if len(data) < 22: return result
            vlan2 = struct.unpack('!H', data[18:20])[0] & 0x0FFF
            result['vlan_ids'].append(vlan2)
            result['double_tagged'] = True
    return result

def run_vlan_hop(duration=WATCH_SECS):
    from modules.core.alerts import fire as add_alert
    print(f'\n  [VLAN] hop detection — {duration}s')
    findings = []
    try:
        sock = socket.socket(socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003))
        sock.settimeout(2)
    except:
        print('  [VLAN] raw socket requires root — skipping')
        _save([])
        return
    deadline = time.time() + duration
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65535)
            parsed = parse_frame(data)
            if not parsed: continue
            if parsed['double_tagged']:
                src_mac = ':'.join(f'{b:02x}' for b in data[6:12])
                vlans = parsed['vlan_ids']
                msg = f'DOUBLE-TAG src={src_mac} vlans={vlans}'
                print(f'  [!!!] VLAN HOP DETECTED {msg}')
                findings.append({
                    'src_mac':src_mac,
                    'vlan_ids':vlans,
                    'type':'DOUBLE_TAG',
                    'ts':datetime.datetime.now().isoformat()})
                add_alert(f'VLAN HOP {msg}', severity='CRITICAL')
        except: pass
    sock.close()
    _save(findings)

def _save(findings):
    write_json('vlan_findings.json',{
        'timestamp':datetime.datetime.now().isoformat(),
        'findings':findings})
    print(f'  [VLAN] {len(findings)} anomalies — vlan_findings.json written')
