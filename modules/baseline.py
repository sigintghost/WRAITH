import json, os, datetime
from modules.filestack import get_stack, write_json

def load_json(name):
    p = os.path.join(get_stack(), name)
    if not os.path.exists(p): return {}
    try:
        with open(p) as f: return json.load(f)
    except: return {}

def build_snapshot():
    hosts = load_json('hosts.json').get('hosts', [])
    scans = load_json('portscan.json').get('scans', [])
    arps  = load_json('arp_table.json').get('hosts', [])
    ttls  = load_json('ttl_fingerprints.json').get('hosts', [])
    snap = {}
    for h in hosts:
        ip = h.get('ip') if isinstance(h,dict) else h
        if not ip: continue
        snap[ip] = {'ports':[], 'mac':'', 'os':'', 'seen':1}
    for s in scans:
        ip = s.get('target')
        if ip not in snap: snap[ip] = {'ports':[],'mac':'','os':'','seen':1}
        snap[ip]['ports'] = [p.get('port') for p in s.get('ports',[])
            if isinstance(p,dict) and p.get('state')=='OPEN']
    for a in arps:
        if not isinstance(a,dict): continue
        ip = a.get('ip')
        if ip in snap: snap[ip]['mac'] = a.get('mac','')
    for t in ttls:
        if not isinstance(t,dict): continue
        ip = t.get('ip')
        if ip in snap: snap[ip]['os'] = t.get('os','')
    return snap

def compare(old, new):
    alerts = []
    for ip, nd in new.items():
        if ip not in old:
            alerts.append({'ip':ip,'type':'NEW_HOST','detail':'first appearance'})
            continue
        od = old[ip]
        added = set(nd['ports']) - set(od['ports'])
        removed = set(od['ports']) - set(nd['ports'])
        if added:
            alerts.append({'ip':ip,'type':'PORT_OPENED','detail':list(added)})
        if removed:
            alerts.append({'ip':ip,'type':'PORT_CLOSED','detail':list(removed)})
        if nd['mac'] and od['mac'] and nd['mac'] != od['mac']:
            alerts.append({'ip':ip,'type':'MAC_CHANGED','detail':f"{od['mac']} -> {nd['mac']}"})
        if nd['os'] and od['os'] and nd['os'] != od['os']:
            alerts.append({'ip':ip,'type':'OS_CHANGED','detail':f"{od['os']} -> {nd['os']}"})
    return alerts

def save_baseline(snap):
    write_json('baseline.json', {
        'timestamp': datetime.datetime.now().isoformat(),
        'hosts': snap
    })

def run_baseline():
    from modules.alerts import fire as add_alert
    print('\n  [BASELINE] building snapshot...')
    existing = load_json('baseline.json')
    old_snap = existing.get('hosts', {})
    if isinstance(old_snap, list): old_snap = {}
    new_snap = build_snapshot()
    if not old_snap:
        save_baseline(new_snap)
        print(f'  [BASELINE] initial baseline set — {len(new_snap)} hosts')
        return
    alerts = compare(old_snap, new_snap)
    save_baseline(new_snap)
    if not alerts:
        print(f'  [BASELINE] no deviation — {len(new_snap)} hosts nominal')
        return
    print(f'  [BASELINE] {len(alerts)} deviations detected')
    for a in alerts:
        msg = f"{a['ip']} {a['type']}: {a['detail']}"
        print(f'  [!] {msg}')
        add_alert(msg, severity='HIGH' if 'MAC' in a['type'] else 'MEDIUM')
