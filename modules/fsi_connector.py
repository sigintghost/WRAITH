import os, json, csv, datetime
from modules.filestack import get_stack, write_json

def detect_format(path):
    if path.endswith('.json'): return 'json'
    if path.endswith('.csv'): return 'csv'
    try:
        with open(path) as f: json.load(f)
        return 'json'
    except:
        return 'csv'

def parse_json(path):
    with open(path) as f: data = json.load(f)
    if isinstance(data, list): return data
    if isinstance(data, dict):
        for k in ('assets','devices','equipment','items'):
            if k in data: return data[k]
    return []

def parse_csv(path):
    assets = []
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            assets.append(dict(row))
    return assets

def normalize(raw):
    normalized = []
    for a in raw:
        lower = {k.lower().strip(): v for k,v in a.items()}
        asset = {
            'asset_id':   lower.get('asset_id', lower.get('id','')),
            'name':       lower.get('name', lower.get('asset_name','')),
            'ip':         lower.get('ip', lower.get('ip_address','')),
            'mac':        lower.get('mac', lower.get('mac_address','')),
            'location':   lower.get('location', lower.get('room','')),
            'vendor':     lower.get('vendor', lower.get('manufacturer','')),
            'model':      lower.get('model', lower.get('model_number','')),
            'firmware':   lower.get('firmware', lower.get('firmware_rev','')),
            'protocol':   lower.get('protocol', lower.get('comm_protocol','')),
            'status':     lower.get('status', lower.get('asset_status','')),
            'sop':        lower.get('sop', lower.get('maintenance_sop','')),
            'notes':      lower.get('notes', lower.get('comments','')),
        }
        normalized.append(asset)
    return normalized

def gap_analysis(assets):
    from modules.alerts import add_alert
    stack = get_stack()
    p = os.path.join(stack, 'hosts.json')
    if not os.path.exists(p): return []
    with open(p) as f: hosts = json.load(f).get('hosts',[])
    live_ips = set()
    for h in hosts:
        ip = h.get('ip') if isinstance(h,dict) else h
        if ip: live_ips.add(ip)
    asset_ips = set(a['ip'] for a in assets if a.get('ip'))
    rogues = live_ips - asset_ips
    offline = asset_ips - live_ips
    gaps = []
    for ip in rogues:
        msg = f'ROGUE: {ip} on wire — not in FSI asset database'
        print(f'  [!!!] {msg}')
        gaps.append({'ip':ip,'type':'ROGUE','source':'fsi_gap'})
        add_alert(msg, severity='CRITICAL')
    for ip in offline:
        asset = next((a for a in assets if a.get('ip')==ip), {})
        msg = f'OFFLINE: {ip} in FSI but not on wire — {asset.get("name","")}'
        print(f'  [!] {msg}')
        gaps.append({'ip':ip,'type':'OFFLINE','source':'fsi_gap',
            'asset':asset.get('name','')})
        add_alert(msg, severity='MEDIUM')
    return gaps

def run_fsi_connector():
    print('\n  [FSI] asset connector')
    print('  supported formats: CSV, JSON')
    path = input('  FSI export path: ').strip()
    if not path or not os.path.exists(path):
        print('  [FSI] file not found')
        return
    fmt = detect_format(path)
    print(f'  [FSI] detected format: {fmt}')
    raw = parse_json(path) if fmt=='json' else parse_csv(path)
    assets = normalize(raw)
    print(f'  [FSI] {len(assets)} assets loaded')
    gaps = gap_analysis(assets)
    write_json('fsi_assets.json', {
        'timestamp': datetime.datetime.now().isoformat(),
        'source': path,
        'format': fmt,
        'assets': assets,
        'gaps': gaps
    })
    print(f'  [FSI] {len(gaps)} gaps — fsi_assets.json written')
