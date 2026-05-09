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
    from modules.alerts import fire as add_alert
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
        msg = f'ROGUE: {ip} on wire — not in asset database'
        print(f'  [!!!] {msg}')
        gaps.append({'ip':ip,'type':'ROGUE','source':'asset_db_gap'})
        add_alert(msg, severity='CRITICAL')
    for ip in offline:
        asset = next((a for a in assets if a.get('ip')==ip), {})
        msg = f'OFFLINE: {ip} in asset DB but not on wire — {asset.get("name","")}'
        print(f'  [!] {msg}')
        gaps.append({'ip':ip,'type':'OFFLINE','source':'asset_db_gap',
            'asset':asset.get('name','')})
        add_alert(msg, severity='MEDIUM')
    return gaps

def run_asset_db_connector():
    print('\n  [ASSET DB] asset connector')
    print('  supported formats: CSV, JSON')
    path = input('  Asset DB file path (CSV or JSON): ').strip()
    if not path or not os.path.exists(path):
        print('  [ASSET DB] file not found')
        return
    fmt = detect_format(path)
    print(f'  [ASSET DB] detected format: {fmt}')
    raw = parse_json(path) if fmt=='json' else parse_csv(path)
    assets = normalize(raw)
    print(f'  [ASSET DB] {len(assets)} assets loaded')
    gaps = gap_analysis(assets)
    write_json('asset_db.json', {
        'timestamp': datetime.datetime.now().isoformat(),
        'source': path,
        'format': fmt,
        'assets': assets,
        'gaps': gaps
    })
    print(f'  [ASSET DB] {len(gaps)} gaps — asset_db.json written')
