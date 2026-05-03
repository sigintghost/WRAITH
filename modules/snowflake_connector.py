import os, json, datetime
from modules.filestack import get_stack

SNOW_CONFIG_PATH = os.path.expanduser('~/.wraith/snowflake.json')

def load_config():
    if not os.path.exists(SNOW_CONFIG_PATH):
        return None
    with open(SNOW_CONFIG_PATH) as f:
        return json.load(f)

def save_config(cfg):
    os.makedirs(os.path.dirname(SNOW_CONFIG_PATH), exist_ok=True)
    with open(SNOW_CONFIG_PATH, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.chmod(SNOW_CONFIG_PATH, 0o600)
    print('  [SNOW] config saved chmod 600')

def build_payload():
    stack = get_stack()
    ts = datetime.datetime.now().isoformat()
    payload = {'timestamp': ts, 'records': []}
    files = {
        'hosts.json': 'SWEEP',
        'portscan.json': 'PORTSCAN',
        'alerts.json': 'ALERT',
        'baseline.json': 'BASELINE',
        'mac_findings.json': 'MAC',
        'dns_findings.json': 'DNS',
        'icmp_findings.json': 'ICMP',
        'traffic_findings.json': 'TRAFFIC',
        'vlan_findings.json': 'VLAN',
        'rf_findings.json': 'RF',
        'fsi_assets.json': 'FSI',
    }
    for fn, record_type in files.items():
        fp = os.path.join(stack, fn)
        if not os.path.exists(fp): continue
        try:
            with open(fp) as f: data = json.load(f)
            payload['records'].append({
                'type': record_type,
                'source': fn,
                'timestamp': ts,
                'data': data
            })
        except: pass
    return payload

def push_to_snowflake(payload):
    cfg = load_config()
    if not cfg:
        print('  [SNOW] no config — run setup first')
        return False
    try:
        import urllib.request, urllib.error
        url = cfg.get('endpoint','')
        token = cfg.get('token','')
        if not url or not token:
            print('  [SNOW] missing endpoint or token')
            return False
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url,
            data=body,
            headers={'Content-Type':'application/json',
                     'Authorization':f'Bearer {token}'},
            method='POST')
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f'  [SNOW] pushed {len(payload["records"])} types — {r.status}')
            return True
    except Exception as e:
        print(f'  [SNOW] push failed: {e}')
        return False

def setup_snowflake():
    print('\n  [SNOW] Snowflake pipeline setup')
    endpoint = input('  endpoint URL: ').strip()
    token = input('  bearer token: ').strip()
    account = input('  account name: ').strip()
    warehouse = input('  warehouse: ').strip()
    database = input('  database: ').strip()
    schema = input('  schema [WRAITH]: ').strip() or 'WRAITH'
    cfg = {'endpoint':endpoint,'token':token,
           'account':account,'warehouse':warehouse,
           'database':database,'schema':schema}
    save_config(cfg)
    print('  [SNOW] setup complete')

def run_snowflake():
    print('\n  [SNOW] Snowflake pipeline')
    print('  [1] setup connection')
    print('  [2] push filestack now')
    print('  [3] test connection')
    print('  [0] back')
    c = input('  > ').strip()
    if c == '1': setup_snowflake()
    elif c == '2':
        payload = build_payload()
        push_to_snowflake(payload)
    elif c == '3':
        cfg = load_config()
        if cfg:
            print(f'  [SNOW] account={cfg.get("account")} db={cfg.get("database")}')
        else: print('  [SNOW] no config — run setup')
    else: return
