import os, json, datetime
from modules.core.filestack import get_stack, write_json

WO_CONFIG_PATH = os.path.expanduser('~/.wraith/workorder.json')
WATCH_PATH = os.path.expanduser('~/.wraith/fault_watch/')

def load_config():
    if not os.path.exists(WO_CONFIG_PATH): return {}
    with open(WO_CONFIG_PATH) as f: return json.load(f)

def save_config(cfg):
    os.makedirs(os.path.dirname(WO_CONFIG_PATH), exist_ok=True)
    with open(WO_CONFIG_PATH, 'w') as f: json.dump(cfg, f, indent=2)
    os.chmod(WO_CONFIG_PATH, 0o600)
    print('  [WO] config saved')

def parse_fault_line(line):
    line = line.strip()
    if not line: return None
    fault = {
        'raw': line,
        'timestamp': datetime.datetime.now().isoformat(),
        'device': '',
        'fault': '',
        'priority': 'MEDIUM',
    }
    parts = line.split(',')
    if len(parts) >= 2:
        fault['device'] = parts[0].strip()
        fault['fault'] = parts[1].strip()
    else:
        fault['fault'] = line
    critical = ['fail','fault','alarm','critical','offline','trip']
    if any(w in line.lower() for w in critical):
        fault['priority'] = 'HIGH'
    return fault

def parse_fault_file(path):
    faults = []
    with open(path) as f:
        for line in f:
            parsed = parse_fault_line(line)
            if parsed: faults.append(parsed)
    return faults

def build_work_order(fault, cfg):
    return {
        'title': f'[WRAITH] {fault["device"]} — {fault["fault"]}',
        'device': fault['device'],
        'fault': fault['fault'],
        'priority': fault['priority'],
        'timestamp': fault['timestamp'],
        'building': cfg.get('building',''),
        'assigned_to': cfg.get('default_assignee',''),
        'source': 'WRAITH auto-generated',
        'notes': f'Auto-generated from WebCTRL fault export.\nRaw: {fault["raw"]}'
    }

def push_work_order(wo, cfg):
    api_url = cfg.get('api_url','')
    api_key = cfg.get('api_key','')
    if not api_url:
        print(f'  [WO] no API — logging locally: {wo["title"]}')
        return False
    try:
        import urllib.request
        body = json.dumps(wo).encode()
        req = urllib.request.Request(api_url,
            data=body,
            headers={'Content-Type':'application/json',
                     'Authorization':f'Bearer {api_key}'},
            method='POST')
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f'  [WO] created: {wo["title"]} — {r.status}')
            return True
    except Exception as e:
        print(f'  [WO] push failed: {e}')
        return False

def watch_fault_folder():
    cfg = load_config()
    watch = cfg.get('watch_path', WATCH_PATH)
    os.makedirs(watch, exist_ok=True)
    print(f'  [WO] watching {watch}')
    processed = []
    files = [f for f in os.listdir(watch) if f.endswith('.txt') or f.endswith('.csv')]
    if not files:
        print('  [WO] no fault files found')
        return
    for fn in files:
        if fn in processed: continue
        path = os.path.join(watch, fn)
        faults = parse_fault_file(path)
        print(f'  [WO] {fn} — {len(faults)} faults')
        for fault in faults:
            wo = build_work_order(fault, cfg)
            push_work_order(wo, cfg)
        processed.append(fn)
    write_json('workorders.json', {
        'timestamp': datetime.datetime.now().isoformat(),
        'processed': processed,
        'count': len(processed)
    })

def setup_workorder():
    print('\n  [WO] CMMS work order setup')
    api_url = input('  CMMS API endpoint: ').strip()
    api_key = input('  API key: ').strip()
    building = input('  building name: ').strip()
    assignee = input('  default assignee: ').strip()
    watch = input(f'  fault watch path [{WATCH_PATH}]: ').strip() or WATCH_PATH
    save_config({'api_url':api_url,'api_key':api_key,
        'building':building,'default_assignee':assignee,
        'watch_path':watch})

def run_workorder_agent():
    print('\n  [WO] CMMS work orders')
    print('  [1] setup connection')
    print('  [2] scan fault folder')
    print('  [3] view config')
    print('  [4] edit config')
    print('  [0] back')
    c = input('  > ').strip()
    if c == '1': setup_workorder()
    elif c == '2': watch_fault_folder()
    elif c == '3':
        cfg = load_config()
        if cfg:
            for k,v in cfg.items(): print(f'  {k}: {v}')
        else: print('  [WO] no config — run setup')
    elif c == '4':
        cfg = load_config() or {}
        building = input(f'  building [{cfg.get("building","")}]: ').strip()
        assignee = input(f'  assignee [{cfg.get("default_assignee","")}]: ').strip()
        api_url = input(f'  API URL [{cfg.get("api_url","")}]: ').strip()
        if building: cfg['building'] = building
        if assignee: cfg['default_assignee'] = assignee
        if api_url: cfg['api_url'] = api_url
        save_config(cfg)
        print('  [WO] config updated')
