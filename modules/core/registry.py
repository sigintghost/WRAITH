import json, os
from datetime import datetime

REG_PATH = os.path.expanduser('~/.wraith/registry.json')

def load_registry():
    if os.path.exists(REG_PATH):
        try:
            with open(REG_PATH) as f: return json.load(f)
        except: pass
    return {}

def save_registry(reg):
    os.makedirs(os.path.dirname(REG_PATH), exist_ok=True)
    with open(REG_PATH, 'w') as f: json.dump(reg, f, indent=2)

def update_registry(hosts):
    reg = load_registry()
    now = datetime.utcnow().isoformat()
    for ip, mac, vendor in hosts:
        if ip not in reg:
            reg[ip] = {'first_seen': now, 'last_seen': now,
                       'mac': mac, 'vendor': vendor, 'seen_count': 1}
        else:
            reg[ip]['last_seen'] = now
            reg[ip]['mac'] = mac
            reg[ip]['vendor'] = vendor
            reg[ip]['seen_count'] = reg[ip].get('seen_count',1) + 1
    save_registry(reg)
    return reg

def get_new_hosts(hosts):
    reg = load_registry()
    return [ip for ip,_,_ in hosts if ip not in reg]
