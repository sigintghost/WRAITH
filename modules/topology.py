import json, os
from datetime import datetime

TOPO_PATH = os.path.expanduser('~/.wraith/topology.json')

def load_topology():
    try:
        with open(TOPO_PATH) as f: return json.load(f)
    except: return {'nodes': {}, 'edges': []}

def save_topology(t):
    os.makedirs(os.path.dirname(TOPO_PATH), exist_ok=True)
    with open(TOPO_PATH, 'w') as f: json.dump(t, f, indent=2)

def add_node(subnet, label='', source='observed'):
    t = load_topology()
    if subnet not in t['nodes']:
        t['nodes'][subnet] = {
            'first_seen': datetime.utcnow().isoformat(),
            'last_seen': datetime.utcnow().isoformat(),
            'label': label, 'source': source, 'scanned': False}
    else:
        t['nodes'][subnet]['last_seen'] = datetime.utcnow().isoformat()
        if label: t['nodes'][subnet]['label'] = label
    save_topology(t)

def add_edge(src_subnet, dst_subnet, method='observed'):
    t = load_topology()
    edge = {'src': src_subnet, 'dst': dst_subnet, 'method': method}
    if edge not in t['edges']:
        t['edges'].append(edge)
    save_topology(t)

def mark_scanned(subnet):
    t = load_topology()
    if subnet in t['nodes']:
        t['nodes'][subnet]['scanned'] = True
        save_topology(t)

def get_unscanned():
    t = load_topology()
    return [s for s,d in t['nodes'].items() if not d.get('scanned')]

def discover_from_filestack(stack_path):
    import re
    found = set()
    pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b')
    for fname in os.listdir(stack_path):
        fpath = os.path.join(stack_path, fname)
        try:
            txt = open(fpath).read()
            for m in pattern.finditer(txt):
                found.add(m.group(1))
        except: pass
    return found
