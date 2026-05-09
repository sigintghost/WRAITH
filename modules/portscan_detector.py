import json, os, datetime
from collections import defaultdict

STACK = os.path.expanduser("~/.wraith/loot/stack")
_hits = defaultdict(list)
THRESHOLD = 5
WINDOW = 60

def _alert(src, targets):
    path = os.path.join(STACK, "alerts.json")
    try:
        data = json.load(open(path)) if os.path.exists(path) else []
    except Exception:
        data = []
    data.append({"ts": datetime.datetime.utcnow().isoformat(),
        "type": "PORTSCAN_DETECTED", "src": src,
        "ports_probed": targets, "severity": "HIGH"})
    json.dump(data, open(path, "w"), indent=2)

def record_attempt(src_ip, dst_port):
    now = datetime.datetime.utcnow().timestamp()
    _hits[src_ip].append((now, dst_port))
    _hits[src_ip] = [(t, p) for t, p in _hits[src_ip]
        if now - t <= WINDOW]
    ports = [p for _, p in _hits[src_ip]]
    if len(ports) >= THRESHOLD:
        _alert(src_ip, ports)
        _hits[src_ip].clear()
        return True
    return False

def get_active_scanners():
    return list(_hits.keys())
