import json, os, datetime

STACK = os.path.expanduser("~/.wraith/loot/stack")
_allowlists = {}

def set_allowlist(host_ip, allowed_destinations):
    _allowlists[host_ip] = set(allowed_destinations)

def _alert(src, dst):
    path = os.path.join(STACK, "alerts.json")
    try:
        data = json.load(open(path)) if os.path.exists(path) else []
    except Exception:
        data = []
    data.append({"ts": datetime.datetime.utcnow().isoformat(),
        "type": "UNEXPECTED_DESTINATION", "src": src,
        "dst": dst, "severity": "MEDIUM"})
    json.dump(data, open(path, "w"), indent=2)

def check_destination(src_ip, dst_ip):
    allowed = _allowlists.get(src_ip)
    if allowed is None:
        return True
    if dst_ip not in allowed:
        _alert(src_ip, dst_ip)
        return False
    return True

def get_violations(src_ip):
    return _allowlists.get(src_ip, set())
