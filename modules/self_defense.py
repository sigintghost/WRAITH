import json, os, socket, datetime

STACK = os.path.expanduser("~/.wraith/loot/stack")
ALLOWLIST = {"api.anthropic.com", "localhost", "127.0.0.1"}

def _alert(host, port):
    path = os.path.join(STACK, "alerts.json")
    try:
        data = json.load(open(path)) if os.path.exists(path) else []
    except Exception:
        data = []
    data.append({"ts": datetime.datetime.utcnow().isoformat(),
        "type": "C2_OUTBOUND", "host": host, "port": port,
        "severity": "HIGH"})
    json.dump(data, open(path, "w"), indent=2)

def check_connection(host, port):
    if host in ALLOWLIST:
        return True
    _alert(host, port)
    return False

def resolve_and_check(host, port):
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host
    allowed = ip in ALLOWLIST or host in ALLOWLIST
    if not allowed:
        _alert(host, port)
    return allowed

def add_to_allowlist(entry):
    ALLOWLIST.add(entry)
