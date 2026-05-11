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

def check_websocket_beacon(host, path):
    suspicious = ['/ws','/api/v1/beacon','/api/v1/result']
    for p in suspicious:
        if path.startswith(p):
            _alert(host, 80)
            return True
    return False

def check_dns_tunnel(query):
    import re
    b32 = re.compile(r'^[A-Z2-7]{15,}$')
    label = query.split('.')[0].upper()
    if b32.match(label):
        _alert(query, 53)
        return True
    return False

def check_cron_persistence(filepath):
    cron_paths = [
        '/etc/cron','/var/spool/cron',
        '/etc/systemd/system','/etc/anacrontab'
    ]
    for p in cron_paths:
        if filepath.startswith(p):
            _alert('localhost', 0)
            return True
    return False
