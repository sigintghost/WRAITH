import json, os, socket, datetime, time

STACK = os.path.expanduser("~/.wraith/loot/stack")
COMMON_PORTS = [21,22,23,80,443,502,1883,4840,47808,8080,8443]

def _scan(host, ports, timeout=1):
    open_ports = []
    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(timeout)
            if s.connect_ex((host, p)) == 0:
                open_ports.append(p)
            s.close()
        except Exception:
            pass
    return open_ports

def _alert(host, new, closed):
    path = os.path.join(STACK, "alerts.json")
    try:
        data = json.load(open(path)) if os.path.exists(path) else []
    except Exception:
        data = []
    data.append({"ts": datetime.datetime.utcnow().isoformat(),
        "type": "PORT_CHANGE", "host": host,
        "new_ports": new, "closed_ports": closed,
        "severity": "MEDIUM"})
    json.dump(data, open(path, "w"), indent=2)

def watch(host, ports=None, interval=60, cycles=5):
    ports = ports or COMMON_PORTS
    baseline = set(_scan(host, ports))
    print(f"  baseline: {sorted(baseline)}")
    for i in range(cycles):
        time.sleep(interval)
        current = set(_scan(host, ports))
        new = sorted(current - baseline)
        closed = sorted(baseline - current)
        if new or closed:
            _alert(host, new, closed)
            print(f"  [!] new={new} closed={closed}")
        else:
            print(f"  [{i+1}] no change")
        baseline = current
