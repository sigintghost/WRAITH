import json, os, datetime

STACK = os.path.expanduser("~/.wraith/loot/stack")

def _path():
    return os.path.join(STACK, "port_history.json")

def load():
    try:
        return json.load(open(_path()))
    except Exception:
        return {}

def save(data):
    json.dump(data, open(_path(), "w"), indent=2)

def record(host_ip, ports):
    data = load()
    entry = data.get(host_ip, {"union": [], "sessions": []})
    union = set(entry["union"]) | set(ports)
    entry["union"] = sorted(union)
    entry["sessions"].append({
        "ts": datetime.datetime.utcnow().isoformat(),
        "ports": sorted(ports)
    })
    entry["sessions"] = entry["sessions"][-20:]
    data[host_ip] = entry
    save(data)

def get_union(host_ip):
    return load().get(host_ip, {}).get("union", [])

def get_new_ports(host_ip, current_ports):
    union = set(get_union(host_ip))
    return sorted(set(current_ports) - union)

def summary():
    data = load()
    out = {}
    for ip, entry in data.items():
        out[ip] = {
            "total_unique": len(entry["union"]),
            "union": entry["union"],
            "sessions": len(entry["sessions"])
        }
    return out
