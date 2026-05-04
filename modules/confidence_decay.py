import json, os, datetime

STACK = os.path.expanduser("~/.wraith/loot/stack")
THRESHOLDS = {"DECOMMISSION_CANDIDATE": 90, "STALE": 30, "OFFLINE": 7}

def _age_days(ts_str):
    try:
        ts = datetime.datetime.fromisoformat(ts_str)
        return (datetime.datetime.utcnow() - ts).days
    except Exception:
        return 9999

def score(ts_str):
    age = _age_days(ts_str)
    for label, days in THRESHOLDS.items():
        if age >= days:
            return label
    return "ACTIVE"

def decay_hosts():
    path = os.path.join(STACK, "hosts.json")
    try:
        hosts = json.load(open(path))
    except Exception:
        return
    for h in hosts:
        ts = h.get("last_seen") or h.get("ts", "")
        h["confidence"] = score(ts)
    json.dump(hosts, open(path, "w"), indent=2)

def get_decayed(hosts):
    return [h for h in hosts if score(
        h.get("last_seen") or h.get("ts","")) != "ACTIVE"]
