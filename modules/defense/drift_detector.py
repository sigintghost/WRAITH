import json, os
from datetime import datetime

STACK = os.path.expanduser("~/.wraith/loot/stack")
BASELINE = os.path.join(STACK, "drift_baseline.json")
ALERTS = os.path.join(STACK, "alerts.json")
WATCHED = ["name","description","vendor","firmware",
    "sysdescr","sysname","location","device_name",
    "model","hardware","software","version"]

def load_json(path):
    try:
        if os.path.exists(path):
            with open(path) as f: return json.load(f)
    except: pass
    return {}

def save_json(path, data):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    except: pass

def write_alert(ip, field, old, new, count):
    severity = "CRITICAL" if count >= 3 else "WARNING"
    alert = {"timestamp": datetime.now().isoformat(),
        "module": "drift_detector",
        "severity": severity,
        "ip": ip, "field": field,
        "old_value": str(old)[:80],
        "new_value": str(new)[:80],
        "change_count": count,
        "message": f"Field drift detected: {ip} {field} changed {count}x"}
    data = load_json(ALERTS)
    if isinstance(data, dict):
        alerts = data.get("alerts", [])
    else:
        alerts = data if isinstance(data, list) else []
    alerts.append(alert)
    save_json(ALERTS, alerts)
    return alert

def extract_assets():
    assets = {}
    for fname in ["bacnet_inventory.json","snmp_inventory.json",
        "hosts.json","arp_table.json","modbus_map.json"]:
        data = load_json(os.path.join(STACK, fname))
        if not isinstance(data, dict): continue
        for key in ["hosts","inventory","devices"]:
            items = data.get(key, {})
            if isinstance(items, dict):
                for ip, d in items.items():
                    if isinstance(d, dict):
                        assets.setdefault(ip, {}).update(d)
            elif isinstance(items, list):
                for d in items:
                    if isinstance(d, dict) and d.get("ip"):
                        assets.setdefault(d["ip"], {}).update(d)
    return assets

def check_drift():
    baseline = load_json(BASELINE)
    assets = extract_assets()
    alerts = []
    for ip, data in assets.items():
        if ip not in baseline:
            baseline[ip] = {"fields": {}, "counts": {}}
        for field in WATCHED:
            val = data.get(field)
            if val is None: continue
            val = str(val).strip().lower()
            prev = baseline[ip]["fields"].get(field)
            if prev is None:
                baseline[ip]["fields"][field] = val
                continue
            if val != prev:
                count = baseline[ip]["counts"].get(field,0)+1
                baseline[ip]["counts"][field] = count
                a = write_alert(ip, field, prev, val, count)
                alerts.append(a)
                baseline[ip]["fields"][field] = val
    save_json(BASELINE, baseline)
    return alerts

def run_drift_check():
    print("\033[36m[DRIFT]\033[0m Checking asset field stability...")
    alerts = check_drift()
    if not alerts:
        print("\033[32m[DRIFT]\033[0m No field drift detected.")
    else:
        for a in alerts:
            sev = a.get("severity","WARNING")
            col = "\033[31m" if sev=="CRITICAL" else "\033[33m"
            print(f"{col}[{sev}]\033[0m {a['ip']} "
                f"{a['field']}: {a['old_value']} -> "
                f"{a['new_value']} (x{a['change_count']})")
    return alerts

if __name__ == "__main__":
    run_drift_check()
