import json, os
from datetime import datetime
from modules.sanitize import Sanitizer

STACK = os.path.expanduser("~/.wraith/loot/stack")
ALERTS = os.path.join(STACK, "alerts.json")
PULSE = os.path.join(STACK, "pulse_tracker.json")
_s = Sanitizer()

def load_json(path):
    try:
        if os.path.exists(path):
            with open(path) as f: return json.load(f)
    except: pass
    return {}

def save_json(path, data):
    try:
        with open(path,'w') as f:
            json.dump(data, f, indent=2)
    except: pass

def load_authorized():
    authorized = set()
    fsi = load_json(os.path.join(STACK, "fsi_assets.json"))
    for a in fsi.get("assets", []):
        if isinstance(a, dict):
            ip = _s.sanitize(str(a.get("ip","")),
                "fsi","ip")
            if ip: authorized.add(ip)
    return authorized

def load_wire():
    wire = set()
    sweep = load_json(os.path.join(STACK, "hosts.json"))
    for h in sweep.get("hosts", []):
        if isinstance(h, dict):
            ip = _s.sanitize(str(h.get("ip","")),
                "sweep","ip")
            if ip: wire.add(ip)
    return wire

def write_alert(ip, reason, severity):
    alert = {"timestamp": datetime.now().isoformat(),
        "module": "presence_monitor",
        "severity": severity, "ip": ip,
        "reason": reason,
        "message": f"{severity}: {ip} — {reason}"}
    data = load_json(ALERTS)
    if isinstance(data, dict):
        alerts = data.get("alerts", [])
    else:
        alerts = data if isinstance(data, list) else []
    alerts.append(alert)
    save_json(ALERTS, alerts)

def check_pulse(ip, wire_ips):
    pulse = load_json(PULSE)
    if ip not in pulse:
        pulse[ip] = {"seen": 0, "absent": 0,
            "first_seen": datetime.now().isoformat()}
    if ip in wire_ips:
        pulse[ip]["seen"] = pulse[ip].get("seen",0) + 1
    else:
        pulse[ip]["absent"] = pulse[ip].get("absent",0)+1
    save_json(PULSE, pulse)
    seen = pulse[ip]["seen"]
    absent = pulse[ip]["absent"]
    if seen >= 2 and absent >= 2:
        return True, seen, absent
    return False, seen, absent

def run_presence_check():
    print("\033[36m[PRESENCE]\033[0m checking asset authorization...")
    authorized = load_authorized()
    wire = load_wire()
    alerts = []
    for ip in wire:
        if ip not in authorized:
            hour = datetime.now().hour
            sev = "CRITICAL" if (hour >= 22 or
                hour <= 5) else "WARNING"
            write_alert(ip, "UNKNOWN_ASSET", sev)
            print(f"\033[31m[{sev}]\033[0m "
                f"{ip} on wire — not in asset DB")
            alerts.append(ip)
        pulse, seen, absent = check_pulse(ip, wire)
        if pulse and ip in authorized:
            write_alert(ip, "PULSE_EVASION", "CRITICAL")
            print(f"\033[31m[CRITICAL]\033[0m "
                f"{ip} pulse pattern: "
                f"seen={seen} absent={absent}")
    if not alerts:
        print("\033[32m[PRESENCE]\033[0m "
            "all wire assets authorized")
    return alerts

if __name__ == "__main__":
    run_presence_check()
