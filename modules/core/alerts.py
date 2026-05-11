import traceback
def _caller():
    for f in traceback.extract_stack()[:-2]:
        n=f.filename.split('/')[-1].replace('.py','')
        if n not in ('alerts','wraith'): return n
    return 'wraith'
# modules/alerts.py
# WRAITH alert throttling engine
import os, json, time
from datetime import datetime
STACK_DIR = os.path.expanduser("~/.wraith/loot/stack")
ALERT_FILE = os.path.join(STACK_DIR, "alerts.json")
SEVERITY = {"INFO": 1, "WARN": 2, "CRITICAL": 3}
COOLDOWNS = {
    "bacnet_new_device": 300,
    "bacnet_bbmd": 600,
    "modbus_new_device": 300,
    "mqtt_new_broker": 300,
    "mstp_new_master": 300,
    "high_port_count": 600,
    "osint_high_risk": 900,
    "default": 60,
}
_last_fired = {}
def _load_alerts():
    os.makedirs(STACK_DIR, exist_ok=True)
    if not os.path.exists(ALERT_FILE): return []
    try:
        with open(ALERT_FILE) as f: return json.load(f)
    except: return []
def _save_alerts(alerts):
    os.makedirs(STACK_DIR, exist_ok=True)
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)
def _throttled(alert_type):
    now = time.time()
    cooldown = COOLDOWNS.get(alert_type, COOLDOWNS["default"])
    last = _last_fired.get(alert_type, 0)
    if now - last < cooldown: return True
    _last_fired[alert_type] = now
    return False
def fire(alert_type, message, severity="WARN", source=None, ip=""):
    if _throttled(alert_type): return False
    ts = datetime.now().isoformat()
    alert = {
        "timestamp": ts,
        "type": alert_type,
        "severity": severity,
        "source": source or _caller(),
        "ip": ip,
        "message": message,
    }
    alerts = _load_alerts()
    alerts.append(alert)
    alerts = alerts[-500:]
    _save_alerts(alerts)
    _print_alert(alert)
    return True
def _print_alert(alert):
    sev = alert["severity"]
    c_info = "[94m"
    c_warn = "[93m"
    c_crit = "[91m"
    reset = "[0m"
    color = c_info if sev == "INFO" else c_crit if sev == "CRITICAL" else c_warn
    ts = alert["timestamp"][11:19]
    msg = alert["message"]
    src = alert["source"]
    print(color + "  [ALERT] " + ts + " " + sev + " " + src + ": " + msg + reset)
def get_recent(limit=20):
    alerts = _load_alerts()
    return alerts[-limit:]
def get_by_severity(severity):
    alerts = _load_alerts()
    return [a for a in alerts if a["severity"] == severity]
def clear_alerts():
    _save_alerts([])
    print("  [*] Alert log cleared")
