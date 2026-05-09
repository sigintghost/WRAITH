import json, os, statistics
from datetime import datetime
from modules.sanitize import Sanitizer

STACK = os.path.expanduser("~/.wraith/loot/stack")
ALERTS = os.path.join(STACK, "alerts.json")
HISTORY = os.path.join(STACK, "beacon_history.json")
_s = Sanitizer()
MIN_SAMPLES = 4
JITTER_MIN = 0.10
JITTER_MAX = 0.30
BURST_THRESHOLD = 5

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

def write_alert(ip, reason, severity, detail):
    ip = _s.sanitize(str(ip), "jitter", "ip")
    alert = {"timestamp": datetime.now().isoformat(),
        "module": "jitter_beacon",
        "severity": severity, "ip": ip,
        "reason": reason, "detail": detail,
        "message": f"{severity}: {ip} — {reason}"}
    data = load_json(ALERTS)
    if isinstance(data, dict):
        alerts = data.get("alerts", [])
    else:
        alerts = data if isinstance(data, list) else []
    alerts.append(alert)
    save_json(ALERTS, alerts)

def record_observation(ip):
    ip = _s.sanitize(str(ip), "jitter", "ip")
    history = load_json(HISTORY)
    if ip not in history:
        history[ip] = []
    history[ip].append(datetime.now().isoformat())
    history[ip] = history[ip][-20:]
    save_json(HISTORY, history)
    return history[ip]

def analyze_intervals(timestamps):
    if len(timestamps) < MIN_SAMPLES:
        return None, None
    from datetime import datetime as dt
    times = []
    for t in timestamps:
        try: times.append(dt.fromisoformat(t))
        except: continue
    if len(times) < MIN_SAMPLES:
        return None, None
    intervals = [(times[i+1]-times[i]).total_seconds()
        for i in range(len(times)-1)]
    mean = statistics.mean(intervals)
    if mean <= 0:
        return None, None
    stdev = statistics.stdev(intervals) if \
        len(intervals) > 1 else 0
    cv = stdev / mean
    return mean, cv

def check_burst(timestamps):
    if len(timestamps) < BURST_THRESHOLD:
        return False
    from datetime import datetime as dt
    try:
        recent = [dt.fromisoformat(t)
            for t in timestamps[-BURST_THRESHOLD:]]
        window = (recent[-1]-recent[0]).total_seconds()
        return window < 60
    except: return False

def check_ip(ip):
    timestamps = record_observation(ip)
    mean, cv = analyze_intervals(timestamps)
    alerts = []
    if check_burst(timestamps):
        detail = f"burst: {BURST_THRESHOLD} connections in <60s"
        write_alert(ip, "BEACON_BURST", "CRITICAL", detail)
        alerts.append("BEACON_BURST")
        print(f"\033[31m[CRITICAL]\033[0m {ip} {detail}")
    if mean and cv is not None:
        if JITTER_MIN <= cv <= JITTER_MAX:
            detail = (f"mean={mean:.1f}s "
                f"cv={cv:.2f} — programmatic jitter")
            write_alert(ip, "BEACON_JITTER",
                "CRITICAL", detail)
            alerts.append("BEACON_JITTER")
            print(f"\033[31m[CRITICAL]\033[0m "
                f"{ip} BEACON_JITTER {detail}")
        elif cv < JITTER_MIN:
            detail = f"mean={mean:.1f}s cv={cv:.2f} — fixed interval"
            write_alert(ip, "BEACON_FIXED",
                "WARNING", detail)
            alerts.append("BEACON_FIXED")
            print(f"\033[33m[WARNING]\033[0m "
                f"{ip} BEACON_FIXED {detail}")
    return alerts

def run_jitter_check(ip_list):
    print("\033[36m[JITTER]\033[0m analyzing beacon patterns...")
    all_alerts = []
    for ip in ip_list:
        alerts = check_ip(ip)
        all_alerts.extend(alerts)
    if not all_alerts:
        print("\033[32m[JITTER]\033[0m no beacon patterns detected")
    return all_alerts

if __name__ == "__main__":
    import sys
    ips = sys.argv[1:] or ["192.168.1.72"]
    run_jitter_check(ips)
