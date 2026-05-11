# modules/beacon_detector.py
# detects C2 beacon timing patterns
# Cobalt Strike default = 60s interval
import time, json, os
from collections import defaultdict
RED='\033[31m';YELLOW='\033[33m';DIM='\033[2m'
CYAN='\033[36m';RESET='\033[0m'
STACK=os.path.expanduser("~/.wraith/loot/stack")
beacon_log=defaultdict(list)
def record_packet(src_ip):
    beacon_log[src_ip].append(time.time())
    if len(beacon_log[src_ip])>20:
        beacon_log[src_ip]=beacon_log[src_ip][-20:]
def check_beacon(src_ip, threshold=5, tolerance=0.15):
    times=beacon_log[src_ip]
    if len(times)<threshold: return None
    intervals=[times[i+1]-times[i] for i in range(len(times)-1)]
    if len(intervals)<2: return None
    avg=sum(intervals)/len(intervals)
    if avg<5: return None
    variance=[abs(i-avg)/avg for i in intervals]
    if sum(variance)/len(variance)<tolerance:
        return round(avg,1)
    return None
def run_beacon_check():
    alerts=[]
    for ip,times in beacon_log.items():
        interval=check_beacon(ip)
        if interval:
            msg=f"BEACON detected {ip} interval={interval}s"
            print(f"  {RED}[BEACON]{RESET} {msg}")
            alerts.append({"ip":ip,"interval":interval,"type":"beacon"})
    if alerts:
        try:
            from modules.core.filestack import write_json
            write_json("beacon_alerts.json",{"alerts":alerts})
        except: pass
    return alerts
