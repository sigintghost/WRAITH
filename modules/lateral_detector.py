# modules/lateral_detector.py
# detects lateral movement via ARP delta
import os, json, time
RED='\033[31m';YELLOW='\033[33m';DIM='\033[2m'
CYAN='\033[36m';RESET='\033[0m'
STACK=os.path.expanduser("~/.wraith/loot/stack")
def load_previous_hosts():
    fp=os.path.join(STACK,"arp_table.json")
    if not os.path.exists(fp): return set()
    try:
        with open(fp) as f: data=json.load(f)
        return set(h.get("ip","") for h in data.get("hosts",[])
                  if isinstance(h,dict))
    except: return set()
def load_session_baseline():
    fp=os.path.join(STACK,"hosts.json")
    if not os.path.exists(fp): return set()
    try:
        with open(fp) as f: data=json.load(f)
        hosts=data.get("hosts",[])
        ips=set()
        for h in hosts:
            if isinstance(h,dict): ips.add(h.get("ip",""))
            elif isinstance(h,str): ips.add(h)
        return ips
    except: return set()
def check_lateral_movement(current_hosts):
    previous=load_previous_hosts()
    baseline=load_session_baseline()
    known=previous|baseline
    new_hosts=[ip for ip in current_hosts if ip not in known and ip]
    alerts=[]
    for ip in new_hosts:
        print(f"  {RED}[LATERAL]{RESET} new host {ip} not in baseline")
        alerts.append({"ip":ip,"type":"lateral_movement",
                       "time":time.strftime('%Y-%m-%dT%H:%M:%S')})
    if alerts:
        try:
            from modules.filestack import write_json
            write_json("lateral_alerts.json",{"alerts":alerts})
        except: pass
    return alerts
