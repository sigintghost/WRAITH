import os, json
from modules.core.filestack import get_stack

GREEN  = '\033[32m'
YELLOW = '\033[33m'
RED    = '\033[31m'
CYAN   = '\033[36m'
DIM    = '\033[2m'
RESET  = '\033[0m'

def load_arp():
    p = os.path.join(get_stack(), 'arp_table.json')
    if not os.path.exists(p): return []
    with open(p) as f: return json.load(f).get('hosts', [])

def load_findings():
    p = os.path.join(get_stack(), 'mac_findings.json')
    if not os.path.exists(p): return []
    with open(p) as f: return json.load(f).get('findings', [])

def show_mac_table():
    hosts = load_arp()
    findings = load_findings()
    flagged = {f['ip']: f['flags'] for f in findings}
    print(f'\n  {CYAN}MAC REGISTRY{RESET}')
    print(f'  {"IP":<18} {"MAC":<19} {"VENDOR":<22} FLAGS')
    print(f'  {"-"*18} {"-"*18} {"-"*21} {"-"*15}')
    if not hosts:
        print(f'  {DIM}no ARP data — run SWEEP first{RESET}')
        return
    for h in hosts:
        if not isinstance(h, dict): continue
        ip     = h.get('ip','?')
        mac    = h.get('mac','unknown')
        vendor = h.get('vendor','unknown')[:20]
        flags  = flagged.get(ip,[])
        if flags:
            color=RED; flag_str=','.join(flags)[:20]
        elif mac=='unknown' or vendor=='unknown':
            color=YELLOW; flag_str='UNKNOWN'
        else:
            color=GREEN; flag_str='CLEAN'
        print(f'  {color}{ip:<18}{RESET} {mac:<19} {vendor:<22} {color}{flag_str}{RESET}')
    print(f'\n  {len(hosts)} devices — {RED}{len(flagged)} flagged{RESET}')
