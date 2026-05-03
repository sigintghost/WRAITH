import socket, getpass
import datetime

VERSION = "4.0"

from modules.portscan import PORTS

GREEN  = '\033[32m'
CYAN   = '\033[36m'
YELLOW = '\033[33m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'
def div(): print(f"  {DIM}{'─'*44}{RESET}")
def ts(): return datetime.datetime.now().strftime("%H:%M:%S")
def get_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        base = f"{parts[0]}.{parts[1]}.{parts[2]}"
        for gw in [f"{base}.1", f"{base}.254"]:
            sock = socket.socket()
            sock.settimeout(0.5)
            r = sock.connect_ex((gw, 80))
            sock.close()
            if r == 0:
                return gw, local_ip, base
        return f"{base}.1", local_ip, base
    except:
        return "unknown", "unknown", "unknown"
def recon(gateway, local_ip):
    print(f"\n  [RECON] {ts()}")
    print(f"  local ip : {local_ip}")
    print(f"  gateway  : {gateway}")
    div()
    for l,h in [("gateway",gateway),("cloudflare","1.1.1.1"),("google","google.com")]:
        try:
            ip=socket.gethostbyname(h)
            s=socket.socket()
            s.settimeout(1)
            r=s.connect_ex((ip,80))
            s.close()
            print(f"  {l:<14}{ip:<18}{'ALIVE' if r==0 else 'DARK'}")
        except:
            print(f"  {l:<14}{'---':<18}UNREACHABLE")
    div()

def portscan(gateway):
    print(f"\n  [PORTSCAN] {ts()}")
    print(f"  target: {gateway}")
    div()
    found=[]
    for port,label in PORTS.items():
        try:
            s=socket.socket()
            s.settimeout(0.5)
            r=s.connect_ex((gateway,port))
            s.close()
            if r==0:
                found.append((port,label))
                print(f"  OPEN  {port:<8}{label}")
        except:
            pass
    if not found:
        print("  no open ports detected.")
    http_ports = [p for p,l in found if p in [80,8080,8443,443,8888,8001,8008]]
    if http_ports:
        from modules.portscan import http_fingerprint
        for p in http_ports[:2]:
            try: http_fingerprint(gateway, p)
            except: pass
    try:
        from modules.filestack import write_json,get_stack
        import os
        sp=os.path.join(get_stack(),'portscan.json')
        import json
        data=json.load(open(sp)) if os.path.exists(sp) else {'scans':[]}
        data['scans'].append({'target':gateway,'ports':[{'port':p,'service':s,'state':'OPEN'} for p,s in found]})
        write_json('portscan.json',data)
        print(f'  stack written: portscan.json')
    except Exception as e:
        print(f'  [WARN] filestack: {e}')
    div()
def dns():
    print(f"\n  [DNS] {ts()}")
    div()
    names=["router","gateway","iphone","android","laptop","desktop","tv","appletv","camera","printer","nas","server","niagara","jace","bacnet","controller"]
    found=False
    for n in names:
        for sfx in ["",".local",".home",".attlocal.net"]:
            try:
                ip=socket.getaddrinfo(n+sfx,None)[0][4][0]
                if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."):
                    print(f"  RESOLVED  {n+sfx:<26}{ip}")
                    found=True
                    break
            except:
                pass
    if not found:
        print("  no hosts resolved.")
    div()

def banner(gateway):
    print(f"\n  [BANNER] {ts()}")
    print(f"  target: {gateway}")
    div()
    try:
        s=socket.socket()
        s.settimeout(2)
        s.connect((gateway,80))
        s.send(f"HEAD / HTTP/1.0\r\nHost: {gateway}\r\n\r\n".encode())
        data=s.recv(1024).decode(errors="ignore")
        s.close()
        for line in data.splitlines()[:6]:
            if line.strip():
                print(f"  {line.strip()}")
    except:
        print("  no banner retrieved.")
    div()
def run_osint(gateway):
    import sys
    sys.path.insert(0,'.')
    from modules.osint import osint_lookup
    custom = input("  enter target IP [default: " + gateway + "]: ").strip()
    target = custom if custom else gateway
    osint_lookup(target)






def run_mqtt_module():
    import sys
    sys.path.insert(0, '.')
    from modules.mqtt import run_mqtt
    run_mqtt()

def run_alerts_module():
    from modules.alerts import get_recent, clear_alerts
    alerts = get_recent(20)
    if not alerts:
        print(chr(32)*2 + chr(91) + chr(42) + chr(93) + chr(32) + chr(78) + chr(111) + chr(32) + chr(97) + chr(108) + chr(101) + chr(114) + chr(116) + chr(115) + chr(32) + chr(111) + chr(110) + chr(32) + chr(102) + chr(105) + chr(108) + chr(101))
        return
    for a in alerts:
        sev = a.get(chr(115)+chr(101)+chr(118)+chr(101)+chr(114)+chr(105)+chr(116)+chr(121))
        ts = a.get(chr(116)+chr(105)+chr(109)+chr(101)+chr(115)+chr(116)+chr(97)+chr(109)+chr(112))[11:19]
        msg = a.get(chr(109)+chr(101)+chr(115)+chr(115)+chr(97)+chr(103)+chr(101))
        print(chr(32)*2 + ts + chr(32) + sev + chr(32) + msg)

def run_snmp_module():
    from modules.snmp import run_snmp
    run_snmp()

def run_mstp_module():
    from modules.serial_mstp import run_mstp
    run_mstp()

def run_doxa_module():
    import sys
    sys.path.insert(0, '.')
    from modules.doxa import run_doxa
    run_doxa()

def run_modbus_module():
    import sys
    sys.path.insert(0, '.')
    from modules.modbus import run_modbus
    run_modbus()

def run_bacnet_module():
    import sys
    sys.path.insert(0, '.')
    from modules.bacnet import run_bacnet
    run_bacnet()

def run_sweep_module(gateway, local_ip, base):
    from modules.topology import add_node, mark_scanned, discover_from_filestack
    from modules.filestack import get_stack
    add_node(f"{base}.0/24", source='sweep')
    import sys
    sys.path.insert(0, '.')
    from modules.sweep import run_sweep
    from modules.logger import log_result
    results = run_sweep(base, local_ip)
    from modules.registry import update_registry, get_new_hosts
    arp_hosts = [(ip, '', '') for ip, port, hostname in results]
    new_hosts = get_new_hosts(arp_hosts)
    update_registry(arp_hosts)
    if new_hosts:
        print(f"  [33m[REGISTRY] {len(new_hosts)} new host(s) first seen[0m")
    for ip, port, hostname in results:
        log_result(local_ip, "SWEEP", f"{ip} port={port} {hostname}")
    mark_scanned(f"{base}.0/24")
    from modules.portscan import run_portscan
    new_reg = get_new_hosts([(ip,'','') for ip,port,hostname in results])
    for new_ip in new_reg[:3]:
        print(f"  [33m[AUTO-SCAN] new host {new_ip} — scanning[0m")
        try: run_portscan(new_ip)
        except: pass
    discovered = discover_from_filestack(get_stack())
    current = base.rsplit('.',1)[0] if base.count('.')==3 else base
    for s in discovered:
        if s != current:
            add_node(f"{s}.0/24", source='passive')
            print(f"  [33m[TOPOLOGY] new subnet observed: {s}.0/24[0m")

def auto_chain(gateway, local_ip):
    import sys
    sys.path.insert(0, '.')
    from modules.logger import log_result
    from modules.portscan import run_portscan
    from modules.osint import osint_lookup
    print(f"\n  [AUTO] starting full chain on {gateway}")
    log_result(gateway, "AUTO", "chain scan started")
    recon(gateway, local_ip)
    log_result(gateway, "RECON", "complete")
    results = run_portscan(gateway)
    for port, service, state in results:
        log_result(gateway, "PORTSCAN", f"{port} {service} {state}")
    dns()
    log_result(gateway, "DNS", "complete")
    banner(gateway)
    log_result(gateway, "BANNER", "complete")
    osint_lookup(gateway)
    log_result(gateway, "OSINT", "complete")
    try:
        from modules.ttl import run_ttl
        run_ttl([gateway])
        log_result(gateway, "TTL", "complete")
    except Exception as e: print(f'  [TTL] {e}')
    try:
        from modules.snmp import run_snmp
        run_snmp(gateway)
        log_result(gateway, "SNMP", "complete")
    except Exception as e: print(f'  [SNMP] {e}')
    log_result(gateway, "AUTO", "chain scan complete")
    print(f"\n  [AUTO] complete. log saved to ~/.wraith/loot/logs/")

def doxa_login_alert():
    import json, os
    mem = os.path.expanduser('~/.wraith/memory.json')
    alerts = os.path.expanduser('~/.wraith/loot/stack/alerts.json')
    flags = []
    from modules.filestack import get_stack
    stack = get_stack()
    alert_path = os.path.join(stack, 'alerts.json')
    scan_path = os.path.join(stack, 'portscan.json')
    hunt_target = None
    if os.path.exists(alert_path):
        try:
            with open(alert_path) as f: a = json.load(f)
            if a:
                top = a[-1]
                msg = top.get('message', top.get('type', str(top)))[:60]
                flags.append(f"{len(a)} alert(s) — latest: {msg}")
                hunt_target = top.get('ip') or top.get('src')
        except: pass
    if os.path.exists(scan_path):
        try:
            with open(scan_path) as f: s = json.load(f)
            scans = s.get('scans', [])
            if scans:
                last = scans[-1]
                ip = last.get('target','')
                ports = [p.get('port') for p in last.get('ports',[])]
                risky = [p for p in ports if p in [4444,50050,9001,9050,445,3389,5985,23]]
                if risky:
                    flags.append(f"RISK: {ip} has suspicious ports {risky}")
                    if not hunt_target: hunt_target = ip
        except: pass
    if os.path.exists(mem):
        try:
            with open(mem) as f: h = json.load(f)
            if h: flags.append(f"DOXA memory: {len(h)} prior exchanges loaded")
        except: pass
    if flags:
        print("\n  \033[33m[DOXA BRIEFING]\033[0m")
        for f in flags:
            print(f"  [33m! {f}[0m")
        if hunt_target:
            print(f"  [31m> suggested: hunt {hunt_target}[0m")
        print()

def get_public_ip():
    try:
        import urllib.request
        r = urllib.request.urlopen('https://api.ipify.org', timeout=5)
        return r.read().decode().strip()
    except:
        return 'unknown'

def show_main_menu():
    div()
    print(f"  {CYAN}[1]{RESET} SWEEP        {DIM}discover + TTL{RESET}")
    print(f"  {CYAN}[2]{RESET} SCAN         {DIM}portscan + banner + SNMP{RESET}")
    print(f"  {CYAN}[3]{RESET} PROTOCOLS    {DIM}BACnet Modbus MQTT MSTP{RESET}")
    print(f"  {CYAN}[4]{RESET} INTEL        {DIM}OSINT CVE DNS{RESET}")
    print(f"  {CYAN}[5]{RESET} DOXA         {DIM}AI agent{RESET}")
    print(f"  {CYAN}[6]{RESET} ALERTS")
    print(f"  {CYAN}[7]{RESET} ADMIN")
    print(f"  {CYAN}[8]{RESET} KEYS")
    print(f"  {DIM}[0] EXIT{RESET}")
    div()
def show_protocols_menu():
    div()
    print(f"  {CYAN}[1]{RESET} BACnet/IP  {DIM}47808{RESET}")
    print(f"  {CYAN}[2]{RESET} Modbus TCP {DIM}502{RESET}")
    print(f"  {CYAN}[3]{RESET} MQTT       {DIM}1883{RESET}")
    print(f"  {CYAN}[4]{RESET} MSTP       {DIM}RS485{RESET}")
    print(f"  {CYAN}[5]{RESET} PORTSCAN   {DIM}OT/BAS{RESET}")
    print(f"  {CYAN}[6]{RESET} SNMP       {DIM}161{RESET}")
    print(f"  {DIM}[0] BACK{RESET}")
    div()
def show_intel_menu():
    div()
    print(f"  {CYAN}[1]{RESET} OSINT")
    print(f"  {CYAN}[2]{RESET} CVE")
    print(f"  {CYAN}[3]{RESET} DNS")
    print(f"  {CYAN}[4]{RESET} BANNER")
    print(f"  {DIM}[0] BACK{RESET}")
    div()
def main2():
    from modules.netcheck import run_network_check
    ok=run_network_check()
    if not ok: return
    print(f"  WRAITH v{VERSION}")
    div()
    gateway,local_ip,base=get_network()
    from modules.filestack import set_subnet
    set_subnet(f"{base}.0_24")
    print(f"  gateway  : {gateway}")
    print(f"  local ip : {local_ip}")
    print(f"  subnet   : {base}.0/24")
    while True:
        show_main_menu()
        c = input(" > ")
        if c == "0": break
        elif c == "1":
            from modules.subnet_selector import select_subnet
            from modules.filestack import set_subnet
            sel = select_subnet(base)
            if sel is None: print("  [SWEEP] cancelled")
            else:
                set_subnet(f"{sel}.0_24")
                run_sweep_module(gateway,local_ip,sel)
                set_subnet(f"{base}.0_24")
        elif c == "2":
            from modules.portscan import select_target_from_sweep
            t=select_target_from_sweep()
            if not t: t=input("  enter IP > ").strip()
            if t:
                portscan(t)
                banner(t)
                run_snmp_module()
                from modules.baseline import run_baseline
                run_baseline()
                from modules.mac_verify import verify_macs
                verify_macs()
        elif c == "5":
            from modules.doxa import run_doxa
            run_doxa(gateway, local_ip)
        elif c == "6": run_alerts_module()
        elif c == "7":
            from modules.admin import run_admin
            run_admin()
        elif c == "8":
            from modules.keys_manager import run_keys_manager
            run_keys_manager()
        elif c == "3":
            while True:
                show_protocols_menu()
                p = input(" > ")
                if p == "0": break
                elif p == "1": run_bacnet_module()
                elif p == "2": run_modbus_module()
                elif p == "3": run_mqtt_module()
                elif p == "4": run_mstp_module()
                elif p == "5":
                    from modules.portscan import select_target_from_sweep
                    t=select_target_from_sweep()
                    if t: portscan(t)
                    else:
                        custom=input("  enter IP manually > ").strip()
                        if custom: portscan(custom)
                elif p == "6": run_snmp_module()
                else: print("  invalid")
        elif c == "4":
            while True:
                show_intel_menu()
                p = input(" > ")
                if p == "0": break
                elif p == "1":
                    pub = get_public_ip()
                    t = input(f"  target [{pub}]: ").strip() or pub
                    run_osint(t)
                elif p == "2":
                    from modules.cve import run_cve_module
                    run_cve_module()
                elif p == "3": dns()
                elif p == "4": banner(gateway)
                else: print("  invalid")
        else: print("  invalid option")
    from modules.ghost import ghost_exit
    ghost_exit()
    import sys; sys.path.insert(0,'.')
def run_auth():
    from modules.auth import first_run, create_user, login, logout, get_session
    print("  [WRAITH] authentication required")
    if first_run():
        print("  [*] first run — create admin account")
        u = input("  username: ")
        while True:
            p = getpass.getpass("  password: ")
            from modules.auth import validate_password
            err = validate_password(p)
            if not err: break
            print(f"  [!] {err} — try again")
        create_user(u, p, "admin")
        print("  [+] admin account created")
    while True:
        u = input("  username: ")
        p = getpass.getpass("  password: ")
        result = login(u, p)
        if result is True:
            get_session()
            print("  [+] access granted")
            doxa_login_alert()
            main2()
            logout()
            return
        elif isinstance(result,str) and result.startswith("locked:"):
            secs=result.split(":")[1]
            print(f"  [!] account locked — try again in {secs}s")
        elif isinstance(result,str) and result.startswith("fail:"):
            left=result.split(":")[1]
            print(f"  [-] invalid — {left} attempts remaining")
        else:
            print("  [-] invalid credentials")
    print("  [!] too many failed attempts. exiting.")
run_auth()
