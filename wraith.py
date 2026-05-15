import socket, getpass
import datetime

VERSION = "4.6"

from modules.core.portscan import PORTS

GREEN  = '\033[32m'
CYAN   = '\033[36m'
YELLOW = '\033[33m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'
def div(): print(f"  {DIM}{'─'*44}{RESET}")
def ts(): return datetime.datetime.now().strftime("%H:%M:%S")
from modules.utils.hash_check import run_hash_check

def get_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        priv = lambda ip: ip.startswith(('10.','192.168.','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.','172.23.','172.24.','172.25.','172.26.','172.27.','172.28.','172.29.','172.30.','172.31.'))
        if not priv(local_ip):
            import subprocess
            r=subprocess.run(['ip','route'],capture_output=True,text=True)
            for line in r.stdout.splitlines():
                if 'src' in line:
                    parts2=line.split()
                    idx=parts2.index('src')
                    candidate=parts2[idx+1]
                    if priv(candidate): local_ip=candidate; break
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
        from modules.core.portscan import http_fingerprint
        for p in http_ports[:2]:
            try: http_fingerprint(gateway, p)
            except: pass
    try:
        from modules.core.filestack import write_json,get_stack
        import os
        sp=os.path.join(get_stack(),'portscan.json')
        import json
        data=json.load(open(sp)) if os.path.exists(sp) else {'scans':[]}
        data['scans'].append({'target':gateway,'ports':[{'port':p,'service':s,'state':'OPEN'} for p,s in found]})
        write_json('portscan.json',data)
        print(f'  stack written: portscan.json')
        from modules.core.asset_registry import upsert as reg_upsert
        reg_upsert(ip=gateway, mac='', source='portscan', **{'network.open_ports':[p for p,l in found]})
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
    from modules.intel.osint import osint_lookup
    priv = lambda ip: any(ip.startswith(p) for p in ('10.','192.168.','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.','172.23.','172.24.','172.25.','172.26.','172.27.','172.28.','172.29.','172.30.','172.31.'))
    if not priv(gateway): print(f'  [WARN] default {gateway} appears to be a public IP — enter local target')
    custom = input("  enter target IP [default: " + gateway + "]: ").strip()
    target = custom if custom else gateway
    osint_lookup(target)






def run_mqtt_module():
    import sys
    sys.path.insert(0, '.')
    from modules.protocols.mqtt import run_mqtt
    run_mqtt()

def run_alerts_module():
    from modules.core.alerts import get_recent, clear_alerts
    alerts = get_recent(20)
    if not alerts:
        print(chr(32)*2 + chr(91) + chr(42) + chr(93) + chr(32) + chr(78) + chr(111) + chr(32) + chr(97) + chr(108) + chr(101) + chr(114) + chr(116) + chr(115) + chr(32) + chr(111) + chr(110) + chr(32) + chr(102) + chr(105) + chr(108) + chr(101))
        return
    for a in alerts:
        ts = a.get("ts", "")[11:19] if a.get("ts") else "unknown"
        msg = a.get("message") or a.get("type","unknown")
        sev = a.get("severity","?")
        c = "\033[91m" if sev=="HIGH" else "\033[93m" if sev=="MEDIUM" else "\033[92m"
        print("  " + c + sev + "\033[0m" + " " + ts + " " + msg)

def run_snmp_module():
    from modules.protocols.snmp import run_snmp
    run_snmp()

def run_mstp_module():
    from modules.protocols.serial_mstp import run_mstp
    run_mstp()

def run_doxa_module():
    import sys
    sys.path.insert(0, '.')
    from modules.doxa.doxa import run_doxa
    run_doxa()

def run_modbus_module():
    import sys
    sys.path.insert(0, '.')
    from modules.protocols.modbus import run_modbus
    run_modbus()

def run_bacnet_module():
    import sys
    sys.path.insert(0, '.')
    from modules.protocols.bacnet import run_bacnet
    run_bacnet()

def run_sweep_module(gateway, local_ip, base):
    from modules.core.topology import add_node, mark_scanned, discover_from_filestack
    from modules.core.filestack import get_stack
    add_node(f"{base}.0/24", source='sweep')
    import sys
    sys.path.insert(0, '.')
    from modules.core.sweep import run_sweep
    from modules.core.logger import log_result
    results = run_sweep(base, local_ip)
    try:
        from modules.arp import run_arp
        run_arp(gateway, local_ip)
    except: pass
    try:
        from modules.arp import read_arp_cache
        result = read_arp_cache()
        if not result:
            from modules.arp import seed_arp_from_hosts
            seed_arp_from_hosts()
    except Exception as e:
        try:
            from modules.arp import seed_arp_from_hosts
            seed_arp_from_hosts()
        except: pass
    from modules.core.registry import update_registry, get_new_hosts
    arp_hosts = [(ip, '', '') for ip, port, hostname in results]
    new_hosts = get_new_hosts(arp_hosts)
    update_registry(arp_hosts)
    if new_hosts:
        print(f"  [33m[REGISTRY] {len(new_hosts)} new host(s) first seen[0m")
    for ip, port, hostname in results:
        log_result(local_ip, "SWEEP", f"{ip} port={port} {hostname}")
    mark_scanned(f"{base}.0/24")
    from modules.core.portscan import run_portscan
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
    from modules.core.logger import log_result
    from modules.core.portscan import run_portscan
    from modules.intel.osint import osint_lookup
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
        from modules.protocols.snmp import run_snmp
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
    from modules.core.filestack import get_stack
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

def check_role(required):
    from modules.admin.auth import CURRENT_ROLE
    order = ['readonly','technician','admin']
    if order.index(CURRENT_ROLE) >= order.index(required):
        return True
    print(f"  [AUTH] {required} role required — you are {CURRENT_ROLE}")
    return False

def get_public_ip():
    try:
        import urllib.request
        r = urllib.request.urlopen('https://api.ipify.org', timeout=5)
        return r.read().decode().strip()
    except:
        return 'unknown'


def show_integrations_menu():
    print(f"\n  {CYAN}WRAITH{RESET} > {CYAN}INTEGRATIONS{RESET}")
    div()
    print(f"  {CYAN}[1]{RESET} ASSET REG    {DIM}operator asset registry{RESET}")
    print(f"  {CYAN}[2]{RESET} DATA EXPORT  {DIM}pipeline connector{RESET}")
    print(f"  {CYAN}[3]{RESET} CMMS         {DIM}work order connector{RESET}")
    print(f"  {CYAN}[4]{RESET} WEBCTRL DB   {DIM}PostgreSQL{RESET}")
    print(f"  {CYAN}[5]{RESET} ISO 50001    {DIM}energy gap analysis{RESET}")
    print(f"  {DIM}[0] BACK{RESET}")
    div()
def show_main_menu():
    print(f"\n  {CYAN}WRAITH v{VERSION}{RESET} > {DIM}main{RESET}")
    div()
    print(f"  {CYAN}[1]{RESET} SWEEP        {DIM}discover + TTL{RESET}")
    print(f"  {CYAN}[2]{RESET} SCAN         {DIM}portscan + banner + SNMP{RESET}")
    print(f"  {CYAN}[3]{RESET} PROTOCOLS    {DIM}BACnet Modbus MQTT MSTP{RESET}")
    print(f"  {CYAN}[4]{RESET} INTEL        {DIM}OSINT CVE DNS signals{RESET}")
    print(f"  {CYAN}[5]{RESET} DOXA         {DIM}AI agent{RESET}")
    print(f"  {CYAN}[6]{RESET} ALERTS")
    print(f"  {CYAN}[r]{RESET} REPORT       {DIM}export markdown report{RESET}")
    print(f"  {CYAN}[7]{RESET} INTEGRATIONS {DIM}Asset DB WebCTRL Connectors{RESET}")
    print(f"  {CYAN}[8]{RESET} ADMIN")
    print(f"  {CYAN}[9]{RESET} KEYS")
    print(f"  {DIM}[0] EXIT{RESET}")
    div()
def show_protocols_menu():
    print(f"\n  {CYAN}WRAITH{RESET} > {CYAN}PROTOCOLS{RESET}")
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
    print(f"\n  {CYAN}WRAITH{RESET} > {CYAN}INTEL{RESET}")
    div()
    print(f"  {CYAN}[1]{RESET} OSINT")
    print(f"  {CYAN}[2]{RESET} CVE")
    print(f"  {CYAN}[3]{RESET} DNS")
    print(f"  {CYAN}[4]{RESET} BANNER")
    print(f"  {CYAN}[5]{RESET} BASELINE")
    print(f"  {CYAN}[6]{RESET} MAC VERIFY")
    print(f"  {CYAN}[m]{RESET} MAC TABLE")
    print(f"  {CYAN}[7]{RESET} DNS TUNNEL")
    print(f"  {CYAN}[8]{RESET} ICMP TUNNEL")
    print(f"  {CYAN}[9]{RESET} TRAFFIC")
    print(f"  {CYAN}[p]{RESET} PORT HOP")
    print(f"  {CYAN}[a]{RESET} VLAN HOP")
    print(f"  {CYAN}[b]{RESET} RF SIGNAL")
    print(f"  {DIM}[0] BACK{RESET}")
    div()
def main2():
    run_hash_check(silent=True)
    from modules.core.netcheck import run_network_check
    ok=run_network_check()
    if not ok: return
    print(f"  WRAITH v{VERSION}")
    div()
    gateway,local_ip,base=get_network()
    from modules.core.filestack import set_subnet
    set_subnet(f"{base}.0_24")
    print(f"  gateway  : {gateway}")
    print(f"  local ip : {local_ip}")
    print(f"  subnet   : {base}.0/24")
    while True:
        show_main_menu()
        c = input(" > ")
        if c == "r":
            from modules.reporting.report import run_report
            run_report()
        elif c == "0": break
        elif c == "1":
            from modules.core.subnet_selector import select_subnet
            from modules.core.filestack import set_subnet
            sel = select_subnet(base)
            if sel is None: print("  [SWEEP] cancelled")
            else:
                set_subnet(f"{sel}.0_24")
                run_sweep_module(gateway,local_ip,sel)
                set_subnet(f"{base}.0_24")
                from modules.core.mac_table import show_mac_table
                show_mac_table()
        elif c == "2":
            if not check_role('technician'): continue
            from modules.core.portscan import select_target_from_sweep
            t=select_target_from_sweep()
            if not t: t=input("  enter IP > ").strip()
            if t:
                from modules.core.portscan import run_portscan
                run_portscan(t)
                banner(t)
                run_snmp_module()
                from modules.core.baseline import run_baseline
                run_baseline()
                from modules.intel.mac_verify import verify_macs
                verify_macs()
        elif c == "5":
            if not check_role('technician'): continue
            from modules.doxa.doxa import run_doxa
            run_doxa(gateway, local_ip)
        elif c == "6": run_alerts_module()
        elif c == "7":
            if not check_role('technician'): continue
            while True:
                show_integrations_menu()
                p = input(" > ")
                if p == "0": break
                elif p == "1":
                    from modules.core.asset_registry import all_records
                    recs = all_records()
                    print(f'\n  ASSET REGISTRY — {len(recs)} records')
                    for r in recs:
                        print(f"  {r['network']['ip']:<18} {r['type']:<14} {'AUTH' if r['authorized'] else 'UNAUTH'}")
                elif p == "2":
                    from modules.integrations.snowflake_connector import run_snowflake
                    run_snowflake()
                elif p == "3":
                    from modules.integrations.workorder_agent import run_workorder_agent
                    run_workorder_agent()
                elif p == "4":
                    from modules.integrations.pg_connector import run_pg_connector
                    run_pg_connector()
                elif p == "5":
                    from modules.integrations.iso50001_gap import run_iso50001
                    run_iso50001()
                else: print("  invalid")
        elif c == "8":
            if not check_role('admin'): continue
            from modules.admin.admin import run_admin
            run_admin()
        elif c == "9":
            if not check_role('admin'): continue
            from modules.admin.keys_manager import run_keys_manager
            run_keys_manager()
        elif c == "3":
            if not check_role('technician'): continue
            while True:
                show_protocols_menu()
                p = input(" > ")
                if p == "0": break
                elif p == "1": run_bacnet_module()
                elif p == "2": run_modbus_module()
                elif p == "3": run_mqtt_module()
                elif p == "4": run_mstp_module()
                elif p == "5":
                    from modules.core.portscan import select_target_from_sweep
                    t=select_target_from_sweep()
                    if t: portscan(t)
                    else:
                        custom=input("  enter IP manually > ").strip()
                        if custom: portscan(custom)
                elif p == "6": run_snmp_module()
                else: print("  invalid")
        elif c == "4":
            if not check_role('technician'): continue
            while True:
                show_intel_menu()
                p = input(" > ")
                if p == "0": break
                elif p == "1":
                    run_osint(gateway)
                elif p == "2":
                    from modules.intel.cve import run_cve_module
                    run_cve_module()
                elif p == "3": dns()
                elif p == "4": banner(gateway)
                elif p == "5":
                    from modules.core.baseline import run_baseline
                    run_baseline()
                elif p == "6":
                    from modules.intel.mac_verify import verify_macs
                    verify_macs()
                elif p == "m":
                    from modules.core.mac_table import show_mac_table
                    show_mac_table()
                elif p == "7":
                    from modules.intel.dns_tunnel import run_dns_tunnel
                    run_dns_tunnel()
                elif p == "8":
                    from modules.intel.icmp_tunnel import run_icmp_tunnel
                    run_icmp_tunnel()
                elif p == "9":
                    from modules.intel.traffic_anomaly import run_traffic_anomaly
                    run_traffic_anomaly()
                elif p == "p":
                    from modules.defense.port_hop_detector import run_port_hop
                    run_port_hop()
                elif p == "a":
                    from modules.intel.vlan_hop import run_vlan_hop
                    run_vlan_hop()
                elif p == "b":
                    from modules.intel.rf import run_rf
                    run_rf()
                else: print("  invalid")
        else: print("  invalid option")
    from modules.core.ghost import ghost_exit
    ghost_exit()
    import sys; sys.path.insert(0,'.')
def run_first_run_check():
    from modules.core.first_run import is_first_run, run_first_run
    if is_first_run():
        run_first_run()

def run_auth():
    from modules.admin.auth import first_run, create_user, login, logout, get_session
    print("  [WRAITH] authentication required")
    if first_run():
        print("  [*] first run — create admin account")
        u = input("  username: ")
        while True:
            p = getpass.getpass("  password: ")
            from modules.admin.auth import validate_password
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
run_first_run_check()
run_auth()
