import socket, getpass
import datetime

VERSION = "3.4"

PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "TELNET",
    53:    "DNS",
    80:    "HTTP",
    443:   "HTTPS",
    3389:  "RDP",
    8080:  "HTTP-ALT",
    47808: "BACNET",
    502:   "MODBUS",
    102:   "S7COMM",
    44818: "ETHERNET-IP",
    20000: "DNP3",
    1911:  "NIAGARA",
    4911:  "NIAGARA-SSL",
    1883:  "MQTT",
    8883:  "MQTT-SSL",
    161:   "SNMP",
    162:   "SNMP-TRAP",
    1900:  "UPNP",
    5353:  "MDNS",
}

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

def run_oracle_module():
    import sys
    sys.path.insert(0, '.')
    from modules.oracle import run_oracle
    run_oracle()

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
    import sys
    sys.path.insert(0, '.')
    from modules.sweep import run_sweep
    from modules.logger import log_result
    results = run_sweep(base, local_ip)
    for ip, port, hostname in results:
        log_result(local_ip, "SWEEP", f"{ip} port={port} {hostname}")

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
    log_result(gateway, "AUTO", "chain scan complete")
    print(f"\n  [AUTO] complete. log saved to ~/.wraith/loot/logs/")

def show_main_menu():
    div()
    print(f"  {CYAN}[1]{RESET} RECON")
    print(f"  {CYAN}[2]{RESET} PROTOCOLS")
    print(f"  {CYAN}[3]{RESET} INTELLIGENCE")
    print(f"  {CYAN}[4]{RESET} ALERTS")
    print(f"  {CYAN}[5]{RESET} SWEEP")
    print(f"  {CYAN}[8]{RESET} KEY MANAGEMENT")
    print(f"  {CYAN}[9]{RESET} WISHLIST")
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
    print(f"  {CYAN}[2]{RESET} ORACLE")
    print(f"  {CYAN}[3]{RESET} AUTO")
    print(f"  {CYAN}[4]{RESET} DNS")
    print(f"  {CYAN}[5]{RESET} BANNER")
    print(f"  {DIM}[0] BACK{RESET}")
    div()
def main2():
    print(f"  WRAITH v{VERSION}")
    div()
    gateway,local_ip,base=get_network()
    print(f"  gateway  : {gateway}")
    print(f"  local ip : {local_ip}")
    print(f"  subnet   : {base}.0/24")
    while True:
        show_main_menu()
        c = input(" > ")
        if c == "0": break
        elif c == "1":
            recon(gateway,local_ip)
            try:
                from modules.sweep import run_sweep
                from modules.ttl import run_ttl
                hosts = run_sweep(base, local_ip)
                if hosts: run_ttl(hosts)
            except Exception as e: pass
        elif c == "8":
            from modules.keys_manager import run_keys_manager
            run_keys_manager()
        elif c == "9":
            from modules.wishlist_agent import run_wishlist_agent
            run_wishlist_agent()
        elif c == "4": run_alerts_module()
        elif c == "5": run_sweep_module(gateway,local_ip,base)
        elif c == "2":
            while True:
                show_protocols_menu()
                p = input(" > ")
                if p == "0": break
                elif p == "1": run_bacnet_module()
                elif p == "2": run_modbus_module()
                elif p == "3": run_mqtt_module()
                elif p == "4": run_mstp_module()
                elif p == "5": portscan(gateway)
                elif p == "6": run_snmp_module()
                else: print("  invalid")
        elif c == "3":
            while True:
                show_intel_menu()
                p = input(" > ")
                if p == "0": break
                elif p == "1": run_osint(gateway)
                elif p == "2": run_oracle_module()
                elif p == "3": auto_chain(gateway,local_ip)
                elif p == "4": dns()
                elif p == "5": banner(gateway)
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
        p = getpass.getpass("  password: ")
        create_user(u, p, "admin")
        print("  [+] admin account created")
    attempts = 0
    while attempts < 3:
        u = input("  username: ")
        p = getpass.getpass("  password: ")
        if login(u, p):
            s = get_session()
            print("  [+] access granted")
            main2()
            logout()
            return
        attempts += 1
        print(f"  [-] invalid — {3-attempts} remaining")
    print("  [!] too many failed attempts. exiting.")
run_auth()
