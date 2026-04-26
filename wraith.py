import socket
import datetime

VERSION = "1.3"

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

def div(): print("  " + "="*44)
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
def main():
    print(f"\n  WRAITH v{VERSION} — sig.int.ghost")
    print(f"  passive observer. anomaly is the signal.")
    div()
    print(f"  detecting network...")
    gateway,local_ip,base=get_network()
    print(f"  gateway  : {gateway}")
    print(f"  local ip : {local_ip}")
    print(f"  subnet   : {base}.0/24")
    div()
    print("  [1] RECON")
    print("  [2] PORTSCAN — full OT/BAS/ICS port map")
    print("  [3] DNS")
    print("  [4] BANNER")
    print("  [5] ALL")
    div()
    c=input("\n  > ")
    print()
    if c=="1": recon(gateway,local_ip)
    elif c=="2": portscan(gateway)
    elif c=="3": dns()
    elif c=="4": banner(gateway)
    elif c=="5":
        recon(gateway,local_ip)
        portscan(gateway)
        dns()
        banner(gateway)
    print(f"\n  ghost offline. v{VERSION}\n")


def osint_module(gateway):
    import sys
    sys.path.insert(0, '.')
    from modules.osint import osint_lookup
    print(f"\n  [OSINT] target: {gateway}")
    osint_lookup(gateway)

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

def main2():
    print(f"\n  WRAITH v3.1 — sig.int.ghost")
    print(f"  passive observer. anomaly is the signal.")
    div()
    print(f"  detecting network...")
    gateway,local_ip,base=get_network()
    print(f"  gateway  : {gateway}")
    print(f"  local ip : {local_ip}")
    print(f"  subnet   : {base}.0/24")
    div()
    print("  [1] RECON")
    print("  [2] PORTSCAN — full OT/BAS/ICS port map")
    print("  [3] DNS")
    print("  [4] BANNER")
    print("  [5] ALL")
    print("  [6] OSINT — threat intelligence lookup")
    print("  [7] AUTO — full chain scan with logging")
    print("  [8] SWEEP — discover live hosts on subnet")
    print("  [9] BACNET — passive BACnet/IP listener and device inventory")
    print("  [10] MODBUS — passive Modbus TCP listener")
    print("  [11] MQTT — passive MQTT broker listener")
    print("  [12] ORACLE — ghost intelligence module")
    div()
    c=input("\n  > ")
    print()
    if c=="1": recon(gateway,local_ip)
    elif c=="2": portscan(gateway)
    elif c=="3": dns()
    elif c=="4": banner(gateway)
    elif c=="5":
        recon(gateway,local_ip)
        portscan(gateway)
        dns()
        banner(gateway)
    elif c=="6": run_osint(gateway)
    elif c=="7": auto_chain(gateway, local_ip)
    elif c=="8": run_sweep_module(gateway, local_ip, base)
    elif c=="9": run_bacnet_module()
    elif c=="10": run_modbus_module()
    elif c=="11": run_mqtt_module()
    elif c=="12": run_oracle_module()
    import sys; sys.path.insert(0,'.')
    from modules.ghost import ghost_exit
    ghost_exit()

main2()
