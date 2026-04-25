import socket
import datetime

VERSION = "1.1"

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

main()
