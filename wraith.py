import socket, datetime

T = "192.168.1.254"

def div():
    print("  " + "="*40)

def ts():
    return datetime.datetime.now().strftime("%H:%M:%S")

def recon():
    print(f"\n  [RECON] {ts()}")
    div()
    for l,h in [("gateway",T),("cloudflare","1.1.1.1"),("google","google.com")]:
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

def portscan():
    print(f"\n  [PORTSCAN] {ts()}")
    div()
    for port,label in [(53,"DNS"),(80,"HTTP"),(443,"HTTPS"),(47808,"BACNET")]:
        try:
            s=socket.socket()
            s.settimeout(0.5)
            r=s.connect_ex((T,port))
            s.close()
            if r==0:
                print(f"  OPEN  {port:<8}{label}")
        except:
            pass
    div()

def dns():
    print(f"\n  [DNS] {ts()}")
    div()
    for n in ["iphone","router","laptop","tv","camera"]:
        for sfx in ["",".local",".attlocal.net"]:
            try:
                ip=socket.getaddrinfo(n+sfx,None)[0][4][0]
                if ip.startswith("192.168"):
                    print(f"  RESOLVED  {n+sfx:<24}{ip}")
                    break
            except:
                pass
    div()

print("\n  WRAITH — sig.int.ghost")
print("  passive observer. anomaly is the signal.")
div()
print("  [1] RECON  [2] PORTS  [3] DNS  [4] ALL")
div()
c=input("\n  > ")
if c=="1": recon()
elif c=="2": portscan()
elif c=="3": dns()
elif c=="4": recon();portscan();dns()
print("\n  ghost offline.\n")
