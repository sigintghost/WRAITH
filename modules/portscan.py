# WRAITH portscan.py — port state detection
# open / closed / filtered — pure Python sockets
# sig.int.ghost
# %MW100 — memory word. state unknown.
# open is a confession. filtered is a whisper.

import socket
import errno

PORTS = {
    21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",
    53:"DNS",67:"DHCP",69:"TFTP",80:"HTTP",
    110:"POP3",123:"NTP",135:"MSRPC",
    139:"NETBIOS",143:"IMAP",161:"SNMP",
    162:"SNMP-TRAP",389:"LDAP",443:"HTTPS",
    445:"SMB",514:"SYSLOG",587:"SMTP-TLS",
    636:"LDAPS",1433:"MSSQL",3306:"MYSQL",
    3389:"RDP",5900:"VNC",5985:"WINRM",
    8080:"HTTP-ALT",8443:"HTTPS-ALT",
    47808:"BACNET-IP",47809:"BACNET-ALT",
    47810:"BACNET-BBMD",1911:"NIAGARA-FOX",
    4911:"NIAGARA-FOXS",85:"JCI-METASYS",
    5000:"JCI-NAE",10001:"SIEMENS-APOGEE",
    4840:"OPC-UA",4843:"OPC-UA-TLS",
    502:"MODBUS-TCP",802:"MODBUS-ALT",
    44818:"ETHERNET-IP",2222:"ENIP-IO",
    102:"S7COMM",20000:"DNP3",19999:"DNP3-ALT",
    2404:"IEC-60870",9600:"OMRON-FINS",
    1962:"PCWORX",1200:"CODESYS",
    18245:"GE-SRTP",34964:"PROFINET",
    1883:"MQTT",8883:"MQTT-SSL",
    9001:"MQTT-WS",6454:"ARTNET-DMX",
    5568:"SACN-DMX",2430:"LUTRON",
    41794:"CRESTRON-CIP",8888:"EASYIO",
    4059:"ANSI-C12-22",1900:"UPNP",
    5353:"MDNS",5355:"LLMNR",
    1880:"NODE-RED",8086:"INFLUXDB",
    3000:"GRAFANA",9200:"ELASTICSEARCH",
    27017:"MONGODB",6379:"REDIS",
    5672:"AMQP",9092:"KAFKA",
    4444:"MSFPORT-HIGHRISK",
    50050:"CSTRIKE-HIGHRISK",
    3074:"XBOX-LIVE",3075:"XBOX-ALT",
    3478:"PLAYSTATION",27015:"STEAM",
    27036:"STEAM-REMOTE",25565:"MINECRAFT",
    40000:"ROBLOX",49152:"ROBLOX-ALT",
    8009:"CHROMECAST",7000:"AIRPLAY",
    32400:"PLEX",32469:"PLEX-ALT",
    1935:"RTMP-STREAM",8554:"RTSP",
    9080:"SAMSUNG-TV",8001:"SAMSUNG-API",
    55000:"SAMSUNG-ALT",7676:"LG-TV",
    3000:"WEBOS-LG",9998:"VIZIO-TV",
    5555:"ADB-FIRESTICK",8088:"FIRESTICK-ALT",
    62078:"IPHONE-SYNC",5228:"GOOGLE-PUSH",
    5554:"ADB-ANDROID",8123:"HOME-ASSISTANT",
    1400:"SONOS",4070:"SPOTIFY-CONNECT",
    2323:"TELNET-IOT-ALT",37777:"DAHUA-DVR",
    34567:"DVR-CHINA",9527:"DVR-ALT",
    81:"CAM-HTTP-ALT",
}

def check_port(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return "OPEN"
        elif result in (errno.ECONNREFUSED, 111):
            return "CLOSED"
        else:
            return "FILTERED"
    except socket.timeout:
        return "FILTERED"
    except Exception:
        return "FILTERED"

C='[36m';G='[32m';R='[31m'
Y='[33m';D='[2m';RS='[0m'
HIGH={4444,50050,23,69,102,502,44818,20000,5555,5554,2323,37777,34567,9527,81}
OT={47808,47809,47810,1911,4911,502,802,
    44818,20000,102,4840,6454,5568,2430,
    41794,4059,9600,1962,2404,34964,1200}
def select_target_from_sweep():
    import os,json
    stack=os.path.expanduser("~/.wraith/loot/stack")
    fp=os.path.join(stack,"hosts.json")
    if not os.path.exists(fp):
        print(f"  {R}no sweep results — run sweep first{RS}")
        return None
    with open(fp) as f: data=json.load(f)
    hosts=data.get("hosts",[])
    if not hosts:
        print(f"  {R}no hosts in filestack{RS}")
        return None
    print(f"\n{C}  SELECT SCAN TARGET{RS}")
    print(f"  {D}{'─'*46}{RS}")
    ips=[]
    for i,h in enumerate(hosts):
        if isinstance(h,dict):
            ip=h.get("ip","")
            port=h.get("port",0)
            host=h.get("hostname",ip)
        else:
            ip=str(h);port=0;host=ip
        if ip:
            ips.append(ip)
            print(f"  [{i+1}] {ip:<18} {D}port={port} {host}{RS}")
    print(f"  {D}[0] cancel{RS}")
    sel=input("  select target > ").strip()
    if sel=='0': return None
    try: return ips[int(sel)-1]
    except: return None

def run_portscan(ip):
    print(f"\n{C}  [PORTSCAN]{RS} target: {ip}")
    print(f"  {D}scanning {len(PORTS)} ports...{RS}")
    print(f"  {D}{'─'*46}{RS}")
    results=[]
    open_count=0
    for port,service in sorted(PORTS.items()):
        state=check_port(ip,port)
        if state=="OPEN":
            open_count+=1
            if port in HIGH:
                col=R; risk="HIGH"
            elif port in OT:
                col=Y; risk="OT"
            else:
                col=G; risk="std"
            print(f"  {col}{port:<7}{service:<20}{state:<10}{risk}{RS}")
        results.append((port,service,state))
    print(f"  {D}{'─'*46}{RS}")
    print(f"  {C}open: {open_count}{RS} of {len(PORTS)} scanned")
    plist=[p for p,s,st in results if st=="OPEN"]
    mitre=[]
    if any(p in plist for p in [502,44818]):
        mitre.append("T0855 Unauthorized Command Message")
    if 23 in plist:
        mitre.append("T0886 Remote Services Telnet")
    if any(p in plist for p in [4444,50050]):
        mitre.append("T0822 Exploit Public Facing C2")
    if 102 in plist:
        mitre.append("T0843 Program Download S7Comm")
    if 20000 in plist:
        mitre.append("T0869 Standard App Layer DNP3")
    if 5555 in plist or 5554 in plist:
        mitre.append("ADB open — Android device exploitable")
    if any(p in plist for p in [37777,34567,9527]):
        mitre.append("DVR/Camera default port — likely unpatched")
    if 2323 in plist:
        mitre.append("Telnet alt — IoT Mirai botnet signature")
    if 81 in plist:
        mitre.append("Camera HTTP alt — default credential risk")
    if mitre:
        print(f"  {R}FINDINGS:{RS}")
        for m in mitre:
            print(f"  {D}  {m}{RS}")
    try:
        from modules.filestack import write_json
        write_json('portscan.json', {'target': ip, 'ports': [
            {'port': p, 'service': s, 'state': st} for p,s,st in results
        ]})
    except: pass
    return results
