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
    6463:"DISCORD-RPC",6472:"DISCORD-RPC-ALT",
    3478:"DISCORD-VOICE",3479:"DISCORD-VOICE-ALT",
    6881:"BITTORRENT",6969:"BITTORRENT-TRACKER",
    25565:"MINECRAFT",8211:"PALWORLD",
    7777:"TERRARIA",19132:"MINECRAFT-BEDROCK",
    5222:"XMPP-WHATSAPP",5223:"XMPP-SSL",
    4244:"WHATSAPP-VOIP",5228:"TELEGRAM-PUSH",
    1080:"SIGNAL-PROXY",5269:"XMPP-SERVER",
    6667:"IRC",6697:"IRC-SSL",
    9001:"TOR-ORPORT",9030:"TOR-DIRPORT",
    9050:"TOR-SOCKS",9051:"TOR-CONTROL",
    1194:"OPENVPN",1723:"PPTP-VPN",
    500:"ISAKMP-VPN",4500:"NAT-VPN",
    51820:"WIREGUARD",1701:"L2TP",
    443:"HTTPS-VPN",8443:"HTTPS-VPN-ALT",
    9443:"REDDIT-ALT",80:"HTTP-REDDIT",
    6881:"BITTORRENT-VPN",8080:"PROXY-HTTP",
    3128:"SQUID-PROXY",8118:"PRIVOXY",
    9091:"TRANSMISSION-RPC",
    135:"MSRPC-L4",593:"MSRPC-HTTP",
    88:"KERBEROS",464:"KERBEROS-PASS",
    636:"LDAPS-L5",3268:"GLOBAL-CATALOG",
    3269:"GLOBAL-CATALOG-SSL",
    5985:"WINRM-HTTP",5986:"WINRM-HTTPS",
    47001:"WINRM-ALT",2179:"VMCONNECT",
    5900:"VNC-L5",5901:"VNC-ALT",
    6000:"XWINDOWS",6001:"XWINDOWS-ALT",
    5060:"SIP-VOIP",5061:"SIPS-VOIP",
    4569:"IAX2-VOIP",9943:"SNAPCHAT",
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
HIGH={4444,50050,23,69,102,502,44818,20000,5555,5554,2323,37777,34567,9527,81,6463}
OT={47808,47809,47810,1911,4911,502,802,
    44818,20000,102,4840,6454,5568,2430,
    41794,4059,9600,1962,2404,34964,1200}
def http_fingerprint(ip, port=80):
    import socket
    try:
        s=socket.socket()
        s.settimeout(3)
        s.connect((ip,port))
        req=f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        s.send(req.encode())
        resp=s.recv(2048).decode(errors='ignore')
        s.close()
        headers={}
        lines=resp.split('\r\n')
        status=lines[0] if lines else ''
        for line in lines[1:10]:
            if ':' in line:
                k,v=line.split(':',1)
                headers[k.strip().lower()]=v.strip()
        server=headers.get('server','unknown')
        powered=headers.get('x-powered-by','')
        title=''
        if '<title>' in resp.lower():
            t=resp.lower().split('<title>')[1]
            title=t.split('</title>')[0][:50]
        print(f"  {C}HTTP {port}{RS} {status[:40]}")
        print(f"  {D}server: {server}{RS}")
        if powered: print(f"  {D}powered: {powered}{RS}")
        if title: print(f"  {D}title: {title}{RS}")
        for keyword,device in [
            ('router','ROUTER'),('camera','IP-CAMERA'),
            ('dvr','DVR-RECORDER'),('nas','NAS-STORAGE'),
            ('samsung','SAMSUNG-DEVICE'),('lg','LG-DEVICE'),
            ('hikvision','HIKVISION-CAM'),('dahua','DAHUA-CAM'),
            ('ubiquiti','UBIQUITI-AP'),('mikrotik','MIKROTIK'),
            ('niagara','NIAGARA-BAS'),('webctrl','WEBCTRL-BAS'),
            ('bacnet','BACNET-DEVICE'),('tridium','TRIDIUM-BAS'),
        ]:
            if keyword in resp.lower():
                print(f"  {Y}DEVICE TYPE: {device}{RS}")
                break
        banner = {'ip': ip, 'port': port, 'status': status[:40], 'server': server, 'powered': powered, 'title': title}
        try:
            from modules.core.filestack import STACK
            import os, json
            from modules.core.filestack import get_stack
            bp = os.path.join(get_stack(), 'http_banners.json')
            banners = []
            if os.path.exists(bp):
                with open(bp) as f: banners = json.load(f)
            banners = [b for b in banners if not (b.get('ip')==ip and b.get('port')==port)]
            banners.append(banner)
            with open(bp,'w') as f: json.dump(banners, f, indent=2)
        except: pass
        return resp
    except Exception as e:
        print(f"  {D}port {port}: {e}{RS}")
        return None

def select_target_from_sweep():
    import os,json
    stack=os.path.expanduser("~/.wraith/loot/stack")
    from modules.core.filestack import STACK
    fp=os.path.join(STACK,"hosts.json")
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
    print('PORTSCAN START')
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
    if 6463 in plist:
        mitre.append("Discord RPC open — token theft risk")
    if 5222 in plist or 5223 in plist:
        mitre.append("XMPP open — WhatsApp messaging protocol")
    if 5060 in plist or 5061 in plist:
        mitre.append("SIP open — VOIP interception risk")
    if 6667 in plist or 6697 in plist:
        mitre.append("IRC open — known C2 channel")
    if mitre:
        print(f"  {R}FINDINGS:{RS}")
        for m in mitre:
            print(f"  {D}  {m}{RS}")
    http_open=[p for p in plist if p in [80,8080,8443,443,8888,8001,8008,8009,8123,8086,3000,8010,9080,8181,8088]]
    if http_open:
        print(f"\n{C}  HTTP FINGERPRINT{RS}")
        print(f"  {D}{'─'*46}{RS}")
        for p in http_open[:3]:
            try: http_fingerprint(ip,p)
            except: pass
    try:
        import os,json,datetime
        from modules.core.filestack import write_json,get_stack
        stack=get_stack()
        print(f'  [DEBUG] stack={stack}')
        sp=os.path.join(stack,'portscan.json')
        data=json.load(open(sp)) if os.path.exists(sp) else {'scans':[]}
        data['scans'].append({'target':ip,'ports':[{'port':p,'service':s,'state':st} for p,s,st in results if st=='OPEN']})
        write_json('portscan.json',data)
        print(f'  [DEBUG] wrote {len(data["scans"])} scans')
    except Exception as e:
        print(f'  [PORTSCAN ERR] {e}')
    return results
