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
HIGH={4444,50050,23,69,102,502,44818,20000}
OT={47808,47809,47810,1911,4911,502,802,
    44818,20000,102,4840,6454,5568,2430,
    41794,4059,9600,1962,2404,34964,1200}
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
    if mitre:
        print(f"  {R}MITRE ATT&CK ICS:{RS}")
        for m in mitre:
            print(f"  {D}  {m}{RS}")
    try:
        from modules.filestack import write_json
        write_json('portscan.json', {'target': ip, 'ports': [
            {'port': p, 'service': s, 'state': st} for p,s,st in results
        ]})
    except: pass
    return results
