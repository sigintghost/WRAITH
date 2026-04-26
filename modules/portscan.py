# WRAITH portscan.py — port state detection
# open / closed / filtered — pure Python sockets
# sig.int.ghost

import socket
import errno

PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 3389: "RDP",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    47808: "BACNET", 502: "MODBUS", 102: "S7COMM",
    44818: "ETHERNET-IP", 20000: "DNP3",
    1911: "NIAGARA", 4911: "NIAGARA-SSL",
    1883: "MQTT", 8883: "MQTT-SSL",
    161: "SNMP", 162: "SNMP-TRAP",
    1900: "UPNP", 5353: "MDNS"
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

def run_portscan(ip):
    print(f"\n  [PORTSCAN] target: {ip}")
    print(f"  {'PORT':<8} {'SERVICE':<14} {'STATE'}")
    print(f"  {'-'*8} {'-'*14} {'-'*8}")
    results = []
    for port, service in sorted(PORTS.items()):
        state = check_port(ip, port)
        if state == "OPEN":
            marker = "<<<<"
        elif state == "CLOSED":
            marker = ""
        else:
            marker = ""
        line = f"  {port:<8} {service:<14} {state} {marker}"
        print(line)
        results.append((port, service, state))
    return results
