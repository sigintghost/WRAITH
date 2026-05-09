import json, os, socket, ssl
from datetime import datetime
from modules.sanitize import Sanitizer

STACK = os.path.expanduser("~/.wraith/loot/stack")
ALERTS = os.path.join(STACK, "alerts.json")
INVENTORY = os.path.join(STACK, "bacnet_inventory.json")
SC_PORTS = [47808, 47809, 443, 8443]
_s = Sanitizer()

def load_json(path):
    try:
        if os.path.exists(path):
            with open(path) as f: return json.load(f)
    except: pass
    return {}

def save_json(path, data):
    try:
        with open(path,'w') as f:
            json.dump(data, f, indent=2)
    except: pass

def write_alert(ip, reason, severity, detail=""):
    ip = _s.sanitize(str(ip), "bacnet_sc", "ip")
    alert = {"timestamp": datetime.now().isoformat(),
        "module": "bacnet_sc",
        "severity": severity, "ip": ip,
        "reason": reason, "detail": detail,
        "message": f"{severity}: {ip} — {reason}"}
    data = load_json(ALERTS)
    if isinstance(data, dict):
        alerts = data.get("alerts", [])
    else:
        alerts = data if isinstance(data, list) else []
    alerts.append(alert)
    save_json(ALERTS, alerts)

def probe_tcp_port(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET,
            socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except: return False

def harvest_tls_metadata(ip, port, timeout=3):
    meta = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(
                (ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock,
                    server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                meta['cipher'] = ssock.cipher()
                meta['version'] = ssock.version()
                if cert:
                    meta['subject'] = dict(
                        x[0] for x in
                        cert.get('subject',[]))
                    meta['issuer'] = dict(
                        x[0] for x in
                        cert.get('issuer',[]))
                    meta['expires'] = cert.get(
                        'notAfter','')
    except: pass
    return meta

def detect_migration_mode(ip):
    udp_open = False
    try:
        s = socket.socket(socket.AF_INET,
            socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b'\x81\x0b\x00\x0c\x01\x20'
            b'\xff\xff\x00\xff\x10\x08', (ip, 47808))
        s.recvfrom(1024)
        udp_open = True
        s.close()
    except: pass
    tcp_open = probe_tcp_port(ip, 47808)
    return udp_open, tcp_open

def scan_host(ip):
    ip = _s.sanitize(str(ip), "bacnet_sc", "ip")
    result = {"ip": ip, "mode": "unknown",
        "sc_ports": [], "tls_meta": {},
        "timestamp": datetime.now().isoformat()}
    print(f"  \033[36m[SC]\033[0m scanning {ip}...")
    for port in SC_PORTS:
        if probe_tcp_port(ip, port):
            result["sc_ports"].append(port)
            print(f"  \033[32m[SC]\033[0m "
                f"{ip}:{port} open")
            if port in [443, 8443, 47808]:
                meta = harvest_tls_metadata(ip, port)
                if meta:
                    result["tls_meta"][port] = meta
                    subj = meta.get('subject',{})
                    cn = subj.get('commonName','')
                    if cn:
                        cn = _s.sanitize(cn,
                            "bacnet_sc", "cn")
                        print(f"  \033[36m[SC]\033[0m "
                            f"cert CN: {cn}")
    udp, tcp = detect_migration_mode(ip)
    if udp and tcp:
        result["mode"] = "migration_dual_stack"
        write_alert(ip, "SC_MIGRATION_MODE",
            "INFO", "BACnet/IP and SC both active")
        print(f"  \033[33m[INFO]\033[0m "
            f"{ip} dual-stack migration detected")
    elif tcp and not udp:
        result["mode"] = "sc_only"
        print(f"  \033[36m[SC]\033[0m "
            f"{ip} SC-only mode")
    elif udp and not tcp:
        result["mode"] = "bacnet_ip_legacy"
    return result

def run_sc_scan(targets):
    print("\n  \033[36m[BACNET/SC]\033[0m "
        "passive SC reconnaissance")
    print("  \033[33mpassive mode — no enrollment"
        " — no packets injected\033[0m")
    inventory = load_json(INVENTORY)
    sc_devices = inventory.get("sc_devices", {})
    results = []
    for ip in targets:
        result = scan_host(ip)
        if result["sc_ports"]:
            sc_devices[ip] = result
            results.append(result)
    inventory["sc_devices"] = sc_devices
    inventory["sc_scan_time"] = \
        datetime.now().isoformat()
    save_json(INVENTORY, inventory)
    print(f"\n  [SC] {len(results)} SC-capable "
        f"devices found")
    print("  [SC] CREDENTIALED MODE: not active")
    print("  [SC] requires owner CA enrollment")
    return results

def credentialed_mode_stub():
    print("\n  [SC] CREDENTIALED MODE")
    print("  [SC] requires owner-provisioned cert")
    print("  [SC] contact site CA administrator")
    print("  [SC] enrollment not implemented")
    print("  [SC] see WISHLIST.md for roadmap")

if __name__ == "__main__":
    import sys
    targets = sys.argv[1:] or ["192.168.1.254"]
    run_sc_scan(targets)
