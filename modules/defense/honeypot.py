import socket, json, os, threading
from datetime import datetime
from modules.defense.sanitize import Sanitizer

STACK = os.path.expanduser("~/.wraith/loot/stack")
ALERTS = os.path.join(STACK, "alerts.json")
HITS = os.path.join(STACK, "honeypot_hits.json")
_s = Sanitizer()

FAKE_BACNET_RESPONSE = b'\x81\x0b\x00\x18\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
FAKE_MODBUS_RESPONSE = b'\x00\x01\x00\x00\x00\x03\x01\x03\x00'

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

def check_port_free(port, proto='tcp'):
    try:
        if proto == 'udp':
            s = socket.socket(socket.AF_INET,
                socket.SOCK_DGRAM)
        else:
            s = socket.socket(socket.AF_INET,
                socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,
            socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.close()
        return True
    except: return False

def write_hit(src_ip, src_port, proto, data):
    src_ip = _s.sanitize(str(src_ip),
        "honeypot", "src_ip")
    data_sample = _s.sanitize(
        data.hex()[:80] if data else "",
        "honeypot", "data")
    hit = {"timestamp": datetime.now().isoformat(),
        "src_ip": src_ip, "src_port": src_port,
        "protocol": proto, "data": data_sample}
    hits = load_json(HITS)
    if not isinstance(hits, list): hits = []
    hits.append(hit)
    save_json(HITS, hits)
    alert = {"timestamp": datetime.now().isoformat(),
        "module": "honeypot",
        "severity": "WARNING",
        "ip": src_ip,
        "reason": f"HONEYPOT_HIT_{proto.upper()}",
        "message": f"probe from {src_ip}:{src_port}"}
    alerts = load_json(ALERTS)
    if isinstance(alerts, dict):
        alerts = alerts.get("alerts", [])
    if not isinstance(alerts, list): alerts = []
    alerts.append(alert)
    save_json(ALERTS, alerts)
    print(f"  \033[31m[HONEYPOT]\033[0m "
        f"probe from {src_ip}:{src_port} "
        f"via {proto}")

def bacnet_listener(port=47808):
    if not check_port_free(port, 'udp'):
        print(f"  [HONEYPOT] port {port}/udp in use — aborted")
        return
    s = socket.socket(socket.AF_INET,
        socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET,
        socket.SO_REUSEADDR, 1)
    s.settimeout(1)
    s.bind(('0.0.0.0', port))
    print(f"  \033[36m[HONEYPOT]\033[0m "
        f"BACnet listener on UDP:{port}")
    return s

def modbus_listener(port=502):
    if not check_port_free(port, 'tcp'):
        print(f"  [HONEYPOT] port {port}/tcp in use — aborted")
        return None
    s = socket.socket(socket.AF_INET,
        socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,
        socket.SO_REUSEADDR, 1)
    s.settimeout(1)
    s.bind(('0.0.0.0', port))
    s.listen(5)
    print(f"  \033[36m[HONEYPOT]\033[0m "
        f"Modbus listener on TCP:{port}")
    return s

def run_bacnet_loop(sock, stop_event):
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(1024)
            write_hit(addr[0], addr[1],
                "bacnet_udp", data)
            sock.sendto(FAKE_BACNET_RESPONSE, addr)
        except socket.timeout: continue
        except: break

def run_modbus_loop(sock, stop_event):
    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            data = conn.recv(256)
            write_hit(addr[0], addr[1],
                "modbus_tcp", data)
            conn.send(FAKE_MODBUS_RESPONSE)
            conn.close()
        except socket.timeout: continue
        except: break

def authorize():
    print("\n  \033[31m[HONEYPOT]\033[0m "
        "AUTHORIZATION REQUIRED")
    print("  honeypot binds to network ports.")
    print("  only use on networks you own and")
    print("  are authorized to monitor.")
    confirm = input(
        "  type AUTHORIZED to proceed: ").strip()
    return confirm == "AUTHORIZED"

def run_honeypot(bacnet=True, modbus=True):
    print("\n  \033[36m[HONEYPOT]\033[0m "
        "passive trap module")
    if not authorize():
        print("  [HONEYPOT] authorization failed — exit")
        return
    stop_event = threading.Event()
    threads = []
    if bacnet:
        sock_b = bacnet_listener()
        if sock_b:
            t = threading.Thread(
                target=run_bacnet_loop,
                args=(sock_b, stop_event),
                daemon=True)
            t.start()
            threads.append(t)
    if modbus:
        sock_m = modbus_listener()
        if sock_m:
            t = threading.Thread(
                target=run_modbus_loop,
                args=(sock_m, stop_event),
                daemon=True)
            t.start()
            threads.append(t)
    if not threads:
        print("  [HONEYPOT] no listeners started")
        return
    print("  [HONEYPOT] running — ctrl+c to stop")
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        print("\n  [HONEYPOT] stopped")

if __name__ == "__main__":
    run_honeypot()
