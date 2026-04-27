# modules/serial_mstp.py
# WRAITH BACnet MSTP passive listener
import os, time, json, struct
from datetime import datetime
MSTP_PREAMBLE_1 = 0x55
MSTP_PREAMBLE_2 = 0xFF
BAUD_RATES = [9600,19200,38400,57600,76800,115200]
STACK_DIR = os.path.expanduser("~/.wraith/loot/stack")
MSTP_FILE = os.path.join(STACK_DIR, "mstp_topology.json")

def find_serial_port():
    candidates = ["/dev/ttyUSB0","/dev/ttyUSB1","/dev/ttyACM0","/dev/ttyACM1","/dev/ttyS0"]
    for port in candidates:
        if os.path.exists(port):
            print(f"  [+] Found serial port: {port}")
            return port
    return None

def open_serial(port, baud):
    import termios
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    baud_map = {9600:termios.B9600,19200:termios.B19200,38400:termios.B38400,57600:termios.B57600,115200:termios.B115200}
    speed = baud_map.get(baud, termios.B9600)
    attrs[4] = speed
    attrs[5] = speed
    attrs[0] = 0
    attrs[1] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    return fd

def detect_baud(port):
    print("  [*] Auto baud detection...")
    for baud in BAUD_RATES:
        print(f"  [*] Trying {baud}...")
        fd = None
        try:
            fd = open_serial(port, baud)
            import time
            time.sleep(0.5)
            data = b""
            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    chunk = os.read(fd, 64)
                    if chunk: data += chunk
                except BlockingIOError:
                    time.sleep(0.05)
            os.close(fd)
            if MSTP_PREAMBLE_1 in data and MSTP_PREAMBLE_2 in data:
                print(f"  [+] MSTP detected at {baud} baud")
                return baud
        except Exception as e:
            print(f"  [-] {baud} failed: {e}")
            if fd:
                try: os.close(fd)
                except: pass
    print("  [-] No MSTP traffic detected")
    return None

def parse_mstp_frame(data, offset):
    if offset + 8 > len(data): return None, offset + 1
    if data[offset] != MSTP_PREAMBLE_1: return None, offset + 1
    if data[offset+1] != MSTP_PREAMBLE_2: return None, offset + 1
    frame_type = data[offset+2]
    dst = data[offset+3]
    src = data[offset+4]
    length = (data[offset+5] << 8) | data[offset+6]
    payload_end = offset + 8 + length
    if payload_end > len(data): return None, offset + 1
    payload = data[offset+8:payload_end]
    frame = {
        "type_id": frame_type,
        "type_name": MSTP_FRAME_TYPES.get(frame_type, f"Unknown-0x{frame_type:02X}"),
        "dst": dst,
        "src": src,
        "length": length,
        "payload_hex": payload.hex(),
        "timestamp": datetime.now().isoformat(),
    }
    return frame, payload_end

def update_topology(topology, frame):
    src = str(frame["src"])
    dst = str(frame["dst"])
    ftype = frame["type_name"]
    ts = frame["timestamp"]
    masters = topology.setdefault("masters", {})
    slaves = topology.setdefault("slaves", {})
    if ftype in ["Token", "Poll-For-Master"]:
        if src not in masters:
            masters[src] = {"mac": int(src), "token_count": 0, "first_seen": ts, "last_seen": ts}
        masters[src]["token_count"] += 1
        masters[src]["last_seen"] = ts
    if ftype in ["BACnet-Data-Expecting-Reply", "BACnet-Data-Not-Expecting-Reply"]:
        if dst not in slaves:
            slaves[dst] = {"mac": int(dst), "response_count": 0, "first_seen": ts, "last_seen": ts}
        slaves[dst]["response_count"] += 1
        slaves[dst]["last_seen"] = ts
    topology.setdefault("frames", []).append(frame)
    return topology

def save_topology(topology):
    os.makedirs(STACK_DIR, exist_ok=True)
    with open(MSTP_FILE, "w") as f:
        json.dump(topology, f, indent=2)
    print(f"  [+] MSTP topology saved to {MSTP_FILE}")


    print(chr(10) + chr(32)*2 + chr(91) + chr(87) + chr(82) + chr(65) + chr(73) + chr(84) + chr(72) + chr(93) + chr(32) + chr(66) + chr(65) + chr(67) + chr(110) + chr(101) + chr(116) + chr(32) + chr(77) + chr(83) + chr(84) + chr(80) + chr(32) + chr(80) + chr(97) + chr(115) + chr(115) + chr(105) + chr(118) + chr(101) + chr(32) + chr(76) + chr(105) + chr(115) + chr(116) + chr(101) + chr(110) + chr(101) + chr(114))
    port = find_serial_port()
    if not port:
        print("  [-] No serial port found. Connect USB-RS485.")
        return
    baud = detect_baud(port)
    if not baud:
        print("  [-] Baud detect failed. Check wiring.")
        return
    topology = {"port": port, "baud": baud, "masters": {}, "slaves": {}, "frames": []}
    print("  [+] Listening on " + port + " at " + str(baud) + " baud for " + str(duration) + "s...")
    print("  [*] Ctrl+C to stop early")
    fd = open_serial(port, baud)
    buf = b""
    deadline = time.time() + duration
    frame_count = 0
    try:
        while time.time() < deadline:
            try:
                chunk = os.read(fd, 256)
                if chunk: buf += chunk
            except BlockingIOError:
                time.sleep(0.01)
            offset = 0
            while offset < len(buf) - 8:
                frame, offset = parse_mstp_frame(buf, offset)
                if frame:
                    frame_count += 1
                    topology = update_topology(topology, frame)
                    ts = frame["timestamp"][11:19]
                    tn = frame["type_name"]
                    sr = frame["src"]
                    ds = frame["dst"]
                    print("  [" + ts + "] " + tn + " src=" + str(sr) + " dst=" + str(ds))
            buf = buf[offset:]
    except KeyboardInterrupt:
        print(chr(32)*2 + chr(91) + chr(42) + chr(93) + chr(32) + chr(67) + chr(97) + chr(112) + chr(116) + chr(117) + chr(114) + chr(101) + chr(32) + chr(115) + chr(116) + chr(111) + chr(112) + chr(112) + chr(101) + chr(100))
    finally:
        os.close(fd)
    print(chr(10) + chr(32)*2 + chr(91) + chr(43) + chr(93) + chr(32) + chr(67) + chr(97) + chr(112) + chr(116) + chr(117) + chr(114) + chr(101) + chr(100) + chr(32) + str(frame_count) + chr(32) + chr(102) + chr(114) + chr(97) + chr(109) + chr(101) + chr(115))
    _print_summary(topology)
    save_topology(topology)

def _print_summary(topology):
    print(chr(10) + '=== MSTP TOPOLOGY SUMMARY ==="')
    masters = topology.get("masters", {})
    slaves = topology.get("slaves", {})
    print("  Masters: " + str(len(masters)))
    for mac, info in masters.items():
        print("    MAC " + str(mac) + "  tokens=" + str(info["token_count"]))
    print("  Slaves: " + str(len(slaves)))
    for mac, info in slaves.items():
        print("    MAC " + str(mac) + "  responses=" + str(info["response_count"]))
    print("  Baud: " + str(topology.get("baud")))
    print("  Port: " + str(topology.get("port")))
    print("  Frames: " + str(len(topology.get("frames", []))))
    print("  ==============================")

def run_mstp(duration=60):
    port = find_serial_port()
    if not port:
        print("  [-] No serial port found. Connect USB-RS485.")
        return
    baud = detect_baud(port)
    if not baud:
        print("  [-] Baud detect failed. Check wiring.")
        return
    print("  [+] Listening on " + port + " at " + str(baud) + " baud for " + str(duration) + "s...")
    print("  [*] Ctrl+C to stop early")
    topology = {"port": port, "baud": baud, "masters": {}, "slaves": {}, "frames": []}
    fd = open_serial(port, baud)
    buf = b""
    deadline = time.time() + duration
    frame_count = 0
    try:
        while time.time() < deadline:
            try:
                chunk = os.read(fd, 256)
                if chunk: buf += chunk
            except BlockingIOError:
                time.sleep(0.01)
            offset = 0
            while offset < len(buf) - 8:
                frame, offset = parse_mstp_frame(buf, offset)
                if frame:
                    frame_count += 1
                    topology = update_topology(topology, frame)
                    ts = frame["timestamp"][11:19]
                    tn = frame["type_name"]
                    print(chr(32)*2 + chr(91) + ts + chr(93) + chr(32) + tn + chr(32) + chr(115) + chr(114) + chr(99) + chr(61) + str(frame[chr(34) + chr(115) + chr(114) + chr(99) + chr(34)]) + chr(32) + chr(100) + chr(115) + chr(116) + chr(61) + str(frame[chr(34) + chr(100) + chr(115) + chr(116) + chr(34)]))
            buf = buf[offset:]
    except KeyboardInterrupt:
        print("  [*] Capture stopped")
    finally:
        os.close(fd)
    print("  [+] Captured " + str(frame_count) + " frames")
    _print_summary(topology)
    save_topology(topology)
