# WRAITH bacnet.py — BACnet passive intelligence module
# BACnet/IP — BACnet/MSTP — BACnet/ARCnet
# sig.int.ghost
# the wire speaks BACnet. WRAITH listens.
# instance is identity. network is territory.

import socket
import struct
import threading
import datetime
import os
import sys

# BACnet vendor ID table — partial, most common in field
VENDORS = {
    0:   "ASHRAE",
    1:   "NIST",
    2:   "The Trane Company",
    4:   "PolarSoft",
    5:   "Johnson Controls",
    7:   "Siemens",
    8:   "Honeywell",
    10:  "Automated Logic",
    24:  "Automated Logic",
    26:  "Delta Controls",
    27:  "Distech Controls",
    86: "Carrier",
    105: "Alerton",
    135: "KMC Controls",
    185: "Reliable Controls",
    260: "Schneider Electric",
    295: "Carel",
    400: "Daikin",
    999: "Generic/Unknown",
}

# BACnet service choice codes
SERVICES = {
    0:  "acknowledgeAlarm",
    1:  "confirmedCOVNotification",
    2:  "confirmedEventNotification",
    3:  "getAlarmSummary",
    4:  "getEnrollmentSummary",
    5:  "subscribeCOV",
    6:  "atomicReadFile",
    7:  "atomicWriteFile",
    8:  "addListElement",
    9:  "removeListElement",
    10: "createObject",
    11: "deleteObject",
    12: "readProperty",
    14: "readPropertyMultiple",
    15: "writeProperty",
    16: "writePropertyMultiple",
    17: "deviceCommunicationControl",
    18: "confirmedPrivateTransfer",
    19: "confirmedTextMessage",
    20: "reinitializeDevice",
    26: "whoHas",
    27: "whoIs",
    28: "readRange",
}

# MSTP baud rates to try for auto-detect
MSTP_BAUDS = [9600, 19200, 38400, 57600, 76800, 115200]

# Device inventory — keyed by device instance
inventory = {}

# ANSI colors
GREEN  = '\033[32m'
CYAN   = '\033[36m'
YELLOW = '\033[33m'
RED    = '\033[31m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

def get_vendor(vid):
    return VENDORS.get(vid, f"vendor_{vid}")

def parse_whois(data):
    # BACnet Who-Is — unconfirmed service request
    # returns range or global broadcast
    try:
        if len(data) >= 4:
            low  = data[2] if len(data) > 2 else 0
            high = data[3] if len(data) > 3 else 4194303
            return {'type': 'whoIs', 'low': low, 'high': high}
    except:
        pass
    return {'type': 'whoIs', 'low': 0, 'high': 4194303}

def parse_iam(data):
    # BACnet I-Am response
    # device instance, max apdu, segmentation, vendor id
    try:
        idx = 0
        # skip BVLC header (4 bytes) + NPDU (varies)
        # look for I-Am tag structure
        device_id = None
        vendor_id = None
        max_apdu  = None

        i = 0
        while i < len(data) - 3:
            # device object identifier tag
            if data[i] == 0xC4 and i + 4 < len(data):
                raw = struct.unpack('>I', bytes(data[i+1:i+5]))[0]
                device_id = raw & 0x3FFFFF
                i += 5
                continue
            # max apdu length tag
            if data[i] == 0x22 and i + 2 < len(data):
                max_apdu = struct.unpack('>H', bytes(data[i+1:i+3]))[0]
                i += 3
                continue
            # vendor id tag
            if data[i] == 0x91 and i + 1 < len(data):
                vendor_id = data[i+1]
                i += 2
                continue
            if data[i] == 0x21 and i + 1 < len(data):
                vendor_id = data[i+1]
                i += 2
                continue
            i += 1

        if device_id is not None:
            return {
                'type':      'iAm',
                'device_id': device_id,
                'vendor_id': vendor_id or 999,
                'vendor':    get_vendor(vendor_id or 999),
                'max_apdu':  max_apdu or 0,
            }
    except Exception as e:
        pass
    return None

def parse_bacnet_packet(data, src_ip):
    try:
        if len(data) < 6:
            return None
        # BVLC check — BACnet/IP always starts with 0x81
        if data[0] != 0x81:
            return None
        bvlc_func = data[1]
        # NPDU starts at byte 4
        npdu_ver  = data[4]
        npdu_ctrl = data[5]
        apdu_start = 6
        # if NPDU has destination network info skip it
        if npdu_ctrl & 0x20:
            apdu_start += 5
        if apdu_start >= len(data):
            return None
        apdu_type = (data[apdu_start] >> 4) & 0x0F
        # unconfirmed request = type 1
        if apdu_type == 1:
            service = data[apdu_start + 1]
            payload = data[apdu_start + 2:]
            if service == 27:  # Who-Is
                return parse_whois(payload)
            if service == 8:   # I-Am (unconfirmed = 8 in some stacks)
                return parse_iam(data)
        # I-Am is unconfirmed service 0
        if apdu_type == 1 and data[apdu_start+1] == 0:
            return parse_iam(data)
    except:
        pass
    return None

def display_device(ip, info, new=False):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    tag = f"{GREEN}NEW{RESET} " if new else "    "
    vid = info.get('vendor_id', 999)
    vendor = info.get('vendor', 'unknown')
    dev_id = info.get('device_id', '?')
    count = info.get('packet_count', 1)
    last = info.get('last_seen', ts)
    print(f"\n{tag}{CYAN}{BOLD}[BACNET/IP]{RESET} {BOLD}{ip}{RESET}")
    print(f"      {DIM}device id  :{RESET} {YELLOW}{dev_id}{RESET}")
    print(f"      {DIM}vendor id  :{RESET} {vid} — {GREEN}{vendor}{RESET}")
    print(f"      {DIM}max apdu   :{RESET} {info.get('max_apdu', '?')}")
    print(f"      {DIM}packets    :{RESET} {count}")
    print(f"      {DIM}last seen  :{RESET} {last}")

def update_inventory(ip, parsed):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    dev_id = parsed.get('device_id')
    if dev_id is None:
        return
    is_new = dev_id not in inventory
    if is_new:
        inventory[dev_id] = {
            'ip':           ip,
            'device_id':    dev_id,
            'vendor_id':    parsed.get('vendor_id', 999),
            'vendor':       parsed.get('vendor', 'unknown'),
            'max_apdu':     parsed.get('max_apdu', 0),
            'first_seen':   ts,
            'last_seen':    ts,
            'packet_count': 1,
        }
        display_device(ip, inventory[dev_id], new=True)
    else:
        inventory[dev_id]['last_seen']    = ts
        inventory[dev_id]['packet_count'] += 1
        inventory[dev_id]['ip']            = ip

def print_inventory():
    print(f"\n{CYAN}{BOLD}  BACNET DEVICE INVENTORY{RESET}")
    print(f"  {DIM}{'─'*50}{RESET}")
    if not inventory:
        print(f"  {RED}no devices discovered yet{RESET}")
        return
    print(f"  {CYAN}{'DEVICE ID':<12} {'IP':<18} {'VENDOR':<25} {'PKTS'}{RESET}")
    print(f"  {DIM}{'─'*12} {'─'*18} {'─'*25} {'─'*6}{RESET}")
    for dev_id, info in sorted(inventory.items()):
        print(f"  {YELLOW}{dev_id:<12}{RESET} "
              f"{GREEN}{info['ip']:<18}{RESET} "
              f"{info['vendor']:<25} "
              f"{info['packet_count']}")

def run_bacnet(idle_timeout=30, max_duration=300):
    print(f"\n  {CYAN}{BOLD}[BACNET/IP]{RESET} passive listener on port 47808")
    print(f"  {DIM}listening for Who-Is and I-Am broadcasts...{RESET}")
    print(f"  {DIM}max {max_duration}s — stops after {idle_timeout}s idle{RESET}\n")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', 47808))
        sock.settimeout(1.0)
    except Exception as e:
        print(f"  {RED}[BACNET] socket error: {e}{RESET}")
        return
    from modules.core.logger import log_result
    import time
    start = datetime.datetime.now()
    deadline = time.time() + max_duration
    last_pkt = time.time()
    try:
        while time.time() < deadline:
            idle = int(time.time() - last_pkt)
            if idle >= idle_timeout:
                print(f"  {YELLOW}[BACNET]{RESET} {idle_timeout}s idle — stopping")
                break
            if idle > 0 and idle % 10 == 0:
                print(f"  {DIM}[BACNET] idle {idle}s — listening...{RESET}")
            try:
                data, addr = sock.recvfrom(1024)
                src_ip = addr[0]
                parsed = parse_bacnet_packet(list(data), src_ip)
                bbmd = parse_bbmd_packet(list(data), src_ip)
                if bbmd:
                    update_bbmd(src_ip, bbmd)
                    log_result(src_ip, "BBMD", bbmd.get('func_name','?'))
                if parsed:
                    last_pkt = time.time()
                    if parsed['type'] == 'whoIs':
                        ts = datetime.datetime.now().strftime("%H:%M:%S")
                        print(f"  {DIM}[{ts}] Who-Is from {src_ip}{RESET}")
                        log_result(src_ip, "BACNET", "whoIs broadcast")
                    elif parsed['type'] == 'iAm':
                        update_inventory(src_ip, parsed)
                        log_result(src_ip, "BACNET",
                            f"iAm device={parsed.get('device_id')} "
                            f"vendor={parsed.get('vendor')}")
            except socket.timeout:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print_inventory()
        print_bbmd_table()
        try:
            import sys; sys.path.insert(0,'.')
            from modules.core.filestack import write_bacnet
            from modules.protocols.bacnet import inventory, bbmd_table
            write_bacnet(inventory, bbmd_table)
            print(f"  stack written: bacnet_inventory.json")
        except Exception as e:
            pass

# BBMD inventory — keyed by IP
bbmd_table = {}

# BVLC function codes
BVLC_FUNCS = {
    0x00: "BVLC-Result",
    0x01: "Write-BDT",
    0x02: "Read-BDT-Request",
    0x03: "Read-BDT-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-FDT-Request",
    0x07: "Read-FDT-Ack",
    0x08: "Delete-FDT-Entry",
    0x09: "Distribute-Broadcast",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
}

def parse_bdt(data, offset):
    # BDT entry = 4 bytes IP + 4 bytes mask = 8 bytes each
    entries = []
    while offset + 8 <= len(data):
        ip   = '.'.join(str(b) for b in data[offset:offset+4])
        mask = '.'.join(str(b) for b in data[offset+4:offset+8])
        entries.append({'ip': ip, 'mask': mask})
        offset += 8
    return entries

def parse_fdt(data, offset):
    # FDT entry = 4 bytes IP + 2 bytes port + 2 bytes TTL + 2 bytes remaining
    entries = []
    while offset + 10 <= len(data):
        ip   = '.'.join(str(b) for b in data[offset:offset+4])
        port = (data[offset+4] << 8) | data[offset+5]
        ttl  = (data[offset+6] << 8) | data[offset+7]
        rem  = (data[offset+8] << 8) | data[offset+9]
        entries.append({'ip': ip, 'port': port, 'ttl': ttl, 'remaining': rem})
        offset += 10
    return entries

def parse_bbmd_packet(data, src_ip):
    if len(data) < 4:
        return None
    if data[0] != 0x81:
        return None
    func = data[1]
    length = (data[2] << 8) | data[3]

    result = {'func': func, 'func_name': BVLC_FUNCS.get(func, f"0x{func:02x}"), 'src': src_ip}

    # Forwarded-NPDU — reveals original sender and BBMD router
    if func == 0x04 and len(data) >= 10:
        orig_ip   = '.'.join(str(b) for b in data[4:8])
        orig_port = (data[8] << 8) | data[9]
        result['type']      = 'forwarded'
        result['origin_ip'] = orig_ip
        result['origin_port'] = orig_port
        return result

    # Read-BDT-Ack — full broadcast distribution table
    if func == 0x03:
        result['type'] = 'bdt'
        result['bdt']  = parse_bdt(data, 4)
        return result

    # Write-BDT
    if func == 0x01:
        result['type'] = 'bdt_write'
        result['bdt']  = parse_bdt(data, 4)
        return result

    # Read-FDT-Ack — foreign device table
    if func == 0x07:
        result['type'] = 'fdt'
        result['fdt']  = parse_fdt(data, 4)
        return result

    # Register-Foreign-Device
    if func == 0x05 and len(data) >= 6:
        ttl = (data[4] << 8) | data[5]
        result['type'] = 'foreign_register'
        result['ttl']  = ttl
        return result

    return None

def update_bbmd(src_ip, parsed):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    if src_ip not in bbmd_table:
        bbmd_table[src_ip] = {
            'ip':         src_ip,
            'first_seen': ts,
            'last_seen':  ts,
            'bdt':        [],
            'fdt':        [],
            'forwards':   [],
            'foreign_devices': [],
        }
        print(f"\n{GREEN}NEW{RESET} {CYAN}{BOLD}[BBMD]{RESET} {BOLD}{src_ip}{RESET}")
    else:
        bbmd_table[src_ip]['last_seen'] = ts

    b = bbmd_table[src_ip]
    ptype = parsed.get('type')

    if ptype in ('bdt', 'bdt_write'):
        b['bdt'] = parsed.get('bdt', [])
        print(f"  {CYAN}[BBMD]{RESET} {src_ip} BDT updated — "
              f"{len(b['bdt'])} entries")
        for entry in b['bdt']:
            print(f"    {DIM}→{RESET} {GREEN}{entry['ip']}{RESET} "
                  f"mask {entry['mask']}")

    elif ptype == 'fdt':
        b['fdt'] = parsed.get('fdt', [])
        print(f"  {CYAN}[BBMD]{RESET} {src_ip} FDT — "
              f"{len(b['fdt'])} foreign devices")
        for entry in b['fdt']:
            print(f"    {DIM}→{RESET} {YELLOW}{entry['ip']}:{entry['port']}{RESET} "
                  f"TTL {entry['ttl']}s remaining {entry['remaining']}s")

    elif ptype == 'forwarded':
        orig = parsed.get('origin_ip')
        if orig not in b['forwards']:
            b['forwards'].append(orig)
        print(f"  {DIM}[BBMD]{RESET} {src_ip} forwarded from "
              f"{YELLOW}{orig}{RESET}")

    elif ptype == 'foreign_register':
        ttl = parsed.get('ttl')
        if src_ip not in b['foreign_devices']:
            b['foreign_devices'].append(src_ip)
        print(f"  {YELLOW}[FOREIGN]{RESET} {src_ip} registered "
              f"TTL {ttl}s")

def print_bbmd_table():
    if not bbmd_table:
        return
    print(f"\n{CYAN}{BOLD}  BBMD TOPOLOGY MAP{RESET}")
    print(f"  {DIM}{'─'*50}{RESET}")
    for ip, b in bbmd_table.items():
        print(f"\n  {CYAN}{BOLD}{ip}{RESET} — BBMD")
        print(f"  {DIM}first seen : {b['first_seen']}{RESET}")
        if b['bdt']:
            print(f"  {DIM}BDT routes :{RESET}")
            for e in b['bdt']:
                print(f"    {GREEN}→ {e['ip']}{RESET} "
                      f"{DIM}mask {e['mask']}{RESET}")
        if b['fdt']:
            print(f"  {DIM}foreign devices :{RESET}")
            for e in b['fdt']:
                print(f"    {YELLOW}→ {e['ip']}:{e['port']}{RESET} "
                      f"TTL {e['ttl']}s")
        if b['forwards']:
            print(f"  {DIM}forwarded from :{RESET}")
            for f in b['forwards']:
                print(f"    {DIM}→ {f}{RESET}")
        subnets = set()
        for e in b['bdt']:
            subnets.add('.'.join(e['ip'].split('.')[:3]))
        if subnets:
            print(f"  {DIM}routes to {len(subnets)} subnet(s) :{RESET} "
                  f"{GREEN}{', '.join(sorted(subnets))}{RESET}")
