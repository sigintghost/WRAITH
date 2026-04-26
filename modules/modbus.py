# WRAITH modbus.py — Modbus TCP passive listener
# port 502 — industrial equipment and BAS integration
# sig.int.ghost
# registers don't lie. read the state directly.

import socket
import struct
import datetime
import threading

GREEN  = '\033[32m'
CYAN   = '\033[36m'
YELLOW = '\033[33m'
RED    = '\033[31m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

FUNC_CODES = {
    0x01: 'Read Coils',
    0x02: 'Read Discrete Inputs',
    0x03: 'Read Holding Registers',
    0x04: 'Read Input Registers',
    0x05: 'Write Single Coil',
    0x06: 'Write Single Register',
    0x0F: 'Write Multiple Coils',
    0x10: 'Write Multiple Registers',
    0x2B: 'Read Device Identification',
}

EXCEPTIONS = {
    0x01: 'Illegal Function',
    0x02: 'Illegal Data Address',
    0x03: 'Illegal Data Value',
    0x04: 'Server Device Failure',
    0x06: 'Server Device Busy',
    0x0A: 'Gateway Path Unavailable',
    0x0B: 'Gateway Target Device Failed',
}

modbus_inventory = {}

def parse_modbus(data, src_ip, src_port):
    try:
        if len(data) < 8:
            return None
        trans_id  = (data[0] << 8) | data[1]
        proto_id  = (data[2] << 8) | data[3]
        length    = (data[4] << 8) | data[5]
        unit_id   = data[6]
        func_code = data[7]
        if proto_id != 0:
            return None
        result = {
            'src_ip':    src_ip,
            'src_port':  src_port,
            'unit_id':   unit_id,
            'func_code': func_code,
            'func_name': FUNC_CODES.get(func_code & 0x7F, f'func_{func_code:02x}'),
            'trans_id':  trans_id,
            'exception': False,
        }
        if func_code & 0x80:
            exc = data[8] if len(data) > 8 else 0
            result['exception']      = True
            result['exception_code'] = exc
            result['exception_name'] = EXCEPTIONS.get(exc, f'exc_{exc}')
            return result
        if func_code in (0x01,0x02,0x03,0x04) and len(data) >= 12:
            result['reg_addr']  = (data[8] << 8) | data[9]
            result['reg_count'] = (data[10] << 8) | data[11]
            result['type']      = 'request'
        elif func_code in (0x03,0x04) and len(data) >= 9:
            byte_count = data[8]
            values = []
            for i in range(9, 9 + byte_count - 1, 2):
                if i + 1 < len(data):
                    values.append((data[i] << 8) | data[i+1])
            result['values'] = values
            result['type']   = 'response'
        elif func_code == 0x06 and len(data) >= 12:
            result['reg_addr'] = (data[8] << 8) | data[9]
            result['value']    = (data[10] << 8) | data[11]
            result['type']     = 'write'
        return result
    except Exception:
        return None

def update_modbus_inventory(parsed):
    ts  = datetime.datetime.now().strftime('%H:%M:%S')
    ip  = parsed['src_ip']
    uid = parsed['unit_id']
    key = f'{ip}:{uid}'
    is_new = key not in modbus_inventory
    if is_new:
        modbus_inventory[key] = {
            'ip':           ip,
            'unit_id':      uid,
            'first_seen':   ts,
            'last_seen':    ts,
            'packet_count': 1,
            'func_codes':   set(),
            'registers':    {},
            'exceptions':   [],
            'writes':       [],
        }
        print(f'\n{GREEN}NEW{RESET} {CYAN}{BOLD}[MODBUS]{RESET} {BOLD}{ip}{RESET} unit {YELLOW}{uid}{RESET}')
    else:
        modbus_inventory[key]['last_seen']     = ts
        modbus_inventory[key]['packet_count'] += 1
    dev = modbus_inventory[key]
    fc  = parsed['func_code'] & 0x7F
    dev['func_codes'].add(fc)
    if parsed.get('exception'):
        exc = parsed.get('exception_name', '?')
        dev['exceptions'].append(exc)
        print(f'  {RED}[EXCEPTION]{RESET} {ip} unit {uid} {exc}')
    elif parsed.get('type') == 'write':
        reg = parsed.get('reg_addr', '?')
        val = parsed.get('value', '?')
        dev['writes'].append({'reg': reg, 'val': val, 'ts': ts})
        print(f'  {YELLOW}[WRITE]{RESET} {ip} unit {uid} reg {reg} = {val}')
    elif parsed.get('type') == 'response' and parsed.get('values'):
        reg  = parsed.get('reg_addr', 0)
        vals = parsed.get('values', [])
        for i, v in enumerate(vals[:4]):
            dev['registers'][reg + i] = v
        print(f'  {DIM}[MODBUS]{RESET} {ip} unit {uid} reg {reg} -> {vals[:4]}')

def print_modbus_inventory():
    if not modbus_inventory:
        print(f'\n\033[36m\033[1m  MODBUS DEVICE INVENTORY\033[0m')
        print(f'  \033[2m' + chr(8212)*50 + '\033[0m')
        print(f'  \033[31mno devices discovered yet\033[0m')
        return
    print(f'\n{CYAN}{BOLD}  MODBUS DEVICE INVENTORY{RESET}')
    print(f'  {DIM}{chr(8212)*50}{RESET}')
    for key, dev in sorted(modbus_inventory.items()):
        funcs = [FUNC_CODES.get(f, str(f)) for f in dev['func_codes']]
        ip=dev['ip']; uid=dev['unit_id']; print(f'\n  {CYAN}{BOLD}{ip}{RESET} unit {YELLOW}{uid}{RESET}')
        print(f'  {DIM}packets   :{RESET} {dev["packet_count"]}')
        print(f'  {DIM}last seen :{RESET} {dev["last_seen"]}')
        print(f'  {DIM}functions :{RESET} {", ".join(funcs)}')
        if dev['registers']:
            print(f'  {DIM}registers :{RESET}')
            for reg, val in sorted(dev['registers'].items())[:8]:
                print(f'    {DIM}[{reg:05d}]{RESET} {GREEN}{val}{RESET}')
        if dev['writes']:
            print(f'  {YELLOW}writes: {len(dev["writes"])}{RESET}')
        if dev['exceptions']:
            print(f'  {RED}exceptions: {", ".join(dev["exceptions"])}{RESET}')

def run_modbus():
    print(f'\n  {CYAN}{BOLD}[MODBUS]{RESET} passive listener on port 502')
    print(f'  {DIM}listening for Modbus TCP traffic...{RESET}')
    print(f'  {DIM}press Ctrl+C to stop and show inventory{RESET}\n')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', 502))
        sock.listen(10)
        sock.settimeout(1.0)
    except Exception as e:
        print(f'  {RED}[MODBUS] socket error: {e}{RESET}')
        print(f'  {DIM}port 502 requires root on Linux{RESET}')
        return
    from modules.logger import log_result
    def handle_client(conn, addr):
        conn.settimeout(5.0)
        try:
            while True:
                data = conn.recv(256)
                if not data:
                    break
                parsed = parse_modbus(list(data), addr[0], addr[1])
                if parsed:
                    update_modbus_inventory(parsed)
                    log_result(addr[0], 'MODBUS',
                        f'unit={parsed["unit_id"]} func={parsed["func_name"]}')
        except:
            pass
        finally:
            conn.close()
    try:
        while True:
            try:
                conn, addr = sock.accept()
                t = threading.Thread(target=handle_client, args=(conn, addr))
                t.daemon = True
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print_modbus_inventory()
        try:
            import sys; sys.path.insert(0,'.')
            from modules.filestack import write_modbus
            from modules.modbus import modbus_inventory
            write_modbus(modbus_inventory)
            print(f"  stack written: modbus_map.json")
        except Exception as e:
            pass
