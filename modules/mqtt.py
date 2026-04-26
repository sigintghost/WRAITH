# WRAITH mqtt.py — MQTT passive listener
# port 1883 — IoT, BAS messaging, sensor networks
# sig.int.ghost
# topics reveal architecture. payloads reveal state.

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

# MQTT packet types
PACKET_TYPES = {
    1:  'CONNECT',
    2:  'CONNACK',
    3:  'PUBLISH',
    4:  'PUBACK',
    5:  'PUBREC',
    6:  'PUBREL',
    7:  'PUBCOMP',
    8:  'SUBSCRIBE',
    9:  'SUBACK',
    10: 'UNSUBSCRIBE',
    11: 'UNSUBACK',
    12: 'PINGREQ',
    13: 'PINGRESP',
    14: 'DISCONNECT',
}

# CONNACK return codes
CONNACK_CODES = {
    0: 'Connection Accepted',
    1: 'Refused — Bad Protocol',
    2: 'Refused — Client ID Rejected',
    3: 'Refused — Server Unavailable',
    4: 'Refused — Bad Credentials',
    5: 'Refused — Not Authorized',
}

mqtt_inventory = {}
mqtt_topics    = {}

def decode_remaining_length(data, offset):
    multiplier = 1
    value = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) * multiplier
        multiplier *= 128
        if not (byte & 0x80):
            break
    return value, offset

def parse_mqtt(data, src_ip, src_port):
    try:
        if len(data) < 2:
            return None
        ptype = (data[0] >> 4) & 0x0F
        flags  = data[0] & 0x0F
        if ptype not in PACKET_TYPES:
            return None
        rem_len, offset = decode_remaining_length(data, 1)
        result = {
            'src_ip':   src_ip,
            'src_port': src_port,
            'type':     ptype,
            'type_name': PACKET_TYPES[ptype],
        }
        if ptype == 1 and offset + 6 < len(data):
            proto_len = (data[offset] << 8) | data[offset+1]
            offset += 2
            proto = bytes(data[offset:offset+proto_len]).decode('utf-8','ignore')
            offset += proto_len
            proto_ver = data[offset]; offset += 1
            conn_flags = data[offset]; offset += 1
            keepalive = (data[offset] << 8) | data[offset+1]; offset += 2
            client_id = ''
            if offset + 2 < len(data):
                cid_len = (data[offset] << 8) | data[offset+1]
                offset += 2
                client_id = bytes(data[offset:offset+cid_len]).decode('utf-8','ignore')
            result['protocol']  = proto
            result['version']   = proto_ver
            result['client_id'] = client_id
            result['keepalive'] = keepalive
            result['clean']     = bool(conn_flags & 0x02)
            result['has_user']  = bool(conn_flags & 0x80)
            result['has_pass']  = bool(conn_flags & 0x40)
        elif ptype == 2 and offset + 1 < len(data):
            result['session_present'] = bool(data[offset] & 0x01)
            result['return_code'] = data[offset+1]
            result['return_msg']  = CONNACK_CODES.get(data[offset+1], 'unknown')
        elif ptype == 3:
            if offset + 2 < len(data):
                topic_len = (data[offset] << 8) | data[offset+1]
                offset += 2
                topic = bytes(data[offset:offset+topic_len]).decode('utf-8','ignore')
                offset += topic_len
                if flags & 0x06:
                    offset += 2
                payload = bytes(data[offset:]).decode('utf-8','ignore')
                result['topic']   = topic
                result['payload'] = payload[:200]
                result['qos']     = (flags >> 1) & 0x03
                result['retain']  = bool(flags & 0x01)
        elif ptype == 8:
            offset += 2
            topics = []
            while offset + 2 < len(data):
                tlen = (data[offset] << 8) | data[offset+1]
                offset += 2
                topic = bytes(data[offset:offset+tlen]).decode('utf-8','ignore')
                offset += tlen + 1
                topics.append(topic)
            result['topics'] = topics
        return result
    except Exception:
        return None

def update_mqtt_inventory(parsed):
    ts  = datetime.datetime.now().strftime('%H:%M:%S')
    ip  = parsed['src_ip']
    ptype = parsed['type_name']
    if ip not in mqtt_inventory:
        mqtt_inventory[ip] = {
            'ip':           ip,
            'first_seen':   ts,
            'last_seen':    ts,
            'packet_count': 1,
            'client_ids':   set(),
            'topics_seen':  set(),
            'publishes':    0,
            'subscribes':   0,
            'has_auth':     False,
        }
        print(f'\n{GREEN}NEW{RESET} {CYAN}{BOLD}[MQTT]{RESET} {BOLD}{ip}{RESET}')
    else:
        mqtt_inventory[ip]['last_seen']     = ts
        mqtt_inventory[ip]['packet_count'] += 1
    dev = mqtt_inventory[ip]
    if ptype == 'CONNECT':
        cid = parsed.get('client_id','')
        if cid: dev['client_ids'].add(cid)
        if parsed.get('has_user'): dev['has_auth'] = True
        print(f'  {CYAN}[CONNECT]{RESET} {ip} id={YELLOW}{cid}{RESET}')
        if parsed.get('has_user'):
            print(f'  {YELLOW}[AUTH]{RESET} {ip} credentials present')
    elif ptype == 'CONNACK':
        code = parsed.get('return_code',0)
        msg  = parsed.get('return_msg','')
        color = GREEN if code == 0 else RED
        print(f'  {color}[CONNACK]{RESET} {ip} {msg}')
    elif ptype == 'PUBLISH':
        topic   = parsed.get('topic','')
        payload = parsed.get('payload','')
        qos     = parsed.get('qos',0)
        dev['publishes'] += 1
        dev['topics_seen'].add(topic)
        if topic not in mqtt_topics:
            mqtt_topics[topic] = {'count':0,'last_payload':'','publishers':set()}
        mqtt_topics[topic]['count'] += 1
        mqtt_topics[topic]['last_payload'] = payload[:100]
        mqtt_topics[topic]['publishers'].add(ip)
        print(f'  {GREEN}[PUBLISH]{RESET} {ip} topic={YELLOW}{topic}{RESET} qos={qos}')
        if payload:
            print(f'    {DIM}payload: {payload[:80]}{RESET}')
    elif ptype == 'SUBSCRIBE':
        topics = parsed.get('topics',[])
        dev['subscribes'] += 1
        for t in topics:
            dev['topics_seen'].add(t)
        print(f'  {CYAN}[SUBSCRIBE]{RESET} {ip} topics={YELLOW}{topics}{RESET}')
    elif ptype in ('PINGREQ','PINGRESP'):
        print(f'  {DIM}[PING]{RESET} {ip}')
    elif ptype == 'DISCONNECT':
        print(f'  {RED}[DISCONNECT]{RESET} {ip}')

def print_mqtt_inventory():
    print(f'\n{CYAN}{BOLD}  MQTT BROKER INVENTORY{RESET}')
    print(f'  {DIM}' + chr(8212)*50 + f'{RESET}')
    if not mqtt_inventory:
        print(f'  {RED}no devices discovered yet{RESET}')
    for ip, dev in sorted(mqtt_inventory.items()):
        print(f'\n  {CYAN}{BOLD}{ip}{RESET}')
        print(f'  {DIM}packets    :{RESET} {dev["packet_count"]}')
        print(f'  {DIM}last seen  :{RESET} {dev["last_seen"]}')
        print(f'  {DIM}publishes  :{RESET} {dev["publishes"]}')
        print(f'  {DIM}subscribes :{RESET} {dev["subscribes"]}')
        if dev['client_ids']:
            ids = ', '.join(dev['client_ids'])
            print(f'  {DIM}client ids :{RESET} {ids}')
        if dev['has_auth']:
            print(f'  {YELLOW}auth credentials observed{RESET}')
        if dev['topics_seen']:
            print(f'  {DIM}topics     :{RESET}')
            for t in list(dev['topics_seen'])[:8]:
                print(f'    {GREEN}{t}{RESET}')
    if mqtt_topics:
        print(f'\n{CYAN}{BOLD}  MQTT TOPIC MAP{RESET}')
        print(f'  {DIM}' + chr(8212)*50 + f'{RESET}')
        for topic, info in sorted(mqtt_topics.items()):
            print(f'  {YELLOW}{topic}{RESET} — {info["count"]} msgs')
            if info['last_payload']:
                print(f'    {DIM}last: {info["last_payload"][:60]}{RESET}')

def run_mqtt():
    print(f'\n  {CYAN}{BOLD}[MQTT]{RESET} passive listener on port 1883')
    print(f'  {DIM}listening for MQTT broker traffic...{RESET}')
    print(f'  {DIM}press Ctrl+C to stop and show inventory{RESET}\n')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', 1883))
        sock.listen(10)
        sock.settimeout(1.0)
    except Exception as e:
        print(f'  {RED}[MQTT] socket error: {e}{RESET}')
        return
    from modules.logger import log_result
    def handle_client(conn, addr):
        conn.settimeout(5.0)
        try:
            while True:
                data = conn.recv(512)
                if not data: break
                parsed = parse_mqtt(list(data), addr[0], addr[1])
                if parsed:
                    update_mqtt_inventory(parsed)
                    log_result(addr[0], 'MQTT', parsed['type_name'])
        except: pass
        finally: conn.close()
    try:
        while True:
            try:
                conn, addr = sock.accept()
                t = threading.Thread(target=handle_client, args=(conn,addr))
                t.daemon = True
                t.start()
            except socket.timeout: continue
    except KeyboardInterrupt: pass
    finally:
        sock.close()
        print_mqtt_inventory()
        try:
            import sys; sys.path.insert(0,'.')
            from modules.filestack import write_mqtt
            from modules.mqtt import mqtt_inventory, mqtt_topics
            write_mqtt(mqtt_inventory, mqtt_topics)
            print(f"  stack written: mqtt_brokers.json")
        except Exception as e:
            pass
