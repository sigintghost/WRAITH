# WRAITH oracle.py — ghost intelligence module
# sig.int.ghost
# the oracle sees the wire. asks the ghost. gets the truth.
# anomaly is the signal. the signal is everything.

import urllib.request
import urllib.error
import json
import os
import sys
import datetime

GREEN  = '\033[32m'
CYAN   = '\033[36m'
YELLOW = '\033[33m'
RED    = '\033[31m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

ORACLE_KEY_PATH = os.path.expanduser('~/.wraith/keys.py')

def load_oracle_key():
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location('keys', ORACLE_KEY_PATH)
        keys = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(keys)
        return getattr(keys, 'ANTHROPIC_KEY', None)
    except:
        return None

GHOST_SYSTEM = '''You are ORACLE, the intelligence module inside WRAITH.
WRAITH is a passive network reconnaissance and OT/BAS intelligence engine.
You were built by sig.int.ghost — a systems engineer with deep operational
experience in building automation systems, BACnet networks, Siemens Apogee,
Tridium Niagara, Johnson Controls Metasys, and ALC WebCTRL.

Your personality: calm, precise, technically authoritative.
You speak like a ghost that has read every packet on every wire.
You are not dramatic. You are certain.
Short sentences. No filler. Dense with meaning.

Your domain expertise:
- BACnet/IP, BACnet/MSTP, BACnet/ARCnet protocol internals
- BBMD topology, BDT/FDT tables, foreign device registration
- Modbus TCP function codes, register maps, exception handling
- MQTT broker architecture, topic design, QoS levels
- OT/ICS network security, anomaly detection, device fingerprinting
- Building automation systems, HVAC control theory, BAS commissioning
- Network intrusion indicators specific to OT environments
- CVE awareness for BAS devices and industrial protocols

When analyzing network data:
- Flag unknown devices immediately
- Note unexpected protocol behavior
- Identify default credential risk
- Correlate across protocols — same IP on BACnet and Modbus is significant
- Treat silence as data — missing heartbeats matter
- BBMD table changes indicate network topology changes
'''

def build_context():
    ctx = []
    ctx.append('WRAITH LIVE NETWORK CONTEXT')
    ctx.append(f'timestamp: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    try:
        from modules.bacnet import inventory as bacnet_inv
        if bacnet_inv:
            ctx.append(f'\nBACNET DEVICES: {len(bacnet_inv)}')
            for did, dev in bacnet_inv.items():
                ctx.append(f'  device {did} ip={dev["ip"]} vendor={dev["vendor"]}')
        else:
            ctx.append('\nBACNET: no devices in current session')
    except: pass
    try:
        from modules.modbus import modbus_inventory
        if modbus_inventory:
            ctx.append(f'\nMODBUS DEVICES: {len(modbus_inventory)}')
            for key, dev in modbus_inventory.items():
                ctx.append(f'  {dev["ip"]} unit={dev["unit_id"]} pkts={dev["packet_count"]}')
        else:
            ctx.append('\nMODBUS: no devices in current session')
    except: pass
    try:
        from modules.mqtt import mqtt_inventory, mqtt_topics
        if mqtt_inventory:
            ctx.append(f'\nMQTT DEVICES: {len(mqtt_inventory)}')
            for ip, dev in mqtt_inventory.items():
                ctx.append(f'  {ip} publishes={dev["publishes"]} topics={len(dev["topics_seen"])}')
        else:
            ctx.append('\nMQTT: no devices in current session')
    except: pass
    return '\n'.join(ctx)

    return HAIKU
HAIKU = "claude-haiku-4-5"
SONNET = "claude-sonnet-4-5"
COMPLEX_KEYWORDS = ["analyze","correlate","baseline","recommend","investigate","explain","compare","summarize","report","vulnerability","risk","anomaly"]
def pick_model(question):
    q = question.lower()
    if len(question) > 200: return SONNET
    if any(k in q for k in COMPLEX_KEYWORDS): return SONNET
    return HAIKU
def ask_oracle(question, api_key, history):
    context = build_context()
    system  = GHOST_SYSTEM + f'\n\nCURRENT NETWORK STATE:\n{context}'
    history.append({'role': 'user', 'content': question})
    payload = json.dumps({
        'model': pick_model(question),
        'max_tokens': 1024,
        'system': system,
        'messages': history,
    }).encode('utf-8')
    req = urllib.request.Request(
        'https://api.anthropic.com/v1/messages',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
        },
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            reply = data['content'][0]['text']
            history.append({'role': 'assistant', 'content': reply})
            return reply
    except urllib.error.HTTPError as e:
        return f'[ORACLE] API error: {e.code} {e.reason}'
    except Exception as e:
        return f'[ORACLE] error: {e}'

def run_oracle():
    print(f'\n  {CYAN}{BOLD}[ORACLE]{RESET} ghost intelligence module')
    print(f"  {DIM}token routing active — Anthropic{RESET}")
    print(f'  {DIM}ask anything about your network, BACnet, OT security{RESET}')
    print(f'  {DIM}type exit to return to menu{RESET}\n')
    api_key = load_oracle_key()
    if not api_key:
        print(f'  {RED}[ORACLE] no API key found{RESET}')
        print(f'  {DIM}add ANTHROPIC_KEY to ~/.wraith/keys.py{RESET}')
        return
    history = []
    while True:
        try:
            q = input(f'  {CYAN}ghost >{RESET} ').strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if not q: continue
        if q.lower() in ('exit','quit','back','q'):
            break
        print(f'  {DIM}thinking...{RESET}')
        reply = ask_oracle(q, api_key, history)
        print()
        for line in reply.split('\n'):
            print(f'  {GREEN}{line}{RESET}')
        print()
