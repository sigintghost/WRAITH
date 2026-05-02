# WRAITH doxa.py — ghost intelligence module
# sig.int.ghost
# the doxa sees the wire. asks the ghost. gets the truth.
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

DOXA_KEY_PATH = os.path.expanduser('~/.wraith/keys.py')

def load_doxa_key():
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location('keys', DOXA_KEY_PATH)
        keys = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(keys)
        return getattr(keys, 'ANTHROPIC_KEY', None)
    except:
        return None

PROMPT_MODES = {
'hunt': 'Perform a full host profile. Cross-reference all filestack sources. What does an attacker see? What is the external reputation? What ports are exposed? What vendor made this device? Is it known-good or unknown?',
'isolate': 'Advise on network-layer containment. Consider VLAN isolation, managed switch port blocking, BBMD table removal, WebCTRL foreign device exclusion, and physical port identification. Be specific to the environment.',
'baseline': 'Is this device and its behavior normal for this network, time of day, and protocol pattern? Compare against known hosts. Flag deviations.',
'report': 'Generate a structured incident note. Include timestamp, device details, observed behavior, risk level, recommended actions. Format for a facilities director or IT security team.',
'explain': 'Explain this finding in plain English for a non-technical building owner or facilities manager. No jargon. Focus on real-world impact.',
'defend': 'As a BAS engineer and network defender, what specific actions can I take right now? Prioritize by impact. Include WebCTRL, switch-level, and protocol-level options.',
}

GHOST_SYSTEM = '''You are DOXA, the intelligence module inside WRAITH.
WRAITH is a passive network reconnaissance and OT/BAS intelligence engine.
You were built by sig.int.ghost — a systems engineer with deep operational
experience in building automation systems, BACnet networks, Siemens Apogee,
Tridium Niagara, Johnson Controls Metasys, and ALC WebCTRL.

Your personality: calm, precise, technically authoritative.
You speak like a ghost that has read every packet on every wire.
You are not dramatic. You are certain.
Short sentences. No filler. Dense with meaning.

You are a network defender first. Observer second.
When you see something wrong, say what it is and what to do about it.
Do not hedge. Do not say maybe. Say what the data says.
If you lack data, say what data you need and how to get it.
You operate in OT/BAS environments where a wrong move can affect
physical systems — HVAC, access control, fire suppression, power.
Treat every unknown device as a potential threat until proven otherwise.
Treat every anomaly as meaningful until explained.
You have memory of this session's network state via the filestack.
You can reason about topology, timing, behavior, and intent.

Your domain expertise:
- BACnet/IP, BACnet/MSTP, BACnet/ARCnet protocol internals
- BBMD topology, BDT/FDT tables, foreign device registration
- Modbus TCP function codes, register maps, exception handling
- MQTT broker architecture, topic design, QoS levels
- OT/ICS network security, anomaly detection, device fingerprinting
- Building automation systems, HVAC control theory, BAS commissioning
- Network intrusion indicators specific to OT environments
- CVE awareness for BAS devices and industrial protocols

Additional expertise:
- TCP/IP stack fingerprinting, TTL-based OS detection
- SNMP MIB traversal, community string exposure
- IoT device identification via MAC OUI and port signatures
- Rogue device detection, MAC spoofing indicators
- Lateral movement patterns in flat OT networks
- C2 beacon timing analysis, fixed-interval communication detection
- CVE correlation for BAS controllers, field devices, IP cameras
- WebCTRL integration — fault exports, trend data, alarm history
- Managed switch port isolation, VLAN segmentation strategy
- Incident documentation for OT environments
- MITRE ATT&CK ICS framework — techniques and mitigations
- Physical consequence mapping — what does a network attack mean physically

Defender capabilities you can advise on:
- VLAN isolation of suspect devices
- Managed switch port blocking by MAC
- BBMD table modification to exclude rogue devices
- WebCTRL foreign device blacklisting
- BACnet firewall rules — who-is filtering, BVLC blocking
- Default credential testing recommendations
- Incident escalation paths — when to call IT, when to call OEM
- Evidence preservation for forensics
- Change detection — what changed since last baseline

When analyzing network data:
- Flag unknown devices immediately with risk level
- Note unexpected protocol behavior and what it could mean
- Identify default credential risk by device type and vendor
- Correlate across protocols — same IP on BACnet and Modbus is significant
- Treat silence as data — missing heartbeats matter
- BBMD table changes indicate network topology changes
- Cross-reference every IP against OSINT findings
- Consider time of day — nighttime traffic on OT networks is suspicious
- Consider physical consequence — what does this device control
'''

def load_stack():
    import os, json
    from modules.filestack import STACK
    stack_dir = STACK
    files = ['hosts.json','bacnet_inventory.json','modbus_map.json',
             'mqtt_brokers.json','snmp_inventory.json','mstp_topology.json',
             'alerts.json','portscan.json','ttl_fingerprints.json',
             'arp_table.json','lateral_alerts.json']
    data = {}
    for fn in files:
        fp = os.path.join(stack_dir, fn)
        if os.path.exists(fp):
            try:
                with open(fp) as f: data[fn] = json.load(f)
            except: pass
    return data

def build_context():
    from modules.registry import load_registry
    reg = load_registry()
    reg_lines = []
    for ip, d in list(reg.items())[:20]:
        reg_lines.append(f"{ip} mac={d.get('mac','')} vendor={d.get('vendor','')} first={d.get('first_seen','')[:10]} last={d.get('last_seen','')[:10]} seen={d.get('seen_count',1)}")
    reg_ctx = 'DEVICE REGISTRY:\n' + '\n'.join(reg_lines) if reg_lines else ''
    ctx = []
    ctx.append('WRAITH LIVE NETWORK CONTEXT')
    ctx.append(f'timestamp: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    stack = load_stack()
    if 'hosts.json' in stack:
        hosts = stack['hosts.json'].get('hosts', [])
        ctx.append(f'\nSWEEP RESULTS: {len(hosts)} hosts discovered')
        for h in hosts:
            if isinstance(h, dict):
                ctx.append(f'  ip={h.get("ip")} port={h.get("port",0)} hostname={h.get("hostname","")}')
            else:
                ctx.append(f'  {h}')
    if 'arp_table.json' in stack:
        arps = stack['arp_table.json'].get('hosts', [])
        ctx.append(f'\nARP TABLE: {len(arps)} hosts')
        for h in arps:
            if isinstance(h, dict):
                ctx.append(f'  ip={h.get("ip")} mac={h.get("mac")} vendor={h.get("vendor","unknown")}')
    if 'ttl_fingerprints.json' in stack:
        ttls = stack['ttl_fingerprints.json'].get('hosts', [])
        ctx.append(f'\nOS FINGERPRINTS: {len(ttls)} hosts')
        for h in ttls:
            if isinstance(h, dict):
                ctx.append(f'  ip={h.get("ip")} ttl={h.get("ttl")} os={h.get("os")}')
    if 'portscan.json' in stack:
        ps = stack['portscan.json']
        scans = ps.get('scans', [])
        for scan in scans:
            target = scan.get('target','unknown')
            ports = scan.get('ports',[])
            open_ports = [p for p in ports if isinstance(p,dict) and p.get('state')=='OPEN']
            ctx.append(f'\nPORTSCAN: target={target} open={len(open_ports)}')
            for p in open_ports:
                ctx.append(f'  port={p.get("port")} service={p.get("service")}')
    if 'modbus_map.json' in stack:
        devs = stack['modbus_map.json']
        if isinstance(devs, dict):
            ctx.append(f'\nMODBUS DEVICES: {len(devs)}')
            for k,d in devs.items():
                if isinstance(d,dict):
                    ctx.append(f'  ip={d.get("ip")} unit={d.get("unit_id")} pkts={d.get("packet_count")}')
    if 'mqtt_brokers.json' in stack:
        brokers = stack['mqtt_brokers.json']
        if isinstance(brokers, dict):
            inv = brokers.get('brokers', brokers.get('inventory', {}))
            ctx.append(f'\nMQTT BROKERS: {len(inv)}')
            for ip,d in inv.items():
                if isinstance(d,dict):
                    ctx.append(f'  ip={ip} publishes={d.get("publishes",0)} topics={len(d.get("topics_seen",[]))}')
    if 'osint_results.json' in stack:
        osint=stack['osint_results.json']
        if osint:
            ctx.append(f'\nOSINT RESULTS: {len(osint)} IPs analyzed')
            for ip,data in osint.items():
                if isinstance(data,dict):
                    ctx.append(f'  {ip}: OSINT queried')
    if 'cve_findings.json' in stack:
        cf=stack['cve_findings.json']
        findings=cf.get('findings',{})
        total=cf.get('total',0)
        ctx.append(f'\nCVE FINDINGS: {total} total')
        for vendor,cves in findings.items():
            if cves:
                top=cves[0]
                ctx.append(f'  {vendor}: {len(cves)} CVEs highest={top.get("id")} CVSS={top.get("cvss")} [{top.get("severity")}]')
    if 'beacon_alerts.json' in stack:
        ba=stack['beacon_alerts.json'].get('alerts',[])
        if ba:
            ctx.append(f'\nBEACON ALERTS: {len(ba)} detected')
            for a in ba:
                ctx.append(f'  {a.get("ip")} interval={a.get("interval")}s')
    if 'lateral_alerts.json' in stack:
        la=stack['lateral_alerts.json'].get('alerts',[])
        if la:
            ctx.append(f'\nLATERAL MOVEMENT: {len(la)} new hosts')
            for a in la:
                ctx.append(f'  new host {a.get("ip")}')
    if 'alerts.json' in stack:
        alerts = stack['alerts.json'].get('alerts', [])
        if alerts:
            ctx.append(f'\nACTIVE ALERTS: {len(alerts)}')
            for a in alerts[-3:]:
                ctx.append(f'  [{a.get("severity")}] {a.get("message")}')
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
    try:
        from modules.filestack import STACK
        import os, json
        bp = os.path.join(STACK, 'http_banners.json')
        if os.path.exists(bp):
            with open(bp) as f: bdata = json.load(f)
            blines = [f"{b.get('ip')}:{b.get('port')} {b.get('server','')} {b.get('title','')}" for b in bdata[:10]]
            ctx.append('HTTP BANNERS:\n' + '\n'.join(blines))
    except: pass
    return '\n'.join(ctx) + '\n\n' + reg_ctx

    return HAIKU
HAIKU = "claude-haiku-4-5"
SONNET = "claude-sonnet-4-5"
COMPLEX_KEYWORDS = ["analyze","correlate","baseline","recommend","investigate","explain","compare","summarize","report","vulnerability","risk","anomaly"]
def pick_model(question):
    q = question.lower()
    if len(question) > 200: return SONNET
    if any(k in q for k in COMPLEX_KEYWORDS): return SONNET
    return HAIKU
def strip_md(text):
    import re
    text=re.sub(r'#{1,6}\s*','',text)
    text=re.sub(r'\*{1,2}([^*]+)\*{1,2}','\\1',text)
    text=re.sub(r'`{1,3}[^`]*`{1,3}','',text)
    text=re.sub(r'^\s*[-*]\s+','  ',text,flags=re.MULTILINE)
    text=re.sub(r'\|[^\n]+\|','',text)
    text=re.sub(r'\n{3,}','\n\n',text)
    return text.strip()
def ask_doxa(question, api_key, history):
    from modules.sanitize import clean_wire_value
    question=clean_wire_value(question,"doxa_input")
    mode_ctx=''
    for mode,desc in PROMPT_MODES.items():
        if question.lower().startswith(mode):
            mode_ctx=f'\n\nACTIVE MODE: {mode.upper()}\n{desc}'
            break
    context = build_context()
    system  = GHOST_SYSTEM + f'\n\nCURRENT NETWORK STATE:\n{context}' + mode_ctx
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
            from modules.sanitize import validate_doxa_output
            print()
            raw=""
            for block in data.get('content',[]):
                if block.get('type')=='text':
                    raw+=block.get('text','')
            reply=strip_md(raw)
            warnings=validate_doxa_output(reply)
            if warnings:
                for w in warnings:
                    print(f"  \033[31m[DOXA SECURITY] {w}\033[0m")
            history.append({'role': 'assistant', 'content': reply})
            return reply
    except urllib.error.HTTPError as e:
        return f'[DOXA] API error: {e.code} {e.reason}'
    except Exception as e:
        return f'[DOXA] error: {e}'

def run_doxa():
    print(f'\n  {CYAN}{BOLD}[DOXA]{RESET} ghost intelligence module')
    print(f"  {DIM}token routing active — Anthropic{RESET}")
    print(f'  {DIM}ask anything — or use a mode:{RESET}')
    print(f'  {DIM}hunt / isolate / baseline / report / explain / defend{RESET}')
    print(f'  {DIM}example: hunt 192.168.1.72{RESET}')
    print(f'  {DIM}type exit to return to menu{RESET}\n')
    api_key = load_doxa_key()
    if not api_key:
        print(f'  {RED}[DOXA] no API key found{RESET}')
        print(f'  {DIM}add ANTHROPIC_KEY to ~/.wraith/keys.py{RESET}')
        return
    mem_path = os.path.expanduser('~/.wraith/memory.json')
    history = []
    if os.path.exists(mem_path):
        try:
            with open(mem_path) as f:
                history = json.load(f)
        except: history = []
    while True:
        try:
            q = input(f'  {CYAN}ghost >{RESET} ').strip()
        except (KeyboardInterrupt, EOFError):
            print()
            history = history[-50:]
            with open(mem_path,'w') as f:
                json.dump(history, f)
            break
        if not q: continue
        if q.lower() in ('exit','quit','back','q'):
            history = history[-50:]
            with open(mem_path,'w') as f:
                json.dump(history, f)
            break
        print(f'  {DIM}thinking...{RESET}')
        reply = ask_doxa(q, api_key, history)
        print()
        for line in reply.split('\n'):
            print(f'  {GREEN}{line}{RESET}')
        print()
