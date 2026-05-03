import os, json, datetime
from modules.filestack import get_stack, write_json

ZIGBEE_PORTS = [17754, 17755, 17756]
ZWAVE_PORTS = [4123]
BT_PORTS = [17184, 30896]
ROGUE_AP_PORTS = [8080, 8443, 9090]

WIRELESS_BAS = {
    'Tridium Niagara Wireless': [4911],
    'Distech ECLYPSE': [1883, 8883],
    'Automated Logic Wireless': [10050],
    'Zigbee Gateway': ZIGBEE_PORTS,
    'Z-Wave Controller': ZWAVE_PORTS,
}

def analyze_rf():
    from modules.alerts import add_alert
    print('\n  [RF] signal intelligence scan')
    findings = []
    stack = get_stack()
    p = os.path.join(stack, 'portscan.json')
    if not os.path.exists(p):
        print('  [RF] no portscan.json — run SCAN first')
        _save(findings)
        return
    with open(p) as f: ps = json.load(f)
    scans = ps.get('scans', [])
    for scan in scans:
        target = scan.get('target','?')
        ports = [x.get('port') for x in scan.get('ports',[])
            if isinstance(x,dict) and x.get('state')=='OPEN']
        for port in ports:
            if port in ZIGBEE_PORTS:
                _flag(findings, target, port, 'ZIGBEE', 'Zigbee gateway port', add_alert)
            if port in ZWAVE_PORTS:
                _flag(findings, target, port, 'ZWAVE', 'Z-Wave controller port', add_alert)
            if port in BT_PORTS:
                _flag(findings, target, port, 'BLUETOOTH', 'Bluetooth service port', add_alert)
        for dev, dports in WIRELESS_BAS.items():
            matches = [p for p in ports if p in dports]
            if matches:
                msg = f'{target} matches {dev} ports={matches}'
                print(f'  [RF] {msg}')
                findings.append({'ip':target,'device':dev,
                    'ports':matches,'type':'WIRELESS_BAS',
                    'ts':datetime.datetime.now().isoformat()})
    _save(findings)

def _flag(findings, ip, port, typ, detail, add_alert):
    msg = f'{ip} port={port} type={typ} — {detail}'
    print(f'  [!] {msg}')
    findings.append({'ip':ip,'port':port,'type':typ,
        'detail':detail,
        'ts':datetime.datetime.now().isoformat()})
    add_alert(f'RF SIGNAL {msg}', severity='MEDIUM')

def _save(findings):
    write_json('rf_findings.json',{
        'timestamp':datetime.datetime.now().isoformat(),
        'findings':findings,
        'note':'hardware RF capture not yet active — wire-based indicators only'})
    print(f'  [RF] {len(findings)} indicators — rf_findings.json written')

def run_rf():
    analyze_rf()
