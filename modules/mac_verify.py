import json, os, datetime
from modules.filestack import get_stack, write_json

OUI = {
'00:1A:11':'Google','00:17:F2':'Apple','AC:DE:48':'Apple',
'F4:F5:D8':'Google','B8:27:EB':'Raspberry Pi','DC:A6:32':'Raspberry Pi',
'00:50:56':'VMware','08:00:27':'VirtualBox','00:1C:42':'Parallels',
'54:27:1E':'Samsung','8C:71:F8':'Samsung','F4:7B:5E':'Samsung',
'00:07:AB':'Samsung','18:29:9E':'Samsung','A4:EB:D3':'Apple',
'3C:22:FB':'Apple','00:1E:C2':'Apple','BC:9F:EF':'Apple',
'00:E0:4C':'Realtek','00:1D:72':'Cisco','00:1B:54':'Cisco',
'FC:FB:FB':'Cisco','00:0C:29':'VMware','00:25:B5':'Cisco',
}

def get_oui(mac):
    if not mac: return 'unknown'
    prefix = mac.upper().replace('-',':')[:8]
    return OUI.get(prefix, 'unknown')

def verify_macs():
    from modules.alerts import add_alert
    stack = get_stack()
    ap = os.path.join(stack, 'arp_table.json')
    if not os.path.exists(ap):
        print('  [MAC] no arp_table.json found')
        return
    with open(ap) as f: arp = json.load(f)
    hosts = arp.get('hosts', [])
    findings = []
    print(f'\n  [MAC VERIFY] checking {len(hosts)} hosts')
    for h in hosts:
        if not isinstance(h, dict): continue
        ip  = h.get('ip','?')
        mac = h.get('mac','')
        claimed = h.get('vendor','unknown')
        oui_vendor = get_oui(mac)
        flags = []
        if not mac:
            flags.append('NO_MAC')
        elif oui_vendor == 'unknown':
            flags.append('UNKNOWN_OUI')
        elif claimed != 'unknown' and oui_vendor != 'unknown':
            if oui_vendor.lower() not in claimed.lower():
                flags.append(f'VENDOR_MISMATCH:{claimed}vs{oui_vendor}')
        status = 'CLEAN' if not flags else 'FLAG'
        print(f'  {ip} mac={mac} oui={oui_vendor} [{status}]')
        if flags:
            detail = f"{ip} mac={mac} flags={flags}"
            findings.append({'ip':ip,'mac':mac,'oui':oui_vendor,
                'claimed':claimed,'flags':flags,
                'ts':datetime.datetime.now().isoformat()})
            add_alert(f'MAC ANOMALY {detail}', severity='HIGH')
    write_json('mac_findings.json',{
        'timestamp':datetime.datetime.now().isoformat(),
        'findings':findings})
    print(f'  [MAC] {len(findings)} anomalies — mac_findings.json written')
