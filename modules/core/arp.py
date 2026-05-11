# WRAITH arp.py — pure Python ARP host discovery
# sig.int.ghost
# %X0.0 — first rung. first contact.
# the device does not know it has been seen.

import socket
from modules.core.asset_registry import upsert as reg_upsert
OUI = {
    '00:50:56':'VMware','00:0c:29':'VMware','00:1a:11':'Google',
    '00:17:88':'Philips Hue','b8:27:eb':'Raspberry Pi',
    'dc:a6:32':'Raspberry Pi','e4:5f:01':'Raspberry Pi',
    '00:1b:44':'Siemens','00:0d:f0':'Siemens',
    '00:80:f4':'Tridium','00:60:35':'Tridium',
    '00:50:c2':'Johnson Controls','00:30:48':'Supermicro',
    '00:1d:7e':'Cisco','00:23:ab':'Cisco',
    '4c:c9:5e':'Samsung','4c:bd:8f':'Samsung',
    '00:07:ab':'Samsung','00:12:fb':'Samsung',
    '00:15:b9':'Samsung','00:16:32':'Samsung',
    '00:17:c9':'Samsung','00:18:af':'Samsung',
    '00:1a:8a':'Samsung','00:1b:98':'Samsung',
    '00:1c:43':'Samsung','00:1d:25':'Samsung',
    '00:1e:7d':'Samsung','00:1f:cc':'Samsung',
    '00:21:19':'Samsung','00:23:39':'Samsung',
    '38:01:97':'Samsung-TV','8c:77:12':'Samsung-TV',
    'f4:7b:5e':'Samsung-TV','78:bd:bc':'Samsung-TV',
    'b4:e6:2d':'Apple','3c:22:fb':'Apple',
    'ac:bc:32':'Apple','00:11:32':'Synology',
}
_oui_cache = {}
def _load_oui():
    import os
    p = os.path.expanduser('~/.wraith/oui.txt')
    if not os.path.exists(p): return
    with open(p) as f:
        for ln in f:
            if '(hex)' in ln:
                pts=ln.split('(hex)')
                if len(pts)==2:
                    k=pts[0].strip().replace('-',':').lower()[:8]
                    _oui_cache[k]=pts[1].strip()
def oui_lookup(mac):
    if not _oui_cache: _load_oui()
    if not mac: return 'unknown'
    return _oui_cache.get(mac[:8].lower(),'unknown')
import struct
import os
import sys

def get_mac():
    import uuid
    mac = uuid.getnode()
    return struct.pack("!6B", *[
        (mac >> (5-i)*8) & 0xff for i in range(6)
    ])

def build_arp_request(src_mac, src_ip, target_ip):
    # ethernet header
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    eth_type = b'\x08\x06'
    eth = dst_mac + src_mac + eth_type
    # arp payload
    htype = b'\x00\x01'
    ptype = b'\x08\x00'
    hlen  = b'\x06'
    plen  = b'\x04'
    oper  = b'\x00\x01'
    sha   = src_mac
    spa   = socket.inet_aton(src_ip)
    tha   = b'\x00\x00\x00\x00\x00\x00'
    tpa   = socket.inet_aton(target_ip)
    arp   = htype+ptype+hlen+plen+oper+sha+spa+tha+tpa
    return eth + arp

def arp_scan(network_prefix, src_ip, timeout=1):
    try:
        src_mac = get_mac()
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        s.settimeout(timeout)
        iface = "eth0"
        s.bind((iface, 0))
    except Exception as e:
        print(f"  [ARP] socket error: {e}")
        print("  [ARP] raw socket requires root and AF_PACKET support")
        return []

    alive = []
    for i in range(1, 255):
        target = f"{network_prefix}.{i}"
        pkt = build_arp_request(src_mac, src_ip, target)
        try:
            s.send(pkt)
        except:
            pass

    import time
    time.sleep(timeout)

    while True:
        try:
            raw = s.recv(1024)
            if raw[12:14] == b'\x08\x06' and raw[20:22] == b'\x00\x02':
                ip = socket.inet_ntoa(raw[28:32])
                mac = ':'.join(f'{b:02x}' for b in raw[22:28])

                vendor = oui_lookup(mac)
                print(f"  [ARP] {ip} — {mac} ({vendor})")
                alive.append((ip, mac, vendor))
                reg_upsert(ip=ip, mac=mac, source='arp', **{'network.vendor':vendor})
        except socket.timeout:
            break
        except:
            break

    s.close()
    return alive

def seed_arp_from_hosts():
    import os, json, datetime
    from modules.core.filestack import get_stack, write_json
    hp = os.path.join(get_stack(), 'hosts.json')
    if not os.path.exists(hp): return []
    with open(hp) as f: data = json.load(f)
    hosts = data.get('hosts', {})
    if isinstance(hosts, dict): hosts = list(hosts.values())
    entries = []
    for h in hosts:
        if not isinstance(h, dict): continue
        entries.append({'ip':h.get('ip',''),'mac':'unknown',
            'vendor':'unknown',
            'ts':datetime.datetime.now().isoformat()})
    if entries:
        write_json('arp_table.json',{'hosts':entries})
        print(f'  [ARP] seeded {len(entries)} hosts from sweep data')
    return entries

def read_arp_cache():
    import subprocess, os
    from modules.core.filestack import write_json
    import datetime
    try:
        result = subprocess.run(['arp','-a'],
            capture_output=True, text=True)
        hosts = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4: continue
            ip = parts[1].strip('()')
            mac = parts[3]
            if mac == '<incomplete>': continue
            hosts.append({'ip':ip,'mac':mac,
                'vendor':'unknown',
                'ts':datetime.datetime.now().isoformat()})
        if hosts:
            write_json('arp_table.json',{'hosts':hosts})
            print(f'  [ARP] {len(hosts)} hosts from system cache')
        return hosts
    except Exception as e:
        print(f'  [ARP] cache read failed: {e}')
        return []

def run_arp(gateway, local_ip):
    from modules.core.registry import update_registry, get_new_hosts
    prefix = '.'.join(local_ip.split('.')[:3])
    print(f"\n  [ARP] scanning {prefix}.1-254")
    hosts = arp_scan(prefix, local_ip)
    new_hosts = get_new_hosts(hosts)
    update_registry(hosts)
    if new_hosts:
        print(f"  [33m[REGISTRY] {len(new_hosts)} new host(s) first seen[0m")
        for ip in new_hosts:
            print(f"  [31m[ROGUE?] {ip} — first appearance[0m")
            try:
                from modules.core.filestack import get_stack
                import json, os
                ap = os.path.join(get_stack(), 'alerts.json')
                alerts = json.load(open(ap)) if os.path.exists(ap) else []
                alerts.append({'type':'rogue_device','ip':ip,'message':f'New host {ip}'})
                json.dump(alerts, open(ap,'w'), indent=2)
            except: pass
    if not hosts:
        print("  [ARP] no hosts found or raw socket unavailable")
    try:
        from modules.core.filestack import write_json
        write_json('arp_table.json', {'hosts': [
            {'ip': h[0], 'mac': h[1]} for h in hosts
        ]})
    except: pass
    return hosts
