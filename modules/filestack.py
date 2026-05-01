# WRAITH filestack.py — structured JSON output engine
# feeds the agent architecture
# sig.int.ghost
# the wire speaks. WRAITH writes. agents read.

import json
import os
import datetime

LOOT = os.path.expanduser('~/.wraith/loot')
STACK = os.path.join(LOOT, 'stack')
_subnet = 'default'
def set_subnet(subnet):
    global STACK,_subnet
    _subnet = subnet.replace('.','_').replace('/','_')
    STACK = os.path.join(LOOT,'stack',_subnet)

def get_stack():
    return STACK
def ensure_stack():
    os.makedirs(STACK, exist_ok=True)

def write_hosts(results):
    hosts = []
    for item in results:
        if len(item) == 3:
            ip, port, hostname = item
            hosts.append({'ip':ip,'port':port,'hostname':hostname})
        else:
            hosts.append({'ip':item[0]})
    write_json('hosts.json', {'hosts': hosts, 'count': len(hosts)})

def write_json_safe(filename, data):
    try:
        from modules.sanitize import sanitize_filestack
        data=sanitize_filestack(data,filename)
    except: pass
    return write_json(filename,data)

def write_json(filename, data):
    ensure_stack()
    path = os.path.join(STACK, filename)
    data['_updated'] = datetime.datetime.now().isoformat()
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    return path

def read_json(filename):
    path = os.path.join(STACK, filename)
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        return json.load(f)

def write_hosts(sweep_results):
    hosts = {}
    for ip, port, hostname in sweep_results:
        hosts[ip] = {
            'ip': ip,
            'port': port,
            'hostname': hostname,
            'first_seen': datetime.datetime.now().isoformat(),
        }
    write_json('hosts.json', {'hosts': hosts})

def write_bacnet(inventory, bbmd_table):
    data = {'devices': {}, 'bbmds': {}}
    for did, dev in inventory.items():
        data['devices'][str(did)] = dev
    for ip, bbmd in bbmd_table.items():
        data['bbmds'][ip] = bbmd
    write_json('bacnet_inventory.json', data)

def write_modbus(inventory):
    data = {'devices': {}}
    for key, dev in inventory.items():
        d = dict(dev)
        d['func_codes'] = list(d.get('func_codes', []))
        data['devices'][key] = d
    write_json('modbus_map.json', data)

def write_mqtt(inventory, topics):
    data = {'brokers': {}, 'topics': {}}
    for ip, dev in inventory.items():
        d = dict(dev)
        d['client_ids'] = list(d.get('client_ids', []))
        d['topics_seen'] = list(d.get('topics_seen', []))
        data['brokers'][ip] = d
    for topic, info in topics.items():
        t = dict(info)
        t['publishers'] = list(t.get('publishers', []))
        data['topics'][topic] = t
    write_json('mqtt_brokers.json', data)

def write_alerts(alerts):
    write_json('alerts.json', {'alerts': alerts})

def stack_summary():
    ensure_stack()
    files = os.listdir(STACK)
    summary = {}
    for f in files:
        path = os.path.join(STACK, f)
        summary[f] = os.path.getsize(path)
    return summary
