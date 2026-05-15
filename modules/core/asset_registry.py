import json, os, uuid
from datetime import datetime

import os as _os
_LOOT = _os.environ.get('WRAITH_STACK_PATH', _os.path.expanduser('~/.wraith'))
REGISTRY_PATH = _os.path.join(_LOOT, 'asset_registry.json')

def _load():
    if not os.path.exists(REGISTRY_PATH): return {}
    with open(REGISTRY_PATH) as f: return json.load(f)

def _save(db):
    os.makedirs(os.path.dirname(REGISTRY_PATH), exist_ok=True)
    tmp = REGISTRY_PATH + '.tmp'
    with open(tmp,'w') as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, REGISTRY_PATH)

def _now():
    return datetime.utcnow().isoformat()+'Z'

def _blank(ip='', mac='', source=''):
    return {
        'asset_id': str(uuid.uuid4()),
        'label':'', 'type':'unknown',
        'authorized':False, 'criticality':'unknown',
        'network':{'ip':ip,'mac':mac,'hostname':'',
            'vendor':'','subnet':'','vlan':'',
            'open_ports':[],'os_fingerprint':'','ttl_guess':''},
        'protocols':[], 'services':[],
        'ot':{'bacnet_id':'','bacnet_vendor':'',
            'modbus_unit_id':'','object_list':[],
            'device_description':''},
        'wireless':{'signal_type':'','frequency':'',
            'rssi':'','pan_id':'','eui':''},
        'physical':{'location':'','floor':'','room':'',
            'sensor_id':'','switch_port':'','lldp_neighbor':''},
        'threat':{'ioc_flags':[],'mitre_techniques':[],
            'alert_refs':[],'confidence_score':0.0,
            'investigation_status':'none'},
        'temporal':{'first_seen':_now(),'last_seen':_now(),
            'last_changed':_now(),'last_enriched':''},
        'provenance':{'added_by':'scanner','added_at':_now(),
            'source_module':source,'notes':''}}

def _key(ip, mac):
    return ip.strip() if ip else mac.strip().lower()

def upsert(ip='', mac='', source='', **kwargs):
    db = _load()
    k = _key(ip, mac)
    if not k: return None
    if k not in db:
        db[k] = _blank(ip, mac, source)
    rec = db[k]
    rec['temporal']['last_seen'] = _now()
    net = rec['network']
    if ip: net['ip'] = ip
    if mac: net['mac'] = mac
    changed = False
    for field, val in kwargs.items():
        if '.' in field:
            sec, key = field.split('.', 1)
            if sec in rec and key in rec[sec]:
                if rec[sec][key] != val:
                    rec[sec][key] = val
                    changed = True
        else:
            if field in rec and rec[field] != val:
                rec[field] = val
                changed = True
    if changed:
        rec['temporal']['last_changed'] = _now()
        rec['provenance']['source_module'] = source
    db[k] = rec
    _save(db)
    return rec['asset_id']

def get(ip='', mac=''):
    db = _load()
    return db.get(_key(ip, mac))

def all_records():
    return list(_load().values())

def unauthorized():
    return [r for r in all_records() if not r['authorized']]

def by_type(t):
    return [r for r in all_records() if r['type']==t]

def authorize(ip='', mac=''):
    db = _load()
    k = _key(ip, mac)
    if k in db:
        db[k]['authorized'] = True
        db[k]['temporal']['last_changed'] = _now()
        _save(db)
        return True
    return False
