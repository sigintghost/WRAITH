import os, json, uuid
from datetime import datetime
SENSOR_FILE = os.path.expanduser('~/.wraith/sensors.json')
def _now(): return datetime.utcnow().isoformat()+'Z'
def _load():
    if not os.path.exists(SENSOR_FILE): return {}
    with open(SENSOR_FILE) as f: return json.load(f)
def _save(db):
    os.makedirs(os.path.dirname(SENSOR_FILE), exist_ok=True)
    tmp = SENSOR_FILE+'.tmp'
    with open(tmp,'w') as f: json.dump(db,f,indent=2)
    os.replace(tmp,SENSOR_FILE)
def register(label, platform, ip='', mac='', stack_path=''):
    db = _load()
    sid = str(uuid.uuid4())[:8]
    db[sid] = {
        'sensor_id': sid,
        'label': label,
        'platform': platform,
        'ip': ip,
        'mac': mac,
        'stack_path': stack_path,
        'status': 'active',
        'deployed': _now(),
        'last_seen': _now(),
    }
    _save(db)
    print(f"  [SENSOR] registered {label} id={sid}")
    return sid
def all_sensors(): return list(_load().values())
def get(sid): return _load().get(sid)
def update_seen(sid):
    db = _load()
    if sid in db:
        db[sid]['last_seen'] = _now()
        _save(db)
def set_status(sid, status):
    db = _load()
    if sid in db:
        db[sid]['status'] = status
        db[sid]['last_seen'] = _now()
        _save(db)
def retire(sid):
    db = _load()
    if sid in db:
        db[sid]['status'] = 'retired'
        _save(db)
        print(f"  [SENSOR] retired {sid}")
def show_all():
    C='\033[36m';G='\033[32m';Y='\033[33m';R='\033[31m'
    D='\033[2m';RS='\033[0m'
    sensors = all_sensors()
    if not sensors: print(f"  {D}no sensors registered{RS}"); return
    print(f"\n{C}  SENSOR FLEET — {len(sensors)} registered{RS}")
    print(f"  {D}{'─'*56}{RS}")
    for s in sensors:
        st = s['status']
        sc = G if st=='active' else Y if st=='stale' else R
        print(f"  {C}{s['sensor_id']}{RS} {s['label']:<20} {s['platform']:<10} {sc}{st}{RS}")
        print(f"  {D}  ip={s['ip']} last={s['last_seen'][:10]}{RS}")
    print(f"  {D}{'─'*56}{RS}")
