import os, json, datetime
from modules.filestack import get_stack, write_json

PG_CONFIG_PATH = os.path.expanduser('~/.wraith/pg.json')

def load_config():
    if not os.path.exists(PG_CONFIG_PATH): return {}
    with open(PG_CONFIG_PATH) as f: return json.load(f)

def save_config(cfg):
    os.makedirs(os.path.dirname(PG_CONFIG_PATH), exist_ok=True)
    with open(PG_CONFIG_PATH, 'w') as f: json.dump(cfg, f, indent=2)
    os.chmod(PG_CONFIG_PATH, 0o600)
    print('  [PG] config saved chmod 600')

def get_conn():
    cfg = load_config()
    if not cfg: return None
    try:
        import psycopg2
        return psycopg2.connect(
            host=cfg.get('host',''),
            port=cfg.get('port', 5432),
            dbname=cfg.get('dbname',''),
            user=cfg.get('user',''),
            password=cfg.get('password',''))
    except ImportError:
        print('  [PG] psycopg2 not installed — pip install psycopg2-binary')
        return None
    except Exception as e:
        print(f'  [PG] connection failed: {e}')
        return None

def fetch_alarms(conn, limit=50):
    try:
        cur = conn.cursor()
        cur.execute('''
            SELECT alarm_time, point_path, alarm_text,
                   priority, state
            FROM alarms
            ORDER BY alarm_time DESC
            LIMIT %s
        ''', (limit,))
        rows = cur.fetchall()
        alarms = []
        for r in rows:
            alarms.append({
                'time': str(r[0]),
                'point': r[1],
                'text': r[2],
                'priority': r[3],
                'state': r[4]
            })
        cur.close()
        return alarms
    except Exception as e:
        print(f'  [PG] alarm query failed: {e}')
        return []

def fetch_trends(conn, limit=100):
    try:
        cur = conn.cursor()
        cur.execute('''
            SELECT sample_time, point_path,
                   value, units
            FROM trend_data
            ORDER BY sample_time DESC
            LIMIT %s
        ''', (limit,))
        rows = cur.fetchall()
        trends = []
        for r in rows:
            trends.append({
                'time': str(r[0]),
                'point': r[1],
                'value': float(r[2]) if r[2] else None,
                'units': r[3]
            })
        cur.close()
        return trends
    except Exception as e:
        print(f'  [PG] trend query failed: {e}')
        return []

def sync_to_filestack():
    conn = get_conn()
    if not conn:
        print('  [PG] no connection')
        return
    print('  [PG] fetching alarms...')
    alarms = fetch_alarms(conn)
    print('  [PG] fetching trends...')
    trends = fetch_trends(conn)
    conn.close()
    ts = datetime.datetime.now().isoformat()
    write_json('webctrl_alarms.json', {
        'timestamp': ts,
        'count': len(alarms),
        'alarms': alarms
    })
    write_json('webctrl_trends.json', {
        'timestamp': ts,
        'count': len(trends),
        'trends': trends
    })
    print(f'  [PG] {len(alarms)} alarms, {len(trends)} trends written')

def setup_pg():
    print('\n  [PG] WebCTRL PostgreSQL setup')
    host = input('  host: ').strip()
    port = input('  port [5432]: ').strip() or '5432'
    dbname = input('  database: ').strip()
    user = input('  username: ').strip()
    import getpass
    password = getpass.getpass('  password: ')
    save_config({'host':host,'port':int(port),
        'dbname':dbname,'user':user,'password':password})

def run_pg_connector():
    print('\n  [PG] WebCTRL PostgreSQL')
    print('  [1] setup connection')
    print('  [2] sync to filestack')
    print('  [3] test connection')
    print('  [0] back')
    c = input('  > ').strip()
    if c == '1': setup_pg()
    elif c == '2': sync_to_filestack()
    elif c == '3':
        conn = get_conn()
        if conn:
            print('  [PG] connected OK')
            conn.close()
    elif c == '0': return
    else: print('  invalid')
