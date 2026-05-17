# WRAITH credential_check.py — default cred probe
# operator authorized only — HITL required
# passive observer. anomaly is the signal.
import urllib.request, urllib.error
import base64, time, json, os
from modules.core.alerts import fire

PAIRS = [
    ('admin','admin'),
    ('admin',''),
    ('admin','password'),
    ('ubnt','ubnt'),
    ('admin','cisco'),
]
TIMEOUT = 3
DELAY = 1.0

def _try_cred(url, user, pwd):
    try:
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Basic {token}')
        req.add_header('User-Agent', 'Mozilla/5.0')
        r = urllib.request.urlopen(req, timeout=TIMEOUT)
        return r.status in (200, 301, 302, 403)
    except urllib.error.HTTPError as e:
        return e.code not in (401, 407)
    except: return False

def _write_result(ip, user, pwd, success):
    if success:
        fire('default_creds',
            f"{ip} default credentials valid {user}:{pwd}", severity='CRITICAL')

def run_credential_check(ip=None):
    C='\033[36m'; R='\033[0m'; Y='\033[33m'; D='\033[2m'
    print(f"\n  [{C}CRED CHECK{R}] default credential probe")
    if not ip:
        ip = input("  target IP > ").strip()
    if not ip: return
    print(f"\n  target   : {ip}")
    print(f"  pairs    : {len(PAIRS)}")
    print(f"  {Y}[!] operator authorization required{R}")
    confirm = input("  confirm target is yours [y/N] > ").strip().lower()
    if confirm != 'y':
        print("  [CRED] aborted")
        return
    results = []
    for scheme in ('https', 'http'):
        url = f"{scheme}://{ip}/"
        print(f"\n  [{D}probing{R}] {url}")
        for user, pwd in PAIRS:
            label = f"{user}:{pwd}" if pwd else f"{user}:[blank]"
            hit = _try_cred(url, user, pwd)
            status = f"{C}HIT{R}" if hit else f"{D}miss{R}"
            print(f"  {label:<20} {status}")
            _write_result(ip, user, pwd, hit)
            if hit: results.append((scheme,user,pwd))
            time.sleep(DELAY)
        if results: break
    if results:
        print(f"\n  [{Y}CRITICAL{R}] valid credentials found")
        for scheme, u, p in results:
            print(f"  {scheme}  {u}:{p if p else '[blank]'}")
    else:
        print(f"\n  [CRED] no default credentials accepted")
    return results
