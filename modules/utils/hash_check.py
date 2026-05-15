import os, json, hashlib
from datetime import datetime
MANIFEST = os.path.expanduser('~/.wraith/module_hashes.json')
MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def _hash_file(path):
    h = hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''): h.update(chunk)
    return h.hexdigest()
def _collect():
    hashes = {}
    for root,dirs,files in os.walk(MODULE_ROOT):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for fn in files:
            if not fn.endswith('.py'): continue
            fp = os.path.join(root,fn)
            hashes[os.path.relpath(fp,MODULE_ROOT)] = _hash_file(fp)
    return hashes
def baseline():
    hashes = _collect()
    os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
    with open(MANIFEST,'w') as f:
        json.dump({'created':datetime.utcnow().isoformat()+'Z','count':len(hashes),'hashes':hashes},f,indent=2)
    print(f"  [HASH] baseline set — {len(hashes)} modules")
    return True
def verify():
    if not os.path.exists(MANIFEST): return baseline() or True
    with open(MANIFEST) as f: manifest = json.load(f)
    stored = manifest.get('hashes',{})
    current = _collect()
    violations = []
    for rel,h in current.items():
        if rel not in stored: violations.append(f'NEW: {rel}')
        elif stored[rel] != h: violations.append(f'MODIFIED: {rel}')
    for rel in stored:
        if rel not in current: violations.append(f'MISSING: {rel}')
    return violations
def run_hash_check(silent=False):
    RED='\033[31m';GREEN='\033[32m';RESET='\033[0m'
    violations = verify()
    if violations is True or not violations:
        if not silent: print(f"  {GREEN}[HASH] all modules verified{RESET}")
        return True
    print(f"  {RED}[HASH] INTEGRITY VIOLATIONS: {len(violations)}{RESET}")
    for v in violations: print(f"  {RED}  ! {v}{RESET}")
    try:
        from modules.core.alerts import fire
        for v in violations: fire('MODULE_INTEGRITY',v,severity='CRITICAL',source='hash_check')
    except: pass
    return False
