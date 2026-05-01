# modules/auth.py
# WRAITH authentication and audit engine
import os, json, hashlib, uuid, time
from datetime import datetime
AUTH_DIR = os.path.expanduser("~/.wraith")
AUTH_FILE = os.path.join(AUTH_DIR, "auth.cfg")
AUDIT_FILE = os.path.join(AUTH_DIR, "audit.log")
SESSION_ID = None
CURRENT_USER = None
CURRENT_ROLE = None
ROLES = ["admin", "technician", "readonly"]
def _hash(pw): return hashlib.sha256(pw.encode()).hexdigest()
def _load_users():
    if not os.path.exists(AUTH_FILE): return {}
    with open(AUTH_FILE) as f: return json.load(f)
def _save_users(users):
    os.makedirs(AUTH_DIR, exist_ok=True)
    with open(AUTH_FILE, "w") as f: json.dump(users, f, indent=2)
    os.chmod(AUTH_FILE, 0o600)
def validate_password(pw):
    import re
    if len(pw)<8: return "min 8 characters"
    if not re.search(r'[A-Z]',pw): return "need uppercase"
    if not re.search(r'[0-9]',pw): return "need number"
    if not re.search(r'[!@#$%^&*]',pw): return "need special char"
    return None
def create_user(username, password, role="technician"):
    users = _load_users()
    if username in users: return False
    users[username] = {"hash": _hash(password), "role": role, "created": datetime.now().isoformat()}
    _save_users(users)
    return True
def change_password(username, old_pw, new_pw):
    users = _load_users()
    if username not in users: return False
    if users[username]["hash"] != _hash(old_pw): return False
    users[username]["hash"] = _hash(new_pw)
    _save_users(users)
    return True
def login(username, password):
    global SESSION_ID, CURRENT_USER, CURRENT_ROLE
    import time
    users = _load_users()
    if username not in users: return "invalid"
    u = users[username]
    max_attempts = 5 if u.get("role")=="admin" else 3
    locked_until = u.get("locked_until",0)
    if time.time() < locked_until:
        remaining = int(locked_until - time.time())
        return f"locked:{remaining}"
    if u["hash"] != _hash(password):
        u["fails"] = u.get("fails",0) + 1
        if u["fails"] >= max_attempts:
            u["locked_until"] = time.time() + 300
            u["fails"] = 0
        _save_users(users)
        remaining = max_attempts - u["fails"]
        return f"fail:{remaining}"
    u["fails"] = 0
    u["locked_until"] = 0
    _save_users(users)
    CURRENT_USER = username
    CURRENT_ROLE = u["role"]
    SESSION_ID = str(uuid.uuid4())[:8]
    _audit("LOGIN","session started")
    return True
def logout():
    global SESSION_ID, CURRENT_USER, CURRENT_ROLE
    _audit("LOGOUT", "session ended")
    SESSION_ID = None
    CURRENT_USER = None
    CURRENT_ROLE = None
def _audit(action, detail=""):
    if not CURRENT_USER: return
    ts = datetime.now().isoformat()
    line = ts + " | " + SESSION_ID + " | " + CURRENT_USER + " | " + CURRENT_ROLE + " | " + action + " | " + detail
    os.makedirs(AUTH_DIR, exist_ok=True)
    with open(AUDIT_FILE, "a") as f: f.write(line + chr(10))
def audit_action(action, detail=""):
    _audit(action, detail)
def get_session():
    return {"user": CURRENT_USER, "role": CURRENT_ROLE, "session": SESSION_ID}
def require_admin(): return CURRENT_ROLE == "admin"
def first_run(): return not os.path.exists(AUTH_FILE) or len(_load_users()) == 0
def check_keys_on_login():
    if CURRENT_ROLE=='admin':
        try:
            from modules.keys_manager import warn_missing_keys
            warn_missing_keys()
        except: pass
def delete_user(username):
    users = _load_users()
    if username not in users: return False
    del users[username]
    _save_users(users)
    return True
def list_users():
    return _load_users()
def set_role(username, role):
    users = _load_users()
    if username not in users: return False
    users[username]["role"] = role
    _save_users(users)
    return True
def set_buildings(username, buildings):
    users = _load_users()
    if username not in users: return False
    users[username]["buildings"] = buildings
    _save_users(users)
    return True
def delete_user(username):
    users = _load_users()
    if username not in users: return False
    del users[username]
    _save_users(users)
    return True
def list_users():
    return _load_users()
def set_role(username, role):
    users = _load_users()
    if username not in users: return False
    users[username]["role"] = role
    _save_users(users)
    return True
def set_buildings(username, buildings):
    users = _load_users()
    if username not in users: return False
    users[username]["buildings"] = buildings
    _save_users(users)
    return True
def change_password_admin(username, new_pw):
    users = _load_users()
    if username not in users: return False
    users[username]["hash"] = _hash(new_pw)
    _save_users(users)
    return True
