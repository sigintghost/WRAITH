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
    users = _load_users()
    if username not in users: return False
    if users[username]["hash"] != _hash(password): return False
    CURRENT_USER = username
    CURRENT_ROLE = users[username]["role"]
    SESSION_ID = str(uuid.uuid4())[:8]
    _audit("LOGIN", "session started")
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
