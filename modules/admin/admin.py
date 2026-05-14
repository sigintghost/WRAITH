# modules/admin.py — WRAITH admin panel
import modules.admin.auth as auth
from modules.core.asset_registry import all_records, authorize, upsert as reg_upsert
CYAN='\033[36m';GREEN='\033[32m';RED='\033[31m'
YELLOW='\033[33m';BOLD='\033[1m';DIM='\033[2m';RESET='\033[0m'
ROLES_ALL = ["admin","technician","viewer"]
ROLES_SAFE = ["technician","viewer"]

def _review_assets():
    recs = all_records()
    unauth = [r for r in recs if not r['authorized']]
    print(f"\n{CYAN}  ASSET REGISTRY{RESET} — {len(recs)} total, {RED}{len(unauth)} unauthorized{RESET}")
    print(f"  {DIM}{'─'*56}{RESET}")
    print(f"  {CYAN}{'IP':<18}{'TYPE':<14}{'SOURCE':<16}STATUS{RESET}")
    for r in sorted(recs,key=lambda x:x['network']['ip']):
        ip=r['network']['ip']
        typ=r['type']
        src=r['provenance']['source_module']
        ac=GREEN if r['authorized'] else RED
        al="AUTH  " if r['authorized'] else "UNAUTH"
        print(f"  {ip:<18}{typ:<14}{src:<16}{ac}{al}{RESET}")
    print(f"  {DIM}{'─'*56}{RESET}")

def _authorize_asset():
    unauth=[r for r in all_records() if not r['authorized']]
    if not unauth: print(f"  {GREEN}all assets authorized{RESET}"); return
    print(f"\n  {RED}UNAUTHORIZED — {len(unauth)} assets{RESET}")
    for r in unauth:
        ip=r['network']['ip']; ts=r['temporal']['first_seen'][:19]
        src=r['provenance']['source_module']
        print(f"  {CYAN}{ip}{RESET} first={ts} src={src}")
    print()
    ip=input("  authorize IP [0=cancel] > ").strip()
    if not ip or ip=='0': return
    typ=input("  type [controller/server/workstation/mobile/unknown] > ").strip() or 'unknown'
    reg_upsert(ip=ip,mac='',source='operator',**{'type':typ})
    print(f"  {GREEN}authorized: {ip}{RESET}" if authorize(ip=ip) else f"  {RED}not found: {ip}{RESET}")

def _header():
    print(f"\n{CYAN}{BOLD}  ADMIN PANEL{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")

def _list_users():
    users = auth.list_users()
    if not users:
        print(f"  {DIM}no users{RESET}"); return
    for u,d in users.items():
        role=d.get("role","unknown")
        bld=d.get("buildings","all")
        created=d.get("created","?")[:10]
        print(f"  {CYAN}{u:<16}{RESET} role={GREEN}{role:<12}{RESET} buildings={YELLOW}{bld}{RESET}")
        print(f"  {DIM}  created {created}{RESET}")
def _pick_role():
    caller=auth.CURRENT_ROLE
    roles=ROLES_ALL if caller=="admin" else ROLES_SAFE
    for i,r in enumerate(roles,1):
        print(f"  {CYAN}[{i}]{RESET} {r}")
    c=input(f"  role > ").strip()
    if c.isdigit() and 1<=int(c)<=len(roles):
        return roles[int(c)-1]
    return None
def _create_user():
    u=input(f"  {CYAN}username [0=cancel]:{RESET} ").strip()
    if not u or u=="0": print(f"  {DIM}cancelled{RESET}"); return
    p=input(f"  {CYAN}password [0=cancel]:{RESET} ").strip()
    if not p or p=="0": print(f"  {DIM}cancelled{RESET}"); return
    err=auth.validate_password(p)
    if err: print(f"  {RED}password rejected: {err}{RESET}"); return
    print(f"  select role:")
    r=_pick_role()
    if not r: print(f"  {RED}invalid role{RESET}"); return
    b=input(f"  {CYAN}buildings [all]:{RESET} ").strip() or "all"
    if auth.create_user(u,p,r):
        auth.set_buildings(u,b)
        print(f"  {GREEN}created: {u} role={r}{RESET}")
    else: print(f"  {RED}user exists{RESET}")
def _edit_user():
    u=input(f"  {CYAN}username [0=cancel]:{RESET} ").strip()
    if not u or u=="0": print(f"  {DIM}cancelled{RESET}"); return
    if u not in auth.list_users():
        print(f"  {RED}not found{RESET}"); return
    print(f"  {CYAN}[1]{RESET} change role")
    print(f"  {CYAN}[2]{RESET} reset password")
    print(f"  {CYAN}[3]{RESET} set buildings")
    print(f"  {CYAN}[0]{RESET} cancel")
    c=input(f"  > ").strip()
    if c=="0": return
    elif c=="1":
        r=_pick_role()
        if r and auth.set_role(u,r): print(f"  {GREEN}role updated{RESET}")
    elif c=="2":
        p=input(f"  {CYAN}new password:{RESET} ").strip()
        if not p: return
        err=auth.validate_password(p)
        if err: print(f"  {RED}rejected: {err}{RESET}"); return
        if auth.change_password_admin(u,p): print(f"  {GREEN}password reset{RESET}")
    elif c=="3":
        b=input(f"  {CYAN}buildings:{RESET} ").strip()
        if b and auth.set_buildings(u,b):
            print(f"  {GREEN}buildings updated{RESET}")
PRIMARY_ADMIN="kgod450"
def _delete_user():
    users=auth.list_users()
    current=auth.CURRENT_USER
    print(f"  {DIM}users:{RESET}")
    for u,d in users.items():
        role=d.get("role","?")
        if u==PRIMARY_ADMIN: tag=f"{RED}[protected]{RESET}"
        elif u==current: tag=f"{YELLOW}[you]{RESET}"
        else: tag=""
        print(f"  {CYAN}{u:<16}{RESET} {role} {tag}")
    u=input(f"  username [0=cancel]: ").strip()
    if not u or u=="0": print(f"  {DIM}cancelled{RESET}"); return
    if u==PRIMARY_ADMIN: print(f"  {RED}protected — cannot delete primary admin{RESET}"); return
    if u==current: print(f"  {RED}cannot delete your own account{RESET}"); return
    if u not in users: print(f"  {RED}not found{RESET}"); return
    print(f"  {RED}[1]{RESET} confirm delete {u}")
    print(f"  {CYAN}[0]{RESET} cancel")
    if input(f"  > ").strip()=="1" and auth.delete_user(u):
        print(f"  {GREEN}deleted: {u}{RESET}")
    else: print(f"  {DIM}cancelled{RESET}")
def run_admin():
    if auth.CURRENT_ROLE != "admin":
        print(f"  {RED}access denied — admin only{RESET}"); return
    _header()
    while True:
        print(f"\n  {CYAN}[1]{RESET} list users")
        print(f"  {CYAN}[2]{RESET} create user")
        print(f"  {CYAN}[3]{RESET} edit user")
        print(f"  {CYAN}[4]{RESET} delete user")
        print(f"  {CYAN}[5]{RESET} asset review")
        print(f"  {CYAN}[6]{RESET} authorize asset")
        print(f"  {CYAN}[0]{RESET} back")
        c=input(f"  > ").strip()
        if c=="0": break
        elif c=="1": _header(); _list_users()
        elif c=="2": _create_user()
        elif c=="3": _edit_user()
        elif c=="4": _delete_user()
        elif c=="5": _review_assets()
        elif c=="6": _authorize_asset()
