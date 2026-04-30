# modules/admin.py — WRAITH admin panel
import modules.auth as auth
CYAN='\033[36m';GREEN='\033[32m';RED='\033[31m'
YELLOW='\033[33m';BOLD='\033[1m';DIM='\033[2m';RESET='\033[0m'
ROLES_ALL = ["admin","technician","viewer"]
ROLES_SAFE = ["technician","viewer"]

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
        if p and auth.change_password_admin(u,p):
            print(f"  {GREEN}password reset{RESET}")
    elif c=="3":
        b=input(f"  {CYAN}buildings:{RESET} ").strip()
        if b and auth.set_buildings(u,b):
            print(f"  {GREEN}buildings updated{RESET}")
def _delete_user():
    u=input(f"  {CYAN}username [0=cancel]:{RESET} ").strip()
    if not u or u=="0": print(f"  {DIM}cancelled{RESET}"); return
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
        print(f"  {CYAN}[0]{RESET} back")
        c=input(f"  > ").strip()
        if c=="0": break
        elif c=="1": _header(); _list_users()
        elif c=="2": _create_user()
        elif c=="3": _edit_user()
        elif c=="4": _delete_user()
