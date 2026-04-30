# modules/netcheck.py
# network context validator
# detects network changes between sessions
import os, json, socket
YELLOW='\033[33m';RED='\033[31m';GREEN='\033[32m'
CYAN='\033[36m';DIM='\033[2m';RESET='\033[0m'
STACK=os.path.expanduser("~/.wraith/loot/stack")
CTX_FILE=os.path.join(STACK,"network_context.json")
def get_current_context():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80))
        ip=s.getsockname()[0]
        s.close()
        parts=ip.split(".")
        subnet=f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        gateway=f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        return {"ip":ip,"subnet":subnet,"gateway":gateway}
    except: return {"ip":"unknown","subnet":"unknown","gateway":"unknown"}
def load_previous_context():
    if not os.path.exists(CTX_FILE): return None
    try:
        with open(CTX_FILE) as f: return json.load(f)
    except: return None
def save_context(ctx):
    os.makedirs(STACK,exist_ok=True)
    with open(CTX_FILE,"w") as f: json.dump(ctx,f,indent=2)
def run_network_check():
    current=get_current_context()
    previous=load_previous_context()
    print(f"\n{CYAN}  NETWORK CONTEXT{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
    print(f"  ip      : {current['ip']}")
    print(f"  subnet  : {current['subnet']}")
    print(f"  gateway : {current['gateway']}")
    if previous:
        changed=[]
        if current['subnet']!=previous.get('subnet'):
            changed.append('subnet')
            print(f"  {RED}[!] subnet changed{RESET}")
            print(f"  {DIM}  was: {previous.get('subnet')}{RESET}")
        if current['gateway']!=previous.get('gateway'):
            changed.append('gateway')
            print(f"  {RED}[!] gateway changed{RESET}")
            print(f"  {DIM}  was: {previous.get('gateway')}{RESET}")
        if changed:
            print(f"\n  {YELLOW}network has changed since last session{RESET}")
            confirm=input("  continue on this network? [y/n] > ").strip().lower()
            if confirm!='y':
                print(f"  {RED}aborted — network not confirmed{RESET}")
                return False
        else:
            print(f"  {GREEN}network unchanged from last session{RESET}")
    else:
        print(f"  {DIM}first session on this network{RESET}")
    save_context(current)
    print(f"  {DIM}{'─'*46}{RESET}")
    return True
