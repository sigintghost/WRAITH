# modules/keys_manager.py
# WRAITH key management module
import os, getpass
KEYS_DIR = os.path.expanduser("~/.wraith")
KEYS_FILE = os.path.join(KEYS_DIR, "keys.py")
CYAN='\033[36m';GREEN='\033[32m';YELLOW='\033[33m'
RED='\033[31m';DIM='\033[2m';BOLD='\033[1m';RESET='\033[0m'
KEY_INFO = {
"ANTHROPIC_KEY":{"label":"Anthropic DOXA","url":"console.anthropic.com","free":"pay per token — no free tier","modules":"DOXA AI agent","fmt":"sk-ant-","req":True},
"SHODAN_KEY":{"label":"Shodan","url":"shodan.io/register","free":"free limited, paid $69/yr","modules":"OSINT ports, CVEs, services","fmt":"","req":False},
"IPINFO_KEY":{"label":"IPInfo","url":"ipinfo.io/signup","free":"50k/month free","modules":"OSINT geo, ASN, org","fmt":"","req":False},
"GREYNOISE_KEY":{"label":"GreyNoise","url":"greynoise.io/signup","free":"community plan free","modules":"OSINT noise classification","fmt":"","req":False},
"ABUSEIPDB_KEY":{"label":"AbuseIPDB","url":"abuseipdb.com/register","free":"1000/day free","modules":"OSINT abuse scoring","fmt":"","req":False},
"SMTP_HOST":{"label":"SMTP Email","url":"myaccount.google.com — App Passwords","free":"use existing Gmail or Proton account","modules":"CRITICAL email alerts","fmt":"","req":False,"multi":True},
"THREATFOX_KEY":{"label":"ThreatFox","url":"auth.abuse.ch/login","free":"free account required","modules":"OSINT IOC threat feed","fmt":"","req":False},
"PUSHOVER_KEY":{"label":"Pushover","url":"pushover.net","free":"$5 one time","modules":"phone push notifications","fmt":"","req":False},
}
def load_keys():
    if not os.path.exists(KEYS_FILE): return {}
    keys = {}
    with open(KEYS_FILE) as f:
        for line in f:
            line=line.strip()
            if '=' in line and not line.startswith('#'):
                k,v=line.split('=',1)
                keys[k.strip()]=v.strip().strip('"').strip("'")
    return keys
def save_keys(keys):
    os.makedirs(KEYS_DIR,exist_ok=True)
    lines=['# WRAITH keys — chmod 600 — never commit\n\n']
    for k,v in keys.items():
        lines.append(f'{k} = "{v}"\n')
    with open(KEYS_FILE,'w') as f: f.writelines(lines)
    os.chmod(KEYS_FILE,0o600)
    print(f"  {GREEN}saved{RESET} — {KEYS_FILE} chmod 600")
def check_keys():
    keys=load_keys()
    return [(k,i) for k,i in KEY_INFO.items() if not keys.get(k)]
def show_key_status():
    keys=load_keys()
    print(f"\n{CYAN}{BOLD}  API KEY STATUS{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
    for k,info in KEY_INFO.items():
        if info.get('multi'):
            host=keys.get('SMTP_HOST','')
            user=keys.get('SMTP_USER','')
            if host and user:
                status=f"{GREEN}SET{RESET} {DIM}{host}{RESET}"
            elif host or user:
                status=f"{YELLOW}PARTIAL{RESET} {DIM}incomplete{RESET}"
            else:
                status=f"{RED}MISSING{RESET} [{YELLOW}optional{RESET}]"
        else:
            val=keys.get(k,'')
            if val:
                status=f"{GREEN}SET{RESET} {DIM}[{len(val)} chars]{RESET}"
            else:
                req=f"{RED}REQUIRED{RESET}" if info['req'] else f"{YELLOW}optional{RESET}"
                status=f"{RED}MISSING{RESET} [{req}]"
        print(f"  {CYAN}{k:<20}{RESET} {status}")
        print(f"  {DIM}  {info['modules']}{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
def warn_missing_keys():
    missing=check_keys()
    if not missing: return
    req=[k for k,i in missing if i['req']]
    opt=[k for k,i in missing if not i['req']]
    if req:
        print(f"\n  {RED}[KEYS] REQUIRED missing:{RESET}")
        for k in req: print(f"  {RED}  — {k}{RESET}")
    if opt:
        print(f"  {YELLOW}[KEYS] optional not set:{RESET}")
        for k in opt: print(f"  {DIM}  — {k}{RESET}")
    print(f"  {DIM}  configure via [8] KEY MANAGEMENT{RESET}")
def setup_key(key_name):
    info=KEY_INFO[key_name]
    keys=load_keys()
    current=keys.get(key_name,'')
    print(f"\n{CYAN}{BOLD}  {info['label'].upper()}{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
    print(f"  enables : {info['modules']}")
    print(f"  register: {CYAN}{info['url']}{RESET}")
    print(f"  pricing : {info['free']}")
    if info['fmt']: print(f"  format  : starts with '{info['fmt']}'")
    if current:
        print(f"  current : {GREEN}SET [{len(current)} chars]{RESET}")
        if input("  keep current? [y/n] > ").strip().lower()=='y': return
    try: val=getpass.getpass("  paste key (hidden) > ")
    except: val=input("  paste key > ").strip()
    if not val: print(f"  {YELLOW}skipped{RESET}"); return
    if info['fmt'] and not val.startswith(info['fmt']):
        print(f"  {YELLOW}warning: expected '{info['fmt']}...'{RESET}")
        if input("  save anyway? [y/n] > ").strip().lower()!='y': return
    keys[key_name]=val
    save_keys(keys)
    print(f"  {GREEN}{key_name} saved{RESET}")
def setup_smtp():
    keys=load_keys()
    print(f"\n{CYAN}  SMTP EMAIL ALERTS{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
    print(f"  enables : CRITICAL event email alerts")
    print(f"  examples: smtp.gmail.com, smtp.office365.com")
    print(f"  {DIM}current:{RESET}")
    for k in ['SMTP_HOST','SMTP_PORT','SMTP_USER','SMTP_PASS','SMTP_TO']:
        v=keys.get(k,'')
        if v and k!='SMTP_PASS':
            print(f"  {k}: {GREEN}{v}{RESET}")
        elif v and k=='SMTP_PASS':
            print(f"  {k}: {GREEN}SET [{len(v)} chars]{RESET}")
        else:
            print(f"  {k}: {RED}not set{RESET}")
    print()
    host=input("  SMTP host [enter to skip] > ").strip()
    if host: keys['SMTP_HOST']=host
    port=input("  SMTP port [587] > ").strip()
    if host: keys['SMTP_PORT']=port if port else '587'
    user=input("  SMTP username/email > ").strip()
    if user: keys['SMTP_USER']=user
    try:
        import getpass
        pw=getpass.getpass("  SMTP password (hidden) > ")
    except:
        pw=input("  SMTP password > ").strip()
    if pw: keys['SMTP_PASS']=pw
    to=input("  send alerts to email > ").strip()
    if to: keys['SMTP_TO']=to
    save_keys(keys)
    print(f"  {GREEN}SMTP configured{RESET}")

def setup_pushover():
    keys=load_keys()
    print(f"\n{CYAN}  PUSHOVER NOTIFICATIONS{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
    print(f"  enables : phone push notifications")
    print(f"  register: pushover.net")
    print(f"  pricing : 7 day trial then $5 one time")
    try:
        import getpass
        token=getpass.getpass("  Pushover app token (hidden) > ")
        user=getpass.getpass("  Pushover user key (hidden) > ")
    except:
        token=input("  app token > ").strip()
        user=input("  user key > ").strip()
    if token: keys['PUSHOVER_KEY']=token
    if user: keys['PUSHOVER_USER']=user
    save_keys(keys)
    print(f"  {GREEN}Pushover configured{RESET}")

def delete_key(key_name):
    keys=load_keys()
    if not keys.get(key_name):
        print(f"  {YELLOW}{key_name} not set{RESET}"); return
    if input(f"  delete {key_name}? [y/n] > ").strip().lower()=='y':
        keys[key_name]=""
        save_keys(keys)
        print(f"  {RED}{key_name} deleted{RESET}")
def test_key(key_name):
    keys=load_keys()
    val=keys.get(key_name,'')
    if not val: print(f"  {RED}{key_name} not set{RESET}"); return
    print(f"  {DIM}testing {key_name}...{RESET}")
    if key_name=='ANTHROPIC_KEY':
        try:
            import urllib.request,json,ssl
            ctx=ssl._create_unverified_context()
            payload=json.dumps({"model":"claude-haiku-4-5","max_tokens":10,"messages":[{"role":"user","content":"ping"}]}).encode()
            req=urllib.request.Request("https://api.anthropic.com/v1/messages",data=payload,headers={"x-api-key":val,"anthropic-version":"2023-06-01","content-type":"application/json"})
            urllib.request.urlopen(req,context=ctx,timeout=5)
            print(f"  {GREEN}ANTHROPIC_KEY valid{RESET}")
        except Exception as e: print(f"  {RED}failed: {e}{RESET}")
    elif key_name=='SHODAN_KEY':
        try:
            import urllib.request,ssl
            ctx=ssl._create_unverified_context()
            urllib.request.urlopen(f"https://api.shodan.io/api-info?key={val}",context=ctx,timeout=5)
            print(f"  {GREEN}SHODAN_KEY valid{RESET}")
        except Exception as e: print(f"  {RED}failed: {e}{RESET}")
    else: print(f"  {YELLOW}test not available — run the module to verify{RESET}")
def run_keys_manager():
    while True:
        show_key_status()
        print(f"\n  {CYAN}[1]{RESET} add or update a key")
        print(f"  {CYAN}[2]{RESET} delete a key")
        print(f"  {CYAN}[3]{RESET} test a key")
        print(f"  {CYAN}[4]{RESET} setup all missing")
        print(f"  {CYAN}[5]{RESET} configure SMTP email")
        print(f"  {CYAN}[6]{RESET} configure Pushover")
        print(f"  {DIM}[0] back{RESET}")
        c=input("  > ").strip()
        if c=='0': break
        kl=list(KEY_INFO.keys())
        if c in('1','2','3'):
            for i,k in enumerate(kl):
                print(f"  [{i+1}] {k} {DIM}— {KEY_INFO[k]['modules']}{RESET}")
            sel=input("  select > ").strip()
            try:
                k=kl[int(sel)-1]
                if c=='1': setup_key(k)
                elif c=='2': delete_key(k)
                elif c=='3': test_key(k)
            except: print(f"  {RED}invalid{RESET}")
        elif c=='4':
            missing=check_keys()
            if not missing: print(f"  {GREEN}all keys configured{RESET}")
            else:
                for k,_ in missing: setup_key(k)
        elif c=='5': setup_smtp()
        elif c=='6': setup_pushover()
def first_run_keys():
    missing=[(k,i) for k,i in check_keys() if i['req']]
    if not missing: return
    print(f"\n  {YELLOW}[KEYS] configure required keys{RESET}")
    for k,_ in missing: setup_key(k)
