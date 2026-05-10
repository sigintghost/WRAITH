import os, json
from modules.filestack import get_stack

FIRST_RUN_FLAG = os.path.expanduser('~/.wraith/.initialized')

def is_first_run():
    return not os.path.exists(FIRST_RUN_FLAG)

def mark_initialized():
    os.makedirs(os.path.dirname(FIRST_RUN_FLAG), exist_ok=True)
    with open(FIRST_RUN_FLAG, 'w') as f:
        import datetime
        f.write(datetime.datetime.now().isoformat())

CYAN  = '\033[36m'
DIM   = '\033[2m'
RESET = '\033[0m'
BOLD  = '\033[1m'

def print_banner():
    print(f"\n  {CYAN}{'─'*44}{RESET}")
    print(f"  {BOLD}WRAITH — first run setup{RESET}")
    print(f"  {DIM}configure your environment{RESET}")
    print(f"  {CYAN}{'─'*44}{RESET}\n")

def setup_api_keys():
    print(f"\n  {CYAN}[STEP 1] API KEYS{RESET}")
    print(f"  {DIM}Anthropic key required. Others optional.{RESET}\n")
    import getpass
    keys = {}
    ak = getpass.getpass('  Anthropic API key (required): ').strip()
    if ak: keys['ANTHROPIC_KEY'] = ak
    else:
        print('  [!] Anthropic key required — DOXA will not function')
    sk = getpass.getpass('  Shodan API key [enter to skip]: ').strip()
    if sk: keys['SHODAN_KEY'] = sk
    ii = getpass.getpass('  IPInfo API key [enter to skip]: ').strip()
    if ii: keys['IPINFO_KEY'] = ii
    if keys:
        kp = os.path.expanduser('~/.wraith/keys.py')
        os.makedirs(os.path.dirname(kp), exist_ok=True)
        with open(kp, 'w') as f:
            for k,v in keys.items():
                f.write(f'{k} = "{v}"\n')
        os.chmod(kp, 0o600)
        print(f'  [+] {len(keys)} keys saved')
    return bool(keys)

def setup_integrations():
    print(f"\n  {CYAN}[STEP 2] INTEGRATIONS{RESET}")
    print(f"  {DIM}Configure data sources. All skippable.{RESET}\n")
    ans = input('  Setup Snowflake pipeline? [y/N]: ').strip().lower()
    if ans == 'y':
        from modules.snowflake_connector import setup_snowflake
        setup_snowflake()
    ans = input('  Setup WebCTRL PostgreSQL? [y/N]: ').strip().lower()
    if ans == 'y':
        from modules.pg_connector import setup_pg
        setup_pg()
    ans = input('  Setup CMMS work orders? [y/N]: ').strip().lower()
    if ans == 'y':
        from modules.workorder_agent import setup_workorder
        setup_workorder()
    ans = input('  Setup asset database connector? [y/N]: ').strip().lower()
    if ans == 'y':
        fsi_key = input('  Asset DB API key [enter to skip]: ').strip()
        fsi_url = input('  Asset DB base URL [enter to skip]: ').strip()
        if fsi_key and fsi_url:
            cfg = {'api_key': fsi_key, 'base_url': fsi_url}
            kp = os.path.expanduser('~/.wraith/asset_db.json')
            with open(kp,'w') as f: json.dump(cfg,f,indent=2)
            os.chmod(kp, 0o600)
            print('  [+] asset DB config saved')
    print('  [+] integrations configured')

def run_first_run():
    print_banner()
    print('  Welcome to WRAITH.')
    print('  This wizard runs once to configure your environment.')
    print('  All steps can be skipped and configured later.\n')
    ans = input('  Begin setup? [Y/n]: ').strip().lower()
    if ans == 'n':
        print('  [*] setup skipped — configure via KEYS and INTEGRATIONS menus')
        print('  [*] if first login: you will be prompted to create an admin account')
        mark_initialized()
        return
    setup_api_keys()
    setup_integrations()
    print(f"\n  {CYAN}{'─'*44}{RESET}")
    print('  WRAITH is ready.')
    print('  anomaly is the signal.')
    print(f"  {CYAN}{'─'*44}{RESET}\n")
    mark_initialized()
