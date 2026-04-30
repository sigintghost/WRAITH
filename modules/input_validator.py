# modules/input_validator.py
# sanitize all user inputs — IP, subnet, port
import re
RED='\033[31m';YELLOW='\033[33m';RESET='\033[0m'
def valid_ip(ip):
    ip=ip.strip()
    pattern=r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern,ip): return False
    parts=ip.split('.')
    return all(0<=int(p)<=255 for p in parts)
def valid_port(port):
    try:
        p=int(port)
        return 1<=p<=65535
    except: return False
def valid_subnet(subnet):
    try:
        ip,cidr=subnet.split('/')
        return valid_ip(ip) and 0<=int(cidr)<=32
    except: return False
def get_valid_ip(prompt, default=None):
    while True:
        val=input(prompt).strip()
        if not val and default: return default
        if valid_ip(val): return val
        print(f"  {RED}invalid IP — use format x.x.x.x{RESET}")
def get_valid_port(prompt, default=None):
    while True:
        val=input(prompt).strip()
        if not val and default: return default
        if valid_port(val): return int(val)
        print(f"  {RED}invalid port — use 1-65535{RESET}")
def sanitize_text_input(value, max_len=256):
    import html, re
    value=html.escape(value.strip())
    value=re.sub(r'[\x00-\x1f\x7f]','',value)
    return value[:max_len]
