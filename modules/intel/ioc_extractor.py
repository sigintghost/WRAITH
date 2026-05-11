import re, json, os
from modules.core.asset_registry import upsert as reg_upsert
from datetime import datetime
from modules.defense.sanitize import Sanitizer

STACK = os.path.expanduser("~/.wraith/loot/stack")
ALERTS = os.path.join(STACK, "alerts.json")
FINDINGS = os.path.join(STACK, "ioc_findings.json")
_s = Sanitizer()

IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
URL_RE = re.compile(
    r'https?://[^\s<>"\']+', re.IGNORECASE)
DOMAIN_RE = re.compile(
    r'(?<![\w.])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}'
    r'[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(?![\w.])',
    re.IGNORECASE)
PATH_RE = re.compile(
    r'(?:[A-Za-z]:\\|/)[^\s<>"\'*?|]+')
REGISTRY_RE = re.compile(
    r'HKEY_[A-Z_]+\\[^\s<>"\']+')

def load_json(path):
    try:
        if os.path.exists(path):
            with open(path) as f: return json.load(f)
    except: pass
    return {}

def save_json(path, data):
    try:
        with open(path,'w') as f:
            json.dump(data, f, indent=2)
    except: pass

def is_dga(domain):
    name = domain.split('.')[0].lower()
    if len(name) < 6: return False
    consonants = sum(1 for c in name
        if c in 'bcdfghjklmnpqrstvwxyz')
    ratio = consonants / len(name)
    return ratio > 0.70

def get_known_ips():
    known = set()
    for fname in ["hosts.json","arp_table.json"]:
        data = load_json(os.path.join(STACK, fname))
        for h in data.get("hosts", []):
            if isinstance(h, dict):
                ip = h.get("ip","")
                if ip: known.add(ip)
    return known

def write_alert(source, ioc_type, value, reason):
    value = _s.sanitize(str(value),
        "ioc_extractor", ioc_type)
    alert = {"timestamp": datetime.now().isoformat(),
        "module": "ioc_extractor",
        "severity": "WARNING",
        "source": source,
        "ioc_type": ioc_type,
        "value": value[:80],
        "reason": reason}
    data = load_json(ALERTS)
    if isinstance(data, dict):
        alerts = data.get("alerts", [])
    else:
        alerts = data if isinstance(data, list) else []
    alerts.append(alert)
    save_json(ALERTS, alerts)

def extract_iocs(text, source="unknown"):
    text = _s.sanitize(str(text),
        "ioc_extractor", "banner")
    iocs = {"ips": [], "urls": [], "domains": [],
        "paths": [], "registry": [], "dga": []}
    known_ips = get_known_ips()
    for ip in IP_RE.findall(text):
        iocs["ips"].append(ip)
        if ip not in known_ips:
            write_alert(source, "ip", ip,
                "UNKNOWN_IP_IN_BANNER")
            print(f"  \033[31m[IOC]\033[0m "
                f"unknown IP in banner: {ip}")
    return iocs, text

def extract_all(text, source="unknown"):
    iocs, text = extract_iocs(text, source)
    for url in URL_RE.findall(text):
        url = _s.sanitize(url,"ioc_extractor","url")
        iocs["urls"].append(url)
        write_alert(source, "url", url,
            "URL_IN_BANNER")
        print(f"  \033[31m[IOC]\033[0m "
            f"URL in banner: {url[:60]}")
    clean = re.sub(r'[\w.]+@', '', text)
    for domain in DOMAIN_RE.findall(clean):
        domain = _s.sanitize(domain,
            "ioc_extractor", "domain")
        if is_dga(domain):
            iocs["dga"].append(domain)
            write_alert(source, "dga", domain,
                "DGA_PATTERN_DOMAIN")
            print(f"  \033[31m[IOC]\033[0m "
                f"DGA domain: {domain}")
        else:
            iocs["domains"].append(domain)
            write_alert(source, "domain", domain,
                "DOMAIN_IN_BANNER")
            print(f"  \033[33m[IOC]\033[0m "
                f"domain in banner: {domain}")
    for path in PATH_RE.findall(text):
        path = _s.sanitize(path,
            "ioc_extractor","path")
        iocs["paths"].append(path)
        write_alert(source, "path", path,
            "PATH_IN_BANNER")
        print(f"  \033[33m[IOC]\033[0m "
            f"path in banner: {path[:60]}")
    for reg in REGISTRY_RE.findall(text):
        iocs["registry"].append(reg)
        write_alert(source, "registry", reg,
            "REGISTRY_KEY_IN_BANNER")
        print(f"  \033[31m[IOC]\033[0m "
            f"registry key: {reg[:60]}")
    return iocs

def scan_filestack():
    print("\033[36m[IOC]\033[0m scanning "
        "filestack for embedded IOCs...")
    findings = {}
    sources = {"http_banners.json": "banner",
        "snmp_inventory.json": "snmp",
        "bacnet_inventory.json": "bacnet"}
    for fname, label in sources.items():
        data = load_json(os.path.join(STACK, fname))
        text = json.dumps(data)
        if text and text != "{}":
            iocs = extract_all(text, label)
            total = sum(len(v) for v in iocs.values())
            if total:
                findings[fname] = iocs
                print(f"  [IOC] {fname}: "
                    f"{total} IOCs extracted")
    save_json(FINDINGS, findings)
    if not findings:
        print("\033[32m[IOC]\033[0m no IOCs found")
    return findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
        extract_all(text, "cli")
    else:
        scan_filestack()
