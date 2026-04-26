import urllib.request
import urllib.parse
import json
import os
import sys

def div():
    print("  " + "="*44)

def load_keys():
    key_path = os.path.expanduser("~/.wraith/keys.py")
    keys = {
        "SHODAN_KEY": "",
        "IPINFO_KEY": "",
        "GREYNOISE_KEY": "",
        "ABUSEIPDB_KEY": ""
    }
    if os.path.exists(key_path):
        with open(key_path) as f:
            for line in f:
                for key in keys:
                    if line.startswith(key):
                        keys[key] = line.split('"')[1]
        print("  keys loaded from ~/.wraith/keys.py")
    else:
        print("  no keys found — running without OSINT APIs")
        print("  see modules/keys_template.py to set up keys")
    return keys

def ipinfo_lookup(ip, key):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        if key:
            url += f"?token={key}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "WRAITH/1.2"})
        data = json.loads(
            urllib.request.urlopen(req, timeout=3).read())
        print(f"  org      : {data.get('org','unknown')}")
        print(f"  city     : {data.get('city','unknown')}")
        print(f"  country  : {data.get('country','unknown')}")
        print(f"  hostname : {data.get('hostname','unknown')}")
    except Exception as e:
        print(f"  ipinfo   : unavailable")

def shodan_lookup(ip, key):
    if not key:
        print("  shodan   : no key configured")
        return
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        data = json.loads(
            urllib.request.urlopen(url, timeout=3).read())
        ports = data.get('ports', [])
        vulns = list(data.get('vulns', {}).keys())
        print(f"  org      : {data.get('org','unknown')}")
        print(f"  os       : {data.get('os','unknown')}")
        print(f"  ports    : {ports}")
        ot = [p for p in ports if p in [47808,502,1911,4911,102,44818,20000]]
        if ot:
            print(f"  OT PORTS : {ot} — CRITICAL")
        if vulns:
            print(f"  VULNS    : {vulns}")
    except Exception as e:
        print(f"  shodan   : {e}")

def greynoise_check(ip, key):
    if not key:
        print("  greynoise: no key configured")
        return
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        req = urllib.request.Request(
            url, headers={
                "key": key,
                "User-Agent": "WRAITH/1.2"
            })
        data = json.loads(
            urllib.request.urlopen(req, timeout=3).read())
        classification = data.get('classification','unknown')
        noise = data.get('noise', False)
        print(f"  greynoise: {classification} noise={noise}")
        if classification == 'malicious':
            print(f"  WARNING  : IP flagged MALICIOUS")
    except:
        print(f"  greynoise: unavailable")

def abuseipdb_check(ip, key):
    if not key:
        print("  abuseipdb: no key configured")
        return
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(
            url, headers={
                "Key": key,
                "Accept": "application/json",
                "User-Agent": "WRAITH/1.2"
            })
        data = json.loads(
            urllib.request.urlopen(req, timeout=3).read())
        score = data.get('data',{}).get('abuseConfidenceScore',0)
        reports = data.get('data',{}).get('totalReports',0)
        print(f"  abuseipdb: score={score}% reports={reports}")
        if score > 50:
            print(f"  WARNING  : HIGH ABUSE SCORE {score}%")
    except:
        print(f"  abuseipdb: unavailable")

def osint_lookup(ip):
    print(f"\n  [OSINT] {ip}")
    div()
    keys = load_keys()
    print(f"\n  -- IP INFO --")
    ipinfo_lookup(ip, keys["IPINFO_KEY"])
    print(f"\n  -- SHODAN --")
    shodan_lookup(ip, keys["SHODAN_KEY"])
    print(f"\n  -- THREAT INTEL --")
    greynoise_check(ip, keys["GREYNOISE_KEY"])
    abuseipdb_check(ip, keys["ABUSEIPDB_KEY"])
    div()
