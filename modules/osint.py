# WRAITH osint.py — threat intelligence module
# sig.int.ghost
# every IP has a story. WRAITH just listens.
# the wire remembers everything. even silence.

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
    shodan_internetdb(ip)
    censys_lookup(ip)
    urlscan_lookup(ip)
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

def shodan_internetdb(ip):
    print("  -- SHODAN INTERNETDB --")
    try:
        import socket
        url = "internetdb.shodan.io/" + ip
        host = "internetdb.shodan.io"
        req = "GET /" + ip + " HTTP/1.0" + chr(13)+chr(10) + "Host: internetdb.shodan.io" + chr(13)+chr(10)+chr(13)+chr(10)

        s = socket.create_connection((host, 80), timeout=5)
        s.send(req.encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
        s.close()
        body = resp.decode(errors=chr(34)+chr(105)+chr(103)+chr(110)+chr(111)+chr(114)+chr(101)+chr(34)).split(chr(13)+chr(10)+chr(13)+chr(10),1)[-1]
        import json
        data = json.loads(body)
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        tags = data.get("tags", [])
        print(f"  internetdb: ports={ports}")
        print(f"  internetdb: vulns={vulns}")
        print(f"  internetdb: tags={tags}")
    except Exception as e:
        print(f"  internetdb: unavailable {e}")

def censys_lookup(ip):
    print("  -- CENSYS --")
    try:
        import socket, json
        host = "search.censys.io"
        path = "/api/v2/hosts/" + ip
        req = chr(71)+chr(69)+chr(84)+chr(32) + path + chr(32)+chr(72)+chr(84)+chr(84)+chr(80)+chr(47)+chr(49)+chr(46)+chr(48) + chr(13)+chr(10) + chr(72)+chr(111)+chr(115)+chr(116)+chr(58)+chr(32)+chr(115)+chr(101)+chr(97)+chr(114)+chr(99)+chr(104)+chr(46)+chr(99)+chr(101)+chr(110)+chr(115)+chr(121)+chr(115)+chr(46)+chr(105)+chr(111) + chr(13)+chr(10) + chr(65)+chr(99)+chr(99)+chr(101)+chr(112)+chr(116)+chr(58)+chr(32)+chr(97)+chr(112)+chr(112)+chr(108)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)+chr(47)+chr(106)+chr(115)+chr(111)+chr(110) + chr(13)+chr(10) + chr(13)+chr(10)
        s = socket.create_connection((host, 443), timeout=5)
        import ssl
        s = ssl.wrap_socket(s)
        s.send(req.encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
        s.close()
        body = resp.decode(errors=chr(34)+chr(105)+chr(103)+chr(110)+chr(111)+chr(114)+chr(101)+chr(34)).split(chr(13)+chr(10)+chr(13)+chr(10),1)[-1]

        data = json.loads(body)
        result = data.get("result", {})
        services = result.get("services", [])
        print(f"  censys: {len(services)} services found")
        for svc in services[:5]:
            port = svc.get("port")
            proto = svc.get("service_name")
            print(f"    port={port} proto={proto}")
    except Exception as e:
        print(f"  censys: unavailable {e}")

def urlscan_lookup(ip):
    print("  -- URLSCAN --")
    try:
        import socket, json, ssl
        host = "urlscan.io"
        path = "/api/v1/search/?q=ip:" + ip + "&size=5"
        req = chr(71)+chr(69)+chr(84)+chr(32) + path + chr(32)+chr(72)+chr(84)+chr(84)+chr(80)+chr(47)+chr(49)+chr(46)+chr(48) + chr(13)+chr(10) + chr(72)+chr(111)+chr(115)+chr(116)+chr(58)+chr(32)+chr(117)+chr(114)+chr(108)+chr(115)+chr(99)+chr(97)+chr(110)+chr(46)+chr(105)+chr(111) + chr(13)+chr(10) + chr(65)+chr(99)+chr(99)+chr(101)+chr(112)+chr(116)+chr(58)+chr(32)+chr(97)+chr(112)+chr(112)+chr(108)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)+chr(47)+chr(106)+chr(115)+chr(111)+chr(110) + chr(13)+chr(10) + chr(13)+chr(10)
        body = resp.decode(errors=chr(34)+chr(105)+chr(103)+chr(110)+chr(111)+chr(114)+chr(101)+chr(34)).split(chr(13)+chr(10)+chr(13)+chr(10),1)[-1]
        s = socket.create_connection((host, 443), timeout=5)
        s = ssl.wrap_socket(s)
        s.send(req.encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
        s.close()
        body = resp.decode(errors=chr(34)+chr(105)+chr(103)+chr(110)+chr(111)+chr(114)+chr(101)+chr(34)).split(chr(13)+chr(10)+chr(13)+chr(10),1)[-1]

        data = json.loads(body)
        total = data.get("total", 0)
        results = data.get("results", [])
        print(f"  urlscan: {total} historical scans found")
        for r in results[:3]:
            page = r.get("page", {})
            url = page.get("url", "unknown")
            print(f"    url={url}")
    except Exception as e:
        print(f"  urlscan: unavailable {e}")
