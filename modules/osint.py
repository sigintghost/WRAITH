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

osint_results={}
def save_osint_results():
    try:
        from modules.filestack import write_json
        write_json('osint_results.json',osint_results)
    except: pass
def osint_lookup(ip):
    global osint_results
    virustotal_lookup(ip)
    hackertarget_lookup(ip)
    bgpview_lookup(ip)
    threatfox_lookup(ip)
    dnsdumpster_lookup(ip)
    criminalip_lookup(ip)
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
        if not body or body.strip() == "" or body.strip().startswith("<"):
            print("  internetdb: no data returned")
        else:
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
        import urllib.request, ssl, json
        ctx = ssl._create_unverified_context()
        url = "https://search.censys.io/api/v2/hosts/" + ip
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "WRAITH/3.4")
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            data = json.loads(r.read())
        result = data.get("result", {})
        services = result.get("services", [])
        print(f"  censys: {len(services)} services found")
        for svc in services[:5]:
            port = svc.get("port")
            proto = svc.get("service_name")
            print(f"    port={port} proto={proto}")
    except Exception as e:
        print(f"  censys: unavailable {e}")

    save_osint_results()
    osint_results[ip]={"queried":True}
def urlscan_lookup(ip):
    print("  -- URLSCAN --")
    try:
        import socket, json, ssl
        host = "urlscan.io"
        path = "/api/v1/search/?q=ip:" + ip + "&size=5"
        req = chr(71)+chr(69)+chr(84)+chr(32) + path + chr(32)+chr(72)+chr(84)+chr(84)+chr(80)+chr(47)+chr(49)+chr(46)+chr(48) + chr(13)+chr(10) + chr(72)+chr(111)+chr(115)+chr(116)+chr(58)+chr(32)+chr(117)+chr(114)+chr(108)+chr(115)+chr(99)+chr(97)+chr(110)+chr(46)+chr(105)+chr(111) + chr(13)+chr(10) + chr(65)+chr(99)+chr(99)+chr(101)+chr(112)+chr(116)+chr(58)+chr(32)+chr(97)+chr(112)+chr(112)+chr(108)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)+chr(47)+chr(106)+chr(115)+chr(111)+chr(110) + chr(13)+chr(10) + chr(13)+chr(10)
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
def virustotal_lookup(ip):
    print("  -- VIRUSTOTAL --")
    try:
        import urllib.request,json,ssl
        ctx=ssl._create_unverified_context()
        url=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        req=urllib.request.Request(url)
        req.add_header("x-apikey","")
        with urllib.request.urlopen(req,context=ctx,timeout=5) as r:
            data=json.loads(r.read())
        stats=data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        mal=stats.get("malicious",0)
        sus=stats.get("suspicious",0)
        total=sum(stats.values())
        print(f"  virustotal: {mal} malicious {sus} suspicious of {total} engines")
        if mal>0:
            print(f"  FLAGGED AS MALICIOUS by {mal} vendors")
    except Exception as e:
        print(f"  virustotal: unavailable {e}")
def cisa_kev_lookup(vendor_keyword):
    print("  -- CISA KEV --")
    try:
        import urllib.request,json,ssl
        ctx=ssl._create_unverified_context()
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        with urllib.request.urlopen(url,context=ctx,timeout=10) as r:
            data=json.loads(r.read())
        vulns=data.get("vulnerabilities",[])
        matches=[v for v in vulns if vendor_keyword.lower() in
                 v.get("vendorProject","").lower() or
                 vendor_keyword.lower() in v.get("product","").lower()]
        if matches:
            print(f"  CISA KEV: {len(matches)} known exploited CVEs for {vendor_keyword}")
            for v in matches[:3]:
                print(f"  {v.get('cveID')} — {v.get('product')} — due:{v.get('dueDate')}")
        else:
            print(f"  CISA KEV: no known exploited CVEs for {vendor_keyword}")
    except Exception as e:
        print(f"  CISA KEV: unavailable {e}")
def hackertarget_lookup(ip):
    print("  -- HACKERTARGET --")
    try:
        import urllib.request,ssl
        ctx=ssl._create_unverified_context()
        url=f"https://api.hackertarget.com/hostsearch/?q={ip}"
        with urllib.request.urlopen(url,context=ctx,timeout=5) as r:
            data=r.read().decode()
        lines=[l for l in data.split('\n') if l.strip()]
        if lines and 'error' not in lines[0].lower():
            print(f"  hackertarget: {len(lines)} related hosts")
            for l in lines[:3]:
                print(f"  {l}")
        else:
            print(f"  hackertarget: no results")
    except Exception as e:
        print(f"  hackertarget: unavailable {e}")
def bgpview_lookup(ip):
    print("  -- BGPVIEW --")
    try:
        import urllib.request,json,ssl
        ctx=ssl._create_unverified_context()
        url=f"https://api.bgpview.io/ip/{ip}"
        with urllib.request.urlopen(url,context=ctx,timeout=5) as r:
            data=json.loads(r.read())
        prefixes=data.get("data",{}).get("prefixes",[])
        if prefixes:
            p=prefixes[0]
            asn=p.get("asn",{}).get("asn","")
            name=p.get("asn",{}).get("name","")
            prefix=p.get("prefix","")
            print(f"  bgpview: ASN{asn} {name} prefix={prefix}")
        else:
            print(f"  bgpview: no BGP data")
    except Exception as e:
        print(f"  bgpview: unavailable {e}")
def threatfox_lookup(ip):
    print("  -- THREATFOX --")
    try:
        import urllib.request,json,ssl
        keys=load_keys()
        tfkey=keys.get("THREATFOX_KEY","")
        ctx=ssl._create_unverified_context()
        payload=json.dumps({"query":"search_ioc","search_term":ip}).encode()
        hdrs={"Content-Type":"application/json"}
        if tfkey: hdrs["Auth-Key"]=tfkey
        req=urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=payload,
            headers=hdrs)
        with urllib.request.urlopen(req,context=ctx,timeout=5) as r:
            data=json.loads(r.read())
        if data.get("query_status")=="ok":
            iocs=data.get("data",[])
            print(f"  threatfox: {len(iocs)} IOC matches")
            for ioc in iocs[:2]:
                print(f"  {ioc.get('threat_type')} — {ioc.get('malware')}")
        else:
            print(f"  threatfox: not in database")
    except Exception as e:
        print(f"  threatfox: unavailable {e}")
def dnsdumpster_lookup(ip):
    print("  -- DNSDUMPSTER --")
    try:
        import urllib.request,ssl
        ctx=ssl._create_unverified_context()
        url=f"https://api.hackertarget.com/reversedns/?q={ip}"
        with urllib.request.urlopen(url,context=ctx,timeout=5) as r:
            data=r.read().decode()
        if data and 'error' not in data.lower():
            print(f"  reverse dns: {data.strip()[:100]}")
        else:
            print(f"  reverse dns: no results")
    except Exception as e:
        print(f"  dnsdumpster: unavailable {e}")
def criminalip_lookup(ip, key=""):
    print("  -- CRIMINAL IP --")
    try:
        import urllib.request,json,ssl
        ctx=ssl._create_unverified_context()
        url=f"https://api.criminalip.io/v1/ip/summary?ip={ip}"
        req=urllib.request.Request(url)
        if key: req.add_header("x-api-key",key)
        with urllib.request.urlopen(req,context=ctx,timeout=5) as r:
            data=json.loads(r.read())
        score=data.get("inbound_score","")
        country=data.get("country","")
        issues=data.get("issues",{})
        print(f"  criminal ip: score={score} country={country}")
        if issues:
            flags=[k for k,v in issues.items() if v]
            if flags: print(f"  flags: {', '.join(flags)}")
    except Exception as e:
        print(f"  criminal ip: unavailable {e}")
