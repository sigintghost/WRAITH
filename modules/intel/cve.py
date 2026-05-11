# modules/cve.py
# WRAITH CVE intelligence — NIST NVD free API
# no key required — doxa reads findings
# sig.int.ghost — the wire remembers every wound
import urllib.request, json, ssl, os, time
CYAN='\033[36m';GREEN='\033[32m';YELLOW='\033[33m'
RED='\033[31m';DIM='\033[2m';BOLD='\033[1m';RESET='\033[0m'
NVD_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"
STACK=os.path.expanduser("~/.wraith/loot/stack")
def nvd_search(keyword, max_results=5):
    try:
        ctx=ssl._create_unverified_context()
        url=f"{NVD_URL}?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage={max_results}"
        req=urllib.request.Request(url,headers={"User-Agent":"WRAITH/3.6"})
        with urllib.request.urlopen(req,context=ctx,timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error":str(e)}
def parse_cves(data):
    results=[]
    if "error" in data: return results
    for item in data.get("vulnerabilities",[]):
        cve=item.get("cve",{})
        cve_id=cve.get("id","")
        desc=""
        for d in cve.get("descriptions",[]):
            if d.get("lang")=="en":
                desc=d.get("value","")[:200]
                break
        cvss=0.0
        severity="UNKNOWN"
        metrics=cve.get("metrics",{})
        for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if key in metrics and metrics[key]:
                m=metrics[key][0]
                cvss=m.get("cvssData",{}).get("baseScore",0.0)
                severity=m.get("cvssData",{}).get("baseSeverity","UNKNOWN")
                break
        results.append({
            "id":cve_id,
            "cvss":cvss,
            "severity":severity,
            "description":desc
        })
    return sorted(results,key=lambda x:x["cvss"],reverse=True)
def scan_bacnet_inventory():
    fp=os.path.join(STACK,"bacnet_inventory.json")
    if not os.path.exists(fp): return {}
    with open(fp) as f: inv=json.load(f)
    vendors=set()
    for dev in inv.values() if isinstance(inv,dict) else []:
        v=dev.get("vendor","")
        if v and v!="unknown": vendors.add(v)
    return {v:[] for v in vendors}
def scan_snmp_inventory():
    fp=os.path.join(STACK,"snmp_inventory.json")
    if not os.path.exists(fp): return {}
    with open(fp) as f: inv=json.load(f)
    vendors=set()
    devices=inv.get("devices",inv) if isinstance(inv,dict) else {}
    for dev in devices.values():
        v=dev.get("version","")
        if v: vendors.add(v)
    return {v:[] for v in vendors}
def run_cve_scan(keywords=None):
    print(f"\n{CYAN}{BOLD}  CVE INTELLIGENCE{RESET}")
    print(f"  {DIM}NIST NVD — no key required{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
    targets={}
    if not keywords:
        targets.update(scan_bacnet_inventory())
        targets.update(scan_snmp_inventory())
        if not targets:
            kw=input("  enter vendor/product to search > ").strip()
            if kw: targets[kw]=[]
    else:
        for k in keywords: targets[k]=[]
    if not targets:
        print(f"  {YELLOW}no targets found in filestack{RESET}")
        return
    findings={}
    for vendor in targets:
        print(f"  {DIM}searching: {vendor}...{RESET}")
        data=nvd_search(vendor)
        cves=parse_cves(data)
        findings[vendor]=cves
        if cves:
            top=cves[0]
            print(f"  {CYAN}{vendor}{RESET} — {len(cves)} CVEs")
            print(f"  {DIM}highest: {top['id']} CVSS={top['cvss']} [{top['severity']}]{RESET}")
        else:
            print(f"  {GREEN}{vendor}{RESET} — {DIM}no CVEs found{RESET}")
        time.sleep(1)
    return findings
def run_cve_module():
    kw=input("  vendor to check CISA KEV [enter to skip] > ").strip()
    if kw:
        try:
            from modules.intel.osint import cisa_kev_lookup
            cisa_kev_lookup(kw)
        except Exception as e:
            print(f"  CISA KEV error: {e}")
    findings=run_cve_scan()
    if not findings: return
    print(f"\n{CYAN}{BOLD}  CVE DETAIL{RESET}")
    print(f"  {DIM}{'─'*46}{RESET}")
    all_cves=[]
    for vendor,cves in findings.items():
        for c in cves:
            c["vendor"]=vendor
            all_cves.append(c)
            sev=c["severity"]
            col=RED if sev in("CRITICAL","HIGH") else YELLOW if sev=="MEDIUM" else DIM
            print(f"  {col}{c['id']}{RESET} CVSS={c['cvss']} [{sev}]")
            print(f"  {DIM}  vendor: {vendor}{RESET}")
            print(f"  {DIM}  {c['description'][:120]}{RESET}")
    try:
        from modules.core.filestack import write_json
        write_json('cve_findings.json',{
            'scan_time':time.strftime('%Y-%m-%dT%H:%M:%S'),
            'findings':findings,
            'total':len(all_cves)
        })
        print(f"\n  {GREEN}written to cve_findings.json{RESET}")
    except Exception as e:
        print(f"  {YELLOW}filestack write failed: {e}{RESET}")
