import os, json
from datetime import datetime, timezone
from modules.core.asset_registry import all_records, upsert as reg_upsert
from modules.core.alerts import fire

THRESHOLD = 60

def _days_since(ts):
    try:
        dt = datetime.fromisoformat(ts.replace('Z','+00:00'))
        return (datetime.now(timezone.utc) - dt).days
    except: return 0

def score_host(rec):
    score = 0
    reasons = []
    if not rec['authorized']:
        score += 20
        reasons.append('unauthorized +20')
    ports = rec['network']['open_ports']
    PROXY_PORTS = {8080,3128,1080,8888,9090}
    OT_PORTS = {502,47808,102,44818,4840,20000}
    if any(p in PROXY_PORTS for p in ports):
        score += 25
        reasons.append('proxy port +25')
    if any(p in OT_PORTS for p in ports):
        score += 20
        reasons.append('OT port +20')
    ioc = rec['threat']['ioc_flags']
    if ioc:
        score += 20
        reasons.append(f'IOC flags +20 ({len(ioc)})')
    if 'LATERAL_MOVEMENT' in str(ioc):
        score += 30
        reasons.append('lateral movement +30')
    if not rec['network']['mac']:
        score += 10
        reasons.append('MAC missing +10')
    first = rec['temporal']['first_seen']
    if _days_since(first) > 7 and not rec['authorized']:
        score += 10
        reasons.append('persistent unauthorized +10')
    cred_risk = any('DEFAULT_CRED' in str(f) for f in ioc)
    if cred_risk:
        score += 15
        reasons.append('default cred risk +15')
    return score, reasons

def run_scorer(silent=False):
    C='\033[36m';R='\033[31m';Y='\033[33m';G='\033[32m'
    D='\033[2m';B='\033[1m';RS='\033[0m'
    recs = all_records()
    scored = []
    for rec in recs:
        score, reasons = score_host(rec)
        ip = rec['network']['ip']
        reg_upsert(ip=ip, mac='', source='confidence_scorer',
            **{'threat.confidence_score': float(score)})
        scored.append((score, ip, reasons, rec))
        if score >= THRESHOLD:
            fire('HIGH_CONFIDENCE_THREAT',
                f"{ip} confidence score {score} — threshold exceeded",
                severity='CRITICAL' if score>=80 else 'HIGH',
                source='confidence_scorer', ip=ip)
    scored.sort(reverse=True)
    if not silent:
        print(f"\n{C}  [SCORER] confidence threat assessment{RS}")
        print(f"  {D}threshold: {THRESHOLD}{RS}\n")
        for score, ip, reasons, rec in scored:
            color = R if score>=80 else Y if score>=THRESHOLD else G
            auth = '' if rec['authorized'] else f" {R}UNAUTH{RS}"
            print(f"  {color}{B}{score:>3}{RS} {C}{ip}{RS}{auth}")
            if score >= THRESHOLD:
                for r in reasons:
                    print(f"       {D}+ {r}{RS}")
    return scored

def get_high_confidence_hosts():
    scored = run_scorer(silent=True)
    return [(s,ip,r,rec) for s,ip,r,rec in scored if s>=THRESHOLD]

def present_action_queue(ip, score, reasons):
    C='\033[36m';R='\033[31m';Y='\033[33m'
    D='\033[2m';B='\033[1m';RS='\033[0m'
    from modules.doxa.doxa_execute import (
        isolate_recommend, flag_alert,
        annotate_host, tag_device)
    print(f"\n  {R}{B}[ACTION QUEUE]{RS} {C}{ip}{RS} score={score}")
    print(f"  {D}confidence threshold exceeded — operator action required{RS}")
    print(f"\n  {C}[1]{RS} isolate_recommend — VLAN quarantine")
    print(f"  {C}[2]{RS} flag_alert — escalate to CRITICAL")
    print(f"  {C}[3]{RS} annotate_host — add investigation note")
    print(f"  {C}[4]{RS} tag_device — mark for investigation")
    print(f"  {C}[5]{RS} run_portscan — deep scan this host")
    print(f"  {C}[6]{RS} run_passive_dns — resolve hostname")
    print(f"  {C}[0]{RS} skip")
    sel = input(f"  action > ").strip()
    if sel == '0' or not sel: return
    if sel == '1': isolate_recommend(ip)
    elif sel == '2':
        reason = ', '.join(reasons[:3])
        flag_alert(ip, reason)
    elif sel == '3':
        note = f"confidence score {score} — {', '.join(reasons[:2])}"
        annotate_host(ip, note)
    elif sel == '4': tag_device(ip, 'INVESTIGATE')
    elif sel == '5':
        from modules.core.portscan import run_portscan
        run_portscan(ip)
    elif sel == '6':
        from modules.protocols.passive_dns import run_passive_dns
        run_passive_dns()
