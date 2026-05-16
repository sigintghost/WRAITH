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
    if 53 in ports and (80 in ports or 443 in ports):
        score += 25
        reasons.append('gateway position +25')
    if 80 in ports or 443 in ports:
        score += 15
        reasons.append('HTTP management UI +15')
    if 53 in ports:
        score += 10
        reasons.append('DNS exposed +10')
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

def _detect_caps():
    import os, shutil
    caps = {
        'linux': os.path.exists('/proc/version'),
        'root': os.geteuid() == 0 if hasattr(os,'geteuid') else False,
        'rtl_sdr': os.path.exists('/dev/swradio0') or shutil.which('rtl_test') is not None,
        'monitor_wifi': os.path.exists('/sys/class/net'),
        'ble': os.path.exists('/dev/hci0'),
        'tcpdump': shutil.which('tcpdump') is not None,
        'ip_cmd': shutil.which('ip') is not None,
    }
    caps['deauth'] = caps['linux'] and caps['monitor_wifi'] and caps['root']
    caps['null_route'] = caps['linux'] and caps['root'] and caps['ip_cmd']
    caps['pcap'] = caps['linux'] and caps['tcpdump'] and caps['root']
    caps['rf'] = caps['rtl_sdr'] and caps['linux']
    caps['ble_scan'] = caps['ble'] and caps['linux']
    return caps

def present_action_queue(ip, score, reasons):
    C='\033[36m';R='\033[31m';Y='\033[33m'
    D='\033[2m';B='\033[1m';RS='\033[0m'
    from modules.doxa.doxa_execute import (
        isolate_recommend, flag_alert,
        annotate_host, tag_device)
    caps = _detect_caps()
    G='[32m'
    print(f"\n  {R}{B}[ACTION QUEUE]{RS} {C}{ip}{RS} score={score}")
    print(f"  {D}confidence threshold exceeded — operator action required{RS}")
    print(f"\n  {C}[AVAILABLE NOW]{RS}")
    print(f"  {C}[1]{RS} isolate_recommend  — VLAN quarantine steps")
    print(f"  {C}[2]{RS} flag_alert         — escalate to CRITICAL")
    print(f"  {C}[3]{RS} annotate_host      — add investigation note")
    print(f"  {C}[4]{RS} tag_device         — mark INVESTIGATE")
    print(f"  {C}[5]{RS} run_portscan       — deep scan this host")
    print(f"  {C}[6]{RS} run_passive_dns    — resolve hostname")
    print(f"  {C}[7]{RS} run_credentials    — default cred check")
    print(f"  {C}[8]{RS} run_sweep          — full subnet rescan")
    print(f"\n  {Y}[REQUIRES LINUX + ROOT]{RS}")
    lx = G if caps['null_route'] else R
    print(f"  {lx}[9]{RS} null_route         — IP black hole {'[READY]' if caps['null_route'] else '[unlock: Linux+root+ip cmd]'}")
    dh = G if caps['deauth'] else R
    print(f"  {dh}[a]{RS} deauth_storm       — WiFi ejection {'[READY]' if caps['deauth'] else '[unlock: Linux+root+monitor mode WiFi]'}")
    pc = G if caps['pcap'] else R
    print(f"  {pc}[b]{RS} pcap_start         — packet capture {'[READY]' if caps['pcap'] else '[unlock: Linux+root+tcpdump]'}")
    print(f"\n  {Y}[REQUIRES HARDWARE]{RS}")
    rf = G if caps['rf'] else R
    print(f"  {rf}[c]{RS} rtl_scan           — RF spectrum {'[READY]' if caps['rf'] else '[unlock: RTL-SDR V4 + Linux]'}")
    bl = G if caps['ble_scan'] else R
    print(f"  {bl}[d]{RS} ble_scan           — Bluetooth enum {'[READY]' if caps['ble_scan'] else '[unlock: BLE USB + Linux]'}")
    print(f"\n  {C}[0]{RS} skip")
    sel = input(f"  action > ").strip().lower()
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
    elif sel == '7':
        from modules.protocols.credential_exposure import run_credential_exposure
        run_credential_exposure()
    elif sel == '8':
        from modules.core.sweep import run_sweep
        base = ip.rsplit('.',1)[0]
        import socket
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(('8.8.8.8',80)); lip=s.getsockname()[0]; s.close()
        run_sweep(base, lip)
    elif sel == '9':
        if caps['null_route']:
            import subprocess
            subprocess.run(['ip','route','add','blackhole',ip])
            print(f"  {R}[EXEC] null route added for {ip}{RS}")
        else: print(f"  {R}not available — {caps}{RS}")
    elif sel == 'a':
        if caps['deauth']:
            print(f"  {Y}[EXEC] deauth_storm not yet implemented — Linux module pending{RS}")
        else: print(f"  {R}not available — requires Linux+root+monitor mode WiFi{RS}")
    elif sel == 'b':
        if caps['pcap']:
            import subprocess
            subprocess.Popen(['tcpdump','-i','any','-w',
                f'/tmp/wraith_{ip.replace(".","_")}.pcap',f'host {ip}'])
            print(f"  {G}[EXEC] pcap started — /tmp/wraith_{ip.replace('.','_')}.pcap{RS}")
        else: print(f"  {R}not available — requires Linux+root+tcpdump{RS}")
    elif sel == 'c':
        if caps['rf']: print(f"  {Y}[EXEC] rtl_scan pending — RTL-SDR module in development{RS}")
        else: print(f"  {R}not available — requires RTL-SDR V4 + Linux{RS}")
    elif sel == 'd':
        if caps['ble_scan']: print(f"  {Y}[EXEC] ble_scan pending — BLE module in development{RS}")
        else: print(f"  {R}not available — requires BLE USB adapter + Linux{RS}")
