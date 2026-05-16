#!/usr/bin/env python3
# wraith_daemon.py — continuous passive intelligence
# sig.int.ghost
# Linux-native, iSH-compatible, hardware-gated
import os, sys, time, json, signal, random, threading
from datetime import datetime

DAEMON_LOG = os.path.expanduser('~/.wraith/daemon.log')
DAEMON_STATE = os.path.expanduser('~/.wraith/daemon_state.json')
os.makedirs(os.path.dirname(DAEMON_LOG), exist_ok=True)

C='\033[36m';G='\033[32m';Y='\033[33m';R='\033[31m'
D='\033[2m';B='\033[1m';RS='\033[0m'

_running = True
_cycle_count = 0
_last_sweep = None
_alerts_this_cycle = 0

def _now(): return datetime.utcnow().isoformat()+'Z'
def _ts(): return datetime.now().strftime('%H:%M:%S')

def _log(msg, level='INFO'):
    entry = f"{_now()} [{level}] {msg}\n"
    with open(DAEMON_LOG, 'a') as f: f.write(entry)

def _save_state():
    state = {
        'running': _running,
        'cycle_count': _cycle_count,
        'last_sweep': _last_sweep,
        'alerts_this_cycle': _alerts_this_cycle,
        'pid': os.getpid(),
        'started': _now()
    }
    tmp = DAEMON_STATE + '.tmp'
    with open(tmp,'w') as f: json.dump(state,f,indent=2)
    os.replace(tmp, DAEMON_STATE)

def _handle_signal(sig, frame):
    global _running
    print(f"\n  {Y}[DAEMON] signal {sig} received — shutting down{RS}")
    _log(f"signal {sig} received — shutdown initiated")
    _running = False

try:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
except: pass

def _jitter_sleep(base_seconds, jitter_seconds=300):
    jitter = random.randint(0, jitter_seconds)
    total = base_seconds + jitter
    print(f"  {D}next cycle in {total}s (base={base_seconds} jitter={jitter}){RS}")
    _log(f"sleeping {total}s until next cycle")
    deadline = time.time() + total
    while time.time() < deadline and _running:
        try: time.sleep(1)
        except KeyboardInterrupt: _running=False; break

def _check_hardware():
    caps = {
        'raw_socket': False,
        'rtl_sdr': False,
        'monitor_wifi': False,
        'ble': False,
    }
    try:
        import socket
        s = socket.socket(socket.AF_INET,
            socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        caps['raw_socket'] = True
    except: pass
    caps['rtl_sdr'] = os.path.exists('/dev/swradio0') or \
        os.path.exists('/dev/rtl_sdr')
    caps['ble'] = os.path.exists('/dev/hci0')
    return caps

def _network_cycle(gateway, local_ip, subnet):
    global _alerts_this_cycle
    print(f"\n  {C}[DAEMON]{RS} network cycle — {_ts()}")
    _log("network cycle start")
    try:
        from modules.core.sweep import run_sweep
        base = subnet.rsplit('.',1)[0]
        results = run_sweep(base, local_ip)
        _log(f"sweep complete — {len(results)} hosts")
    except Exception as e:
        _log(f"sweep error: {e}", 'WARN')
    try:
        from modules.defense.confidence_scorer import run_scorer, get_high_confidence_hosts
        run_scorer(silent=True)
        high = get_high_confidence_hosts()
        if high:
            print(f"  {R}[DAEMON]{RS} {len(high)} hosts above threshold")
            for score,ip,reasons,rec in high:
                print(f"  {R}  ! {ip} score={score}{RS}")
                _log(f"HIGH CONFIDENCE: {ip} score={score}")
                _alerts_this_cycle += 1
    except Exception as e:
        _log(f"scorer error: {e}", 'WARN')
    try:
        from modules.core.alerts import fire
        from modules.core.asset_registry import all_records
        recs = all_records()
        known_ips = set()
        try:
            with open(os.path.expanduser(
                '~/.wraith/daemon_known.json')) as f:
                known_ips = set(json.load(f))
        except: pass
        current_ips = {r['network']['ip'] for r in recs}
        new_hosts = current_ips - known_ips
        for ip in new_hosts:
            fire('NEW_HOST', f"new host detected: {ip}",
                severity='HIGH', source='daemon', ip=ip)
            print(f"  {Y}[DAEMON]{RS} new host: {ip}")
            _log(f"new host: {ip}", 'ALERT')
        tmp = os.path.expanduser('~/.wraith/daemon_known.json.tmp')
        with open(tmp,'w') as f:
            json.dump(list(current_ips), f)
        os.replace(tmp, os.path.expanduser(
            '~/.wraith/daemon_known.json'))
    except Exception as e:
        _log(f"new host check error: {e}", 'WARN')
    _log("network cycle complete")

def _check_subnet_change(current_subnet):
    state_file = os.path.expanduser('~/.wraith/last_subnet.json')
    try:
        with open(state_file) as f:
            last = json.load(f).get('subnet','')
        if last and last != current_subnet:
            from modules.core.alerts import fire
            fire('SUBNET_CHANGE',
                f"subnet changed: {last} -> {current_subnet}",
                severity='CRITICAL', source='daemon')
            print(f"  {R}[DAEMON] SUBNET CHANGE: {last} -> {current_subnet}{RS}")
            _log(f"subnet change: {last} -> {current_subnet}", 'ALERT')
            return True
    except: pass
    tmp = state_file + '.tmp'
    with open(tmp,'w') as f:
        json.dump({'subnet':current_subnet,'ts':_now()},f)
    os.replace(tmp, state_file)
    return False

def _doxa_cycle(gateway):
    mode = os.environ.get('DOXA_MODE','cloud').lower()
    if mode != 'local':
        _log("DOXA auto-cycle skipped — cloud mode, token protection active")
        return
    try:
        from modules.defense.confidence_scorer import get_high_confidence_hosts
        hosts = get_high_confidence_hosts()
        if not hosts: return
        from modules.doxa.doxa import ask_doxa_ollama, build_context
        model = os.environ.get('OLLAMA_MODEL','llama3')
        for score,ip,reasons,rec in hosts[:2]:
            if score < 80: continue
            ctx = build_context()
            q = f"hunt {ip}"
            reply = ask_doxa_ollama(q, [], model)
            _log(f"DOXA auto-hunt {ip}: {reply[:200]}")
            print(f"  {C}[DAEMON DOXA]{RS} {ip} analyzed")
    except Exception as e:
        _log(f"DOXA cycle error: {e}", 'WARN')

def run_daemon(gateway, local_ip, subnet, interval=900, jitter=300):
    global _running, _cycle_count, _last_sweep
    print(f"\n  {C}{B}[WRAITH DAEMON]{RS} starting")
    print(f"  {D}subnet: {subnet}{RS}")
    print(f"  {D}interval: {interval}s jitter: ±{jitter}s{RS}")
    print(f"  {D}DOXA mode: {os.environ.get('DOXA_MODE','cloud')}{RS}")
    print(f"  {D}pid: {os.getpid()}{RS}")
    _log(f"daemon started — subnet={subnet} interval={interval}")
    caps = _check_hardware()
    print(f"  {D}hardware: {caps}{RS}")
    _log(f"hardware caps: {caps}")
    _check_subnet_change(subnet)
    _save_state()
    while _running:
        _cycle_count += 1
        _last_sweep = _now()
        print(f"\n  {C}[DAEMON]{RS} cycle {_cycle_count} — {_ts()}")
        _network_cycle(gateway, local_ip, subnet)
        _doxa_cycle(gateway)
        _save_state()
        if not _running: break
        _jitter_sleep(interval, jitter)
    print(f"\n  {Y}[DAEMON]{RS} stopped after {_cycle_count} cycles")
    _log(f"daemon stopped after {_cycle_count} cycles")

if __name__ == '__main__':
    import argparse
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(description='WRAITH daemon')
    parser.add_argument('--interval', type=int, default=900)
    parser.add_argument('--jitter', type=int, default=300)
    parser.add_argument('--gateway', default='')
    parser.add_argument('--local-ip', default='')
    parser.add_argument('--subnet', default='')
    args = parser.parse_args()
    if not args.gateway or not args.local_ip or not args.subnet:
        from modules.core.netcheck import run_network_check
        run_network_check()
        from modules.core.netcheck import run_network_check
        info = run_network_check()
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8',80))
        lip = s.getsockname()[0]
        s.close()
        import subprocess
        gw = subprocess.run(['ip','route','show','default'],capture_output=True,text=True).stdout.split()[2] if subprocess.run(['ip','route','show','default'],capture_output=True,text=True).returncode==0 else ''
        sub = lip.rsplit('.',1)[0]+'.0/24'
    else:
        gw, lip, sub = args.gateway, args.local_ip, args.subnet
    run_daemon(gw, lip, sub, args.interval, args.jitter)
