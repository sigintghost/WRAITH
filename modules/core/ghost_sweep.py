# WRAITH ghost_sweep.py — stealth host discovery
# randomized order, jittered timing, single probe
# passive observer. anomaly is the signal.
import socket, random, time, threading
from modules.core.asset_registry import upsert as reg_upsert

GHOST_PORTS = [80, 443, 47808, 22, 8080, 1883, 502]

def _probe(ip, results, lock):
    port = random.choice(GHOST_PORTS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        if s.connect_ex((ip, port)) == 0:
            s.close()
            try: hostname = socket.gethostbyaddr(ip)[0]
            except: hostname = ''
            with lock:
                results.append((ip, port, hostname))
            reg_upsert(ip=ip, mac='', source='ghost_sweep',
                **{'network.hostname': hostname})
            return
        s.close()
    except: pass

def run_ghost_sweep(base, local_ip, jitter_min=0.5, jitter_max=2.5):
    C='\033[36m'; D='\033[2m'; R='\033[0m'
    print(f"\n  [{C}GHOST SWEEP{R}] {base}.1-254")
    print(f"  {D}randomized order — jittered timing — single probe{R}")
    hosts = [f"{base}.{i}" for i in range(1,255)
        if f"{base}.{i}" != local_ip]
    random.shuffle(hosts)
    results = []
    lock = threading.Lock()
    total = len(hosts)
    for idx, ip in enumerate(hosts):
        t = threading.Thread(target=_probe, args=(ip, results, lock))
        t.daemon = True
        t.start()
        t.join(timeout=1.5)
        pct = int(((idx+1)/total)*40)
        bar = '|'*pct + '.'*(40-pct)
        found = len(results)
        print(f"\r  ghost [{bar}] {int((idx+1)/total*100):>3}%"
            f" — {found} found", end='', flush=True)
        time.sleep(random.uniform(jitter_min, jitter_max))
    print(f"\r  ghost [{'|'*40}] 100% — {len(results)} found")
    results.sort(key=lambda x: int(x[0].split('.')[-1]))
    print(f"  {'HOST':<18} {'PORT':<8} {'HOSTNAME'}")
    print(f"  {'-'*18} {'-'*8} {'-'*20}")
    for ip, port, hostname in results:
        print(f"  {ip:<18} {port:<8} {hostname}")
    if not results: print("  [GHOST] no hosts found")
    try:
        from modules.core.filestack import write_hosts
        write_hosts(results)
    except: pass
    return results
