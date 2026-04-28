# WRAITH sweep.py — TCP host sweep
# pure Python, no dependencies
# sig.int.ghost
#
#  ___ ___ ___   ___ _  _ _____
# / __|_ _/ __| |_ _| \| |_   _|
# \__ \| | (_ |  | || .` | | |
# |___/___\___| |___|_|\_| |_|
#  ___ _  _  ___  ___ _____
# / __| || |/ _ \/ __|_   _|
# | (_ | __ | (_) \__ \ | |
#  \___|_||_|\___/|___/ |_|
# passive observer. anomaly is the signal. — @sig.int.ghost

import socket
import threading
import os

PROBE_PORTS = [
    80, 443, 22, 23, 8080, 8443, 53,
    135, 139, 445, 3389, 5900, 7070,
    47808, 1911, 4911, 502, 1883, 161,
    9100, 631, 5353, 1900, 8888, 8000,
    21, 25, 110, 143, 993, 995, 3306,
    5432, 6379, 27017, 8883, 4911,
    2000, 2404, 4840, 102, 44818, 20000,
    7547, 8181, 8888, 9000, 9090, 9443,
    554, 1935, 8554, 10000, 49152
]

def tcp_ping(ip, results, counter, lock, timeout=0.5):
    found = False
    for port in PROBE_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ""
                results.append((ip, port, hostname))
                found = True
                break
            s.close()
        except:
            pass
    if not found:
        try:
            r = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
            if r == 0:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ""
                results.append((ip, 0, hostname))
        except:
            pass
    with lock:
        counter[0] += 1

def run_sweep(base, local_ip):
    prefix = '.'.join(local_ip.split('.')[:3])
    print(f"\n  [SWEEP] scanning {prefix}.1-254")
    results = []
    threads = []
    counter = [0]
    lock = threading.Lock()
    total = 253
    for i in range(1, 255):
        ip = f"{prefix}.{i}"
        if ip == local_ip:
            continue
        t = threading.Thread(target=tcp_ping, args=(ip, results, counter, lock))
        t.daemon = True
        threads.append(t)
        t.start()
    import time
    while counter[0] < total:
        pct = int((counter[0] / total) * 40)
        bar = '|' * pct + '.' * (40 - pct)
        found = len(results)
        print(f"\r  ghost [{bar}] {int(counter[0]/total*100):>3}% — {found} found", end='', flush=True)
        time.sleep(0.2)
    found = len(results)
    print(f"\r  ghost [{'|'*40}] 100% — {found} found")
    print(f"  {'HOST':<18} {'PORT':<8} {'HOSTNAME'}")
    print(f"  {'-'*18} {'-'*8} {'-'*20}")
    results.sort(key=lambda x: int(x[0].split('.')[-1]))
    for ip, port, hostname in results:
        print(f"  {ip:<18} {port:<8} {hostname}")
    if not results:
        print("  [SWEEP] no hosts found")
    try:
        from modules.filestack import write_hosts
        write_hosts(results)
    except Exception as e:
        pass
    return results
