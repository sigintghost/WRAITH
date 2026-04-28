# modules/ttl.py — ICMP TTL OS fingerprinting
import socket, struct, os, time
TTL_MAP = {
    (60,70):'Linux/Android',(124,130):'Windows',
    (62,66):'Cisco IOS',(254,256):'Cisco/Network Device',
    (30,35):'Embedded/BAS Controller',
}
def guess_os(ttl):
    for (lo,hi),name in TTL_MAP.items():
        if lo <= ttl <= hi: return name
    if ttl <= 64: return 'Linux/Unix'
    if ttl <= 128: return 'Windows'
    return 'Network Device'
def ping_ttl(ip, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(timeout)
        payload = b'WRAITH' + b'\x00' * 10
        header = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
        chk = sum(struct.unpack('!8H', header + payload))
        chk = (~((chk >> 16) + (chk & 0xFFFF))) & 0xFFFF
        pkt = struct.pack('!BBHHH', 8, 0, chk, 1, 1) + payload
        s.sendto(pkt, (ip, 0))
        resp, _ = s.recvfrom(1024)
        ttl = resp[8]
        s.close()
        return ttl, guess_os(ttl)
    except: return None, None
def run_ttl(hosts):
    print("\n  [TTL] OS fingerprinting via ICMP")
    results = []
    for item in hosts:
        ip = item[0] if isinstance(item,(list,tuple)) else item
        ttl, os_guess = ping_ttl(ip)
        if ttl:
            print(f"  {ip:<18} TTL={ttl:<4} OS={os_guess}")
            results.append({'ip':ip,'ttl':ttl,'os':os_guess})
        else:
            print(f"  {ip:<18} no response")
    try:
        from modules.filestack import write_json
        write_json('ttl_fingerprints.json', {'hosts': results})
    except: pass
    return results
