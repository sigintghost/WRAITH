# WRAITH arp.py — pure Python ARP host discovery
# sig.int.ghost
# %X0.0 — first rung. first contact.
# the device does not know it has been seen.

import socket
import struct
import os
import sys

def get_mac():
    import uuid
    mac = uuid.getnode()
    return struct.pack("!6B", *[
        (mac >> (5-i)*8) & 0xff for i in range(6)
    ])

def build_arp_request(src_mac, src_ip, target_ip):
    # ethernet header
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    eth_type = b'\x08\x06'
    eth = dst_mac + src_mac + eth_type
    # arp payload
    htype = b'\x00\x01'
    ptype = b'\x08\x00'
    hlen  = b'\x06'
    plen  = b'\x04'
    oper  = b'\x00\x01'
    sha   = src_mac
    spa   = socket.inet_aton(src_ip)
    tha   = b'\x00\x00\x00\x00\x00\x00'
    tpa   = socket.inet_aton(target_ip)
    arp   = htype+ptype+hlen+plen+oper+sha+spa+tha+tpa
    return eth + arp

def arp_scan(network_prefix, src_ip, timeout=1):
    try:
        src_mac = get_mac()
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        s.settimeout(timeout)
        iface = "eth0"
        s.bind((iface, 0))
    except Exception as e:
        print(f"  [ARP] socket error: {e}")
        print("  [ARP] raw socket requires root and AF_PACKET support")
        return []

    alive = []
    for i in range(1, 255):
        target = f"{network_prefix}.{i}"
        pkt = build_arp_request(src_mac, src_ip, target)
        try:
            s.send(pkt)
        except:
            pass

    import time
    time.sleep(timeout)

    while True:
        try:
            raw = s.recv(1024)
            if raw[12:14] == b'\x08\x06' and raw[20:22] == b'\x00\x02':
                ip = socket.inet_ntoa(raw[28:32])
                mac = ':'.join(f'{b:02x}' for b in raw[22:28])
                alive.append((ip, mac))
                print(f"  [ARP] {ip} — {mac}")
        except socket.timeout:
            break
        except:
            break

    s.close()
    return alive

def run_arp(gateway, local_ip):
    prefix = '.'.join(local_ip.split('.')[:3])
    print(f"\n  [ARP] scanning {prefix}.1-254")
    hosts = arp_scan(prefix, local_ip)
    if not hosts:
        print("  [ARP] no hosts found or raw socket unavailable")
    return hosts
