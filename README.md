# WRAITH
### passive network reconnaissance and OT/BAS intelligence engine
### v3.1

> *anomaly is the signal.* — [sig.int.ghost](https://instagram.com/sig.int.ghost)

---

## What It Is

WRAITH is a modular passive network intelligence engine built entirely from raw Python sockets.
No nmap. No libpcap. No wrappers. Pure Python standard library.

Most tools wrap nmap. WRAITH reads the wire directly.

Domain expertise in OT/BAS networks — BACnet/IP, MSTP, Modbus, MQTT — baked into the architecture.

---

## Modules

| Module | Protocol | Port | Status |
|--------|----------|------|--------|
| [RECON](modules/arp.py) | ICMP/TCP | any | v1.3 |
| [PORTSCAN](modules/portscan.py) | TCP | OT/BAS/ICS | v1.3 |
| [SWEEP](modules/sweep.py) | ICMP | subnet | v1.3 |
| [BACNET](modules/bacnet.py) | BACnet/IP | 47808 | v2.1 |
| [MODBUS](modules/modbus.py) | Modbus TCP | 502 | v3.0 |
| [MQTT](modules/mqtt.py) | MQTT | 1883 | v3.0 |
| [MSTP](modules/serial_mstp.py) | BACnet MSTP | RS485 | v3.1 |
| [OSINT](modules/osint.py) | APIs | n/a | v3.1 |
| [ORACLE](modules/oracle.py) | Claude API | n/a | v3.1 |
| SNMP | SNMP | 161 | v3.2 planned |
| ALERTS | internal | n/a | v3.2 planned |
| BASELINE | internal | n/a | v4.0 planned |

---

## OSINT Intelligence Stack

Seven sources per discovered IP:

| Source | Key | Data |
|--------|-----|------|
| [Shodan](https://shodan.io) | paid | port history, services |
| [IPInfo](https://ipinfo.io) | paid | geolocation, ASN, org |
| [GreyNoise](https://greynoise.io) | paid | noise vs targeted |
| [AbuseIPDB](https://abuseipdb.com) | paid | abuse score |
| [Shodan InternetDB](https://internetdb.shodan.io) | free | CVEs, ports, tags |
| [Censys](https://censys.io) | free | certs, services |
| [URLScan](https://urlscan.io) | free | passive scan history |

---

## Version History

| Version | Feature |
|---------|---------|
| v1.0 | raw socket recon, port scan, DNS, banner grab |
| v1.1 | auto gateway detection, OT/BAS port map |
| v1.2 | OSINT module, Shodan/IPInfo/GreyNoise/AbuseIPDB |
| v1.3 | loot directory, logging, ARP, auto chain |
| v1.3.1 | host sweep, progress bar, ASCII art, Easter eggs |
| v2.0 | BACnet/IP passive listener, device inventory |
| v2.1 | BBMD topology, BDT/FDT parsing |
| v3.0 | Modbus TCP, MQTT, ghost sayings |
| v3.1 | Oracle Claude API, filestack JSON, MSTP, OSINT expansion |

---

## Roadmap

- v3.2 — SNMP, alert throttling, email/Pushover notifications
- v4.0 — behavioral baseline, anomaly detection, WebCTRL integration
- v4.1 — CVE intelligence via NVD/NIST free API
- v5.0 — sensor deployment, WireGuard tunnel, edge nodes
- v5.1 — web dashboard, protocol heatmap, alert timeline
- v6.0 — Docker, multi-sensor, API, platform

---

## Requirements

- Python 3.6+
- No pip install required
- Linux or iSH on iOS
- Root or sudo for raw socket capture

---

## Legal

For use only on networks you own or have explicit written authorization to monitor.
Passive observation only. No packet injection. No exploitation.

---

## Author

**sig.int.ghost** — passive observer. ghost in the machine.

- Instagram: [@sig.int.ghost](https://instagram.com/sig.int.ghost)
- GitHub: [sigintghost](https://github.com/sigintghost)

*systems reveal themselves under observation.*
