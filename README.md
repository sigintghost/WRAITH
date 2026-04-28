# WRAITH
### passive network reconnaissance and OT/BAS intelligence engine
### current: v3.3 — dev branch active

> *anomaly is the signal.* — [sig.int.ghost](https://instagram.com/sig.int.ghost)

[![GitHub](https://img.shields.io/badge/github-sigintghost-black)](https://github.com/sigintghost)

---

## What It Is

WRAITH is a modular passive network intelligence engine built from raw Python sockets.
No nmap. No libpcap. No wrappers. Pure Python standard library.

Most tools wrap nmap. WRAITH reads the wire directly.

Domain expertise in OT/BAS — BACnet/IP, MSTP, Modbus, MQTT, Lutron, Crestron, DMX — baked in.

Designed for hospital, campus, clinical, and critical infrastructure environments.

---

## Active Modules

| Module | Protocol | Port | Status |
|--------|----------|------|--------|
| arp.py | ARP | L2 | active |
| sweep.py | ICMP/TCP | subnet | active |
| portscan.py | TCP | OT/BAS/ICS | active |
| bacnet.py | BACnet/IP | 47808 | active |
| modbus.py | Modbus TCP | 502 | active |
| mqtt.py | MQTT | 1883 | active |
| serial_mstp.py | BACnet MSTP | RS485 | active |
| snmp.py | SNMP | 161 | active |
| osint.py | 7 source APIs | n/a | active |
| oracle.py | Claude API | n/a | active |
| alerts.py | throttling | n/a | active |
| auth.py | login/audit | n/a | active |
| logger.py | logging | n/a | active |
| filestack.py | JSON stack | n/a | active |
| ghost.py | ANSI/sayings | n/a | active |

---

## OSINT Stack — 7 Sources Per IP

| Source | Key | Status |
|--------|-----|--------|
| [Shodan](https://shodan.io) | paid | active |
| [IPInfo](https://ipinfo.io) | paid | active |
| [GreyNoise](https://greynoise.io) | paid | active |
| [AbuseIPDB](https://abuseipdb.com) | paid | active |
| [Shodan InternetDB](https://internetdb.shodan.io) | free | active |
| [Censys](https://censys.io) | free | SSL fix pending |
| [URLScan](https://urlscan.io) | free | active |

---

## Oracle Intelligence

AI agent powered by Claude API with token routing:
- Simple queries — Haiku (fast, low cost)
- Complex analysis — Sonnet (deep reasoning)
- Domain locked — OT/BAS/ICS context only
- Reads live filestack before every query

---

## Security — NIST 800-82 + IEC 62443 Aligned

- Passive-first — no packet injection ever
- SHA256 hashed passwords — never plaintext
- Hidden password input — getpass
- Role based access — admin, technician, readonly
- Session UUID — every session uniquely identified
- Audit log — timestamp, user, role, action, session ID
- Keys at ~/.wraith/keys.py chmod 600 — never in repo
- Input validation on all user inputs
- 3 attempt login lockout
- Admin recovery code — emergency access

---

## Strata — Intelligence Layer (v4.0)

Strata sits above WRAITH as the interpretation layer.

WRAITH observes. Strata understands.

WRAITH: BACnet device at IP showing abnormal traffic
Strata: AHU-4 may be operating outside expected behavior

Strata components:
- context_engine.py — IP to device to system mapping
- csv_watcher.py — WebCTRL trend/alarm export ingestion
- email_watcher.py — WebCTRL alarm email ingestion
- baseline.py — rolling mean/stddev per device
- anomaly.py — deviation detection + confidence scoring
- correlator.py — network + BAS unified events
- explainer.py — human readable operator output
- dead_man.py — offline device detection + alerting

---

## Agent Swarm (v4.0)

Multi-agent Oracle architecture:

- Coordinator — routes queries to specialists
- BACnet/BAS Analyst — device fingerprinting, misconfig
- Threat Enrichment — CVE correlation, MITRE ATT&CK ICS
- Alert Triage — noise reduction, priority scoring
- Executive Summary — business language for management
- Lighting Analyst — Lutron/Crestron/DMX context
- Meter Analyst — utility telemetry, demand, cost
- FDD Agent — fault detection across all systems
- Code Writer Agent — generates new WRAITH modules

MITRE ATT&CK ICS mapping — auto tag devices against:
T0822 T0840 T0855 T0886 and full ICS matrix

---

## Planned Protocol Modules

| Module | Protocol | Notes |
|--------|----------|-------|
| smtp.py | SMTP | email alerts on CRITICAL events |
| pushover.py | Pushover API | phone push notifications |
| lutron.py | Telnet port 23 | RadioRA2/QSX integration |
| crestron.py | REST port 443 | Samis education center |
| dmx.py | Art-Net UDP 6454 | Nicolaudie DMX lighting |
| meters.py | Modbus TCP | utility meter register layer |
| webctrl.py | file watcher | WebCTRL trend/alarm ingestion |
| daemon.py | all protocols | simultaneous listener threads |
| baseline.py | internal | rolling stats per device |
| anomaly.py | internal | deviation + confidence scoring |
| cve.py | NVD/NIST API | free CVE lookup per device |

---

## Immediate TODO (v3.3 completion)

- Fix Ctrl+C — timeout loop on all listeners
- Add ANSI color to SNMP output
- Key setup prompt on login if keys missing
- Admin panel — list/create/delete/role users
- Recovery code + tools/reset_admin.py
- Menu ANSI color upgrade
- Verify Shodan/IPInfo/GreyNoise endpoints
- Fix Censys SSL for iSH Alpine
- daemon.py all listeners simultaneous
- Input validation hardening
- Home lab — configure IP controllers
- PTEC MSTP test with RS485 adapter

---

## Version History

| Version | Features |
|---------|----------|
| v1.0 | raw socket recon, port scan, DNS, banner |
| v1.3.1 | OT/BAS port map, sweep, ARP, logging |
| v2.0 | BACnet/IP passive listener, device inventory |
| v2.1 | BBMD topology, BDT/FDT parsing |
| v3.0 | Modbus TCP, MQTT, ghost module |
| v3.1 | Oracle AI, filestack, MSTP, OSINT x7 |
| v3.2 | alerts, menu submenus, token routing |
| v3.3 | auth, audit log, SNMP, OSINT fixes, dev branch |
| v3.4 | daemon mode, admin panel, color UI — planned |
| v4.0 | Strata MVS, baseline, anomaly, WebCTRL — planned |
| v4.1 | Lutron, Crestron, DMX, meters, CVE — planned |
| v5.0 | sensor nodes, WireGuard, VM deployment — planned |
| v5.1 | browser dashboard, health scores — planned |
| v6.0 | multi-user, API, OptigoVN replacement — planned |

---

## Deployment Vision

- WebCTRL VM — primary host, GitHub auto-pull
- Per-building sensor nodes — Pi/Beelink per VLAN
- 9-10 buildings, 1.5M sqft, multiple VLANs
- WireGuard encrypted tunnel — sensor to VM
- Browser dashboard — technician access, no terminal
- SPAN port authorization — zero footprint capture

---

## Requirements

- Python 3.6+
- No pip install required
- Linux or iSH on iOS
- Root or sudo for raw socket capture

---

## Legal

Source Available — All Rights Reserved.
For use only on networks you own or have explicit written authorization to monitor.
Passive observation only. No packet injection. No exploitation.
Commercial use requires written permission.

---

## Author

**sig.int.ghost** — passive observer. ghost in the machine.

- Instagram: [@sig.int.ghost](https://instagram.com/sig.int.ghost)
- GitHub: [sigintghost](https://github.com/sigintghost)

*systems reveal themselves under observation.*
