# WRAITH
### passive network reconnaissance and OT/BAS intelligence engine
### v3.3

> *anomaly is the signal.* — [sig.int.ghost](https://instagram.com/sig.int.ghost)

---

## What It Is

WRAITH is a modular passive network intelligence engine built from raw Python sockets.
No nmap. No libpcap. No wrappers. Pure Python standard library.

Most tools wrap nmap. WRAITH reads the wire directly.

Domain expertise in OT/BAS — BACnet/IP, MSTP, Modbus, MQTT, Lutron, Crestron, DMX — baked in.

---

## Modules

| Module | Protocol | Port | Status |
|--------|----------|------|--------|
| arp.py | ARP | L2 | active |
| sweep.py | ICMP/TCP | subnet | active |
| portscan.py | TCP | OT/BAS/ICS | active |
| bacnet.py | BACnet/IP | 47808 | active |
| modbus.py | Modbus TCP | 502 | active |
| mqtt.py | MQTT | 1883 | active |
| serial_mstp.py | BACnet MSTP | RS485 | active |
| osint.py | 7 source APIs | n/a | active |
| oracle.py | Claude API | n/a | active |
| alerts.py | throttling | n/a | active |
| auth.py | login/audit | n/a | active |
| logger.py | logging | n/a | active |
| filestack.py | JSON stack | n/a | active |
| ghost.py | ANSI/sayings | n/a | active |
| SNMP | port 161 | 161 | v3.3 planned |
| SMTP | email alerts | n/a | v3.3 planned |

---

## OSINT Stack

| Source | Key | Data |
|--------|-----|------|
| [Shodan](https://shodan.io) | paid | ports, services |
| [IPInfo](https://ipinfo.io) | paid | geo, ASN, org |
| [GreyNoise](https://greynoise.io) | paid | noise vs targeted |
| [AbuseIPDB](https://abuseipdb.com) | paid | abuse score |
| [Shodan InternetDB](https://internetdb.shodan.io) | free | CVEs, ports |
| [Censys](https://censys.io) | free | certs, services |
| [URLScan](https://urlscan.io) | free | scan history |

---

## Oracle Intelligence

AI agent powered by Claude API. Token routing active:

- Simple queries — Haiku (fast, cheap)
- Complex analysis — Sonnet (deep reasoning)

Agent swarm planned:
- Coordinator, BACnet Analyst, Threat Enrichment
- Alert Triage, Executive Summary, Lighting Analyst
- Meter Analyst, FDD Agent, Code Writer Agent
- MITRE ATT&CK ICS mapping — coming v3.3

---

## Strata — Intelligence Layer

Strata is the interpretation layer above WRAITH.

WRAITH observes the network.
Strata contextualizes what WRAITH sees against real building systems.

Example:
WRAITH: BACnet device at IP showing abnormal traffic
Strata: AHU-4 may be operating outside expected behavior

Strata components planned:
- context_engine.py — IP to device to system mapping
- csv_watcher.py — WebCTRL export ingestion
- baseline.py — rolling stats per device
- anomaly.py — deviation detection + confidence scoring
- correlator.py — network + BAS unified events
- explainer.py — human readable operator output
- dead_man.py — offline device alerting

---

## Security

NIST SP 800-82 and IEC 62443 aligned:

- Passive-first — no packet injection, no control commands
- Hashed authentication — SHA256, never plaintext
- Role based access — admin, technician, readonly
- Session UUID — every session logged with unique ID
- Audit log — who ran what scan when, append-only
- Keys at ~/.wraith/keys.py chmod 600 — never in repo
- Input validation on all user inputs
- Authorized networks only

---

## Version History

| Version | Feature |
|---------|---------|
| v1.0 | raw socket recon, port scan, DNS, banner |
| v1.3.1 | host sweep, OT/BAS port map, ARP, logging |
| v2.0 | BACnet/IP passive listener, device inventory |
| v2.1 | BBMD topology, BDT/FDT parsing |
| v3.0 | Modbus TCP, MQTT, ghost module |
| v3.3 | Oracle AI, filestack JSON, MSTP, OSINT x7 |
| v3.3 | alerts.py, menu submenus, token routing |
| v3.3 | auth.py, audit log, SNMP, SMTP planned |

## Roadmap

- v3.3 — SNMP, SMTP, input validation, MITRE ATT&CK ICS
- v3.3 — Strata MVS, baseline, anomaly, WebCTRL ingestion
- v3.3 — Lutron, Crestron, DMX, meters, CVE lookup
- v3.3 — sensor nodes, WireGuard, VM deployment
- v5.1 — browser dashboard, health scores, alert timeline
- v6.0 — multi-user, API layer, OptigoVN replacement

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
