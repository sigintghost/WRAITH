# WRAITH
### passive network intelligence engine
### deep OT/BAS protocol awareness
### v3.9 — dev branch active

> *anomaly is the signal.*
> — [sig.int.ghost](https://instagram.com/sig.int.ghost)

[![Instagram](https://img.shields.io/badge/instagram-sig.int.ghost-purple)](https://instagram.com/sig.int.ghost)
[![GitHub](https://img.shields.io/badge/github-sigintghost-black)](https://github.com/sigintghost/WRAITH)

---

## What It Is

WRAITH is a passive network intelligence engine with deep OT/BAS protocol awareness. Built from raw Python sockets. No dependencies. Works on any network.

Red team recon. Blue team awareness. Purple team permanent weapon.


No nmap. No libpcap. No pip install.
Pure Python standard library.

Most tools wrap nmap. WRAITH reads the wire directly.

Built by a BAS engineer. For BAS engineers.
Designed for hospital, campus, clinical, and
critical infrastructure environments.

---

## Active Modules

| Module | Protocol | Port | Notes |
|--------|----------|------|-------|
| arp.py | ARP | L2 | MAC OUI vendor lookup |
| sweep.py | ICMP/TCP | subnet | writes hosts.json |
| portscan.py | TCP | OT/BAS/ICS | writes portscan.json |
| ttl.py | ICMP | all hosts | OS fingerprinting |
| bacnet.py | BACnet/IP | 47808 | idle timeout |
| modbus.py | Modbus TCP | 502 | writes modbus_map.json |
| mqtt.py | MQTT | 1883 | writes mqtt_brokers.json |
| serial_mstp.py | BACnet MSTP | RS485 | USB adapter |
| snmp.py | SNMP | 161 | requires root |
| osint.py | 13 source APIs | — | threat intel |
| doxa.py | Claude API | — | reads full filestack |
| alerts.py | throttling | — | severity + cooldowns |
| auth.py | login/audit | — | SHA256, roles, UUID |
| logger.py | logging | — | session logs |
| filestack.py | JSON stack | — | persistent loot |
| ghost.py | ANSI/brand | — | easter eggs |

---

## DOXA

AI agent powered by Claude API.
Reads everything WRAITH captures before every query.

Context fed to DOXA on every session:
- Sweep hosts and hostnames
- ARP table with MAC vendor lookup
- OS fingerprints via ICMP TTL
- Open OT/BAS ports per host
- Modbus device inventory
- MQTT broker topology
- BACnet device inventory
- Active alerts

Token routing:
- Haiku — fast queries, low cost
- Sonnet — deep analysis, complex reasoning
- Domain locked — OT/BAS/ICS context only

Keys at ~/.wraith/keys.py chmod 600

---

## OSINT — 13 Sources Per IP

| Source | Type |
|--------|------|
| [Shodan](https://shodan.io) | paid |
| [IPInfo](https://ipinfo.io) | paid |
| [GreyNoise](https://greynoise.io) | paid |
| [AbuseIPDB](https://abuseipdb.com) | paid |
| [Shodan InternetDB](https://internetdb.shodan.io) | free |
| [Censys](https://censys.io) | free |
| [URLScan](https://urlscan.io) | free |
| [VirusTotal](https://virustotal.com) | paid |
| [CISA KEV](https://cisa.gov/known-exploited-vulnerabilities) | free |
| [HackerTarget](https://hackertarget.com) | free |
| [BGPView](https://bgpview.io) | free |
| [ThreatFox](https://threatfox.abuse.ch) | free |
| [Criminal IP](https://criminalip.io) | paid |

---

## Security

- Passive-first — no packet injection ever
- SHA256 hashed passwords, getpass hidden input
- Roles: admin, technician, readonly
- Session UUID per login
- Tamper-evident audit log
- Keys chmod 600 — never in repo
- 3 attempt lockout
- Designed with NIST SP 800-82 and IEC 62443 principles
- Relevant to HIPAA, NERC CIP, ISO 50001 environments

---

## Filestack — Persistent Intelligence

All findings written to ~/.wraith/loot/stack/

hosts.json, arp_table.json, ttl_fingerprints.json,
portscan.json, bacnet_inventory.json,
modbus_map.json, mqtt_brokers.json,
snmp_inventory.json, alerts.json

DOXA reads all of these before every query.

---

## Strata

Strata is the interpretation layer above WRAITH.

WRAITH observes. Strata understands.

Strata integrates WebCTRL fault exports, trend
CSVs, and COV events with WRAITH network
intelligence to produce unified building
diagnostics with confidence scoring.

Coming in v4.1.

---

## Version History

| Version | Milestone |
|---------|-----------|
| v1.0 | raw socket recon, port scan, DNS |
| v2.0 | BACnet/IP passive listener |
| v3.0 | Modbus, MQTT, ghost module |
| v3.3 | DOXA AI, OSINT x7, auth, ANSI menus |
| v3.4 | BACnet idle timeout, Censys fix |
| v3.5 | DOXA reads full filestack, MAC OUI, TTL |
| v3.6 | DOXA rename John 1:14, CVE, key mgmt |
| v3.7 | beacon detector, lateral movement, netcheck |
| v3.8 | DOXA streaming, OSINT pipeline, sanitize, prompt injection defense |
| v3.9 | 80+ ports, HTTP fingerprint, MITRE ICS, admin panel, login lockout, 13 OSINT sources — current |
| v4.0 | role enforcement, DOXA memory, subnet filestack, persona JSONs |
| v4.1 | Strata MVS, FDD, WebCTRL integration |
| v5.0 | sensor nodes, WireGuard, per-building |
| v5.1 | browser dashboard, zero dependencies |
| v6.0 | platform, SaaS, API, integrations |

---

## Install

apk add python3 git
git clone https://github.com/sigintghost/WRAITH.git
cd WRAITH
python3 wraith.py

Keys go in ~/.wraith/keys.py
See modules/keys_template.py

---

## Legal

Source Available — All Rights Reserved.
Passive observation only. No packet injection.
Use only on networks you own or have explicit
written authorization to monitor.
Commercial use requires written permission.

---

## Author

**sig.int.ghost** — passive observer

- Instagram: [@sig.int.ghost](https://instagram.com/sig.int.ghost)
- GitHub: [sigintghost](https://github.com/sigintghost/WRAITH)

*systems reveal themselves under observation.*

*WRAITH observes. Strata understands.*
