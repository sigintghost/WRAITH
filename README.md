# WRAITH
### passive network intelligence engine
### deep OT/BAS protocol awareness
### v4.1 — dev branch active

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

## What It Could Be

WRAITH is a platform. The terminal is the first interface.

- Per-subnet AI context — each network segment analyzed independently
- Persistent cross-session memory — DOXA remembers what it saw last week
- Building persona layer — each facility gets its own AI voice and priority model
- PostgreSQL integration — real trend and alarm data from WebCTRL into DOXA
- Topology mapping — passive subnet graph built from observation alone
- OT assessment engine — passive recon to signed PDF report
- Air-gapped mode — local LLM, zero API cost, zero data exposure
- Enterprise scale — thousands of subnets, one engine

Red team finds the gap. Blue team closes it. Purple team never loses it.

---

## The Longer Vision

WRAITH was built for buildings. But the architecture has no ceiling.

Any environment where machines operate autonomously, where humans cannot
be present at every node, where anomaly detection must be passive and
persistent — WRAITH applies.

- **Defense & critical infrastructure** — OT networks in bases, depots,
  and command facilities where BAS and ICS converge
- **Data center automation** — passive monitoring of hyperscale
  infrastructure, thermal systems, power distribution, cooling control
- **Autonomous construction** — drone coordination networks, sensor mesh
  monitoring, equipment telemetry from remote build sites
- **Off-world infrastructure** — lunar and Martian habitat systems will
  run on the same protocols. BACnet does not care about gravity.
  HVAC, power, life support, pressurization — all OT, all monitorable.
- **Swarm intelligence layer** — agentic networks of autonomous units
  require the same passive observation, anomaly detection, and
  AI-driven threat analysis that WRAITH provides today
- **Signal intelligence expansion** — Zigbee, Z-Wave, Bluetooth,
  802.15.4, RF mesh — the wire is just one attack surface

The terminal is the seed. The platform is what grows from it.

*WRAITH observes. Strata understands. DOXA reveals.*

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
| baseline.py | behavioral | — | host snapshot, deviation detection |
| mac_verify.py | MAC/OUI | L2 | spoof detection, vendor validation |
| dns_tunnel.py | DNS | 53 | tunnel detection, query anomaly |
| icmp_tunnel.py | ICMP | — | covert channel, payload anomaly |
| traffic_anomaly.py | TCP | — | micro-exfil, volume detection |
| vlan_hop.py | 802.1Q | L2 | double-tag detection |
| rf.py | RF/wireless | — | Zigbee/BT/ZWave scaffold |
| fsi_connector.py | asset DB | — | FSI ground truth, gap analysis |
| topology.py | graph | — | passive subnet mapping |
| registry.py | registry | — | device tracking, first/last seen |
| subnet_selector.py | subnet | — | multi-subnet context switcher |

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

Coming in v5.0.

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
| v3.9 | 80+ ports, HTTP fingerprint, MITRE ICS, admin panel, login lockout, 13 OSINT sources |
| v4.0 | HITL loop, 6 DOXA modes, rogue detection, topology mapper, auto-scan |
| v4.1 | signal intel suite, menu redesign, FSI connector, baseline, MAC verify |
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
