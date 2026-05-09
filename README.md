# WRAITH
### passive network intelligence engine
### v4.5 — universal OT/IT/RF signal awareness

> *anomaly is the signal.*
> — [sig.int.ghost](https://instagram.com/sig.int.ghost)

[![Instagram](https://img.shields.io/badge/instagram-sig.int.ghost-purple)](https://instagram.com/sig.int.ghost)
[![GitHub](https://img.shields.io/badge/github-sigintghost-black)](https://github.com/sigintghost/WRAITH)

---

## What It Is

WRAITH is a passive network intelligence engine.
No nmap. No libpcap. No pip install.
Pure Python standard library. Raw sockets.
Works on any network. Leaves no trace.

Built by a BAS/OT engineer from field experience —
not from a security textbook.
The threat model comes from inside the infrastructure.

OT/BAS is the origin. Every network that emits
observable signal is the scope.

---

## What It Does

WRAITH passively observes network traffic and device
responses across OT, IT, IoT, and RF environments.
It builds a structured intelligence stack and feeds
it to DOXA — an AI agent that reasons about what
the network is doing, what is wrong, and what to
do about it.

Passive first. Always. No packet injection. Ever.
Active scanning in OT environments causes real
equipment failures. This is non-negotiable.

---

## DOXA

AI intelligence layer powered by Claude API.
Reads the full intelligence stack before every query.
Reasons across protocols, topology, behavior, and time.

DOXA is not a chatbot.
DOXA is a passive network intelligence agent
operating across OT, IT, RF, IoT, industrial,
and enterprise environments.
OT/BAS is the origin.
Every network that emits observable signal is the scope.

Modes: hunt / isolate / baseline / report /
explain / defend / scan / compare / risk / brief

Token routing:
- Haiku — fast queries, low cost
- Sonnet — deep analysis, complex reasoning

Keys at ~/.wraith/keys.py — chmod 600 — never in repo

---

## Defense Architecture

WRAITH implements a multi-layer defense posture
for its own intelligence pipeline:

**Ingestion layer** — sanitize.py guards every
intelligence stack write. Untrusted network data
is sanitized before it reaches DOXA context.
Chained encoding detection strips base64/gzip/url
encoding chains up to 3 layers deep before any
injection check runs.

**Identity layer** — AGENTS.md loaded into system
prompt. Identity separated from observations.
Network data never contaminates DOXA's soul file.

**Drift detection** — drift_detector.py watches
per-asset field values across scan cycles. Gradual
field manipulation flagged as WARNING or CRITICAL.
Answer to multi-turn injection attacks.

**Presence monitoring** — presence_monitor.py
cross-references wire observations against the
operator-owned asset registry. Unauthorized devices
flagged immediately. Pulse evasion detected across
scan cycles.

**Execution control** — doxa_execute.py provides
a five-layer guardrail execution engine.
Confirmation gate. Hardcoded allowlist. Dry run.
Append-only audit log. Pre-execution rollback.

**Deception layer** — honeypot.py deploys passive
BACnet/Modbus traps with authorization gate.
Protocol listeners log probe attempts automatically.

---

## Active Modules — v4.5

### Core
| Module | Function |
|--------|----------|
| sweep.py | ICMP/TCP host discovery |
| arp.py | MAC OUI vendor lookup |
| portscan.py | OT/BAS/ICS port scanning |
| ttl.py | OS fingerprinting via TTL |
| registry.py | Device tracking, first/last seen |
| topology.py | Passive subnet graph |
| filestack.py | Persistent intelligence stack |
| baseline.py | Host behavioral snapshot |
| subnet_selector.py | Multi-subnet context |

### Defense
| Module | Function |
|--------|----------|
| sanitize.py | Ingestion path hardening |
| drift_detector.py | Field stability monitoring |
| self_defense.py | C2 signature detection |
| presence_monitor.py | Unauthorized asset detection |
| jitter_beacon.py | Statistical beacon detection |
| secure_connector.py | TLS enforcement |
| confidence_decay.py | Asset freshness scoring |
| portscan_detector.py | Incoming recon detection |
| allowlist_monitor.py | Unexpected destination flagging |
| port_watch.py | Continuous port monitoring |
| honeypot.py | Passive BACnet/Modbus trap |

### Protocols
| Module | Protocol | Port |
|--------|----------|------|
| bacnet.py | BACnet/IP | 47808 |
| bacnet_sc.py | BACnet/SC | TCP |
| modbus.py | Modbus TCP | 502 |
| mqtt.py | MQTT | 1883 |
| snmp.py | SNMP | 161 |
| serial_mstp.py | BACnet MSTP | RS485 |

### Intelligence
| Module | Function |
|--------|----------|
| osint.py | 13-source threat intel |
| cve.py | CVE/CISA KEV lookup |
| ioc_extractor.py | IOC extraction from banners |
| mitre_attack_map.py | ATT&CK ICS technique mapping |
| dns_tunnel.py | DNS tunnel detection |
| icmp_tunnel.py | ICMP covert channel detection |
| traffic_anomaly.py | Volume anomaly detection |
| vlan_hop.py | 802.1Q double-tag detection |
| rf.py | RF/wireless signal scaffold |
| mac_verify.py | MAC spoof detection |

### DOXA
| Module | Function |
|--------|----------|
| doxa.py | AI agent, streaming SSE |
| doxa_execute.py | Controlled execution engine |

### Integrations
| Module | Function |
|--------|----------|
| asset_registry.py | Operator-owned asset ground truth |
| webctrl.py | WebCTRL PostgreSQL integration |
| fsi_connector.py | Generic asset DB connector |
| snowflake_connector.py | Data pipeline connector |

## Install

    apk add python3 git
    git clone https://github.com/sigintghost/WRAITH
    cd WRAITH
    python3 wraith.py

Keys go in ~/.wraith/keys.py
See modules/keys_template.py

## Legal

Source Available. All Rights Reserved.
Passive observation only. No packet injection.
Use only on networks you own or have explicit
written authorization to monitor.
Commercial use requires written permission.

## Author

sig.int.ghost — passive observer

Instagram: @sig.int.ghost
GitHub: sigintghost/WRAITH

WRAITH observes. Strata understands. DOXA reveals.
