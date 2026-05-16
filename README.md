# WRAITH
### passive network intelligence engine
### v4.6 — universal OT/IT/RF signal awareness

> *anomaly is the signal.*
> — [sig.int.ghost](https://instagram.com/sig.int.ghost)

[![Instagram](https://img.shields.io/badge/instagram-sig.int.ghost-purple)](https://instagram.com/sig.int.ghost)
[![GitHub](https://img.shields.io/badge/github-sigintghost-black)](https://github.com/sigintghost/WRAITH)

---

## What It Is

WRAITH is a passive network intelligence engine built
by a BAS/OT engineer from 15 years of field experience.
Not from a security textbook. The threat model comes
from inside the infrastructure.

No nmap. No libpcap. No pip install.
Pure Python standard library. Raw sockets.
Works on any network. Leaves no trace.

Passive first. Always. Active scanning in OT
environments causes real equipment failures.
This is non-negotiable.

OT/BAS is the origin.
Every network that emits observable signal is scope.

---

## What It Does

WRAITH passively observes network traffic and device
responses across OT, IT, IoT, and RF environments.
Every observation feeds a self-building asset registry.
The registry feeds DOXA — an AI agent that reasons
about what the network is doing, what is wrong,
and what to do about it.

The filestack is a live digital twin of the network.
DOXA reasons across it. Anomaly is the signal.

---

## DOXA

AI intelligence layer. Reads the full asset registry
and intelligence stack before every query. Reasons
across protocols, topology, behavior, and time.

DOXA is not a chatbot.
DOXA is a passive network intelligence director.

Modes:
  hunt     — full host profile from filestack
  risk     — all hosts ranked by threat level
  brief    — one paragraph for facilities leadership
  ghost    — attacker perspective, lateral movement map
  isolate  — containment options for flagged host
  baseline — behavioral deviation analysis
  explain  — plain English for non-technical owners
  defend   — BAS engineer action list
  profile  — 6-layer attack surface map
  timeline — event sequence reconstruction
  creds    — default credential exposure map
  rf       — RF and wireless signal analysis

---

## Asset Registry

WRAITH builds the asset registry automatically.
Every sweep, scan, and protocol run upserts records.
No manual population. No credentials required.
The network builds its own ground truth.

Each record carries:
  Identity — IP, MAC, hostname, vendor
  Classification — device type, protocols, services
  Location — subnet, VLAN, sensor, switch port
  Trust — authorized status, criticality
  Threat — IOC flags, MITRE techniques, alert refs
  Temporal — first seen, last seen, last changed
  Provenance — source module, operator notes

Operator reviews unauthorized assets.
DOXA hunts the unauthorized queue automatically.

---

## Defense Architecture

Multi-layer defense of the intelligence pipeline:

  sanitize.py       — ingestion path hardening
  drift_detector.py — field stability monitoring
  presence_monitor.py — unauthorized asset detection
  jitter_beacon.py  — statistical beacon detection
  hash_check.py     — module integrity on launch
  doxa_execute.py   — five-layer guardrail execution
  honeypot.py       — passive BACnet/Modbus trap
  self_defense.py   — C2 signature detection

---
## Active Modules — v4.6 (63 modules, 10 directories)

### Core
| Module | Function |
|--------|----------|
| sweep.py | ICMP/TCP host discovery + TTL |
| arp.py | ARP scanning, MAC OUI vendor lookup |
| portscan.py | OT/BAS/ICS port scanning |
| ttl.py | OS fingerprinting via TTL analysis |
| asset_registry.py | Self-building universal asset registry |
| topology.py | Passive subnet graph construction |
| filestack.py | Persistent intelligence stack |
| baseline.py | Host behavioral snapshot |
| alerts.py | Alert generation and display |
| subnet_selector.py | Multi-subnet context switching |

### Defense
| Module | Function |
|--------|----------|
| sanitize.py | Ingestion hardening, encoding detection |
| drift_detector.py | Field stability monitoring |
| self_defense.py | C2 and beacon detection |
| presence_monitor.py | Unauthorized asset detection |
| jitter_beacon.py | Statistical beacon detection |
| confidence_decay.py | Asset freshness scoring |
| honeypot.py | Passive BACnet/Modbus trap |
| doxa_execute.py | Five-layer guardrail execution |

### Protocols
| Module | Protocol | Port |
|--------|----------|------|
| bacnet.py | BACnet/IP | 47808 |
| bacnet_sc.py | BACnet/SC passive | TCP |
| modbus.py | Modbus TCP | 502 |
| mqtt.py | MQTT broker analysis | 1883 |
| snmp.py | SNMP passive listener | 161 |
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
| traffic_anomaly.py | Volume and behavior anomaly |
| vlan_hop.py | 802.1Q double-tag detection |
| mac_verify.py | MAC spoof detection |
| rf.py | RF/wireless signal scaffold |

### DOXA
| Module | Function |
|--------|----------|
| doxa.py | AI director, streaming responses |
| doxa_execute.py | Controlled action execution |

### Reporting
| Module | Function |
|--------|----------|
| report.py | Markdown assessment report export |

### Sensors
| Module | Function |
|--------|----------|
| sensor_registry.py | Multi-sensor fleet tracking |

### Utils
| Module | Function |
|--------|----------|
| hash_check.py | Module integrity verification |

### Integrations
| Module | Function |
|--------|----------|
| pg_connector.py | PostgreSQL data layer |

---
## Install

    apk add python3 git
    git clone https://github.com/sigintghost/WRAITH
    cd WRAITH
    python3 wraith.py

API keys at ~/.wraith/keys.py — chmod 600 — never in repo
Anthropic key required for DOXA intelligence layer.

## Deployment

**Development:** iPhone + iSH (Alpine Linux)
**Production:** Linux box or Raspberry Pi on SPAN port
**Sensor deployment:** WRAITH_STACK_PATH env var

Set WRAITH_STACK_PATH to redirect all filestack writes
to a remote sensor's local store. Pull intelligence
from deployed sensors via SSH.

## Legal

Source Available. All Rights Reserved.
Passive observation only. No packet injection.
Use only on networks you own or have explicit
written authorization to monitor.
Commercial use requires written permission.

## Author

sig.int.ghost — BAS/OT engineer, passive observer

Instagram: @sig.int.ghost
GitHub: sigintghost/WRAITH

WRAITH observes. Strata understands. DOXA reveals.
