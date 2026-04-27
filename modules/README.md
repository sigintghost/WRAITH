# WRAITH Modules
Passive OT/IT network intelligence. Raw Python sockets. Zero dependencies.

## Active Modules
| Module | Protocol | Port |
|--------|----------|------|
| arp.py | ARP | L2 |
| sweep.py | ICMP/TCP | any |
| portscan.py | TCP | OT/BAS/ICS |
| bacnet.py | BACnet/IP | 47808 |
| modbus.py | Modbus TCP | 502 |
| mqtt.py | MQTT | 1883 |
| serial_mstp.py | BACnet MSTP | RS485 |
| osint.py | OSINT APIs | n/a |
| oracle.py | Claude API | n/a |
| logger.py | internal | n/a |
| filestack.py | internal | n/a |
| ghost.py | internal | n/a |

## OSINT Sources
| Source | Key Required |
|--------|-------------|
| Shodan | yes |
| IPInfo | yes |
| GreyNoise | yes |
| AbuseIPDB | yes |
| Censys | no |

## Filestack Output
All modules write to ~/.wraith/loot/stack/
| File | Source |
|------|--------|
| hosts.json | sweep |
| bacnet_inventory.json | bacnet |
| bbmd_topology.json | bacnet |
| modbus_map.json | modbus |
| mqtt_brokers.json | mqtt |
| mstp_topology.json | serial_mstp |
| alerts.json | all modules |

## Oracle Agents
1. BACnet/BAS Analyst
2. Threat Enrichment
3. Alert Triage
4. Executive Summary

Model: claude-haiku-4-5
Key: ~/.wraith/keys.py - never in repo

## Planned
- snmp.py - SNMP port 161
- alerts.py - throttling and notifications
- baseline.py - behavioral baseline per device
- webctrl.py - WebCTRL folder watcher
- dashboard.py - local web dashboard

## Architecture
listen -> capture -> decode -> log -> filestack -> agent

Passive only. No injection. No exploitation.
Authorized networks only.
