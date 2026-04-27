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
| osint.py | 7 APIs | n/a |
| oracle.py | Claude API | n/a |
| alerts.py | throttling | n/a |
| auth.py | login/audit | n/a |
| logger.py | logging | n/a |
| filestack.py | JSON stack | n/a |
| ghost.py | ANSI/sayings | n/a |

## Planned
- snmp.py port 161
- smtp.py email alerts
- context_engine.py Strata
- baseline.py rolling stats
- anomaly.py deviation detection
- lutron.py telnet
- crestron.py REST
- dmx.py Art-Net/sACN
- meters.py Modbus layer
- webctrl.py folder watcher

## Filestack
~/.wraith/loot/stack/
hosts.json, bacnet_inventory.json, bbmd_topology.json
modbus_map.json, mqtt_brokers.json, mstp_topology.json, alerts.json

## Security
Passive only. No injection. No exploitation.
Auth: SHA256 hashed, role based, session UUID, audit log.
Keys: ~/.wraith/keys.py chmod 600 — never in repo.
NIST SP 800-82 and IEC 62443 aligned.
