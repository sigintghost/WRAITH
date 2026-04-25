# WRAITH
### Wireless Recon and Intelligence Engine

Passive network reconnaissance and protocol intelligence engine. Built from raw sockets up. No wrappers. No dependencies. Pure Python standard library.

anomaly is the signal. — sig.int.ghost

---

## What It Is

WRAITH is a modular passive network intelligence engine. Unlike tools that wrap nmap or existing scanners, WRAITH reads the wire directly using raw Python sockets. Each protocol gets its own dedicated listener — not just port detection, but full protocol awareness.

Domain expertise in OT/BAS networks including BACnet/IP, MSTP, and building automation systems baked into the architecture.

---

## Architecture

raw socket to ethernet frame to IP header to protocol payload to intelligence

WRAITH core — raw socket engine
├── module: RECON      host reachability
├── module: PORTSCAN   service enumeration
├── module: BANNER     protocol fingerprint
├── module: DNS        port 53
├── module: HTTP       port 80/443
├── module: SSH        port 22
├── module: BACNET     port 47808 — OT/BAS
├── module: MODBUS     port 502 — OT/ICS
├── module: MQTT       port 1883 — IoT/BAS
├── module: SNMP       port 161 — network devices
└── module: CUSTOM     user defined

---

## Module Status

| Module | Port | Domain | Status |
|--------|------|--------|--------|
| RECON | — | Network | v1 complete |
| PORTSCAN | — | Network | v1 complete |
| BANNER | 80/443 | Network | v1 complete |
| DNS | 53 | Network | v1 complete |
| HTTP | 80/443 | Network | v1 complete |
| SSH | 22 | Network | v2 in development |
| BACNET | 47808 | OT/BAS | v2 in development |
| MODBUS | 502 | OT/ICS | v3 planned |
| MQTT | 1883 | IoT/BAS | v3 planned |
| SNMP | 161 | Network | v3 planned |
| CUSTOM | user | Any | v4 planned |

---

## Requirements

- Python 3.6+
- No pip install required
- Linux recommended
- Root or sudo for raw socket capture

---

## Roadmap

v1 — Passive Recon Engine — COMPLETE
- Host reachability mapping
- Port and service enumeration
- DNS hostname resolution
- Protocol fingerprinting
- Banner grabbing

v2 — OT/BAS Protocol Awareness — IN DEVELOPMENT
- BACnet/IP passive listener port 47808
- BACnet device discovery via Who-Is and I-Am
- BACnet object inventory logging
- SSH detection port 22

v3 — Industrial Protocol Suite — PLANNED
- Modbus TCP port 502
- MQTT port 1883
- SNMP port 161
- Cross-protocol device correlation

v4 — Intelligence Layer — PLANNED
- Behavioral baseline per device
- Anomaly detection engine
- Communication health scoring
- OT/BAS network diagnostics

v5 — Sensor Deployment — PLANNED
- Raspberry Pi sensor node
- Wireless passive capture
- Encrypted telemetry reporting
- Multi-site visibility

---

## Legal

For use only on networks you own or have explicit written authorization to monitor. Passive observation only. No packet injection. No exploitation.

---

## Author

sig.int.ghost — passive observer
instagram: @sig.int.ghost

systems reveal themselves under observation.
