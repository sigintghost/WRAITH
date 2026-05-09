# WRAITH Modules — v4.5

59 modules across 5 functional categories.
Refactor to subdirectory structure planned for v4.6.

## Core — network observation foundation
sweep.py — ICMP/TCP host discovery, writes hosts.json
arp.py — MAC OUI vendor lookup, seeds registry
portscan.py — OT/BAS/ICS port scanning
ttl.py — OS fingerprinting via ICMP TTL
registry.py — device tracking, first/last seen
topology.py — passive subnet graph builder
filestack.py — persistent JSON intelligence stack
baseline.py — host behavioral snapshot
subnet_selector.py — multi-subnet context switcher
ghost.py — ANSI/brand, easter eggs
logger.py — session logging
auth.py — SHA256 auth, roles, UUID, lockout
alerts.py — severity throttling, cooldowns

## Defense — pipeline hardening
sanitize.py — ingestion path, chained encoding
drift_detector.py — field stability across cycles
self_defense.py — C2 signatures, beacon detection
presence_monitor.py — unauthorized asset detection
jitter_beacon.py — statistical beacon analysis
secure_connector.py — TLS enforcement
confidence_decay.py — asset freshness scoring
portscan_detector.py — incoming recon detection
allowlist_monitor.py — unexpected destinations
port_watch.py — continuous port monitoring
port_history.py — per-host port union tracking
honeypot.py — passive BACnet/Modbus trap

## Protocols — OT/BAS/ICS listeners
bacnet.py — BACnet/IP passive listener
bacnet_sc.py — BACnet/SC hub fingerprinting
modbus.py — Modbus TCP device mapping
mqtt.py — MQTT broker discovery
snmp.py — SNMP inventory
serial_mstp.py — BACnet MSTP via RS485

## Intelligence — analysis and detection
osint.py — 13-source threat intel pipeline
cve.py — CVE/CISA KEV lookup
ioc_extractor.py — IOC extraction from banners
mitre_attack_map.py — ATT&CK ICS mapping
dns_tunnel.py — DNS tunnel detection
icmp_tunnel.py — ICMP covert channel detection
traffic_anomaly.py — volume anomaly detection
vlan_hop.py — 802.1Q double-tag detection
rf.py — RF/wireless signal scaffold
mac_verify.py — MAC spoof detection
banner.py — HTTP banner harvesting
dns.py — DNS enumeration

## DOXA — AI intelligence layer
doxa.py — Claude API agent, streaming SSE
doxa_execute.py — five-layer execution engine

## Integrations — external connectors
asset_registry.py — operator-owned asset ground truth
webctrl.py — WebCTRL PostgreSQL integration
fsi_connector.py — generic asset DB connector
snowflake_connector.py — data pipeline connector
keys_template.py — API key scaffold

## Planned — v4.6 refactor
Modules will move to subdirectories:
core/ defense/ protocols/ intel/ doxa/ integrations/
Each subdirectory will have its own README.
Each module will have inline docstrings.
