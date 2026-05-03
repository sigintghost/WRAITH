# WRAITH — MODULE REFERENCE
# v4.1 — modules/

## NETWORK DISCOVERY
arp.py — ARP host discovery, MAC OUI vendor lookup
sweep.py — TCP subnet sweep, writes hosts.json, progress bar
portscan.py — 80+ port OT/BAS/ICS/IoT signatures, MITRE ATT&CK tagged
ttl.py — ICMP TTL OS fingerprinting, writes ttl_fingerprints.json

## PROTOCOL LISTENERS
bacnet.py — BACnet/IP UDP 47808, idle timeout 30s/300s
modbus.py — Modbus TCP 502, register map, writes modbus_map.json
mqtt.py — MQTT 1883, broker/topic discovery, writes mqtt_brokers.json
serial_mstp.py — BACnet MSTP via USB RS485
snmp.py — SNMP 161, raw socket, writes snmp_inventory.json

## INTELLIGENCE
osint.py — 13-source threat intel: Shodan, IPInfo, GreyNoise,
  AbuseIPDB, Censys, URLScan, InternetDB, VirusTotal,
  CISA KEV, HackerTarget, BGPView, ThreatFox, Criminal IP
doxa.py — DOXA AI agent, full filestack context, OT/BAS locked
cve.py — NIST NVD CVE lookup, wired into DOXA context
wishlist_agent.py — self-building roadmap, DOXA reads WISHLIST.md

## SECURITY & VALIDATION
sanitize.py — prompt injection defense, HTML escape, pattern blocking
beacon_detector.py — C2 beacon timing analysis, fixed interval detection
lateral_detector.py — ARP delta, new host baseline comparison
netcheck.py — network context validator, session change detection
input_validator.py — IP/port/subnet validation, text sanitization

## SYSTEM
alerts.py — throttled severity alerting, writes alerts.json
auth.py — SHA256 login, roles, session UUID, audit log
logger.py — session logging to loot/logs/
filestack.py — persistent JSON stack to loot/stack/
ghost.py — ANSI color engine, brand voice, PPCL easter eggs
keys_manager.py — API key add/update/delete/test, ~/.wraith/keys.py
keys_template.py — copy to ~/.wraith/keys.py chmod 600
admin.py — user management, role assignment, building selector

## FUTURE — modules/strata/
fdd_agent.py — WebCTRL fault file watcher, DOXA context injection
energy_agent.py, trend_agent.py, cov_agent.py
context_engine.py, baseline.py, anomaly.py
correlator.py, explainer.py, dead_man.py

## FILESTACK — loot/stack/
hosts.json, arp_table.json, ttl_fingerprints.json
portscan.json, modbus_map.json, mqtt_brokers.json
bacnet_inventory.json, snmp_inventory.json, alerts.json

WRAITH observes. Strata understands. DOXA reveals.
