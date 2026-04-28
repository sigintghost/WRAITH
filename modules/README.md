# WRAITH — MODULE REFERENCE
v3.3 — modules/

## NETWORK DISCOVERY
arp.py — ARP host discovery
sweep.py — ICMP/TCP subnet sweep, writes hosts.json
portscan.py — full OT/BAS/ICS port scan

## PROTOCOL LISTENERS
bacnet.py — BACnet/IP UDP 47808, idle timeout 30s/300s
modbus.py — Modbus TCP port 502, idle timeout 30s/300s
mqtt.py — MQTT port 1883, idle timeout 30s/300s
serial_mstp.py — BACnet MSTP via USB RS485
snmp.py — SNMP port 161, raw socket, requires root

## INTELLIGENCE
osint.py — 7-source threat intel per IP
oracle.py — Claude AI, token routed, OT/BAS locked

## SYSTEM
alerts.py — throttled severity alerting, alerts.json
auth.py — SHA256 login, roles, session UUID, audit log
logger.py — session logging to loot/logs/
filestack.py — persistent JSON stack to loot/stack/
ghost.py — ANSI color engine, brand voice, easter eggs
keys_template.py — copy to ~/.wraith/keys.py chmod 600

## FUTURE — modules/strata/
fdd_agent.py, energy_agent.py, trend_agent.py
cov_agent.py, context_engine.py, baseline.py
anomaly.py, correlator.py, explainer.py, dead_man.py

WRAITH observes. Strata understands.
