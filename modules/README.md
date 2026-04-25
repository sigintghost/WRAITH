# WRAITH Modules

Each protocol gets its own dedicated listener.
Modules load on demand from the core engine.
Not just port detection — full protocol awareness.

## Status

### In Development
- bacnet.py — BACnet/IP passive listener — port 47808
- ssh.py — SSH detection — port 22

### Planned
- modbus.py — Modbus TCP — port 502
- mqtt.py — MQTT — port 1883
- snmp.py — SNMP — port 161
- custom.py — user defined

## Architecture

Each module follows the same pattern:
listen → capture → decode → log → baseline → flag
