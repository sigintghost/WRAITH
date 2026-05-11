# protocols/ — OT/BAS/ICS/RF listeners

Passive protocol listeners. No packet injection. Ever.
All writes go through filestack.write().
Hardware-gated modules noted below.

bacnet.py      — BACnet/IP passive listener, port 47808
bacnet_sc.py   — BACnet/SC hub fingerprinting, TCP
modbus.py      — Modbus TCP device mapping, port 502
mqtt.py        — MQTT broker discovery, port 1883
snmp.py        — SNMP inventory, port 161
serial_mstp.py — BACnet MSTP via RS485 (hardware required)

Planned expansion:
bluetooth.py, zigbee.py, zwave.py, lora.py
wifi.py, cellular.py, satellite.py, gps.py
dnp3.py, profinet.py, ethernetip.py, opc_ua.py
