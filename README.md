# WRAITH
### passive OT/BAS network intelligence engine
v3.4 — dev branch active

---

it doesn't knock.
it doesn't announce itself.
it just watches.

---

## WHAT IT IS

WRAITH is a passive network intelligence tool
built for OT, BAS, and ICS environments.
It listens. It maps. It fingerprints.
It correlates. It never transmits unless
you tell it to.

Built by a BAS engineer. For BAS engineers.
No cloud. No dependencies beyond Python stdlib.
No subscription.

## CAPABILITIES

| Module         | Protocol              | Port  |
|----------------|-----------------------|-------|
| bacnet.py      | BACnet/IP listener    | 47808 |
| modbus.py      | Modbus TCP listener   | 502   |
| mqtt.py        | MQTT broker listener  | 1883  |
| serial_mstp.py | BACnet MSTP RS485     | —     |
| snmp.py        | SNMP listener         | 161   |
| portscan.py    | OT/BAS/ICS port map   | multi |
| sweep.py       | Subnet sweep          | multi |
| arp.py         | ARP host discovery    | —     |
| osint.py       | 7-source threat intel | —     |
| oracle.py      | Claude AI agent       | —     |

## OSINT — 7 SOURCES PER IP
Shodan, IPInfo, GreyNoise, AbuseIPDB
Shodan InternetDB, Censys, URLScan

## MENU
MAIN      RECON / PROTOCOLS / INTEL / ALERTS / SWEEP
PROTOCOLS BACnet / Modbus / MQTT / MSTP / PORTSCAN / SNMP
INTEL     OSINT / ORACLE / AUTO / DNS / BANNER

## INSTALL
apk add python3 git
git clone https://github.com/sigintghost/WRAITH.git
cd WRAITH
python3 wraith.py

Keys go in ~/.wraith/keys.py
See modules/keys_template.py

## ROADMAP
v3.4  current  — idle timeouts, ANSI, auth, oracle
v3.4  next     — key mgmt, admin panel, gradient UI
v3.4  strata   — FDD, energy, trend, anomaly
v3.4  protocols — Lutron, Crestron, DMX, EasyIO
v3.4  sensors  — GL.iNet nodes, WireGuard, per-building
v5.1  dashboard — browser UI, zero dependencies
v6.0  platform — FSI/1Call/Tableau, SaaS, API

## STRATA
WRAITH observes. Strata understands.

## LICENSE
Commercial rights reserved. See LICENSE.

@sig.int.ghost
