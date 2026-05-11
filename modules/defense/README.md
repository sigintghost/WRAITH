# defense/ — pipeline hardening

Ingestion and runtime defense layer.
Imports from core/ only.
sanitize.py is the most critical module in WRAITH.
If sanitize.py is compromised, all AI context is exposed.

sanitize.py        — ingestion path, chained encoding detection
drift_detector.py  — field stability across scan cycles
self_defense.py    — C2 signature and beacon detection
presence_monitor.py— unauthorized asset detection
jitter_beacon.py   — statistical beacon analysis
secure_connector.py— TLS enforcement
confidence_decay.py— asset freshness scoring
portscan_detector.py— incoming recon detection
allowlist_monitor.py— unexpected destination flagging
port_watch.py      — continuous port monitoring
port_history.py    — per-host port union tracking
honeypot.py        — passive BACnet/Modbus trap
beacon_detector.py — beacon pattern detection
port_hop_detector.py— port hopping detection
