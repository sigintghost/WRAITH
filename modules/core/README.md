# core/ — network observation foundation

Foundation layer. Everything else depends on this.
Do not import from defense/, intel/, protocols/, or doxa/.

sweep.py          — ICMP/TCP host discovery, writes hosts.json
arp.py            — MAC OUI vendor lookup, seeds registry
portscan.py       — OT/BAS/ICS port scanning
ttl.py            — OS fingerprinting via ICMP TTL
registry.py       — device tracking, first/last seen
topology.py       — passive subnet graph builder
filestack.py      — persistent JSON intelligence stack
baseline.py       — host behavioral snapshot
subnet_selector.py— multi-subnet context switcher
alerts.py         — severity throttling, cooldowns
ghost.py          — ANSI/brand, easter eggs
logger.py         — session logging
netcheck.py       — network interface detection
input_validator.py— input sanitization helpers
mac_table.py      — MAC address tracking
lateral_detector.py— lateral movement detection
first_run.py      — first run setup wizard
