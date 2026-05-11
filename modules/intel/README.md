# intel/ — analysis and detection

Intelligence and anomaly detection layer.
Imports from core/ only.
Feeds findings to filestack and alerts.json.

osint.py           — 13-source threat intel pipeline
cve.py             — CVE/CISA KEV lookup
ioc_extractor.py   — IOC extraction from banners
mitre_attack_map.py— ATT&CK ICS technique mapping
dns_tunnel.py      — DNS tunnel detection
icmp_tunnel.py     — ICMP covert channel detection
traffic_anomaly.py — volume anomaly detection
vlan_hop.py        — 802.1Q double-tag detection
rf.py              — RF/wireless signal scaffold
mac_verify.py      — MAC spoof detection

Planned expansion:
fingerprint.py, proto_anomaly.py, time_anomaly.py
signal_correlate.py, sensor_correlate.py, fleet_anomaly.py
