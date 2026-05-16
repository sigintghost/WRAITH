# WRAITH Modules — v4.6

63 modules across 10 directories.
Refactored from flat structure in v4.6.

## core/ — network observation foundation
sweep.py, arp.py, portscan.py, ttl.py, registry.py, asset_registry.py
topology.py, filestack.py, baseline.py, alerts.py
subnet_selector.py, ghost.py, logger.py, netcheck.py
input_validator.py, mac_table.py, lateral_detector.py
first_run.py

## defense/ — pipeline hardening
sanitize.py, drift_detector.py, self_defense.py
presence_monitor.py, jitter_beacon.py, secure_connector.py
confidence_decay.py, portscan_detector.py, allowlist_monitor.py
port_watch.py, port_history.py, honeypot.py
beacon_detector.py, port_hop_detector.py

## protocols/ — OT/BAS/ICS listeners
bacnet.py, bacnet_sc.py, modbus.py, mqtt.py
snmp.py, serial_mstp.py

## intel/ — analysis and detection
osint.py, cve.py, ioc_extractor.py, mitre_attack_map.py
dns_tunnel.py, icmp_tunnel.py, traffic_anomaly.py
vlan_hop.py, rf.py, mac_verify.py

## doxa/ — AI intelligence layer
doxa.py, doxa_execute.py, wishlist_agent.py, workorder_agent.py

## admin/ — operator control plane
admin.py, auth.py, keys_manager.py, keys_template.py

## integrations/ — external connectors
fsi_connector.py, snowflake_connector.py, pg_connector.py
iso50001_gap.py

## sensors/ — deployment packages (planned)
sensor_registry.py, sensor_transport.py, wraith_deploy.sh

## reporting/ — assessment output (planned)
report_generator.py, dashboard.py

## utils/ — shared helpers (planned)
colors.py, validators.py

## utils/ — integrity and tooling
hash_check.py

## sensors/ — fleet tracking
sensor_registry.py

## reporting/ — output layer
report.py
