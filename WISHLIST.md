# WRAITH WISHLIST — living roadmap
# updated: 2026.05.11
# classification: local only — never push to public repo

## IMMEDIATE — next session
- snmp.py upsert call placement — sysDescr, sysName, vendor
- portscan.py upsert call placement — open_ports array
- ioc_extractor.py upsert call — threat.ioc_flags
- mitre_attack_map.py upsert call — threat.mitre_techniques
- traffic_anomaly.py upsert call — threat.ioc_flags
- vlan_hop.py upsert call — threat.ioc_flags
- bacnet_sc.py upsert call — SC fabric members, node type
- serial_mstp.py upsert call — MSTP frames, protocol tag
- ttl.py upsert call — os_fingerprint, ttl_guess
- asset registry smoke test — full scan, watch registry build
- admin menu — unauthorized review queue, authorize flow
- alerts.json display overhaul — severity color, module, ip

## DOXA — intelligence layer overhaul
- DOXA auto-cycle — continuous context refresh, no manual query
- DOXA hunt modes — autonomous anomaly detection
  hunt IP — single host deep profile
  isolate IP — containment options
  baseline — normal vs anomaly delta
  report — incident note generator
  explain — plain English for facilities leadership
  defend — BAS engineer action list
  scan SUBNET — full subnet analysis
  compare — delta since last session
  risk — ranked risk list all hosts
  brief — one paragraph non-technical summary
  correlate — patterns across all deployed sensors
- DOXA registry integration — asset_registry as primary context
- DOXA threat queue — hunts unauthorized assets automatically
- DOXA legitimacy scoring — not just is traffic known,
  does this pattern make operational sense right now
- DOXA streaming responses — no blocking wait
- DOXA persistent memory — cross-session context retention
- DOXA RAG layer — vector store of historical filestack data
- DOXA prompt library — OT-specific reasoning templates
  separate from business logic per genai.works pattern
- Local DOXA — QLoRA air-gapped model
  4-bit quantized 7B-13B, OT/BACnet/Modbus LoRA adapter
  no API calls, no data leaves facility
  Sergey demo answer for air-gapped environments

## ARCHITECTURE — structural gaps
- config/ layer — model_config.yaml, API keys, env settings
  never hardcoded per genai.works pattern
- data/ layer — cache/, embeddings/, vectordb/
  clean separation per genai.works pattern
- processing/ pipeline — chunk, tokenize, clean
  nothing hits DOXA inference raw
- inference/ layer — inference_engine.py, response_parser.py
  DOXA goes through this, not called directly
- tests/ — unit/ and integration/
  untested AI code ships unpredictable behavior not just bugs
- scripts/ — setup_env.sh, run_tests.sh, build_embeddings.py
  repeatable automation, never manual
- WRAITH_STACK_PATH env var — sensor deployment hook
  all filestack writes respect this for remote sensor support
- Filestack API standardization — filestack.write(key, data)
  uniform across all modules, no custom write paths
- Module hash manifest — hash_check.py
  verify module integrity on every launch
  self_defense.py expanded to watch own file integrity

## DETECTION — gaps identified
- Semantic sanitization — free-text fields from devices
  BACnet object-name, SNMP sysDescr, MQTT topics
  plain English prompt injection bypasses sanitize.py
  needs semantic content validation before DOXA ingestion
- Write provenance tracking — every filestack entry tagged
  source module, timestamp, sensor ID
- Conflict resolution — asset_db vs wire disagreement
  what wins when registry says one thing, network says another
- Partial silence detection — presence_monitor expansion
  device answers ICMP but BACnet goes silent
  network signature of driver unload or service kill
- Legitimacy-aware anomaly scoring
  legitimate protocol used maliciously harder than unknown traffic
  BYOVD OT equivalent — credentialed device pushing malicious config
- Port hop detector — cross-process injection network signature
  new outbound connection on port never used by that host
  chain with confidence_decay for detection
- SNMP process table harvesting
  pull running process list where OID available
  baseline it, flag new processes to alerts.json
- Resident adversary detection gap — fully passive attacker
  no outbound traffic, just listening, invisible to WRAITH
  physical layer problem, cannot solve at network observation alone
  MTD rotation reveals if they follow new IP without provisioning
- Supply chain — module update signature verification
  no hash check before execution currently
  GitHub supply chain attack surface is open

## PROTOCOLS — planned modules
- bluetooth.py — BLE passive scanner, device fingerprint
- zigbee.py — building sensor mesh passive listener
- zwave.py — access control, facility devices
- lora.py — LoRaWAN long range IoT listener
- wifi.py — probe request harvesting, AP fingerprint
- cellular.py — LTE/5G modem detection
- gsm.py — legacy 2G/3G industrial modems
- dnp3.py — SCADA/utility protocol
- profinet.py — Siemens industrial
- ethernetip.py — Rockwell/Allen-Bradley
- opc_ua.py — unified architecture listener
- satellite.py — Starlink/VSAT signal awareness
- gps.py — GPS spoofing detection passive
- pcap.py — full packet capture, requires Linux + SPAN port
- netflow_collector.py — router flow ingestion
  src/dst/bytes/duration without payload
  no SPAN needed, router pushes flows to collector

## INTEL — planned modules
- fingerprint.py — passive OS/device fingerprinting
- proto_anomaly.py — cross-protocol behavior analysis
- time_anomaly.py — temporal pattern detection
- geo_anomaly.py — traffic origin analysis
- signal_correlate.py — cross-signal anomaly correlation
  BLE device appears same time as rogue IP
- spectrum_anomaly.py — RF spectrum deviation detection
- jamming_detect.py — signal suppression detection
- sensor_correlate.py — cross-sensor anomaly correlation
  same MAC seen on sensor A and sensor B
- fleet_anomaly.py — behavior deviation across sensor fleet
- sensor_drift.py — detect sensor data manipulation
  between collection and pull
- passive_dns.py — device DNS resolution logging
- tls_inspect.py — certificate inspection, domain fingerprint
- credential_exposure.py — cleartext auth on BAS protocols

## SENSORS — remote deployment
- wraith_daemon.py — continuous operation, design session first
- sensor_registry.py — multi-sensor fleet tracking
  sensor_id, label, deployed, last_seen, ip, mac, status
- wraith_deploy.sh — single file bootstrap installer
- transport_ssh.py — primary pull mechanism
- transport_ble.py — proximity sync via Bluetooth
- transport_lora.py — long range low bandwidth heartbeat
- transport_cell.py — cellular out of band pull
- transport_sat.py — satellite pull future
- Pi deployment package — post-daemon design session
- OpenWRT deployment — sees all subnet traffic natively

## DEFENSE — deception and moving target
- honeytoken.py — fake filestack entries, alert on reference
- canary.py — fake credential files, alert on access
- tarpit.py — slow-response probe handler
- protocol_decoy.py — fake BACnet device roster
- mtd_controller.py — moving target defense
  OFiSO IP rotation, anomaly-triggered not just timed
  vacated IP becomes honeypot candidate post-rotation
- subnet_fold.py — full subnet collapse to new VLAN
  old subnet becomes full honeypot fabric
  resident adversary stays behind in deception plane
  WRAITH observes both planes simultaneously

## REPORTING — human readable output
- report.py — assessment report export
  facilities leadership readable, not just security engineers
  OT governance requirement — explainable output
- dashboard/ — web UI bolt-on via Flask or FastAPI
  visualization layer, deferred to roadmap
  digital twin map view — nodes and edges
- white_label.py — integrator mode
  operator branding, sanitized output
- incident_note.py — DOXA report mode output
  single page, non-technical, exec summary

## INTEGRATIONS — optional connectors
- webctrl.py — WebCTRL PostgreSQL integration
  wraps pg_connector.py with WebCTRL-specific logic
- cmms.py — generic CMMS/CMDB change management feed
  maintenance window suppression for drift_detector
- asset_export.py — DATA EXPORT generic hook
  operators wire their own Snowflake, Tableau, etc
- bacnet_sc_node_remove.py — Clause 19.8 rogue node removal
  doxa_execute five-layer guardrail gate required
  design session needed before any implementation

## OPTIGO — BACnet/SC integration research
- Review optigo.net leading-the-charge post
  BACnet/SC detection gaps from Nate Benes context
  SC fabric passive monitoring expansion
  Network Port object property queries
  Unauthorized SC node enrollment detection

## SIGNAL INTELLIGENCE — UAV/drone threat layer
- drone_detect.py — passive UAV signal detection
  2.4GHz control link fingerprint
  5.8GHz video downlink detection
  GPS L1 1.57542GHz baseline and spoof detection
  Hardware gated: RTL-SDR, Linux box
- gps_spoof_detect.py — GPS signal anomaly
  baseline genuine satellite signal strength/timing
  detect fake signal injection above threshold
  flag simultaneous genuine + spoofed signal presence
- deauth_detect.py — WiFi deauth storm detection
  passive monitor for 802.11 deauth frame floods
  correlate with drone presence signature
  flag WPA handshake capture attempt pattern
- jamming_detect.py — already in wishlist
  expand: frequency-specific jamming signatures
  2.4GHz, 5.8GHz, GPS L1 bands specifically
  distinguish interference from active jamming
- drone_gcs_map.py — ground control station mapping
  correlate control signal origin with known positions
  rogue GCS detection — signal from unexpected direction
  multi-sensor triangulation for GCS location
- uav_registry — asset_registry type:uav
  drone MAC if WiFi-linked, RF fingerprint if not
  authorized vs unauthorized UAV over facility
  add to asset_registry schema: signal_fingerprint field

## THREAT INTEL — active CVE feed
- cve_feed.py — live CVE ingestion
  cPanel CVE-2026-41940 class: filemanager backdoor
  2000+ attacker IPs active right now
  feed into DOXA context as live threat intel
  cross-reference against WRAITH-observed open ports
- ioc_feed.py — active campaign IP/domain ingestion
  Mr_Rot13 campaign IPs as example
  infrastructure active since 2020, low detection
  any WRAITH-observed host hitting known C2 = immediate alert
- campaign_correlate.py — match observed traffic
  against known campaign infrastructure
  persistent SSH on non-standard port + known C2 IP = flag
  cryptomining signature: high CPU port, known pool endpoints
