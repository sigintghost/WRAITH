# WRAITH WISHLIST
## living backlog — not a roadmap
## agent readable — implementation workflows generated on request

---

## PLATFORM INTELLIGENCE

### Unified Control Plane
Single browser view across all buildings simultaneously.
Cross-building anomaly surfacing by severity.
All protocols, all agents, all locations in one frame.
Not per-building — portfolio wide.
Status: planned v5.1

### FinOps Layer
Cost per building per day.
Cost per fault avoided.
Cost per sqft trending.
ROI calculator vs OptigoVN subscription cost.
Sales tool for Tier 2 and Tier 3.
Status: planned v3.7

### Assessment Report Export
After every session — one click PDF report.
Device inventory, risk findings, protocol map.
DOXA recommendations included.
Client deliverable for Tier 2 professional services.
Status: wishlist

### Assess Baseline Optimize Report Cycle
Every engagement follows this loop automatically.
WRAITH sweeps, DOXA assesses, Strata baselines.
Agents monitor, dashboard reports, cycle repeats.
Sticky. Subscription-worthy.
Status: wishlist

---

## AI AND AGENT ARCHITECTURE

### MCP Server Layer
Formalize filestack as MCP tool endpoints.
DOXA calls tools instead of reading flat files.
Tools: get_sweep_results, get_arp_table,
get_bacnet_inventory, get_active_alerts,
get_portscan, run_sweep, run_portscan,
get_building_context.
AI decides which tools to call per question.
That is agentic. Not just context injection.
Status: wishlist — high priority

### RAG Memory Layer
Vector database for historical filestack.
DOXA answers questions about device state
from weeks or months ago.
Strata baseline memory across seasons.
Status: wishlist

### DOXA Streaming
Print tokens as Claude generates them.
Feels alive. Better UX for long analysis.
Status: wishlist — quick win

### Persistent Cross-Session Memory
DOXA remembers findings from last session.
summary.json written on exit, loaded on start.
Device history, anomaly history, recommendations.
Status: planned v3.7

### Tool Use — DOXA Triggers Modules
DOXA calls run_sweep, run_portscan directly.
No menu interaction required.
AI directs its own investigation.
Status: wishlist — high priority

---

## BUSINESS AND DEPLOYMENT

### White Label Integrator Mode
BAS integrators deploy WRAITH under their brand.
Per building per year licensing.
Admin configures integrator name and logo.
Status: wishlist — Tier 3

### Marketplace Layer
Integrators listed in WRAITH partner directory.
Buildings matched to nearest certified integrator.
Status: wishlist — Tier 3

### License Key System
Per building activation.
Admin generates keys from central dashboard.
Keys expire, rotate, revoke.
Status: wishlist — Tier 3

---

## SELF-BUILDING SYSTEM

### Wishlist Agent — modules/wishlist_agent.py
Reads WISHLIST.md on demand.
Parses each item — status, priority, dependencies.
Generates step by step implementation workflow.
Admin reviews workflow in terminal or dashboard.
Admin approves — agent writes the module scaffold.
Admin runs scaffold — confirms and commits.
Closes the loop: wishlist to working code.
DOXA model: Sonnet for workflow generation.
Status: wishlist — meta priority

---

## SECURITY DETECTION — v3.8+

### Outbound Connection Monitor
BAS controllers should never call external IPs.
Track destination IPs in passive capture.
Alert: controller hitting port 80/443/53 externally.
Status: wishlist — high priority

### TTL Delta Tracking
Compare TTL per IP across sessions.
Flag OS fingerprint changes per device.
Controller changing TTL from 62 to 128 = alert.
Status: wishlist — high priority

### Admin Panel
List all users, roles, created dates.
Create, delete, role change, password reset.
Recovery code system at first run.
tools/reset_admin.py emergency script.
Status: wishlist — next sprint

### DOXA Streaming
Print tokens as Claude generates them.
Feels alive. Better UX for long analysis.
One line change in ask_doxa().
Status: wishlist — quick win

### DOXA Persistent Memory
summary.json written on exit.
Loaded on next session start.
DOXA remembers what it found last week.
Status: wishlist — v3.8

### OSINT Filestack Pipeline
osint.py writes per-IP findings to osint_results.json.
DOXA reads osint_results.json in load_stack().
Cross-reference OSINT intel with network findings.
Status: wishlist — quick win

### Strata Separation
~/strata/ as separate directory or repo.
strata.py separate entry point.
Reads ~/.wraith/loot/stack/ one way only.
Never writes back to WRAITH.
Status: wishlist — v3.8 architecture decision

---

## HYPERSCALE DATA CENTER — future vertical

### Multi-subnet Scanner
/16 subnet support — thousands of devices
Pod/row/rack topology mapping
WRAITH currently does /24 only
Status: wishlist — v3.8+

### DC Protocol Stack
PDU Modbus TCP — APC/Raritan/Vertiv
CRAC/CRAH BACnet — precision cooling units
Generator/UPS Modbus — power chain monitoring
DCIM API bridge — Sunbird/Nlyte read only
Liquid cooling sensors — flow/temp/pressure
Status: wishlist — v3.8+

### Liquid Cooling Intelligence
Direct liquid cooling flow rate baseline
Coolant inlet/outlet delta-T trending
Immersion cooling pump efficiency
Rear door heat exchanger valve monitoring
Anomaly: delta-T outside baseline = alert
All via Modbus TCP — already in WRAITH
Status: wishlist — Strata DC agent

### DC Intelligence Layer
PUE calculation and trending
Cooling efficiency baseline per zone
Power chain tracing utility to rack
Stranded capacity detection
Hot/cold aisle thermal correlation
Status: wishlist — Strata DC persona

### Niagara/Tridium Integration
WRAITH does not need Niagara certification
WRAITH passively observes Niagara via BACnet/IP
Port 4911 Niagara-SSL already in PORTS dict
Sell TO Niagara integrators as assessment layer
They program it. WRAITH watches it.
Status: current capability — marketing angle

### DC Strata Persona
DC-specific language and priorities
Uptime first, efficiency second, cost third
PUE as primary health metric
Liquid cooling as primary thermal layer
Status: wishlist — Strata v2.0

---

## OSINT EXPANSION — HIGH PRIORITY

### Free Sources to Add
CISA KEV — known exploited vulnerabilities feed
  cisa.gov/known-exploited-vulnerabilities-catalog
  no key, JSON feed, cross-reference per device
Criminal IP — OT-focused Korean scanner
  criminalip.io — free tier available
FOFA — Chinese internet scanner sees OT gear
  fofa.info — free tier available
ONYPHE — French scanner good OT coverage
  onyphe.io — free tier available
HackerTarget — host search BGP DNS
  hackertarget.com — free API
Threatfox — IOC malware IP database
  threatfox.abuse.ch — free
AbuseCH — malware botnet IP feeds
  abuse.ch — free
BGPView — ASN routing intelligence
  bgpview.io — free
DNSDumpster — passive DNS reconnaissance
  dnsdumpster.com — free
MXToolbox — blacklist DNS check
  mxtoolbox.com — free API

### Paid Sources to Add
BinaryEdge — attack surface OT protocols
  binaryedge.io — key required
Pulsedive — threat feeds affordable
  pulsedive.com — key required
SecurityTrails — DNS history subdomains
  securitytrails.com — key required
Validin — passive DNS new
  validin.com — key required

### OT/ICS Specific Intel
ICS-CERT advisories — OT specific CVEs
  us-cert.cisa.gov/ics
MITRE ATT&CK ICS — already in portscan
  expand to OSINT cross-reference
Dragos Year In Review — ICS threat landscape
Claroty Team82 — OT research feed

Status: wishlist — next sprint HIGH PRIORITY

## DOXA INTELLIGENCE GAPS — from hunt mode analysis

### Module Filestack Audit Required
Every module must write to subnet-namespaced filestack.
Current status unknown for most modules.
Audit: arp.py, bacnet.py, modbus.py, mqtt.py, snmp.py,
ttl.py, banner grabber, lateral_detector.py

### MAC OUI to DOXA Context
ARP table captures MAC addresses. OUI lookup gives vendor.
This must be included in DOXA filestack context.
Currently not fed into build_context().

### HTTP Banner to Filestack
Banner grabber runs during portscan but results not
written to filestack. DOXA cannot see server headers,
vendor strings, or HTML titles.

### TTL Fingerprint to DOXA
ttl.py writes ttl_fingerprints.json — verify DOXA
reads and includes in hunt context.

### SNMP sysDescr to Filestack
SNMP module captures device type and firmware.
Must be verified writing to subnet filestack.

### BACnet Who-Is Results to DOXA
BACnet inventory must be verified in DOXA context.
Device ID, vendor, instance number are critical for
OT threat assessment.

### DNS Query Monitoring
Log all DNS resolutions from discovered hosts.
Flag known phishing infrastructure — ngrok,
trycloudflare, serveo — as C2 indicators.

## FROM SESSION 2026-05-02
- Subnet selector UX — cancel on invalid input
- DOXA 6-layer attack map report mode
- README: What It Could Be section
- README: DOXA persistent memory mention
- pg_connector.py — WebCTRL PostgreSQL
- DOXA login alert upgrade — real threat + hunt target
- Recon submenu — separate from auto-chain
- crt.sh subdomain recon integration
- DNS deep dive — A/MX/NS/TXT records to filestack
- Cloud enumeration — S3/Azure blob exposure check

## FROM OPENCLAW/EKOMS ANALYSIS 2026-05-02
- Telegram bot integration — control DOXA from anywhere
- DOXA soul file — AGENTS.md defining personality/constraints
- Local LLM via Ollama — air-gapped zero API cost
- ZimaBoard/edge hardware deployment target
- Honeypot module — fake upload endpoints, fake shells
- Honeypot logger — log every IP that hits trap pages
- AI agent 24/7 mode — persistent background DOXA loop
- DOXA via VPS — remote deployment mode
- Constraint-first agent design — do no harm as core truth
- Web search tool for DOXA — live CVE research during session
