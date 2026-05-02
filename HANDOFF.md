# WRAITH PROJECT HANDOFF v4.0
## Continue at v4.0 targeting v4.1

## CRITICAL MOBILE RULES
- iSH iPhone — max 20 lines per paste
- cat > /tmp/fixXX.py << 'EOF' pattern always
- All parts shown together, run separately
- String replace not line insertion
- Never assume a step worked

## IDENTITY
- GitHub: github.com/sigintghost/WRAITH
- Brand: dark, technical, minimal, passive observer
- PPCL Easter eggs: %X0.0 and %MW100

## V4.0 CONFIRMED COMPLETE — 2026-05-02
- DOXA persistent memory — cross-session context
- Device registry — first_seen/last_seen JSON
- HTTP banner filestack write + DOXA context
- MAC OUI confirmed feeding DOXA context
- DOXA login alert — briefing on startup
- Login alert upgrade — real threat + hunt suggestion
- Registry + banner subnet path bug fixed
- Subnet selector — auto-discover + manual entry
- Subnet selector UX — exit/cancel/q cancels
- DOXA subnet-aware context with building label
- L4/L5/L6 ports added — VPN/Tor/AD/WinRM/proxy
- PII purged from git history — all 107 commits
- HANDOFF scrubbed — public safe
- Both branches synced

## DOXA MODES
hunt/isolate/baseline/report/explain/defend
scan SUBNET/compare/risk/brief

## FILESTACK
hosts.json, arp_table.json, ttl_fingerprints.json,
portscan.json, modbus_map.json, mqtt_brokers.json,
bacnet_inventory.json, snmp_inventory.json,
alerts.json, http_banners.json
Subnet-namespaced: loot/stack/SUBNET/
Registry: ~/.wraith/registry.json
Memory: ~/.wraith/memory.json
Subnets: ~/.wraith/subnets.json

## KNOWN BUGS OPEN
- SMTP shows MISSING after configuration
- ThreatFox 401 — needs key from auth.abuse.ch
- Censys 401 — key may be expired
- Role enforcement not wired to menus yet
- Self-service password change not built
- Recon submenu not built — auto-runs on select

## NEXT SESSION BUILD ORDER — v4.1
1. pg_connector.py — WebCTRL PostgreSQL into DOXA
2. Topology mapper — subnet graph from passive obs
3. Role enforcement — technician/viewer restrictions
4. DOXA 6-layer attack map report mode
5. Alert correlation engine — compound triggers
6. README update — What It Could Be section
7. Self-service password change
8. PDF report export — assessment deliverable

## ARCHITECTURE LOCKED
- User storage: ~/.wraith/users.json
- Building assigned to account + selectable
- Terminal is the interface
- PostgreSQL planned — WRAITH own DB + WebCTRL RO
- All SQL queries parameterized — no injection surface
- Snowflake pipeline — long term retention future
- Tableau — visualization layer future
- Local LLM via Ollama — air-gapped DOXA planned

## STRATA MODULE
Building persona system — internal use only.
Personas loaded at login per building assignment.
Config: modules/strata/personas/
Each persona: subnet, priority, alert threshold, voice.
Details in private config — not stored in repo.

## GIT WORKFLOW
git add -A && git commit -m "msg" && git push
Branch: dev active, main stable

## AFTER iSH RESET
apk add python3 git
git clone https://github.com/sigintghost/WRAITH.git
cd WRAITH && python3 wraith.py

WRAITH observes. Strata understands. DOXA reveals.

## SESSION UPDATE — v4.0 FINAL 2026-05-02

### Completed Late Session
- DOXA agent loop — propose/approve/deny HITL
- 6 new DOXA modes: profile/timeline/vlan/creds/ghost/rf
- Rogue device detection — alerts.json on first appearance
- Auto-scan new hosts on sweep
- Subnet selector UX fix — c/enter to cancel
- Topology mapper — modules/topology.py
- DOXA topology context — unscanned subnets surfaced
- OSINT wired into DOXA context
- Version bumped to 4.0
- README: What It Could Be + longer vision section
- L4/L5/L6 ports + VPN/Tor/AD/WinRM added

### Next Session Start
1. pg_connector.py — WebCTRL PostgreSQL
2. RF/Bluetooth/Zigbee module scaffold
3. Fix API keys — VirusTotal/ThreatFox/Censys
4. DOXA persistent alert summary on login
5. Instagram story — purple team content strategy

### API Keys Needed
- VirusTotal: virustotal.com free account
- ThreatFox: auth.abuse.ch free account
- Censys: censys.io — check if key expired
- Shodan: shodan.io — free tier limited

WRAITH observes. Strata understands. DOXA reveals.

## SESSION CLOSE — v4.0 FINAL 2026-05-02

### Instagram Live
- Two slide carousel posted — v4.0 announcement
- Slide 1: clean terminal output — sweep/rogue/lateral/DOXA
- Slide 2: L4/L5/L6 — WinRM/Tor/Kerberos/TTL — CRITICAL
- Caption: WRAITH v4.0 passive persistent aware
- Hashtags: purpleteam OTsecurity threathunting infosec redteam
- Comment on anastasis_king WordPress pentest post
- Comment on ekoms.is.my.savior OpenClaw post

### Accounts Worth Watching
- anastasis_king — WordPress pentest carousels, military bg
- ekoms.is.my.savior — OpenClaw/AI agent crowd, casual tone
- hexsecteam — liked anastasis post, team account
- apex_shield — compliance/visibility competitor, watch only
- venoxploit — OTP attack carousels, similar format to ours

### Next Session Start Instructions
Tell Claude: continuing WRAITH at v4.0
Upload HANDOFF.md first
Start by analyzing any Instagram screenshots for
relevance to WRAITH, wishlist items, and content strategy
Then build in this order:
1. pg_connector.py — WebCTRL PostgreSQL into DOXA
2. Telegram bot — control DOXA from anywhere
3. Honeypot module — fake endpoints, log attackers
4. Fix API keys — VirusTotal/ThreatFox/Censys
5. Role enforcement — technician/viewer menus

### Key Decisions Locked
- PostgreSQL: WRAITH own DB + WebCTRL read-only
- All SQL parameterized — no injection surface
- Snowflake pipeline — future long term retention
- Telegram as DOXA remote interface
- Soul file — AGENTS.md for DOXA personality
- Honeypot feeds directly into alerts.json
- Topology map grows passively from filestack refs

### OpenClaw Relevance
- Soul file concept — AGENTS.md defines constraints
- Telegram control — DOXA from anywhere
- Local LLM — Ollama air-gapped mode
- Honeypot pattern — fake WP login logs every IP
- Constraint-first design — do no harm as core truth

WRAITH observes. Strata understands. DOXA reveals.
