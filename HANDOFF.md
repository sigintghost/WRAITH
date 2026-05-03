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

## FINAL FIXES — SESSION CLOSE 2026-05-02
- PORTS dict unified — wraith.py now imports from portscan.py
- 49152 was ROBLOX-ALT in portscan.py but missing in wraith.py
- Root cause: two separate PORTS dicts out of sync
- Fix: wraith.py imports PORTS directly — no more duplication
- Next sweep will correctly identify port 49152 as ROBLOX-ALT
- Galaxy-S23-FE identified on network — .67
- New host .70 appeared — 49152 open — needs reidentification

## NEXT SESSION START
1. Upload HANDOFF.md
2. Paste any Instagram screenshots for analysis
3. Then build: pg_connector.py first
4. Then Telegram bot integration
5. Then honeypot module

## SESSION UPDATE — v4.0 2026-05-02 late

### Confirmed Working
- Menu redesign live — 1/2/3/4/5/6/7/8
- SCAN chain — portscan + banner + SNMP on target
- INTEL → OSINT defaults to public egress IP
- DOXA context loading fixed — filestack wired
- DOXA profile mode — Samsung TV .72 identified
- DOXA ghost mode self-limiting — HITL working
- Public IP: 172.14.141.247 AT&T Oklahoma City

### Next Build Order
1. baseline.py — per-host behavioral baseline
2. dns_tunnel.py — DNS tunneling detection
3. icmp_tunnel.py — ICMP payload anomaly
4. mac_verify.py — OUI spoofing detection
5. traffic_anomaly.py — micro-exfiltration
6. vlan_hop.py — 802.1Q detection
7. rf.py — RF/Bluetooth/Zigbee scaffold
8. Fix API keys — VT/ThreatFox/Censys/Shodan
9. DOXA active mode — auth-gated cred testing
10. pg_connector.py — WebCTRL PostgreSQL

### Key Findings This Session
- .72 Samsung TV — 8080/9080/8001 open
- 8001 returns 401 Unauthorized — API exposed
- .69 consumer device — IPHONE-SYNC ports
- Public egress confirmed AT&T OKC residential
- DOXA blind spots: DNS tunnel, ICMP tunnel,
  MAC spoof, VLAN hop, micro-exfil, RF

### Architecture Decision
- WRAITH = sensor layer, stays sovereign
- Strata = separate repo, consumes filestack
- DOXA = bridge agent, seed of swarm
- Active mode gates on auth role

WRAITH observes. Strata understands. DOXA reveals.
