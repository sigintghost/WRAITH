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
Status: planned v4.0

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
Status: planned v4.0

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
