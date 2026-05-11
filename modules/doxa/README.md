# doxa/ — AI intelligence layer

DOXA is not a chatbot.
DOXA is a passive network intelligence agent.
Reads full filestack before every query.
Reasons across protocols, topology, behavior, and time.

doxa.py        — Claude API agent, streaming, token routing
doxa_execute.py— five-layer guardrail execution engine
wishlist_agent.py — self-building roadmap agent
workorder_agent.py— CMMS work order integration

Security note: doxa_execute.py integrity is critical.
Hash check this file on every launch.
If tampered, all execution guardrails fail silently.

Modes: hunt/isolate/baseline/report/explain/defend
       scan/compare/risk/brief/correlate
