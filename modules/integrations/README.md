# integrations/ — external connectors

Optional data pipeline connectors.
All skippable. WRAITH core functions without any of these.
Generic hooks only — no vendor-specific product names.

fsi_connector.py      — generic asset DB connector
snowflake_connector.py— data pipeline connector
pg_connector.py       — PostgreSQL integration
iso50001_gap.py       — ISO 50001 energy gap analysis

Planned but not built:
asset_registry.py     — operator-owned asset ground truth
webctrl.py            — WebCTRL-specific pg_connector wrapper
