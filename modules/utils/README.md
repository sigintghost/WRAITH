# utils/ — shared helpers

Shared utilities used across all categories.
All modules planned — not yet built.

colors.py      — ANSI color constants, split from ghost.py
validators.py  — shared input validation helpers
hash_check.py  — module integrity verification
  verifies SHA256 of critical modules on launch
  priority: admin/auth.py, admin/keys_manager.py,
  doxa/doxa_execute.py, defense/sanitize.py
sensor_id.py   — sensor identity and fingerprinting
