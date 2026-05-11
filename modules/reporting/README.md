# reporting/ — assessment output

Assessment report generation and dashboard.
All modules planned — not yet built.

report_generator.py — incident and assessment reports
dashboard.py        — Flask/FastAPI web interface
  serves filestack as browsable web UI
  DOXA query interface via browser
  sensor fleet status display
  alert timeline visualization

Production target: Flask on dedicated Linux box
accessible via local network only — never internet-facing.
