# sensors/ — deployment packages

Remote sensor deployment and management.
All modules in this directory are planned — not yet built.

sensor_registry.py — track all deployed sensors
  fields: sensor_id, label, deployed, last_seen,
  ip, mac, stack_path, status, platform
sensor_transport.py — abstract pull interface
transport_ssh.py    — SSH/IP pull (primary)
transport_ble.py    — Bluetooth proximity sync
transport_lora.py   — LoRa heartbeat
transport_cell.py   — cellular out-of-band pull
transport_sat.py    — satellite pull (future)
wraith_deploy.sh    — bootstrap installer

Sensor status: active / stale / silent
WRAITH_SENSOR_ID env var identifies each deployed sensor.
WRAITH_STACK_PATH env var routes filestack writes locally.
