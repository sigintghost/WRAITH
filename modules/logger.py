# WRAITH logger.py — auto loot logging
# sig.int.ghost

import os
import datetime

LOOT_DIR = os.path.expanduser("~/.wraith/loot")
LOG_DIR = os.path.join(LOOT_DIR, "logs")
REPORT_DIR = os.path.join(LOOT_DIR, "reports")
TARGET_DIR = os.path.join(LOOT_DIR, "targets")

def ensure_dirs():
    for d in [LOG_DIR, REPORT_DIR, TARGET_DIR]:
        os.makedirs(d, exist_ok=True)

def get_log_path(target_ip):
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    filename = f"{date}_{target_ip}.log"
    return os.path.join(LOG_DIR, filename)

def log_result(target_ip, module, data):
    ensure_dirs()
    path = get_log_path(target_ip)
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    with open(path, "a") as f:
        f.write(f"[{timestamp}] [{module}] {data}\n")
