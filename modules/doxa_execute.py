import os, json, hashlib
from datetime import datetime
from modules.sanitize import Sanitizer

AUDIT = os.path.expanduser("~/.wraith/loot/exec_audit.log")
STACK = os.path.expanduser("~/.wraith/loot/stack")
_s = Sanitizer()

ALLOWLIST = {
    "tag_device": "Tag a device in the asset registry",
    "flag_alert": "Escalate an alert to CRITICAL",
    "annotate_host": "Add investigation note to a host",
    "export_report": "Export current session to report",
    "isolate_recommend": "Generate isolation recommendation",
}

def _log(action, target, result, token):
    entry = (f"{datetime.now().isoformat()} | "
        f"action={action} target={target} "
        f"token={token} result={result}\n")
    with open(AUDIT, 'a') as f:
        f.write(entry)

def _gate(action, target):
    if action not in ALLOWLIST:
        print(f"\n  [EXEC] action not in allowlist: {action}")
        return False, None
    print(f"\n  [EXEC] PROPOSED ACTION: {action}")
    print(f"  [EXEC] TARGET: {target}")
    print(f"  [EXEC] DESCRIPTION: {ALLOWLIST[action]}")
    print(f"\n  [EXEC] DRY RUN — no changes made yet")
    print(f"  [EXEC] To confirm, type: {action}:{target}")
    confirm = input("  confirm > ").strip()
    expected = f"{action}:{target}"
    if confirm != expected:
        print("  [EXEC] confirmation mismatch — aborted")
        _log(action, target, "ABORTED", "none")
        return False, None
    token = hashlib.sha256(
        f"{action}{target}{datetime.now().isoformat()}"
        .encode()).hexdigest()[:12]
    return True, token

def _load_registry():
    path = os.path.join(STACK, "hosts.json")
    try:
        with open(path) as f: return json.load(f)
    except: return {}

def _save_registry(data):
    path = os.path.join(STACK, "hosts.json")
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    except: pass

def tag_device(target, tag):
    target = _s.sanitize(target, "exec", "ip")
    tag = _s.sanitize(tag, "exec", "tag")
    ok, token = _gate("tag_device", target)
    if not ok: return
    data = _load_registry()
    hosts = data.get("hosts", [])
    for h in hosts:
        if isinstance(h, dict) and h.get("ip") == target:
            h["tag"] = tag
            h["tagged_at"] = datetime.now().isoformat()
    _save_registry(data)
    _log("tag_device", target, f"tag={tag}", token)
    print(f"  [EXEC] tagged {target} as {tag} [{token}]")

def flag_alert(target, reason):
    target = _s.sanitize(target, "exec", "ip")
    reason = _s.sanitize(reason, "exec", "reason")
    ok, token = _gate("flag_alert", target)
    if not ok: return
    path = os.path.join(STACK, "alerts.json")
    try:
        data = json.load(open(path)) if \
            os.path.exists(path) else []
        if isinstance(data, dict):
            data = data.get("alerts", [])
        data.append({"timestamp": datetime.now().isoformat(),
            "module": "doxa_execute", "severity": "CRITICAL",
            "ip": target, "reason": reason, "token": token})
        json.dump(data, open(path, 'w'), indent=2)
        _log("flag_alert", target, f"reason={reason}", token)
        print(f"  [EXEC] alert flagged CRITICAL [{token}]")
    except Exception as e:
        print(f"  [EXEC] error: {e}")

def annotate_host(target, note):
    target = _s.sanitize(target, "exec", "ip")
    note = _s.sanitize(note, "exec", "note")
    ok, token = _gate("annotate_host", target)
    if not ok: return
    data = _load_registry()
    hosts = data.get("hosts", [])
    for h in hosts:
        if isinstance(h, dict) and h.get("ip") == target:
            h["note"] = note
            h["noted_at"] = datetime.now().isoformat()
    _save_registry(data)
    _log("annotate_host", target, f"note={note[:40]}", token)
    print(f"  [EXEC] note added to {target} [{token}]")

def isolate_recommend(target):
    target = _s.sanitize(target, "exec", "ip")
    ok, token = _gate("isolate_recommend", target)
    if not ok: return
    print(f"\n  [EXEC] ISOLATION RECOMMENDATION: {target}")
    print(f"  [EXEC] 1. Identify switch port for {target}")
    print(f"  [EXEC] 2. Move to isolated VLAN")
    print(f"  [EXEC] 3. Block inter-VLAN routing")
    print(f"  [EXEC] 4. Mirror traffic to capture")
    print(f"  [EXEC] 5. Document port and MAC")
    _log("isolate_recommend", target, "issued", token)
    print(f"  [EXEC] recommendation logged [{token}]")

def run_execute(target_ip=None, action=None, param=None):
    print("\n  \033[36m[DOXA EXECUTE]\033[0m "
        "controlled action engine")
    print("  authorized actions: " + ", ".join(ALLOWLIST))
    if not action:
        action = input("  action > ").strip().lower()
    if not target_ip:
        target_ip = input("  target ip > ").strip()
    dispatch = {"tag_device": lambda: tag_device(
            target_ip, param or input("  tag > ")),
        "flag_alert": lambda: flag_alert(
            target_ip, param or input("  reason > ")),
        "annotate_host": lambda: annotate_host(
            target_ip, param or input("  note > ")),
        "isolate_recommend": lambda: isolate_recommend(
            target_ip)}
    fn = dispatch.get(action)
    if fn: fn()
    else: print(f"  [EXEC] unknown action: {action}")

if __name__ == "__main__":
    run_execute()
