import json, os
from modules.core.asset_registry import upsert as reg_upsert
from datetime import datetime
from modules.defense.sanitize import Sanitizer

STACK = os.path.expanduser("~/.wraith/loot/stack")
ALERTS = os.path.join(STACK, "alerts.json")
FINDINGS = os.path.join(STACK, "mitre_findings.json")
_s = Sanitizer()

ICS_TECHNIQUES = {
    "T0801": {"name": "Monitor Process State",
        "tactic": "Collection",
        "keywords": ["sweep","scan","discover","probe"]},
    "T0802": {"name": "Automated Collection",
        "tactic": "Collection",
        "keywords": ["filestack","harvest","extract"]},
    "T0814": {"name": "Denial of Control",
        "tactic": "Inhibit Response",
        "keywords": ["block","deny","isolate","vlan"]},
    "T0856": {"name": "Spoof Reporting Message",
        "tactic": "Impair Process Control",
        "keywords": ["spoof","inject","fake","forge"]},
    "T0862": {"name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "keywords": ["firmware","update","supply"]},
}

ICS_TECHNIQUES.update({
    "T0840": {"name": "Network Connection Enumeration",
        "tactic": "Discovery",
        "keywords": ["portscan","port","enumerate","sweep"]},
    "T0842": {"name": "Network Sniffing",
        "tactic": "Collection",
        "keywords": ["passive","sniff","capture","pcap"]},
    "T0885": {"name": "Commonly Used Port",
        "tactic": "Command and Control",
        "keywords": ["beacon","c2","47808","502","1883"]},
    "T0884": {"name": "Connection Proxy",
        "tactic": "Command and Control",
        "keywords": ["proxy","tunnel","relay","pivot"]},
    "T0869": {"name": "Standard Application Layer Protocol",
        "tactic": "Command and Control",
        "keywords": ["bacnet","modbus","mqtt","dnp3"]},
    "T0865": {"name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "keywords": ["phish","attachment","email","macro"]},
    "T0817": {"name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "keywords": ["driveby","browser","javascript"]},
    "T0886": {"name": "Remote Services",
        "tactic": "Lateral Movement",
        "keywords": ["lateral","rdp","ssh","remote"]},
})

ICS_TECHNIQUES.update({
    "T0891": {"name": "Hardcoded Credentials",
        "tactic": "Persistence",
        "keywords": ["default","credential","password","hardcoded"]},
    "T0857": {"name": "System Firmware",
        "tactic": "Persistence",
        "keywords": ["firmware","flash","bootloader","bios"]},
    "T0839": {"name": "Module Firmware",
        "tactic": "Persistence",
        "keywords": ["module","plc","controller","firmware"]},
    "T0849": {"name": "Masquerading",
        "tactic": "Evasion",
        "keywords": ["spoof","clone","mac","masquerade"]},
    "T0872": {"name": "Indicator Removal on Host",
        "tactic": "Evasion",
        "keywords": ["evasion","pulse","hide","stealth"]},
    "T0887": {"name": "Wireless Compromise",
        "tactic": "Initial Access",
        "keywords": ["wireless","wifi","zigbee","rf"]},
    "T0888": {"name": "Remote System Information Discovery",
        "tactic": "Discovery",
        "keywords": ["snmp","banner","fingerprint","ttl"]},
})

def map_alert(alert):
    if not isinstance(alert, dict):
        return []
    reason = _s.sanitize(
        str(alert.get("reason","")),
        "mitre", "reason").lower()
    message = _s.sanitize(
        str(alert.get("message","")),
        "mitre", "message").lower()
    combined = reason + " " + message
    matches = []
    for tid, data in ICS_TECHNIQUES.items():
        for kw in data["keywords"]:
            if kw.lower() in combined:
                matches.append({
                    "technique_id": tid,
                    "technique_name": data["name"],
                    "tactic": data["tactic"],
                    "matched_keyword": kw,
                    "alert_reason": reason[:60]})
                break
    return matches

def load_json(path):
    try:
        if os.path.exists(path):
            with open(path) as f: return json.load(f)
    except: pass
    return {}

def save_json(path, data):
    try:
        with open(path,'w') as f:
            json.dump(data, f, indent=2)
    except: pass

def run_mitre_map():
    print("\033[36m[MITRE]\033[0m "
        "mapping alerts to ATT&CK ICS techniques...")
    data = load_json(ALERTS)
    if isinstance(data, dict):
        alerts = data.get("alerts", [])
    else:
        alerts = data if isinstance(data, list) else []
    all_matches = []
    for alert in alerts[-20:]:
        matches = map_alert(alert)
        for m in matches:
            tid = m["technique_id"]
            name = m["technique_name"]
            tactic = m["tactic"]
            kw = m["matched_keyword"]
            print(f"  \033[33m[{tid}]\033[0m "
                f"{name} — {tactic} "
                f"(kw: {kw})")
            all_matches.append(m)
    findings = {"timestamp": datetime.now().isoformat(),
        "total_alerts_scanned": len(alerts[-20:]),
        "techniques_matched": len(all_matches),
        "matches": all_matches}
    save_json(FINDINGS, findings)
    if not all_matches:
        print("\033[32m[MITRE]\033[0m "
            "no technique matches found")
    else:
        print(f"\n  [MITRE] {len(all_matches)} "
            f"technique mappings written to "
            f"mitre_findings.json")
    return all_matches

if __name__ == "__main__":
    run_mitre_map()
