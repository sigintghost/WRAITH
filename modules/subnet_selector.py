import os, json, socket, struct

KNOWN = os.path.expanduser('~/.wraith/subnets.json')

def load_known():
    try:
        with open(KNOWN) as f: return json.load(f)
    except: return {}

def save_known(d):
    os.makedirs(os.path.dirname(KNOWN), exist_ok=True)
    with open(KNOWN,'w') as f: json.dump(d,f,indent=2)

def discover_subnets():
    subnets = []
    try:
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) < 8: continue
                dst = socket.inet_ntoa(struct.pack('<L', int(parts[1],16)))
                mask = socket.inet_ntoa(struct.pack('<L', int(parts[7],16)))
                if dst == '0.0.0.0' or mask == '0.0.0.0': continue
                parts2 = dst.split('.')
                base = f"{parts2[0]}.{parts2[1]}.{parts2[2]}"
                if base not in subnets: subnets.append(base)
    except: pass
    return subnets

def select_subnet(current_base):
    C='\033[36m'; R='\033[0m'; Y='\033[33m'
    discovered = discover_subnets()
    known = load_known()
    all_subs = list(set(discovered + list(known.keys())))
    if current_base not in all_subs:
        all_subs.insert(0, current_base)
    print(f"\n  {C}SELECT SUBNET{R}")
    print(f"  {'─'*44}")
    print(f"  [0] {current_base}.0/24  (current)")
    for i, s in enumerate(all_subs):
        label = known.get(s, '')
        tag = f" — {label}" if label else ''
        print(f"  [{i+1}] {s}.0/24{tag}")
    print(f"  [m] enter manually")
    choice = input("  select > ").strip()
    if choice == '0' or choice == '': return current_base
    if choice == 'm':
        manual = input("  enter base (e.g. 10.10.5): ").strip()
        label = input("  label (optional): ").strip()
        if label: known[manual] = label; save_known(known)
        return manual
    try:
        idx = int(choice) - 1
        selected = all_subs[idx]
        save_known(known)
        return selected
    except: return current_base
