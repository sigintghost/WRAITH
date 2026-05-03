import os, json, datetime
from modules.filestack import get_stack, write_json

ENERGY_POINTS = [
    'chw', 'hw', 'ahu', 'vav', 'kw', 'kwh',
    'btu', 'ton', 'cfm', 'gpm', 'temp', 'rh'
]

def load_trends():
    p = os.path.join(get_stack(), 'webctrl_trends.json')
    if not os.path.exists(p): return []
    with open(p) as f: return json.load(f).get('trends', [])

def load_baseline():
    p = os.path.join(get_stack(), 'energy_baseline.json')
    if not os.path.exists(p): return {}
    with open(p) as f: return json.load(f)

def filter_energy_trends(trends):
    energy = []
    for t in trends:
        point = t.get('point', '').lower()
        if any(k in point for k in ENERGY_POINTS):
            energy.append(t)
    return energy

def build_energy_snapshot(trends):
    snapshot = {}
    for t in trends:
        point = t.get('point', '')
        val = t.get('value')
        units = t.get('units', '')
        if point and val is not None:
            if point not in snapshot:
                snapshot[point] = {
                    'values': [], 'units': units
                }
            snapshot[point]['values'].append(float(val))
    for point, data in snapshot.items():
        vals = data['values']
        data['mean'] = sum(vals) / len(vals)
        data['min'] = min(vals)
        data['max'] = max(vals)
        data['count'] = len(vals)
    return snapshot

def gap_analysis(snapshot, baseline):
    from modules.alerts import fire as add_alert
    gaps = []
    if not baseline:
        print('  [ISO] no baseline — set baseline first')
        return gaps
    for point, data in snapshot.items():
        if point not in baseline: continue
        base_mean = baseline[point].get('mean', 0)
        curr_mean = data.get('mean', 0)
        if base_mean == 0: continue
        deviation = ((curr_mean - base_mean) / base_mean) * 100
        if abs(deviation) > 10:
            severity = 'HIGH' if abs(deviation) > 25 else 'MEDIUM'
            msg = f'ISO50001 GAP {point} deviation={deviation:.1f}% base={base_mean:.2f} current={curr_mean:.2f}'
            print(f'  [!] {msg}')
            gaps.append({
                'point': point,
                'deviation_pct': round(deviation, 2),
                'baseline_mean': round(base_mean, 2),
                'current_mean': round(curr_mean, 2),
                'units': data.get('units', ''),
                'severity': severity,
                'ts': datetime.datetime.now().isoformat()
            })
            add_alert(msg, severity=severity)
    return gaps

def set_baseline(snapshot):
    write_json('energy_baseline.json', {
        'timestamp': datetime.datetime.now().isoformat(),
        'points': snapshot
    })
    print(f'  [ISO] baseline set — {len(snapshot)} energy points')

def run_iso50001():
    print('\n  [ISO] ISO 50001 energy gap analysis')
    print('  [1] set current as baseline')
    print('  [2] run gap analysis')
    print('  [3] show baseline points')
    print('  [0] back')
    c = input('  > ').strip()
    trends = load_trends()
    if not trends and c in ('1','2'):
        print('  [ISO] no trend data — run WEBCTRL DB sync first')
        return
    energy = filter_energy_trends(trends)
    snapshot = build_energy_snapshot(energy)
    if c == '1':
        set_baseline(snapshot)
    elif c == '2':
        baseline = load_baseline().get('points', {})
        gaps = gap_analysis(snapshot, baseline)
        write_json('iso50001_gaps.json', {
            'timestamp': datetime.datetime.now().isoformat(),
            'gaps': gaps,
            'total': len(gaps)
        })
        print(f'  [ISO] {len(gaps)} gaps — iso50001_gaps.json written')
    elif c == '3':
        baseline = load_baseline()
        pts = baseline.get('points', {})
        print(f'  [ISO] {len(pts)} baseline points')
        for p in list(pts.keys())[:10]:
            print(f'    {p}: mean={pts[p].get("mean",0):.2f}')
