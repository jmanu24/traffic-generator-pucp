"""Offline loader/helpers for docs/PILOT_DIAGNOSIS.md. Reads only data already
captured under .runtime/benign-lab; never touches the lab or the controller."""
import json, math, pathlib, sys
ROOT = pathlib.Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab')
RUNS = ROOT / 'data' / 'runs'
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from benign_lab import response_metrics as rm
from benign_lab.experimental_analytics import finite
from benign_lab.ground_truth import overlap

DOMAINS = ('enterprise', 'fixed', 'mobile', 'peering')
SEGMENTS = ((0, 60), (60, 120), (120, 180))


def jl(path):
    out = []
    try:
        for l in open(path):
            l = l.strip()
            if l:
                out.append(json.loads(l))
    except FileNotFoundError:
        pass
    return out


def load():
    manifest = json.load(open(ROOT / 'calibration' / 'pilot_manifest.json'))
    details = {d['run_id']: d for d in json.load(open(ROOT / 'calibration' / 'pilot_run_details.json'))}
    runs = []
    for pos, m in enumerate(manifest):
        f = RUNS / m['run_id']
        run = json.load(open(f / 'run.json'))
        plan = json.load(open(f / 'benign_plan.json'))
        es = json.load(open(f / 'event_states.json'))
        es = list(es.values()) if isinstance(es, dict) else es
        r = dict(pos=pos, seed=m['seed'], cond=m['condition'], scen=m['scenario_id'], rid=m['run_id'],
                 status=m['status'], eligible=details[m['run_id']]['eligible'],
                 excl=details[m['run_id']]['exclusion_reasons'], run=run, plan=plan, es=es,
                 records=jl(f / 'detection_events.jsonl'), logs=jl(f / 'logs.jsonl'), folder=f)
        runs.append(r)
    return runs


def seg_delivery(plan, es, a, b, domain=None):
    """Delivered / planned bytes in [a,b), same proportional-overlap rule as
    response_metrics.compute_availability()."""
    planned = actual = 0.0
    for e in plan.get('events', []):
        if domain and e['domain'] != domain or e.get('duration_s', 0) <= 0:
            continue
        planned += e.get('planned_bytes', 0) * overlap(a, b, e['start_s'], e['start_s'] + e['duration_s']) / e['duration_s']
    for e in es:
        if domain and e.get('domain') != domain or e.get('duration_s', 0) <= 0:
            continue
        actual += (e.get('bytes_tx', 0) + e.get('bytes_rx', 0)) * overlap(a, b, e['start_s'], e['start_s'] + e['duration_s']) / e['duration_s']
    return 100 * actual / planned if planned else None


def availability(r, domain=None, window=(60.001, 120.002)):
    """A over the given window, per-window PASS rule of response_metrics
    (D=90%, L=150ms), optionally restricted to one domain."""
    plan = r['plan']; es = r['es']
    if domain:
        plan = dict(plan, events=[e for e in plan['events'] if e['domain'] == domain])
        es = [e for e in es if e.get('domain') == domain]
    out = rm.compute_availability(plan, r['run'], window[0], window[1], es, dict(rm.DEFAULTS))
    return out['availability_pct']
