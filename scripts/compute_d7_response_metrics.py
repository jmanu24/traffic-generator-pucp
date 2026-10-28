"""Run response_metrics.compute() for real over all 260 D7 campaign runs
(data already local at isp-ddos-ryu/.runtime/benign-lab/data/runs, no
pulling needed -- unlike pilot2b which ran on a remote panel). Pure
computation over already-captured evidence. Writes
d7_response_metrics.json keyed by (seed, condition, scenario_id, run_id).
Same pattern as compute_pilot2b_response_metrics.py."""
import json
import sys
from pathlib import Path

ROOT = Path('/home/ubuntu/traffic-generator-pucp')
sys.path.insert(0, str(ROOT))
from benign_lab.response_metrics import compute

RESULTS = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/campaign_results.json')
RUNS_DIR = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/runs')
OUT = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/d7_response_metrics.json')


def load_records(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main():
    entries = json.loads(RESULTS.read_text())
    results = []
    errors = []
    for e in entries:
        rid = e.get('run_id')
        if not rid or e.get('status') not in ('completed', 'completed_with_errors'):
            errors.append((e.get('seed'), e.get('condition'), e.get('scenario_id'), rid, 'no valid run_id/status'))
            continue
        d = RUNS_DIR / rid
        try:
            run = json.loads((d / 'run.json').read_text())
            records = load_records(d / 'detection_events.jsonl')
            event_states = list(json.loads((d / 'event_states.json').read_text()).values())
            plan_path = d / 'benign_plan.json'
            if not plan_path.exists():
                errors.append((e['seed'], e['condition'], e['scenario_id'], rid, 'no benign_plan.json'))
                continue
            plan = json.loads(plan_path.read_text())
            metrics = compute(plan, run, records, event_states)
        except Exception as exc:  # noqa
            errors.append((e.get('seed'), e.get('condition'), e.get('scenario_id'), rid, f'{type(exc).__name__}: {exc}'))
            continue
        results.append(dict(seed=e['seed'], condition=e['condition'], scenario_id=e['scenario_id'],
                             run_id=rid, metrics=metrics))
    OUT.write_text(json.dumps(results, indent=2))
    print(f'Computed {len(results)}/{len(entries)} runs, {len(errors)} errors')
    for seed, cond, sid, rid, err in errors:
        print('  ERROR', seed, cond, sid, rid, err)
    print('Saved:', OUT)


if __name__ == '__main__':
    main()
