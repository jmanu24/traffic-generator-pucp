"""Run response_metrics.compute() for real over all 78 PILOT2b exports
(cached locally by pull_pilot2b_exports.py). No lab access -- pure
computation over already-captured evidence. Same pattern as
compute_pilot2_response_metrics.py (the original pilot2), pointed at
pilot2b's own manifest/cache. Writes pilot2b_response_metrics.json
keyed by run_id."""
import json
import sys
from pathlib import Path

ROOT = Path('/home/ubuntu/traffic-generator-pucp')
sys.path.insert(0, str(ROOT))
from benign_lab.response_metrics import compute

MANIFEST = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/pilot2b_manifest.json')
CACHE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/pilot2b_exports')
OUT = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/pilot2b_response_metrics.json')


def load_records(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main():
    manifest = json.loads(MANIFEST.read_text())
    results = []
    errors = []
    for e in manifest:
        rid = e['run_id']
        d = CACHE / rid
        try:
            run = json.loads((d / 'run.json').read_text())
            records = load_records(d / 'detection_events.jsonl')
            event_states = list(json.loads((d / 'event_states.json').read_text()).values())
            plan = json.loads((d / 'benign_plan.json').read_text()) if (d / 'benign_plan.json').exists() else None
            if plan is None:
                errors.append((rid, 'no benign_plan.json cached'))
                continue
            metrics = compute(plan, run, records, event_states)
        except Exception as exc:  # noqa
            errors.append((rid, f'{type(exc).__name__}: {exc}'))
            continue
        results.append(dict(seed=e['seed'], condition=e['condition'], scenario_id=e['scenario_id'],
                             run_id=rid, metrics=metrics))
    OUT.write_text(json.dumps(results, indent=2))
    print(f'Computed {len(results)}/{len(manifest)} runs, {len(errors)} errors')
    for rid, err in errors:
        print('  ERROR', rid, err)
    print('Saved:', OUT)


if __name__ == '__main__':
    main()
