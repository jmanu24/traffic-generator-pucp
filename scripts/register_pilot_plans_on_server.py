"""One-off: the pilot's benign and attack plans were generated LOCALLY
(scripts/generate_pilot_benign_plans.py, scripts/generate_regenerated_
attack_plans.py) but the dashboard's own API server (192.168.18.154:8780)
keeps its OWN data/ directory on its own host -- confirmed live:
run_pilot.py's first run failed with 404 "Plan not found" because none
of these plan_hash values exist there. This script re-POSTs the exact
same deterministic generation parameters to the server's own
/api/plans and /api/attacks/plans so it materializes the plans itself,
and verifies the returned plan_hash matches what's already recorded
locally (data/pilot_benign_plans_manifest.json, data/attack_plans_
manifest.json) -- if it doesn't match, that's a real discrepancy (e.g.
different lab capacities on the server) that must be resolved before
the pilot can run, not silently accepted.

Never sends attack traffic or launches any run -- /api/plans and
/api/attacks/plans only materialize plan files, exactly like the local
generator scripts already did.
"""
import json
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from run_pilot import load_token, call
from benign_lab.pilot_schedule import PILOT_SEEDS

BENIGN_MANIFEST = json.loads((ROOT / 'data' / 'pilot_benign_plans_manifest.json').read_text())
ATTACK_MANIFEST = json.loads((ROOT / 'data' / 'attack_plans_manifest.json').read_text())


def register_benign_plans(token):
    by_seed = {e['seed']: e['plan_hash'] for e in BENIGN_MANIFEST}
    for seed in PILOT_SEEDS:
        result = call(token, 'POST', '/api/plans', dict(seed=seed, duration_s=180))
        if result.get('error'):
            print(f'  seed={seed}: FAILED {result}')
            continue
        server_hash = result['plan_hash']
        local_hash = by_seed[seed]
        status = 'MATCH' if server_hash == local_hash else 'MISMATCH'
        print(f'  seed={seed}: server={server_hash} local={local_hash} [{status}]')


def register_attack_plans(token):
    import generate_regenerated_attack_plans as gen
    captured = []
    original = gen.generate_attack_plan

    def spy(seed, duration_s, flows, description):
        plan = original(seed, duration_s, flows, description)
        captured.append(dict(seed=seed, duration_s=duration_s, flows=flows, description=description, plan_hash=plan['plan_hash']))
        return plan

    with mock.patch.object(gen, 'generate_attack_plan', side_effect=spy):
        gen.build_composition_1()
        gen.build_composition_2()
        gen.build_composition_3()

    by_hash = {e['plan_hash']: e for e in captured}
    for entry in ATTACK_MANIFEST:
        src = by_hash.get(entry['plan_hash'])
        if src is None:
            print(f"  {entry['name']}: no local reconstruction found (unexpected)")
            continue
        body = dict(seed=src['seed'], duration_s=src['duration_s'], description=src['description'], flows=src['flows'])
        result = call(token, 'POST', '/api/attacks/plans', body)
        if result.get('error'):
            print(f"  {entry['name']}: FAILED {result}")
            continue
        server_hash = result['plan_hash']
        status = 'MATCH' if server_hash == entry['plan_hash'] else 'MISMATCH'
        print(f"  {entry['name']}: server={server_hash} local={entry['plan_hash']} [{status}]")


def main():
    token = load_token()
    print('--- benign plans ---')
    register_benign_plans(token)
    print('--- attack plans ---')
    register_attack_plans(token)


if __name__ == '__main__':
    main()
