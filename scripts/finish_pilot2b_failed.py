"""PILOT2b cleanup: re-run the 11 blocks (all seed=204, all from before
the /api/runs perf fix + 30s deadline grace) that the full pilot2b
rerun left in 'failed' status. Same /api/runs pattern as
finish_remaining4.py (the equivalent cleanup pass used earlier today
for composition3's mid-run crash)."""
import json
import sys
import time
import urllib.error
from pathlib import Path

ROOT = Path('/home/ubuntu/traffic-generator-pucp')
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from run_pilot import load_token, call, wait_for_completion
from benign_lab.pilot_schedule import build_pilot_schedule, PILOT_RNG_SEED

MANIFEST_PATH = ROOT / 'data' / 'attack_plans_manifest_v2.json'
BENIGN_MANIFEST_PATH = ROOT / 'data' / 'pilot2b_benign_plans_manifest.json'
OUT_PATH = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/pilot2b_manifest.json')
PLAN_HASHES = {e['seed']: e['plan_hash'] for e in json.loads(BENIGN_MANIFEST_PATH.read_text())}


def run_request_body(run):
    body = dict(mode='lab', scenario=run.scenario, pipeline=run.pipeline, speed=1, plan_hash=PLAN_HASHES[run.seed])
    if run.plan_hash is not None:
        body['attack_plan_hash'] = run.plan_hash
    if run.detection_mode is not None:
        body['detection_mode'] = {'isolated': 'I', 'multidomain': 'M'}[run.detection_mode]
    return body


def run_one(token, run):
    for attempt in range(5):
        try:
            result = call(token, 'POST', '/api/runs', run_request_body(run))
            break
        except urllib.error.URLError as exc:
            print(f'  service unreachable ({exc}), waiting 15s (attempt {attempt+1}/5)...', flush=True)
            time.sleep(15)
    else:
        return dict(start_error='service unreachable after 5 attempts')
    if result.get('error'):
        return dict(start_error=result)
    rid = result['id']
    final = wait_for_completion(token, rid)
    return dict(run_id=rid, status=final['status'])


def main():
    manifest = json.loads(MANIFEST_PATH.read_text())
    schedule = build_pilot_schedule(manifest, seeds=(204, 205, 206), rng_seed=PILOT_RNG_SEED)
    by_key = {(r.seed, r.condition, r.scenario_id): r for r in schedule}

    token = load_token()
    results = json.loads(OUT_PATH.read_text())
    by_result_key = {(e['seed'], e['condition'], e['scenario_id']): i for i, e in enumerate(results)}
    remaining = [(e['seed'], e['condition'], e['scenario_id']) for e in results if e.get('status') == 'failed']

    for i, key in enumerate(remaining):
        print(f'--- [{i+1}/{len(remaining)}] seed={key[0]} condition={key[1]} scenario_id={key[2]} ---', flush=True)
        run = by_key[key]
        outcome = run_one(token, run)
        print('  ', outcome, flush=True)
        if outcome.get('status') not in ('completed', 'completed_with_errors'):
            print('  retrying once...', flush=True)
            time.sleep(10)
            outcome = run_one(token, run)
            print('  retry result:', outcome, flush=True)
        idx = by_result_key[key]
        results[idx] = dict(seed=key[0], condition=key[1], scenario_id=key[2], plan_hash=run.plan_hash, **outcome)
        OUT_PATH.write_text(json.dumps(results, indent=2))
        if i < len(remaining) - 1:
            time.sleep(30)
    print('Done.', flush=True)


if __name__ == '__main__':
    main()
