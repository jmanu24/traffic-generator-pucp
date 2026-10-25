"""PILOT2b executor: full rerun of pilot2 (seeds 204-206) after the
attack-only-host separation fix (PILOT2_RESULT.md, 2026-10-24) -- a NEW
per-seed benign plan (pilot2b_benign_plans_manifest.json) excludes
composition3's dedicated attack sources (ent-site-4/5, fixed9/10,
ue4/5) from ALL benign traffic, and composition3's own attack plans
were regenerated against those same dedicated sources (new plan_hashes
in attack_plans_manifest_v2.json). Since the benign plan is shared by
every condition/composition within a seed, this invalidates ALL of
pilot2's 204-206 data, not just composition 3 -- hence a full rerun,
not a partial one. Same /api/runs pattern as run_pilot2.py."""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.pilot_schedule import build_pilot_schedule, PILOT_RNG_SEED

MANIFEST_PATH = ROOT / 'data' / 'attack_plans_manifest_v2.json'
BENIGN_MANIFEST_PATH = ROOT / 'data' / 'pilot2b_benign_plans_manifest.json'
OUT_PATH = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/pilot2b_manifest.json')
PILOT2_SEEDS = (204, 205, 206)

PLAN_HASHES = {e['seed']: e['plan_hash'] for e in json.loads(BENIGN_MANIFEST_PATH.read_text())}

sys.path.insert(0, str(ROOT / 'scripts'))
from run_pilot import load_token, call, wait_for_completion


def run_request_body(run):
    body = dict(mode='lab', scenario=run.scenario, pipeline=run.pipeline, speed=1, plan_hash=PLAN_HASHES[run.seed])
    if run.plan_hash is not None:
        body['attack_plan_hash'] = run.plan_hash
    if run.detection_mode is not None:
        body['detection_mode'] = {'isolated': 'I', 'multidomain': 'M'}[run.detection_mode]
    return body


def main():
    manifest = json.loads(MANIFEST_PATH.read_text())
    schedule = build_pilot_schedule(manifest, seeds=PILOT2_SEEDS, rng_seed=PILOT_RNG_SEED)
    token = load_token()
    results = []
    if OUT_PATH.exists():
        results = json.loads(OUT_PATH.read_text())
    already_done = len(results)
    for i, run in enumerate(schedule):
        if i < already_done:
            continue
        print(f'--- [{i+1}/{len(schedule)}] seed={run.seed} condition={run.condition} scenario_id={run.scenario_id} ---', flush=True)
        result = call(token, 'POST', '/api/runs', run_request_body(run))
        if result.get('error'):
            print('  START FAILED:', result, flush=True)
            results.append(dict(seed=run.seed, condition=run.condition, scenario_id=run.scenario_id, start_error=result))
        else:
            rid = result['id']
            print('  started:', rid, flush=True)
            final = wait_for_completion(token, rid)
            print('  finished:', final['status'], flush=True)
            results.append(dict(seed=run.seed, condition=run.condition, scenario_id=run.scenario_id,
                                 plan_hash=run.plan_hash, run_id=rid, status=final['status']))
        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUT_PATH.write_text(json.dumps(results, indent=2))
        if i < len(schedule) - 1:
            time.sleep(60)
    print('Saved manifest:', OUT_PATH)


if __name__ == '__main__':
    main()
