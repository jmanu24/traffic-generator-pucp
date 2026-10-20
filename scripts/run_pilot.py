"""D7 pilot executor. NOT RUN YET -- waiting for explicit confirmation of
the calendar in docs/PILOT_DESIGN.md before this touches the real lab.

Drives the already-running dashboard's /api/runs for every PilotRun in
benign_lab.pilot_schedule.build_pilot_schedule(), one seed at a time in
order (201, 202, 203), each seed's own runs in the reproducible random
order the schedule already fixed -- same /api/runs pattern
scripts/run_calibration_seeds.py already used against the real lab (one
Manager touching the lab, never this script's own), so there is nothing
new here about HOW a run is launched, only WHICH runs and in WHAT order.

60s pause between every two consecutive runs (PAUSE_S); the controller
restart that detection_mode-bearing runs trigger is NOT forced by this
script -- it is entirely runner.Manager.apply_detection_mode()'s own
decision (skips the restart when DetectionModeControl.read() already
matches), so "restart only when the mode changes" holds for real, not
just in the duration estimate.

Needs BENIGN_API_TOKEN from .runtime/benign-lab/web.env (never inlined
here) and requires a benign plan_hash for each of seeds 201-203 --
PLAN_HASHES below must be filled in (same as calibration's SEED_HASHES)
before this can run; left as a hard failure, not a silent skip, if any
are missing.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.pilot_schedule import build_pilot_schedule, PILOT_SEEDS, PILOT_RNG_SEED

BASE = 'http://192.168.18.154:8780'
ENV_FILE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/web.env')
MANIFEST_PATH = ROOT / 'data' / 'attack_plans_manifest.json'
OUT_PATH = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/pilot_manifest.json')

# Benign plan_hash per pilot seed -- same role as run_calibration_seeds.py's
# SEED_HASHES, but for seeds 201-203 (disjoint from calibration's 101-110).
# Deliberately left empty: generating these plans/hashes and confirming them
# is part of the step this script executes, not something to assume here.
PLAN_HASHES = {
    201: None,
    202: None,
    203: None,
}


def load_token():
    env = {}
    for line in ENV_FILE.read_text().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()
    token = env.get('BENIGN_API_TOKEN')
    if not token:
        raise RuntimeError(f'BENIGN_API_TOKEN not found in {ENV_FILE}')
    return token


def call(token, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                  headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return dict(error=True, status=exc.code, body=exc.read().decode())


def wait_for_completion(token, rid, timeout=600):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = call(token, 'GET', '/api/runs')
        match = next((r for r in rows if r['id'] == rid), None)
        if match and match['status'] in ('completed', 'completed_with_errors', 'failed', 'stopped', 'interrupted'):
            return match
        time.sleep(5)
    raise TimeoutError(f'Run {rid} did not finish within {timeout}s')


def run_request_body(run):
    body = dict(mode='lab', scenario=run.scenario, pipeline=run.pipeline, speed=1, plan_hash=PLAN_HASHES[run.seed])
    if run.plan_hash is not None:
        body['attack_plan_hash'] = run.plan_hash
    if run.detection_mode is not None:
        body['detection_mode'] = {'isolated': 'I', 'multidomain': 'M'}[run.detection_mode]
    return body


def main():
    if any(h is None for h in PLAN_HASHES.values()):
        raise RuntimeError('PLAN_HASHES has unfilled entries -- generate/confirm benign plans for seeds 201-203 first')
    manifest = json.loads(MANIFEST_PATH.read_text())
    schedule = build_pilot_schedule(manifest, seeds=PILOT_SEEDS, rng_seed=PILOT_RNG_SEED)
    token = load_token()
    results = []
    for i, run in enumerate(schedule):
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
            time.sleep(60)  # PAUSE_S, benign_lab.pilot_schedule.PAUSE_S
    print('Saved manifest:', OUT_PATH)


if __name__ == '__main__':
    main()
