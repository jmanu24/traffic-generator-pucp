"""D7 CAMBIOS validation (VALIDACIÓN section of the brief): one real C3 and
one real C4 execution, composition1_enterprise, seed 201 -- confirming A
(availability_pct), tE, and the 3 covariates (sequence_position,
seconds_since_restart, panel_process_memory_kb_at_start) from runner.py's
change 4/5, through the already-running dashboard's own /api/runs (same
single-Manager pattern scripts/run_pilot.py and
scripts/run_calibration_seeds.py already use against the real lab -- this
script never instantiates its own Manager).

Uses im_campaign.block_runs(201, 'composition1_enterprise') filtered to
C3/C4 only (this validation does not need C1-I/C1-M/C2) -- the SAME
RunSpec shape the full campaign executor would consume, so this is a real
exercise of im_campaign.py's own block_runs(), not a hand-rolled request.

Benign plan_hash for seed 201 is scripts/run_pilot.py's own PLAN_HASHES[201]
(already generated/registered on the server); attack plan_hash is
data/attack_plans_manifest.json's 'composition1_enterprise' entry (also
already registered -- confirmed live via GET /api/attacks/plans before
writing this script).
"""
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.im_campaign import block_runs

BASE = 'http://192.168.18.154:8780'
ENV_FILE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/web.env')
DATA_ROOT = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/runs')
OUT_PATH = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/d7_c3c4_validation.json')

SEED = 201
SCENARIO_ID = 'composition1_enterprise'
BENIGN_PLAN_HASH = '5c54495dec246a16d3f5a6ab3e4f46c337ce35f10fdee8f420be28bb6e9e0d80'  # run_pilot.PLAN_HASHES[201]
ATTACK_PLAN_HASH = '958cb0a175672b142f1bf0f496817f7b0a1120535ab64dd260b250117cb56e3b'  # manifest composition1_enterprise


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


def call(token, method, path, body=None, parse_json=True):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                  headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            return json.loads(raw) if parse_json else raw
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
    return dict(mode='lab', scenario=run.scenario, pipeline=run.pipeline, speed=1,
                plan_hash=BENIGN_PLAN_HASH, attack_plan_hash=ATTACK_PLAN_HASH,
                detection_mode={'isolated': 'I', 'multidomain': 'M'}[run.detection_mode])


def main():
    schedule = [r for r in block_runs(SEED, SCENARIO_ID) if r.condition in ('C3', 'C4')]
    token = load_token()
    results = []
    for i, run in enumerate(schedule):
        print(f'--- [{i+1}/{len(schedule)}] seed={run.seed} condition={run.condition} '
              f'scenario_id={run.scenario_id} detection_mode={run.detection_mode} ---', flush=True)
        result = call(token, 'POST', '/api/runs', run_request_body(run))
        if result.get('error'):
            print('  START FAILED:', result, flush=True)
            results.append(dict(condition=run.condition, start_error=result))
            continue
        rid = result['id']
        print('  started:', rid, flush=True)
        final = wait_for_completion(token, rid)
        print('  finished:', final['status'], flush=True)
        # Trigger response_metrics_for()/evaluation_for() persistence (same
        # side effect /api/runs/{rid}/export already has) so
        # response_metrics.json (A, tE, TD, TO, TM, ...) lands on disk.
        # The response body is a zip (binary), never parsed as JSON here --
        # only the side effect of the request matters.
        call(token, 'GET', f'/api/runs/{rid}/export', parse_json=False)
        rm_path = DATA_ROOT / rid / 'response_metrics.json'
        response_metrics = json.loads(rm_path.read_text()) if rm_path.exists() else dict(available=False)
        run_json = json.loads((DATA_ROOT / rid / 'run.json').read_text())
        results.append(dict(
            condition=run.condition, run_id=rid, status=final['status'],
            availability_pct=response_metrics.get('availability_pct'),
            tE=response_metrics.get('tE'), tD=response_metrics.get('tD'), tO=response_metrics.get('tO'),
            TD=response_metrics.get('TD'), TO=response_metrics.get('TO'), TM=response_metrics.get('TM'),
            mitigated_domain=response_metrics.get('mitigated_domain'),
            sequence_position=run_json.get('sequence_position'),
            seconds_since_restart=run_json.get('seconds_since_restart'),
            panel_process_memory_kb_at_start=run_json.get('panel_process_memory_kb_at_start'),
            detection_mode_verification=run_json.get('detection_mode_verification'),
        ))
        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUT_PATH.write_text(json.dumps(results, indent=2))
        if i < len(schedule) - 1:
            time.sleep(60)
    print('Saved:', OUT_PATH)
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
