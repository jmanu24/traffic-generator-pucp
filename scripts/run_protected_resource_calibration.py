"""D7/4.4.2 "protected resource" calibration (docs/PROTECTED_RESOURCE.md),
step 4: 3 real runs against the lab, seed 201, pipeline suspended
throughout (so this never touches ryu-manager / detection mode) --
C1 (no attack), C2+composition3, C2+composition3_enterprise_only.
Same /api/runs + wait_for_completion pattern as scripts/run_pilot.py;
drives the already-running dashboard, never its own Manager."""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from run_pilot import load_token, call, wait_for_completion

BENIGN_PLAN_HASH = '5c54495dec246a16d3f5a6ab3e4f46c337ce35f10fdee8f420be28bb6e9e0d80'
COMPOSITION3_PLAN_HASH = '1990310a26c6ffbdfa28da0025de3a59f082bb6442d2c010317067905375a38e'
ENTERPRISE_ONLY_PLAN_HASH = '89e927a8694615757e970be978f9ef24832afc701c3aa9c6406e0dab8a79456d'
PAUSE_S = 60

RUNS = [
    dict(label='C1_no_attack', body=dict(mode='lab', scenario='B0', pipeline='baseline', speed=1, plan_hash=BENIGN_PLAN_HASH)),
    dict(label='C2_composition3', body=dict(mode='lab', scenario='B0+attack', pipeline='baseline', speed=1,
                                             plan_hash=BENIGN_PLAN_HASH, attack_plan_hash=COMPOSITION3_PLAN_HASH)),
    dict(label='C2_composition3_enterprise_only', body=dict(mode='lab', scenario='B0+attack', pipeline='baseline', speed=1,
                                                             plan_hash=BENIGN_PLAN_HASH, attack_plan_hash=ENTERPRISE_ONLY_PLAN_HASH)),
]


def main():
    token = load_token()
    manifest = []
    for i, run in enumerate(RUNS):
        print(f'--- {run["label"]} ---', flush=True)
        result = call(token, 'POST', '/api/runs', run['body'])
        if result.get('error'):
            print('  START FAILED:', result, flush=True)
            manifest.append(dict(label=run['label'], body=run['body'], start_error=result))
            continue
        rid = result['id']
        print('  started:', rid, flush=True)
        final = wait_for_completion(token, rid)
        print('  finished:', final['status'], flush=True)
        manifest.append(dict(label=run['label'], body=run['body'], run_id=rid, status=final['status']))
        if i < len(RUNS) - 1:
            print(f'  pausing {PAUSE_S}s before next run', flush=True)
            time.sleep(PAUSE_S)
    out = ROOT.parent / 'isp-ddos-ryu' / '.runtime' / 'benign-lab' / 'calibration' / 'protected_resource_calibration_manifest.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2))
    print('Saved manifest:', out)
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
