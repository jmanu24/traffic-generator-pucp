"""Resume run_calibration_seeds_v2_baseline.py after the restart-guard
race killed seed=108/M mid-start (run 20261022T181320-09c2a1ac, status
'stopped', no started_at/ended_at -- never actually ran, safe to redo).
Appends to the same manifest instead of overwriting the 7 good entries
already in it (101-107, M)."""
import json
import os
import time
import urllib.error
import urllib.request

from run_calibration_seeds_v2_baseline import BASE, TOKEN, SEED_HASHES, call, wait_for_completion

OUT = '/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/calibration_seeds_v2_baseline_manifest.json'

REMAINING = [(mode, seed) for mode, seeds in [('M', [108, 109, 110]), ('I', list(range(101, 111)))] for seed in seeds]


def main():
    with open(OUT) as f:
        manifest = json.load(f)
    for mode, seed in REMAINING:
        plan_hash = SEED_HASHES[seed]
        print(f'--- seed={seed} mode={mode} pipeline=baseline ---', flush=True)
        result = call('POST', '/api/runs', dict(plan_hash=plan_hash, mode='lab', scenario='B0',
                                                  pipeline='baseline', speed=1, detection_mode=mode))
        if result.get('error'):
            print('  START FAILED:', result, flush=True)
            manifest.append(dict(seed=seed, mode=mode, plan_hash=plan_hash, start_error=result))
            with open(OUT, 'w') as f:
                json.dump(manifest, f, indent=2)
            continue
        rid = result['id']
        print('  started:', rid, flush=True)
        final = wait_for_completion(rid)
        print('  finished:', final['status'], flush=True)
        manifest.append(dict(seed=seed, mode=mode, plan_hash=plan_hash, run_id=rid, status=final['status']))
        with open(OUT, 'w') as f:
            json.dump(manifest, f, indent=2)
        time.sleep(10)
    print('Saved manifest:', OUT)
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
