"""THRESHOLD_CALIBRATION_V2, Paso 3 (DIST_PPS_THRESHOLD): re-run just the
training set (seeds 101-105, mode M, pipeline=baseline) AFTER deploying
the dist_pps_all_protocols instrumentation (detection/engine.py) to the
controller -- the first 20-run batch predates that instrumentation, so
its observed_rates rows don't have the field this threshold needs.
Writes a SEPARATE manifest; the original 20-run manifest is untouched."""
import json
import time

from run_calibration_seeds_v2_baseline import SEED_HASHES, call, wait_for_completion

OUT = '/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/calibration_seeds_v2_dist_pps_manifest.json'
TRAINING_SEEDS = [101, 102, 103, 104, 105]


def main():
    manifest = []
    for seed in TRAINING_SEEDS:
        plan_hash = SEED_HASHES[seed]
        print(f'--- seed={seed} mode=M pipeline=baseline (dist_pps re-capture) ---', flush=True)
        result = call('POST', '/api/runs', dict(plan_hash=plan_hash, mode='lab', scenario='B0',
                                                  pipeline='baseline', speed=1, detection_mode='M'))
        if result.get('error'):
            print('  START FAILED:', result, flush=True)
            manifest.append(dict(seed=seed, mode='M', plan_hash=plan_hash, start_error=result))
            with open(OUT, 'w') as f:
                json.dump(manifest, f, indent=2)
            continue
        rid = result['id']
        print('  started:', rid, flush=True)
        final = wait_for_completion(rid)
        print('  finished:', final['status'], flush=True)
        manifest.append(dict(seed=seed, mode='M', plan_hash=plan_hash, run_id=rid, status=final['status']))
        with open(OUT, 'w') as f:
            json.dump(manifest, f, indent=2)
        time.sleep(10)
    print('Saved manifest:', OUT)
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
