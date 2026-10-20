"""Verify benign_lab/threshold_replay.py's Paso 4 FPR computation is
independent of the live controller's SYN/UDP/ICMP_THRESHOLD at capture
time -- it reproduces THRESHOLD_CALIBRATION_RESULT.md's published
numbers using ONLY the already-captured raw observed_rates (Paso 1,
which does not depend on SYN_THRESHOLD at all) and the proposed
threshold value passed in as an explicit parameter. Never touches the
real lab; reads already-saved run folders under
.runtime/benign-lab/data/runs/.

Written to settle whether THRESHOLD_CONTROL_PATH_FIX.md's discovery
(the live controller ran with uncalibrated thresholds the whole time
THRESHOLD_CALIBRATION_RESULT.md's FPR validation was computed) means
that FPR validation needs to be re-run. It does not: this script
reproduces the exact same numbers (proposed thresholds, training FPR
1.67%/8 of 480, validation FPR 0.0%/0 of 960) from the same saved raw
data, proving the replay never depended on the live threshold.
"""
import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benign_lab.threshold_replay import (
    iter_cycle_groups, propose_thresholds, replay_activation,
    activation_params_from_snapshot, fpr_from_replay,
)

RUNS_DIR = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/runs')

# Training/validation run_ids from the peering-duration-floor-bug-fixed
# re-run (training_{I,M}_peering_fixed_manifest.json,
# validation_peering_fixed_manifest.json under .runtime/benign-lab/calibration/)
# -- the final data THRESHOLD_CALIBRATION_RESULT.md's numbers came from.
TRAINING_I_RUN_IDS = [
    '20261020T102937-76cd4b25', '20261020T103446-686be5fa', '20261020T103955-ed9a88eb',
    '20261020T104502-5dcf63d1', '20261020T105006-03227638',
]
TRAINING_M_RUN_IDS = [
    '20261020T085811-748c615b', '20261020T090315-d7dd7693', '20261020T090903-08225ed7',
    '20261020T091420-e88a4c21', '20261020T091923-d738622b',
]
VALIDATION_RUN_IDS = {
    (106, 'I'): '20261020T092837-fb5ac64b', (106, 'M'): '20261020T094029-f470fd13',
    (107, 'I'): '20261020T094555-4272216f', (107, 'M'): '20261020T095102-78934a8f',
    (108, 'I'): '20261020T095610-d7bc28b0', (108, 'M'): '20261020T105614-c7aab9a2',
    (109, 'I'): '20261020T100831-6a6cebec', (109, 'M'): '20261020T101346-20db4f2e',
    (110, 'I'): '20261020T101858-61b2beb5', (110, 'M'): '20261020T102401-4f459f21',
}


def load_run(run_id):
    folder = RUNS_DIR / run_id
    records = [json.loads(line) for line in (folder / 'detection_events.jsonl').read_text().splitlines() if line.strip()]
    run = json.loads((folder / 'run.json').read_text())
    plan = json.loads((folder / 'benign_plan.json').read_text())
    return records, run, plan


def _global_fpr(run_ids, thresholds):
    total_eligible, total_fp = 0, 0
    for run_id in run_ids:
        records, run, plan = load_run(run_id)
        groups_sorted = sorted(iter_cycle_groups(records), key=lambda g: g[0])
        snap = next((r['thresholds']['values'] for r in records if r.get('kind') == 'cycle'), {})
        activation_params = activation_params_from_snapshot(snap)
        accepted = replay_activation(groups_sorted, thresholds, activation_params)
        g = fpr_from_replay(plan, run, accepted)['_global']
        total_eligible += g['eligible']
        total_fp += g['fp']
    return dict(eligible=total_eligible, fp=total_fp,
                fpr=total_fp / total_eligible if total_eligible else None)


def main():
    training_records = [load_run(rid)[0] for rid in TRAINING_M_RUN_IDS]
    groups = list(itertools.chain(*(iter_cycle_groups(r) for r in training_records)))
    proposed = propose_thresholds(groups, q=0.999, margin=1.5)
    print('Reproduced proposed thresholds (compare to THRESHOLD_CALIBRATION_RESULT.md):')
    for proto, info in proposed.items():
        print(f"  {proto}: n={info['n']} quantile={info['quantile']:.2f} proposed={info['proposed_threshold']}")

    print('\nTraining FPR (expect: I=0.0%, M=1.67% / 8 of 480):')
    print('  I:', _global_fpr(TRAINING_I_RUN_IDS, proposed))
    print('  M:', _global_fpr(TRAINING_M_RUN_IDS, proposed))

    print('\nValidation FPR (expect: 0.0% / 0 of 960):')
    print(' ', _global_fpr(list(VALIDATION_RUN_IDS.values()), proposed))


if __name__ == '__main__':
    main()
