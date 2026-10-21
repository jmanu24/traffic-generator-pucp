"""D7 pilot analysis (docs/PILOT_RESULT.md). Reproduces the manually
paired M-I indicators and the resulting N estimates from already-saved
data -- never touches the lab. Exists because /api/analytics/report's
automatic pairing failed for almost every cross-seed pair (docs/
PILOT_RESULT.md section 2: an unstable `policy` grouping field), so the
report's numbers were computed by pairing runs directly on
(seed, condition, scenario_id) instead -- this script is that pairing,
made reproducible and testable instead of one-off terminal commands.

Input: .runtime/benign-lab/calibration/pilot_run_details.json, produced
by pulling /api/analytics/runs/{rid} for every run in pilot_manifest.json
(a one-off pull against the live server -- not reproduced here; this
script only recomputes from what was already saved).
"""
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.sample_size import required_seeds, required_seeds_power, required_seeds_noninferiority

DETAILS_PATH = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/pilot_run_details.json')
SEEDS = (201, 202, 203)
SCENARIOS = ('composition1_enterprise', 'composition1_fixed', 'composition1_mobile', 'composition1_peering',
             'composition2_multidomain_over_threshold', 'composition3_multidomain_under_threshold')


def index_by_key(details):
    """[{'seed':..,'condition':..,'scenario_id':..,'selected_metric':{...},'eligible':bool}, ...]
    -> {(seed, condition, scenario_id): {metric: value, eligible: bool}}"""
    by_key = {}
    for r in details:
        sm = r.get('selected_metric') or {}
        by_key[(r['seed'], r['condition'], r['scenario_id'])] = dict(
            delivery_pct=sm.get('delivery_pct'), eligible=r.get('eligible'),
            detection_fpr_pct=sm.get('detection_fpr_pct'), decision_fpr_pct=sm.get('decision_fpr_pct'))
    return by_key


def paired_diffs(by_key, metric, condition_a, condition_b, seeds=SEEDS, scenario_id=None):
    """[(seed, b_value - a_value), ...] over every seed where both
    conditions exist, are eligible, and the metric is finite."""
    diffs = []
    for seed in seeds:
        a = by_key.get((seed, condition_a, scenario_id))
        b = by_key.get((seed, condition_b, scenario_id))
        if not a or not b or not a['eligible'] or not b['eligible']:
            continue
        av, bv = a.get(metric), b.get(metric)
        if av is None or bv is None:
            continue
        diffs.append((seed, bv - av))
    return diffs


def main():
    details = json.loads(DETAILS_PATH.read_text())
    by_key = index_by_key(details)

    print('--- C4-C3 (M-I) delivery_pct, per scenario ---')
    composition3_diffs = []
    for sc in SCENARIOS:
        diffs = paired_diffs(by_key, 'delivery_pct', 'C3', 'C4', scenario_id=sc)
        print(f'  {sc}: {diffs}')
        if sc == 'composition3_multidomain_under_threshold':
            composition3_diffs = diffs

    print('--- C1-M - C1-I delivery_pct (benign-only) ---')
    c1_diffs = paired_diffs(by_key, 'delivery_pct', 'C1-I', 'C1-M', scenario_id=None)
    print(f'  {c1_diffs}')

    print('--- C1-M - C1-I decision_fpr_pct (benign-only) ---')
    fpr_diffs = paired_diffs(by_key, 'decision_fpr_pct', 'C1-I', 'C1-M', scenario_id=None)
    print(f'  {fpr_diffs}')

    values = [d for _, d in composition3_diffs]
    if len(values) > 1:
        mean, sd = statistics.mean(values), statistics.stdev(values)
        print(f'\ncomposition3 (confirmatoria) delivery_pct M-I: mean={mean:.2f} sd={sd:.2f} n={len(values)}')
        EMI = 10.0
        print(f'  N by precision (half-width=EMI/2={EMI/2}): {required_seeds(sd, EMI / 2)}')
        print(f'  N by power (effect=EMI={EMI}): {required_seeds_power(sd, EMI)}')

    c1_values = [d for _, d in c1_diffs]
    if len(c1_values) > 1:
        mean, sd = statistics.mean(c1_values), statistics.stdev(c1_values)
        print(f'\nC1 (benign) delivery_pct M-I: mean={mean:.2f} sd={sd:.2f} n={len(c1_values)}')
        print(f'  N by precision (EMI/2=5): {required_seeds(sd, 5)}')
        print(f'  N by power (EMI=10): {required_seeds_power(sd, 10)}')

    fpr_values = [d for _, d in fpr_diffs]
    if len(fpr_values) > 1:
        mean, sd = statistics.mean(fpr_values), statistics.stdev(fpr_values)
        margin = 5.0
        print(f'\nC1 decision_fpr_pct M-I: mean={mean:.3f} sd={sd:.3f} n={len(fpr_values)}')
        print(f'  N non-inferiority (margin={margin}pp, power=0.80): {required_seeds_noninferiority(sd, margin)}')
        print(f'  N by precision (half-width=margin/2={margin/2}): {required_seeds(sd, margin / 2)}')


if __name__ == '__main__':
    main()
