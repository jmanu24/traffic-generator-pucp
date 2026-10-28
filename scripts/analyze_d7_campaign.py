"""D7 campaign final analysis: paired M-I comparison (response_metrics.
summarize(), the same machinery already validated across PILOT/PILOT2/
PILOT2b) over availability_pct (A), the thesis's main indicator, plus
TD/TO/TM response times and the coverage() cross-run proportions. Pure
computation over d7_response_metrics.json (already produced by
compute_d7_response_metrics.py) -- never touches the lab."""
import json
import sys
from pathlib import Path

ROOT = Path('/home/ubuntu/traffic-generator-pucp')
sys.path.insert(0, str(ROOT))
from benign_lab.response_metrics import summarize, coverage

IN = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/d7_response_metrics.json')
OUT = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/d7_analysis.json')

entries = json.loads(IN.read_text())
by_key = {(e['seed'], e['condition'], e['scenario_id']): e for e in entries}


def mi_entries(cond_i, cond_m, metric, scenario_ids, use_block):
    """Build response_metrics.summarize()'s expected list for one metric,
    pairing cond_i(='C3'/'C1-I') vs cond_m(='C4'/'C1-M') by (seed, block),
    block=scenario_id when use_block else None (C1 has no scenario axis)."""
    out = []
    seeds = sorted(set(e['seed'] for e in entries))
    for seed in seeds:
        for sid in (scenario_ids if use_block else [None]):
            for cond, label in ((cond_i, 'I'), (cond_m, 'M')):
                key = (seed, cond, sid)
                e = by_key.get(key)
                if e is None:
                    continue
                value = e['metrics'].get(metric)
                censored = None
                restriction_s = None
                if isinstance(value, dict) and 'value' in value:
                    censored = value.get('censored')
                    value = value.get('value')
                out.append(dict(seed=seed, condition=label, block=sid, value=value,
                                 censored=bool(censored), restriction_s=restriction_s))
    return out


scenario_ids = sorted(set(e['scenario_id'] for e in entries if e['scenario_id'] is not None))

main = summarize(mi_entries('C3', 'C4', 'availability_pct', scenario_ids, True), 'availability_pct (attack, M-I)')
secondary = summarize(mi_entries('C1-I', 'C1-M', 'availability_pct', scenario_ids, False), 'availability_pct (benign, M-I)')

response_times = {}
for metric in ('TD', 'TO', 'TM'):
    response_times[metric] = summarize(mi_entries('C3', 'C4', metric, scenario_ids, True), f'{metric} (M-I)')

cov_by_cond = {}
for cond in ('C2', 'C3', 'C4', 'C1-I', 'C1-M'):
    results = []
    for e in entries:
        if e['condition'] != cond:
            continue
        m = e['metrics']
        results.append(dict(tD=m.get('tD', {}), tO=m.get('tO', {}), TR=m.get('TR')))
    cov_by_cond[cond] = coverage(results)

c2_availability = [e['metrics'].get('availability_pct') for e in entries if e['condition'] == 'C2']
c2_availability = [v for v in c2_availability if v is not None]
c2_summary = dict(n=len(c2_availability),
                   mean=sum(c2_availability) / len(c2_availability) if c2_availability else None,
                   min=min(c2_availability) if c2_availability else None,
                   max=max(c2_availability) if c2_availability else None)

result = dict(
    n_total_runs=len(entries),
    main_comparison_attack_availability=main,
    secondary_comparison_benign_availability=secondary,
    response_times_attack=response_times,
    coverage_by_condition=cov_by_cond,
    c2_no_mitigation_reference=c2_summary,
)
OUT.write_text(json.dumps(result, indent=2))
print('Saved:', OUT)
print()
print('=== MAIN: availability_pct during attack, M-I paired by (seed,scenario) ===')
print(json.dumps(main['mi_difference'], indent=2))
print()
print('=== SECONDARY: availability_pct benign-only, M-I paired by seed ===')
print(json.dumps(secondary['mi_difference'], indent=2))
print()
print('=== C2 (no mitigation) availability reference ===')
print(json.dumps(c2_summary, indent=2))
print()
print('=== Coverage (detected/mitigated/recovered proportions) by condition ===')
print(json.dumps(cov_by_cond, indent=2))
