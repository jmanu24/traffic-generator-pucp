"""Investigate WHY M has lower overall availability than I during attack
despite much higher detection/mitigation coverage (analyze_d7_campaign.py
finding): break the same availability_pct (A) computation down PER DOMAIN
(enterprise/mobile/fixed/peering), reusing ground_truth.windows()'s exact
5s grid and response_metrics.compute_availability()'s D/L SLA logic, but
restricting the planned/actual byte sums to events of one domain at a
time. Pure computation, never touches the lab."""
import json
import sys
from pathlib import Path

ROOT = Path('/home/ubuntu/traffic-generator-pucp')
sys.path.insert(0, str(ROOT))
from benign_lab.ground_truth import windows as ground_truth_windows, overlap
from benign_lab.response_metrics import _attack_window, finite, summarize

RESULTS = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/campaign_results.json')
RUNS_DIR = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/runs')
OUT = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/d7_by_domain.json')

D, L = 50, 150  # same DEFAULTS as response_metrics.py (cfg['D'], cfg['L'])
DOMAINS = ('enterprise', 'mobile', 'fixed', 'peering')


def domain_availability(plan, run, tA, tF, event_states, domain):
    truth = ground_truth_windows(plan, run)
    eligible, pass_by_window = [], {}
    events_d = [e for e in plan.get('events', []) if e['domain'] == domain]
    es_d = [e for e in event_states if e.get('domain') == domain]
    for w in truth:
        a, b = w['start_s'], w['end_s']
        in_attack = finite(tA) and finite(tF) and overlap(a, b, tA, tF) > 0
        no_attack_window = not finite(tA)
        planned = sum(e.get('planned_bytes', 0) * overlap(a, b, e['start_s'], e['start_s'] + e['duration_s']) / e['duration_s']
                      for e in events_d if e.get('duration_s', 0) > 0)
        actual = sum((e.get('bytes_tx', 0) + e.get('bytes_rx', 0)) * overlap(a, b, e['start_s'], e['start_s'] + e['duration_s']) / e['duration_s']
                     for e in es_d if e.get('duration_s', 0) > 0)
        delivered_pct = 100 * actual / planned if planned else None
        lateness = [e['lateness_s'] * 1000 for e in es_d if finite(e.get('lateness_s')) and
                    a <= (e.get('actual_end_s') if e.get('actual_end_s') is not None else e.get('start_s', -1)) < b]
        p95 = sorted(lateness)[int(0.95 * (len(lateness) - 1))] if lateness else None
        covered = w['evaluation']
        passed = covered and delivered_pct is not None and delivered_pct >= D and (p95 is None or p95 <= L)
        has_domain_traffic_planned = planned > 0 if planned else False
        if not has_domain_traffic_planned:
            continue  # no events of this domain planned in this window -- not this domain's SLA to judge
        if (in_attack or no_attack_window) and covered:
            eligible.append(w['window'])
            pass_by_window[w['window']] = passed
    if not eligible:
        return None
    return 100 * sum(pass_by_window[w] for w in eligible) / len(eligible)


def main():
    entries = json.loads(RESULTS.read_text())
    per_domain_entries = {d: [] for d in DOMAINS}
    skipped = 0
    for e in entries:
        rid = e.get('run_id')
        if not rid or e.get('status') not in ('completed', 'completed_with_errors'):
            continue
        if e['condition'] not in ('C3', 'C4'):
            continue
        d = RUNS_DIR / rid
        plan_path = d / 'benign_plan.json'
        if not plan_path.exists():
            skipped += 1
            continue
        plan = json.loads(plan_path.read_text())
        run = json.loads((d / 'run.json').read_text())
        event_states = list(json.loads((d / 'event_states.json').read_text()).values())
        tA_rel, tF_rel, tA, tF = _attack_window(run)
        label = 'I' if e['condition'] == 'C3' else 'M'
        for domain in DOMAINS:
            a = domain_availability(plan, run, tA_rel, tF_rel, event_states, domain)
            if a is None:
                continue
            per_domain_entries[domain].append(dict(seed=e['seed'], condition=label, block=e['scenario_id'], value=a))

    result = {}
    for domain in DOMAINS:
        s = summarize(per_domain_entries[domain], f'availability_pct[{domain}] (attack, M-I)')
        result[domain] = dict(
            n_I=sum(1 for x in per_domain_entries[domain] if x['condition'] == 'I'),
            n_M=sum(1 for x in per_domain_entries[domain] if x['condition'] == 'M'),
            by_condition_mean={c: s['by_condition'][c]['seed_balanced']['mean'] for c in s['by_condition']},
            mi_difference=s['mi_difference'],
        )
    OUT.write_text(json.dumps(result, indent=2))
    print('Saved:', OUT)
    print(f'(skipped {skipped} runs with no cached benign_plan.json)')
    for domain in DOMAINS:
        r = result[domain]
        mi = r['mi_difference']
        print(f"\n=== {domain}: n_I={r['n_I']} n_M={r['n_M']} ===")
        print('  mean by condition:', r['by_condition_mean'])
        if mi:
            ci = mi['ci95']
            print(f"  M-I mean={mi['seed_balanced']['mean']:.2f}pp  CI95%=[{ci['low']:.2f}, {ci['high']:.2f}]" if ci else f"  M-I mean={mi['seed_balanced']['mean']:.2f}pp  CI unavailable: {mi['ci_unavailable_reason']}")
        else:
            print('  no paired blocks')


if __name__ == '__main__':
    main()
