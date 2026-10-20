"""ATTACK_PLAN_REGENERATION (thesis task C): regenerate the attack plans for
the three compositions, with rates expressed as multiples of the real
calibrated thresholds (docs/THRESHOLD_CALIBRATION_RESULT.md). OFFLINE ONLY:
this script never contacts the real lab -- it only computes rates, builds
ATTACK_FLOOD_V1 plans with attack_planner.generate_attack_plan(), predicts
each plan's expected effective decision score in I and M via
benign_lab.decision_score_estimator (an independent reimplementation, never
the production code path), and saves everything under
data/attack_plans/ + data/attack_plans_manifest.json. The real-lab
validation run (pipeline suspended) is a separate, explicitly confirmed
step -- not run by this script.

Thresholds (THRESHOLD_CALIBRATION_RESULT.md, applied 2026-10-20):
  SYN_THRESHOLD = 76.82, DECISION_THRESHOLD = 1.5 (unchanged).

D4-A (documented limitation, see docs/ATTACK_PLAN_REGENERATION.md): every
composition here uses SYN as its vector, including for the mobile domain,
specifically BECAUSE the engine's UDP/ICMP trigger_pps excludes mobile by
design (mobile is KPM-driven for those two vectors) -- SYN is the only
vector where mobile's own pps rate is comparable to, and combinable with,
the other three domains' rates in the scoring formula.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

from benign_lab.attack_planner import generate_attack_plan, save_attack_plan
from benign_lab.decision_score_estimator import estimate_isolated_and_multidomain

SYN_THRESHOLD = 76.82
VECTOR = 'syn_flood'
SEED = 201  # "semilla de prueba" -- not used by any THRESHOLD_CALIBRATION run (101-110); see docs/ATTACK_PLAN_REGENERATION.md
PLAN_DURATION_S = 180
ATTACK_START_S = 60
ATTACK_DURATION_S = 60  # window 60-120s of the 180s plan

OUT_DIR = ROOT / 'data' / 'attack_plans'
MANIFEST_PATH = ROOT / 'data' / 'attack_plans_manifest.json'

DOMAIN_SOURCES = {
    'enterprise': ['ent-site-1', 'ent-site-2'],
    'fixed': ['fixed1', 'fixed2'],
    'mobile': ['ue1', 'ue2'],
    'peering': ['peer-flow*'],  # only one attack-capable source available
}


def _flow(domain, sources, rate_pps):
    return dict(domain=domain, sources=sources, destination='victim-web',
                wire_protocol=VECTOR, rate_pps=rate_pps, start_s=ATTACK_START_S,
                duration_s=ATTACK_DURATION_S, packet_size_bytes=64)


def _score_block(per_domain_rates):
    """per_domain_rates: dict(domain -> list of per-source pps). Returns the
    estimator's I/M prediction as a plain dict, ready to embed in a plan
    description."""
    est = estimate_isolated_and_multidomain(per_domain_rates, SYN_THRESHOLD, VECTOR)
    return dict(
        isolated={d: (r and {k: round(v, 4) if isinstance(v, float) else v for k, v in r.items()})
                  for d, r in est['isolated'].items()},
        multidomain=est['multidomain'] and {k: round(v, 4) if isinstance(v, float) else v
                                              for k, v in est['multidomain'].items()},
    )


def build_composition_1():
    """Control, single vector: one source per domain, k=4.75x SYN_THRESHOLD."""
    k = 4.75
    rate = round(k * SYN_THRESHOLD, 4)
    plans = []
    for domain, sources in DOMAIN_SOURCES.items():
        source = sources[0]
        per_domain_rates = {domain: [rate]}
        scores = _score_block(per_domain_rates)
        desc = dict(
            composition=1, domain=domain, vector=VECTOR, k=k,
            rate_per_source_pps=rate, sources=[source], num_sources=1,
            aggregate_per_domain_pps=rate, f_effective=k, sum_pps=rate,
            expected_score=scores,
        )
        plan = generate_attack_plan(
            seed=SEED, duration_s=PLAN_DURATION_S,
            flows=[_flow(domain, [source], rate)],
            description=json.dumps(desc, sort_keys=True))
        plans.append((f'composition1_{domain}', plan, desc))
    return plans


def build_composition_2():
    """Multidomain over the local threshold: one domain >= 1.5x (chosen:
    4.5x, comfortably above the single-attacker confidence-saturation bar
    of sqrt(15)~=3.87x, so M actually decides, not just technically
    qualifies as '>= 1.5x'), the other two domains well under their own
    local threshold (0.3x)."""
    over_k, under_k = 4.5, 0.3
    over_domain, under_domains = 'enterprise', ['fixed', 'peering']
    rates = {over_domain: round(over_k * SYN_THRESHOLD, 4)}
    rates.update({d: round(under_k * SYN_THRESHOLD, 4) for d in under_domains})
    per_domain_rates = {d: [r] for d, r in rates.items()}
    scores = _score_block(per_domain_rates)
    flows = [_flow(over_domain, [DOMAIN_SOURCES[over_domain][0]], rates[over_domain])]
    flows += [_flow(d, [DOMAIN_SOURCES[d][0]], rates[d]) for d in under_domains]
    desc = dict(
        composition=2, vector=VECTOR,
        domains={over_domain: dict(k=over_k, rate_per_source_pps=rates[over_domain], num_sources=1),
                 **{d: dict(k=under_k, rate_per_source_pps=rates[d], num_sources=1) for d in under_domains}},
        sum_pps=round(sum(rates.values()), 4), num_sources=3,
        expected_score=scores,
    )
    plan = generate_attack_plan(
        seed=SEED, duration_s=PLAN_DURATION_S, flows=flows,
        description=json.dumps(desc, sort_keys=True))
    return [('composition2_multidomain_over_threshold', plan, desc)]


def build_composition_3():
    """Multidomain under the local threshold (confirmatoria): 6 sources
    across 3 domains (not exactly 5, to stay clear of DIST_MIN_SOURCES'
    own minimum), f in {0.9, 0.7, 0.5} per domain, rate split evenly
    between the 2 sources of each domain for high entropy."""
    f_by_domain = {'enterprise': 0.9, 'fixed': 0.7, 'mobile': 0.5}
    per_domain_rates = {}
    flows = []
    domains_desc = {}
    for domain, f in f_by_domain.items():
        aggregate = f * SYN_THRESHOLD
        sources = DOMAIN_SOURCES[domain]
        per_source = round(aggregate / len(sources), 4)
        per_domain_rates[domain] = [per_source] * len(sources)
        flows.append(_flow(domain, sources, per_source))
        domains_desc[domain] = dict(f=f, aggregate_pps=round(aggregate, 4),
                                     rate_per_source_pps=per_source, num_sources=len(sources))
    scores = _score_block(per_domain_rates)
    sum_pps = round(sum(sum(v) for v in per_domain_rates.values()), 4)
    desc = dict(
        composition=3, vector=VECTOR, domains=domains_desc,
        sum_pps=sum_pps, sum_over_threshold_ratio=round(sum_pps / SYN_THRESHOLD, 4),
        num_sources=sum(len(v) for v in per_domain_rates.values()),
        expected_score=scores,
    )
    plan = generate_attack_plan(
        seed=SEED, duration_s=PLAN_DURATION_S, flows=flows,
        description=json.dumps(desc, sort_keys=True))
    return [('composition3_multidomain_under_threshold', plan, desc)]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []
    warnings = []
    all_plans = build_composition_1() + build_composition_2() + build_composition_3()
    for name, plan, desc in all_plans:
        path = OUT_DIR / f'{name}.json'
        save_attack_plan(plan, path)
        m_result = desc['expected_score']['multidomain']
        if not m_result or not m_result.get('decides'):
            warnings.append(f'{name}: multidomain mode does NOT reach DECISION_THRESHOLD '
                             f'(expected_score.multidomain={m_result})')
        manifest.append(dict(name=name, plan_hash=plan['plan_hash'], seed=SEED,
                              domains=plan['domains'], path=str(path.relative_to(ROOT))))
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Wrote {len(manifest)} plans to {OUT_DIR} and manifest to {MANIFEST_PATH}')
    if warnings:
        print('\n*** WARNING: some compositions do not reach the M decision threshold ***')
        for w in warnings:
            print(' -', w)
    else:
        print('All compositions reach DECISION_THRESHOLD in multidomain (M) mode.')


if __name__ == '__main__':
    main()
