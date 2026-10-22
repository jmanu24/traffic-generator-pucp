"""D7/4.4.2 "protected resource" calibration (docs/PROTECTED_RESOURCE.md),
step 4: the "un solo dominio de la composición 3 (su f x umbral)" attack
plan the brief asks for. OFFLINE ONLY: never contacts the real lab.

Builds a single-flow attack plan using EXACTLY composition 3's own
enterprise component (data/attack_plans/composition3_multidomain_under_threshold.json:
f=0.9, 2 sources at 34.569 pps each = 69.138 pps aggregate, start_s=60,
duration_s=60, within the same 180s/seed=201 plan) -- not a new vector or
a new rate, just that one domain's share isolated from the other two, via
the same generate_attack_plan()/save_attack_plan() used for all three
compositions (scripts/generate_regenerated_attack_plans.py), so the
result is directly comparable: same generator, same seed, same timing,
same packet size, only fewer flows.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.attack_planner import generate_attack_plan, save_attack_plan
from scripts.generate_regenerated_attack_plans import (
    SEED, PLAN_DURATION_S, DOMAIN_SOURCES, _flow,
)

OUT_PATH = ROOT / 'data' / 'attack_plans' / 'composition3_enterprise_only.json'
MANIFEST_PATH = ROOT / 'data' / 'attack_plans_manifest.json'

DOMAIN = 'enterprise'
F = 0.9
SYN_THRESHOLD = 76.82


def main():
    aggregate = F * SYN_THRESHOLD
    sources = DOMAIN_SOURCES[DOMAIN]
    per_source = round(aggregate / len(sources), 4)
    desc = dict(
        composition='3_enterprise_only', vector='syn_flood', domain=DOMAIN, f=F,
        aggregate_pps=round(aggregate, 4), rate_per_source_pps=per_source,
        num_sources=len(sources), sources=sources,
        note='isolated single-domain share of composition3 (same seed/timing/rate), '
             'for the protected-resource calibration (docs/PROTECTED_RESOURCE.md step 4)',
    )
    plan = generate_attack_plan(
        seed=SEED, duration_s=PLAN_DURATION_S,
        flows=[_flow(DOMAIN, sources, per_source)],
        description=json.dumps(desc, sort_keys=True))
    save_attack_plan(plan, OUT_PATH)

    manifest = json.loads(MANIFEST_PATH.read_text())
    entry = dict(name='composition3_enterprise_only', plan_hash=plan['plan_hash'], seed=SEED,
                  domains=plan['domains'], path=str(OUT_PATH.relative_to(ROOT)))
    manifest = [e for e in manifest if e['name'] != 'composition3_enterprise_only'] + [entry]
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + '\n')

    print('aggregate_pps:', round(aggregate, 4), 'per_source_pps:', per_source, 'sources:', sources)
    print('plan_hash:', plan['plan_hash'])
    print('Wrote', OUT_PATH, 'and updated', MANIFEST_PATH)


if __name__ == '__main__':
    main()
