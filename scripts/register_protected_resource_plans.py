"""D7/4.4.2 "protected resource" calibration (docs/PROTECTED_RESOURCE.md),
step 4: register the 3 plans this calibration needs on the dashboard's
own server, the same /api/plans + /api/attacks/plans pattern
scripts/register_pilot_plans_on_server.py already uses for the pilot.
Never sends attack traffic or launches any run."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from run_pilot import load_token, call
from generate_protected_resource_calibration_plan import DOMAIN, F, SYN_THRESHOLD, SEED, PLAN_DURATION_S
from generate_regenerated_attack_plans import DOMAIN_SOURCES, _flow

BENIGN_SEED = 201
BENIGN_PLAN_HASH = '5c54495dec246a16d3f5a6ab3e4f46c337ce35f10fdee8f420be28bb6e9e0d80'
COMPOSITION3_PLAN_HASH = '1990310a26c6ffbdfa28da0025de3a59f082bb6442d2c010317067905375a38e'


def register_benign(token):
    result = call(token, 'POST', '/api/plans', dict(seed=BENIGN_SEED, duration_s=180))
    status = 'MATCH' if not result.get('error') and result.get('plan_hash') == BENIGN_PLAN_HASH else 'MISMATCH/FAILED'
    print(f'  benign seed={BENIGN_SEED}: server={result.get("plan_hash", result)} local={BENIGN_PLAN_HASH} [{status}]')
    return status == 'MATCH'


def register_composition3(token):
    import generate_regenerated_attack_plans as gen
    from unittest import mock
    captured = []
    original = gen.generate_attack_plan

    def spy(seed, duration_s, flows, description):
        plan = original(seed, duration_s, flows, description)
        captured.append(dict(seed=seed, duration_s=duration_s, flows=flows, description=description, plan_hash=plan['plan_hash']))
        return plan

    with mock.patch.object(gen, 'generate_attack_plan', side_effect=spy):
        gen.build_composition_3()
    entry = next((c for c in captured if c['plan_hash'] == COMPOSITION3_PLAN_HASH), None)
    if entry is None:
        print('  composition3: local reconstruction did not match the recorded hash (unexpected)')
        return False
    result = call(token, 'POST', '/api/attacks/plans',
                   dict(seed=entry['seed'], duration_s=entry['duration_s'], description=entry['description'], flows=entry['flows']))
    status = 'MATCH' if not result.get('error') and result.get('plan_hash') == COMPOSITION3_PLAN_HASH else 'MISMATCH/FAILED'
    print(f'  composition3: server={result.get("plan_hash", result)} local={COMPOSITION3_PLAN_HASH} [{status}]')
    return status == 'MATCH'


def register_single_domain(token):
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
    description = json.dumps(desc, sort_keys=True)
    flows = [_flow(DOMAIN, sources, per_source)]
    local_hash = json.loads(Path(ROOT / 'data' / 'attack_plans' / 'composition3_enterprise_only.json').read_text())['plan_hash']
    result = call(token, 'POST', '/api/attacks/plans', dict(seed=SEED, duration_s=PLAN_DURATION_S, description=description, flows=flows))
    status = 'MATCH' if not result.get('error') and result.get('plan_hash') == local_hash else 'MISMATCH/FAILED'
    print(f'  composition3_enterprise_only: server={result.get("plan_hash", result)} local={local_hash} [{status}]')
    return status == 'MATCH'


def main():
    token = load_token()
    print('--- benign plan (seed 201) ---')
    ok1 = register_benign(token)
    print('--- composition3 attack plan ---')
    ok2 = register_composition3(token)
    print('--- composition3_enterprise_only attack plan ---')
    ok3 = register_single_domain(token)
    if ok1 and ok2 and ok3:
        print('\nAll 3 plans registered and hash-matched on the server.')
    else:
        print('\n*** at least one plan FAILED to register/match -- do not launch runs yet ***')


if __name__ == '__main__':
    main()
