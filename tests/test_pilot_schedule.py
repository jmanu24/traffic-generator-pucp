import json
import pytest
from benign_lab.pilot_schedule import (
    PILOT_SEEDS, PILOT_RNG_SEED, seed_runs, build_pilot_schedule, mode_switches, estimate_duration_s,
)
from benign_lab.config import ROOT

MANIFEST = json.loads((ROOT / 'data' / 'attack_plans_manifest.json').read_text())


def test_manifest_has_the_6_expected_compositions():
    names = {e['name'] for e in MANIFEST}
    assert names == {
        'composition1_enterprise', 'composition1_fixed', 'composition1_mobile', 'composition1_peering',
        'composition2_multidomain_over_threshold', 'composition3_multidomain_under_threshold',
    }


def test_seed_runs_has_exactly_2_benign_and_3_per_manifest_entry():
    runs = seed_runs(201, MANIFEST)
    assert len(runs) == 2 + 3 * len(MANIFEST)
    c1 = [r for r in runs if r.condition in ('C1-I', 'C1-M')]
    assert len(c1) == 2
    assert {r.condition for r in c1} == {'C1-I', 'C1-M'}
    assert all(r.scenario_id is None and r.plan_hash is None and r.scenario == 'B0' and r.pipeline == 'enabled' for r in c1)
    assert {r.detection_mode for r in c1} == {'isolated', 'multidomain'}
    for entry in MANIFEST:
        trio = [r for r in runs if r.scenario_id == entry['name']]
        assert {r.condition for r in trio} == {'C2', 'C3', 'C4'}
        assert all(r.plan_hash == entry['plan_hash'] and r.scenario == 'B0+attack' for r in trio)
        by_condition = {r.condition: r for r in trio}
        assert by_condition['C2'].pipeline == 'baseline' and by_condition['C2'].detection_mode is None
        assert by_condition['C3'].pipeline == 'enabled' and by_condition['C3'].detection_mode == 'isolated'
        assert by_condition['C4'].pipeline == 'enabled' and by_condition['C4'].detection_mode == 'multidomain'


def test_seed_runs_rejects_empty_manifest():
    with pytest.raises(ValueError):
        seed_runs(201, [])


def test_build_pilot_schedule_covers_every_seed_in_order_never_interleaved():
    schedule = build_pilot_schedule(MANIFEST)
    assert len(schedule) == 3 * (2 + 3 * len(MANIFEST))
    seed_sequence = [r.seed for r in schedule]
    # every run of seed 201 must appear before every run of seed 202, etc.
    boundaries = [seed_sequence.index(s) for s in PILOT_SEEDS]
    assert boundaries == sorted(boundaries)
    for i, seed in enumerate(PILOT_SEEDS):
        block = [r for r in schedule if r.seed == seed]
        assert len(block) == 2 + 3 * len(MANIFEST)


def test_build_pilot_schedule_is_reproducible_from_the_recorded_rng_seed():
    a = build_pilot_schedule(MANIFEST, rng_seed=PILOT_RNG_SEED)
    b = build_pilot_schedule(MANIFEST, rng_seed=PILOT_RNG_SEED)
    assert a == b
    c = build_pilot_schedule(MANIFEST, rng_seed=PILOT_RNG_SEED + 1)
    assert a != c  # different seed actually changes the order, proving it is not a no-op


def test_build_pilot_schedule_within_seed_order_is_shuffled_not_the_declared_order():
    unshuffled_first_seed = seed_runs(201, MANIFEST)
    schedule = build_pilot_schedule(MANIFEST, seeds=(201,))
    assert [r.condition for r in schedule] != [r.condition for r in unshuffled_first_seed] or \
           [r.scenario_id for r in schedule] != [r.scenario_id for r in unshuffled_first_seed]
    assert sorted(schedule, key=lambda r: (r.condition, r.scenario_id or '')) == \
           sorted(unshuffled_first_seed, key=lambda r: (r.condition, r.scenario_id or ''))


def test_build_pilot_schedule_rejects_no_seeds():
    with pytest.raises(ValueError):
        build_pilot_schedule(MANIFEST, seeds=())


def test_mode_switches_ignores_c2_on_either_side():
    schedule = seed_runs(201, MANIFEST[:1])  # C1-I, C1-M, C2, C3, C4 in declared order
    by_condition = {r.condition: r for r in schedule}
    ordered = [by_condition['C1-I'], by_condition['C2'], by_condition['C1-M']]
    # isolated -> (C2, mode-indifferent) -> multidomain: exactly 1 switch, not 2
    assert mode_switches(ordered) == 1


def test_mode_switches_zero_for_all_same_mode():
    runs = seed_runs(201, MANIFEST[:1])
    same_mode = [r for r in runs if r.detection_mode in (None, 'isolated')]
    assert mode_switches(same_mode) == 0


def test_estimate_duration_s_counts_runs_pauses_and_restarts():
    schedule = build_pilot_schedule(MANIFEST, seeds=(201,))
    est = estimate_duration_s(schedule)
    n = len(schedule)
    assert est['runs'] == n
    assert est['run_duration_s'] == n * 180
    assert est['pause_s'] == (n - 1) * 60
    assert est['mode_switches'] == mode_switches(schedule) + 1  # +1 for the unknown initial mode
    assert est['restart_s'] == est['mode_switches'] * 60
    assert est['total_s'] == est['run_duration_s'] + est['pause_s'] + est['restart_s']


def test_estimate_duration_s_without_initial_mode_assumption():
    schedule = build_pilot_schedule(MANIFEST, seeds=(201,))
    est = estimate_duration_s(schedule, initial_mode_unknown=False)
    assert est['mode_switches'] == mode_switches(schedule)
