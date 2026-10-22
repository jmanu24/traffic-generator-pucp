import pytest
from benign_lab.im_campaign import CONDITIONS, IM_CAMPAIGN_RNG_SEED, block_runs, build_schedule, mode_switches, required_mode_before


def test_block_runs_has_all_five_conditions_with_expected_shape():
    runs = block_runs(3, 'mobile_udp')
    assert [r.condition for r in runs] == list(CONDITIONS)
    by_condition = {r.condition: r for r in runs}
    assert by_condition['C1-I'].scenario == 'B0' and by_condition['C1-I'].pipeline == 'enabled' and by_condition['C1-I'].detection_mode == 'isolated' and not by_condition['C1-I'].has_attack
    assert by_condition['C1-M'].detection_mode == 'multidomain' and not by_condition['C1-M'].has_attack
    assert by_condition['C2'].scenario == 'B0+attack' and by_condition['C2'].pipeline == 'baseline' and by_condition['C2'].detection_mode is None and by_condition['C2'].has_attack
    assert by_condition['C3'].scenario == 'B0+attack' and by_condition['C3'].pipeline == 'enabled' and by_condition['C3'].detection_mode == 'isolated' and by_condition['C3'].has_attack
    assert by_condition['C4'].scenario == 'B0+attack' and by_condition['C4'].pipeline == 'enabled' and by_condition['C4'].detection_mode == 'multidomain' and by_condition['C4'].has_attack
    assert all(r.block == (3, 'mobile_udp') and r.seed == 3 and r.scenario_id == 'mobile_udp' for r in runs)


def test_build_schedule_covers_every_block_exactly_once():
    seeds = [1, 2, 3]
    scenario_ids = ['mobile_udp', 'fixed_syn']
    schedule = build_schedule(seeds, scenario_ids)
    assert len(schedule) == len(seeds) * len(scenario_ids) * len(CONDITIONS)
    seen = {(r.seed, r.scenario_id, r.condition) for r in schedule}
    assert seen == {(seed, sid, c) for seed in seeds for sid in scenario_ids for c in CONDITIONS}


def test_build_schedule_rejects_empty_inputs():
    with pytest.raises(ValueError):
        build_schedule([], ['a'])
    with pytest.raises(ValueError):
        build_schedule([1], [])


def test_build_schedule_covers_every_seed_in_order_never_interleaved():
    # D7: same scheme as pilot_schedule.build_pilot_schedule() -- seeds run
    # in the given order, never reordered or interleaved with each other.
    seeds = [1, 2, 3]
    scenario_ids = ['mobile_udp', 'fixed_syn']
    schedule = build_schedule(seeds, scenario_ids)
    block_size = len(scenario_ids) * len(CONDITIONS)
    seed_sequence = [r.seed for r in schedule]
    boundaries = [seed_sequence.index(s) for s in seeds]
    assert boundaries == sorted(boundaries)
    for seed in seeds:
        assert len([r for r in schedule if r.seed == seed]) == block_size


def test_build_schedule_is_reproducible_from_the_recorded_rng_seed():
    seeds, scenario_ids = [1, 2, 3], ['mobile_udp', 'fixed_syn']
    a = build_schedule(seeds, scenario_ids, rng_seed=IM_CAMPAIGN_RNG_SEED)
    b = build_schedule(seeds, scenario_ids, rng_seed=IM_CAMPAIGN_RNG_SEED)
    assert a == b
    c = build_schedule(seeds, scenario_ids, rng_seed=IM_CAMPAIGN_RNG_SEED + 1)
    assert a != c  # a different seed actually changes the order, proving this is not a no-op


def test_build_schedule_within_seed_order_is_shuffled_not_grouped_by_mode():
    # D7: the previous behaviour grouped every run by detection_mode first
    # (to minimize restarts) -- that is exactly the confound
    # docs/PILOT_DIAGNOSIS.md found live (restart/order perfectly
    # collinear with mode). The new schedule must NOT be sorted by mode
    # within a seed.
    seeds, scenario_ids = [1], ['mobile_udp', 'fixed_syn']
    schedule = build_schedule(seeds, scenario_ids)
    modes = [r.detection_mode for r in schedule]
    assert modes != sorted(modes, key=lambda m: {None: 0, 'isolated': 1, 'multidomain': 2}[m])
    # but still exactly the same set of runs as the declared (unshuffled) order
    declared = [r for sid in scenario_ids for r in block_runs(1, sid)]
    assert sorted(schedule, key=lambda r: (r.scenario_id, r.condition)) == \
           sorted(declared, key=lambda r: (r.scenario_id, r.condition))


def test_build_schedule_can_still_need_many_mode_switches():
    # The flip side of the fix above: a schedule that no longer groups by
    # mode can legitimately need far more restarts than the old minimized
    # scheme's 1 -- documented here as the real, accepted cost of removing
    # the restart/mode confound, not a regression to "fix" back.
    seeds = list(range(1, 12))
    scenario_ids = [f's{i}' for i in range(13)]
    schedule = build_schedule(seeds, scenario_ids)
    assert mode_switches(schedule) > 1


def test_mode_switches_ignores_c2():
    # A schedule of only C2 runs (mode irrelevant, pipeline suspended)
    # must report zero switches even though detection_mode is always None.
    from benign_lab.im_campaign import RunSpec
    runs = [RunSpec(seed=1, scenario_id='x', condition='C2', scenario='B0+attack',
                     pipeline='baseline', detection_mode=None, has_attack=True, block=(1, 'x'))] * 5
    assert mode_switches(runs) == 0


def test_required_mode_before_matches_detection_mode():
    runs = block_runs(1, 'x')
    by_condition = {r.condition: r for r in runs}
    assert required_mode_before(by_condition['C3']) == 'isolated'
    assert required_mode_before(by_condition['C4']) == 'multidomain'
    assert required_mode_before(by_condition['C2']) is None
