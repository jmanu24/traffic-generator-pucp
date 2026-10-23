import pytest
from benign_lab.im_campaign import CONDITIONS, block_runs, build_schedule, mode_switches, required_mode_before


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


def test_schedule_minimizes_controller_mode_switches():
    # 11 seeds x 13 scenarios (the thesis's own N and scenario count) would
    # be 143 blocks; naively running C1-I,C1-M,C2,C3,C4 block-by-block in
    # that order would switch isolated<->multidomain twice per block
    # (286 switches). Grouping by mode must bring this down to 1.
    seeds = list(range(1, 12))
    scenario_ids = [f's{i}' for i in range(13)]
    schedule = build_schedule(seeds, scenario_ids)
    assert mode_switches(schedule) == 1


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
