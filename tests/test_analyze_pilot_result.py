from scripts.analyze_pilot_result import index_by_key, paired_diffs


def test_index_by_key_builds_metric_dict_keyed_by_seed_condition_scenario():
    details = [
        dict(seed=201, condition='C3', scenario_id='s1', eligible=True,
             selected_metric=dict(delivery_pct=50.0, detection_fpr_pct=1.0, decision_fpr_pct=2.0)),
        dict(seed=201, condition='C1-I', scenario_id=None, eligible=True,
             selected_metric=dict(delivery_pct=80.0)),
    ]
    by_key = index_by_key(details)
    assert by_key[(201, 'C3', 's1')] == dict(delivery_pct=50.0, eligible=True, detection_fpr_pct=1.0, decision_fpr_pct=2.0)
    assert by_key[(201, 'C1-I', None)]['delivery_pct'] == 80.0


def test_paired_diffs_computes_b_minus_a_only_when_both_eligible():
    by_key = {
        (201, 'C3', 's1'): dict(delivery_pct=40.0, eligible=True),
        (201, 'C4', 's1'): dict(delivery_pct=70.0, eligible=True),
        (202, 'C3', 's1'): dict(delivery_pct=30.0, eligible=True),
        (202, 'C4', 's1'): dict(delivery_pct=50.0, eligible=False),  # excluded: not eligible
        (203, 'C3', 's1'): dict(delivery_pct=35.0, eligible=True),
        # 203 C4 missing entirely -> excluded
    }
    diffs = paired_diffs(by_key, 'delivery_pct', 'C3', 'C4', seeds=(201, 202, 203), scenario_id='s1')
    assert diffs == [(201, 30.0)]


def test_paired_diffs_skips_none_metric_values():
    by_key = {
        (201, 'C1-I', None): dict(delivery_pct=None, eligible=True),
        (201, 'C1-M', None): dict(delivery_pct=60.0, eligible=True),
    }
    diffs = paired_diffs(by_key, 'delivery_pct', 'C1-I', 'C1-M', seeds=(201,), scenario_id=None)
    assert diffs == []


def test_paired_diffs_preserves_seed_order_and_sign():
    by_key = {
        (201, 'C1-I', None): dict(delivery_pct=10.0, eligible=True),
        (201, 'C1-M', None): dict(delivery_pct=15.0, eligible=True),
        (202, 'C1-I', None): dict(delivery_pct=20.0, eligible=True),
        (202, 'C1-M', None): dict(delivery_pct=12.0, eligible=True),
    }
    diffs = paired_diffs(by_key, 'delivery_pct', 'C1-I', 'C1-M', seeds=(201, 202), scenario_id=None)
    assert diffs == [(201, 5.0), (202, -8.0)]
