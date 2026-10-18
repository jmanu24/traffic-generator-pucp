"""Seed count required for a target CI precision, from calibration variability."""
import math
import pytest
from benign_lab.sample_size import required_seeds, required_seeds_relative, plan_sample_size
from benign_lab.experimental_analytics import T975


def test_required_seeds_satisfies_its_own_t_based_precision_bound():
    n = required_seeds(sd=10, precision=2)
    half = T975[min(n - 1, 30) - 1] * 10 / math.sqrt(n)
    assert half <= 2
    half_minus_one = T975[min(n - 2, 30) - 1] * 10 / math.sqrt(n - 1)
    assert half_minus_one > 2  # n is the smallest that satisfies the bound


def test_required_seeds_is_none_without_variability_or_target():
    assert required_seeds(sd=0, precision=2) is None
    assert required_seeds(sd=5, precision=0) is None
    assert required_seeds(sd=None, precision=2) is None


def test_required_seeds_relative_uses_a_fraction_of_the_mean():
    absolute = required_seeds(sd=5, precision=5)
    relative = required_seeds_relative(sd=5, mean=100, relative_precision=0.05)
    assert absolute == relative
    with pytest.raises(ValueError):
        required_seeds_relative(sd=5, mean=0, relative_precision=0.05)


def test_plan_sample_size_reports_the_most_demanding_metric():
    report = plan_sample_size(
        calibration={'throughput_mbps': {'mean': 95.0, 'sd': 4.0},
                     'delay_ms': {'mean': 12.0, 'sd': 3.0}},
        precision_by_metric={'throughput_mbps': 2.0, 'delay_ms': 1.0},
    )
    assert report['required_seeds'] == max(v['n'] for v in report['per_metric'].values())
    assert report['limiting_metrics'] == ['delay_ms']


def test_plan_sample_size_flags_metrics_without_calibration_data():
    report = plan_sample_size(calibration={}, precision_by_metric={'jitter_ms': 1.0})
    assert report['per_metric']['jitter_ms']['reason'] == 'no_calibration_sample_for_metric'
    assert report['required_seeds'] is None
