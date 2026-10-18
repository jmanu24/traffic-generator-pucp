"""Threshold recommendations from measured baseline traffic (pure function)."""
import pytest
from benign_lab.threshold_recommendation import recommend_thresholds
from benign_lab.threshold_control import FIELDS


def test_recommend_thresholds_scales_the_worst_domain_peak():
    report = recommend_thresholds({
        'mobile': {'syn_pps': 10, 'udp_pps': 40},
        'fixed': {'syn_pps': 25, 'udp_pps': 30},
    }, margin=1.5, dist_margin=2.0)
    assert report['recommended']['SYN_THRESHOLD'] == round(25 * 1.5, 1)
    assert report['recommended']['UDP_THRESHOLD'] == round(40 * 1.5, 1)
    assert set(report['recommended']) <= FIELDS


def test_recommend_thresholds_dist_pps_uses_the_combined_baseline():
    report = recommend_thresholds({
        'mobile': {'udp_pps': 50}, 'fixed': {'udp_pps': 50}, 'enterprise': {'udp_pps': 50},
    }, margin=1.5, dist_margin=2.0)
    assert report['recommended']['DIST_PPS_THRESHOLD'] == round(150 * 2.0, 1)


def test_recommend_thresholds_rejects_margins_at_or_below_one():
    with pytest.raises(ValueError):
        recommend_thresholds({'mobile': {'syn_pps': 10}}, margin=1.0)
    with pytest.raises(ValueError):
        recommend_thresholds({'mobile': {'syn_pps': 10}}, dist_margin=1.0)


def test_recommend_thresholds_requires_at_least_one_domain():
    with pytest.raises(ValueError):
        recommend_thresholds({})


def test_recommend_thresholds_rejects_negative_rates():
    with pytest.raises(ValueError):
        recommend_thresholds({'mobile': {'syn_pps': -1}})
