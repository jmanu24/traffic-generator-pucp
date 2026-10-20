"""Paso 4: quantile proposal + activation-hysteresis replay, synthetic
evidence only (mirrors detection/engine.py's own activation logic
independently -- these tests catch the two diverging)."""
import pytest
from benign_lab import threshold_replay as tr


def test_quantile_matches_known_values():
    assert tr.quantile([1, 2, 3, 4, 5], 0.5) == 3
    assert tr.quantile([10], 0.999) == 10
    assert tr.quantile([], 0.999) is None


def test_iter_cycle_groups_skips_cycles_without_observed_rates():
    records = [
        dict(kind='cycle', timestamp=100, observed_rates=None),
        dict(kind='detection', timestamp=101),
        dict(kind='cycle', timestamp=102, observed_rates=[
            dict(domains=['enterprise'], dst_ip='10.55.0.100',
                 protocols={'UDP': dict(trigger_pps=12.0)})]),
    ]
    rows = list(tr.iter_cycle_groups(records))
    assert rows == [(102, ('enterprise',), '10.55.0.100', 'UDP', 12.0)]


def test_propose_thresholds_quantile_times_margin():
    groups = [(0, ('enterprise',), 'd', 'UDP', v) for v in range(1, 101)]  # 1..100
    out = tr.propose_thresholds(groups, q=0.99, margin=1.5)
    assert out['UDP']['n'] == 100
    assert out['UDP']['quantile'] == pytest.approx(99.01, abs=.1)
    assert out['UDP']['proposed_threshold'] == pytest.approx(99.01 * 1.5, abs=.2)
    assert 'TCP_SYN' not in out  # no samples -> omitted, not fabricated


def test_single_domain_hit_requires_activation_hysteresis():
    """Enterprise MIN_HITS=3 within WINDOW_S=3: the first two hits over
    threshold must NOT be accepted; the third (within the window) must."""
    thresholds = {'UDP': dict(proposed_threshold=10.0)}
    activation = {'enterprise': (3, 3.0)}
    groups = [
        (0.0, ('enterprise',), 'd', 'UDP', 20.0),
        (1.0, ('enterprise',), 'd', 'UDP', 20.0),
        (2.0, ('enterprise',), 'd', 'UDP', 20.0),
    ]
    accepted = tr.replay_activation(groups, thresholds, activation)
    assert len(accepted) == 1
    assert accepted[0][0] == 2.0


def test_hits_outside_the_window_never_accumulate_toward_min_hits():
    thresholds = {'UDP': dict(proposed_threshold=10.0)}
    activation = {'enterprise': (3, 3.0)}
    groups = [
        (0.0, ('enterprise',), 'd', 'UDP', 20.0),
        (10.0, ('enterprise',), 'd', 'UDP', 20.0),  # outside the first hit's window
        (11.0, ('enterprise',), 'd', 'UDP', 20.0),
    ]
    accepted = tr.replay_activation(groups, thresholds, activation)
    assert accepted == []  # never 3 hits within any 3s window


def test_multidomain_group_is_accepted_immediately_no_hysteresis():
    thresholds = {'UDP': dict(proposed_threshold=10.0)}
    activation = {'enterprise': (3, 3.0)}  # would require 3 hits if single-domain
    groups = [(0.0, ('enterprise', 'mobile'), 'd', 'UDP', 20.0)]
    accepted = tr.replay_activation(groups, thresholds, activation)
    assert len(accepted) == 1


def test_mobile_syn_uses_its_own_activation_key_others_dont():
    thresholds = {'TCP_SYN': dict(proposed_threshold=10.0)}
    activation = {'mobile_syn': (2, 5.0)}
    groups = [
        (0.0, ('mobile',), 'd', 'TCP_SYN', 20.0),
        (1.0, ('mobile',), 'd', 'TCP_SYN', 20.0),
    ]
    accepted = tr.replay_activation(groups, thresholds, activation)
    assert len(accepted) == 1  # 2nd hit within window_s=5 completes MIN_HITS=2


def test_domain_with_no_activation_setting_reports_immediately():
    thresholds = {'UDP': dict(proposed_threshold=10.0)}
    activation = {}  # e.g. a domain not in detection/engine.py's _ACTIVATION_SETTINGS
    groups = [(0.0, ('peering_without_setting',), 'd', 'UDP', 20.0)]
    accepted = tr.replay_activation(groups, thresholds, activation)
    assert len(accepted) == 1


def test_below_threshold_never_accepted_regardless_of_hits():
    thresholds = {'UDP': dict(proposed_threshold=100.0)}
    activation = {'enterprise': (1, 3.0)}
    groups = [(0.0, ('enterprise',), 'd', 'UDP', 99.0)]
    assert tr.replay_activation(groups, thresholds, activation) == []


def test_activation_params_from_snapshot_reads_the_runs_own_values():
    values = dict(ENTERPRISE_ACTIVATION_MIN_HITS=3, ENTERPRISE_ACTIVATION_WINDOW_S=3.0,
                   PEERING_ACTIVATION_MIN_HITS=2, PEERING_ACTIVATION_WINDOW_S=6.0,
                   MOBILE_SYN_ACTIVATION_MIN_HITS=3, MOBILE_SYN_ACTIVATION_WINDOW_S=3.0)
    params = tr.activation_params_from_snapshot(values)
    assert params['enterprise'] == (3, 3.0)
    assert params['bgp'] == (2, 6.0)
    assert params['mobile_syn'] == (3, 3.0)
    assert 'broadband' not in params  # not present in this snapshot -> omitted


def test_fpr_from_replay_counts_benign_window_hits_per_domain_and_global():
    plan = dict(duration_s=10, warmup_s=0, events=[], plan_hash='t')
    run = dict(id='x', status='completed', elapsed_s=10, started_at=1000.0,
               attack_windows=[], observed_attacks=[])
    # One hit in window 0 (0-5s) attributed to enterprise.
    accepted = [(1001.0, ('enterprise',), 'd', 'UDP')]
    result = tr.fpr_from_replay(plan, run, accepted, domains=('enterprise', 'fixed'))
    assert result['enterprise']['eligible'] == 2  # both 5s windows are BENIGN+complete
    assert result['enterprise']['fp'] == 1
    assert result['enterprise']['fpr'] == pytest.approx(0.5)
    assert result['fixed']['fp'] == 0
    assert result['_global']['eligible'] == 4  # 2 domains x 2 windows
    assert result['_global']['fp'] == 1


def test_fpr_from_replay_aliases_telemetry_domain_names_to_generator_names():
    """A replayed hit's domain is the telemetry name ('bgp'/'broadband');
    fpr_from_replay must attribute it to the generator's own name
    ('peering'/'fixed') the same way detection_evaluation.py's affected()
    already does elsewhere in this codebase."""
    plan = dict(duration_s=5, warmup_s=0, events=[], plan_hash='t')
    run = dict(id='x', status='completed', elapsed_s=5, started_at=1000.0,
               attack_windows=[], observed_attacks=[])
    accepted = [(1001.0, ('bgp',), 'd', 'TCP_SYN')]
    result = tr.fpr_from_replay(plan, run, accepted, domains=('peering', 'fixed'))
    assert result['peering']['fp'] == 1
    assert result['fixed']['fp'] == 0
