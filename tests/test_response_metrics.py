"""D6 unit tests, synthetic evidence only -- no real lab access.

Covers the three cases the brief explicitly asked for: an ATTACK window
eligible without the attacker IP in observed_sources (scenario_confusion
already covers that one, see test_scenario_series.py), absent detection
producing a censored time, and an isolated-mode run that cannot produce a
multidomain-mode record (that one is detection_mode_control/runner's job,
see test_im_integration.py) -- plus this module's own full set of
indicators, coverage() and summarize()'s paired M-I/censoring handling.
"""
import pytest
from benign_lab import response_metrics as rm


def make_plan(duration_s=30, warmup_s=0, domain='enterprise'):
    return dict(duration_s=duration_s, warmup_s=warmup_s, ground_truth={'window_s': 5}, plan_hash='testplan',
                events=[dict(event_id='benign1', domain=domain, source='ent1', start_s=0, duration_s=duration_s, planned_bytes=duration_s * 1000)])


def make_run(started_at=1000.0, elapsed_s=30, attack_start_s=10.0, attack_end_s=15.0, source_ips=('10.70.0.99',), status='completed'):
    return dict(id='x', status=status, started_at=started_at, elapsed_s=elapsed_s,
                attack_source_ips=list(source_ips),
                observed_attacks=[dict(name='atk', start_s=attack_start_s, end_s=attack_end_s, annotation_source='attack_runner')])


def make_event_states(duration_s=30, domain='enterprise', delivered_pct=1.0, lateness_s=.01):
    return [dict(event_id='benign1', domain=domain, start_s=0, duration_s=duration_s,
                 planned_bytes=duration_s * 1000, bytes_tx=int(duration_s * 1000 * delivered_pct), bytes_rx=0,
                 lateness_s=lateness_s, actual_end_s=duration_s, status='completed')]


def detection_record(timestamp, src_ip='10.70.0.99', activation_delay_s=1.5, domain='enterprise'):
    return dict(kind='detection', timestamp=timestamp,
                detection=dict(src_ip=src_ip, sources=[], domain=domain, activation_delay_s=activation_delay_s))


def mitigation_record(timestamp, src_ip='10.70.0.99', domain='enterprise'):
    return dict(kind='mitigation_issued', timestamp=timestamp,
                action=dict(src_ip=src_ip, sources=[], domain=domain))


def test_full_happy_path_tD_tO_and_availability():
    plan, run = make_plan(), make_run()
    records = [detection_record(1012), mitigation_record(1013)]
    es = make_event_states()
    r = rm.compute(plan, run, records, event_states=es)
    assert r['tA'] == 1010 and r['tF'] == 1015
    assert r['tD']['value'] == 1012 and r['tD']['censored'] is False
    assert r['tD0'] == pytest.approx(1010.5)
    assert r['tO']['value'] == 1013
    assert r['TD'] == pytest.approx(2) and r['TO'] == pytest.approx(1)
    assert r['mitigated_domain'] == 'enterprise'
    assert r['availability_pct'] == 100.0


def test_absent_detection_is_censored_with_observed_duration_not_dropped():
    """The brief's second explicit ask: detección ausente -> tiempo
    censurado, not an excluded/invalid execution."""
    plan, run = make_plan(), make_run()
    records = []  # no detection, no mitigation at all
    es = make_event_states()
    r = rm.compute(plan, run, records, event_states=es)
    assert r['tD']['value'] is None and r['tD']['censored'] is True
    assert r['tD']['reason'] == 'no_matching_detection'
    # observed_duration_s: watched from tA (1010) to run end (1030) = 20s
    assert r['tD']['observed_duration_s'] == pytest.approx(20)
    assert r['tO']['value'] is None and r['tO']['censored'] is True
    assert r['TD'] is None and r['TO'] is None
    # the run itself is not excluded/invalidated -- compute() still
    # returns a full, well-formed result.
    assert r['schema'] == 1 and 'availability_pct' in r


def test_tI_censored_not_observable_without_installation_evidence():
    plan, run = make_plan(), make_run()
    records = [detection_record(1012), mitigation_record(1013)]
    r = rm.compute(plan, run, records, event_states=make_event_states())
    assert r['tI']['value'] is None and r['tI']['reason'] == 'not_observable'
    assert r['TI'] is None


def test_tI_reported_when_installation_evidence_given():
    plan, run = make_plan(), make_run()
    records = [detection_record(1012), mitigation_record(1013)]
    r = rm.compute(plan, run, records, event_states=make_event_states(), installation_evidence={'enterprise': 1013.4})
    assert r['tI']['value'] == pytest.approx(1013.4)
    assert r['TI'] == pytest.approx(.4)


def test_tE_censored_without_rate_series():
    plan, run = make_plan(), make_run()
    records = [detection_record(1012), mitigation_record(1013)]
    r = rm.compute(plan, run, records, event_states=make_event_states())
    assert r['tE']['value'] is None and r['tE']['reason'] == 'no_independent_rate_series'
    assert r['TM'] is None


def test_tE_found_when_rate_sustained_below_threshold():
    plan, run = make_plan(), make_run()
    records = [detection_record(1012), mitigation_record(1013)]
    # Baseline [tA=1010, tO=1013]: steady 100pps. After tO it drops to 10pps
    # (R=80 -> threshold=20pps) and stays there for >= S=5s starting at 1014.
    series = [(1010, 100), (1011, 100), (1012, 100), (1013, 100),
              (1013.5, 10), (1014, 10), (1015, 10), (1016, 10), (1017, 10), (1019, 10), (1020, 10)]
    r = rm.compute(plan, run, records, event_states=make_event_states(), rate_series={'enterprise': series})
    assert r['tE']['value'] == pytest.approx(1013.5)
    assert r['TM'] == pytest.approx(1013.5 - 1012)


def test_tE_not_found_when_drop_not_sustained():
    plan, run = make_plan(), make_run()
    records = [detection_record(1012), mitigation_record(1013)]
    series = [(1010, 100), (1012, 100), (1013, 100), (1013.5, 10), (1014, 100), (1015, 100)]
    r = rm.compute(plan, run, records, event_states=make_event_states(), rate_series={'enterprise': series})
    assert r['tE']['value'] is None
    assert r['tE']['reason'] == 'threshold_crossed_but_not_sustained_for_S'


def test_availability_fails_window_below_delivery_quota():
    plan, run = make_plan(), make_run()
    records = [detection_record(1012), mitigation_record(1013)]
    es = make_event_states(delivered_pct=.5)  # below D=90%
    r = rm.compute(plan, run, records, event_states=es)
    assert r['availability_pct'] == 0.0


def test_recovery_tS_and_TR_after_attack_ends():
    plan = make_plan(duration_s=40)
    run = make_run(elapsed_s=40, attack_start_s=10, attack_end_s=15)
    records = [detection_record(1012), mitigation_record(1013)]
    # Delivery recovers to 100% for every window, including the 3 (K=3)
    # consecutive windows starting right at tF=1015 (window index 3, 15-20s).
    es = make_event_states(duration_s=40)
    r = rm.compute(plan, run, records, event_states=es)
    assert r['tS'] == pytest.approx(15)
    assert r['TR'] == pytest.approx(0)


def test_coverage_proportions_across_runs():
    detected_and_mitigated = dict(tD=dict(value=1012), tO=dict(value=1013), TR=0.0)
    detected_only = dict(tD=dict(value=1012), tO=dict(value=None), TR=None)
    neither = dict(tD=dict(value=None), tO=dict(value=None), TR=None)
    c = rm.coverage([detected_and_mitigated, detected_only, neither])
    assert c == dict(n=3, detected=pytest.approx(2 / 3), mitigated=pytest.approx(1 / 3), recovered=pytest.approx(1 / 3))
    assert rm.coverage([]) == dict(n=0, detected=None, mitigated=None, recovered=None)


def test_restricted_mean_caps_censored_value_at_restriction():
    assert rm.restricted(3.0, False, 10) == 3.0
    assert rm.restricted(None, True, 10) == 10
    assert rm.restricted(50.0, True, 10) == 10  # a late/invalid value is still capped


def test_summarize_pairs_m_minus_i_by_block_with_restricted_censoring():
    entries = [
        dict(seed=1, block=1, condition='I', value=5.0, censored=False, restriction_s=20),
        dict(seed=1, block=1, condition='M', value=2.0, censored=False, restriction_s=20),
        dict(seed=2, block=1, condition='I', value=None, censored=True, restriction_s=20),  # never mitigated under I
        dict(seed=2, block=1, condition='M', value=3.0, censored=False, restriction_s=20),
    ]
    out = rm.summarize(entries, metric='TO')
    assert out['metric'] == 'TO'
    assert out['mi_difference']['n_seeds'] == 2
    # seed1: 2-5=-3; seed2: 3-20(restricted censored I)=-17
    assert out['mi_difference']['seed_balanced']['mean'] == pytest.approx((-3 + -17) / 2)
