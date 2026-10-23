"""Paso 4 (THRESHOLD_CALIBRATION): propose thresholds from the quantile
of real per-cycle benign rates (Paso 1's observed_rates), then replay
detection -- WITH activation hysteresis, the same persistence
detection/engine.py applies in production -- against those same
per-cycle rates under a candidate threshold, to recompute FPR without
ever touching the real controller.

Pure computation: no SSH, no live state. Mirrors detection/engine.py's
own _activation_domain()/_activated() logic (same MIN_HITS/WINDOW_S
settings, read from the run's own recorded thresholds snapshot -- never
hardcoded) closely enough to be a faithful replay, but is a separate,
independent implementation reading already-captured evidence -- this
module is never imported by, and never calls into, the controller.
"""
import math
import statistics
from .ground_truth import windows as ground_truth_windows, overlap

PROTOCOLS = ('TCP_SYN', 'UDP', 'ICMP')

# detection/engine.py's _ACTIVATION_SETTINGS, by telemetry domain name
# (not the generator's own domain aliases) -- the setting names read
# from each run's own recorded LAB_AUDIT thresholds snapshot.
ACTIVATION_SETTING_NAMES = {
    'enterprise': ('ENTERPRISE_ACTIVATION_MIN_HITS', 'ENTERPRISE_ACTIVATION_WINDOW_S'),
    'bgp': ('PEERING_ACTIVATION_MIN_HITS', 'PEERING_ACTIVATION_WINDOW_S'),
    'broadband': ('BROADBAND_ACTIVATION_MIN_HITS', 'BROADBAND_ACTIVATION_WINDOW_S'),
}
MOBILE_SYN_SETTING_NAMES = ('MOBILE_SYN_ACTIVATION_MIN_HITS', 'MOBILE_SYN_ACTIVATION_WINDOW_S')

ALIAS = {'broadband': 'fixed', 'bgp': 'peering'}  # telemetry domain -> generator domain


def quantile(values, q):
    if not values:
        return None
    s = sorted(values)
    idx = q * (len(s) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(s) - 1)
    frac = idx - lo
    return s[lo] + (s[hi] - s[lo]) * frac


def iter_cycle_groups(records):
    """records: a run's own LAB_AUDIT kind=cycle records (already
    parsed). Yields (timestamp, domains_tuple, dst_ip, protocol,
    trigger_pps) for every protocol present in every correlation group
    of every cycle that has observed_rates (Paso 1) -- cycles without it
    (pipeline not yet instrumented, or genuinely nothing correlated)
    are silently skipped, never treated as zero."""
    for rec in records:
        if rec.get('kind') != 'cycle' or not rec.get('observed_rates'):
            continue
        ts = rec['timestamp']
        for group in rec['observed_rates']:
            domains = tuple(sorted(group.get('domains', [])))
            dst = group.get('dst_ip')
            for proto, rate in group.get('protocols', {}).items():
                if proto in PROTOCOLS:
                    yield ts, domains, dst, proto, rate['trigger_pps']


def iter_dist_pps_groups(records):
    """records: a run's own LAB_AUDIT kind=cycle records. Yields (ts,
    domains_tuple, dst_ip, dist_pps_all_protocols) for every correlation
    group of every cycle that has observed_rates AND the
    dist_pps_all_protocols field (THRESHOLD_CALIBRATION_V2 Paso 3 --
    orchestrator-ddos-pucp's detection/engine.py::observed_benign_rates()
    instrumentation; older captures predate it and are silently skipped,
    same policy as iter_cycle_groups for missing observed_rates)."""
    for rec in records:
        if rec.get('kind') != 'cycle' or not rec.get('observed_rates'):
            continue
        ts = rec['timestamp']
        for group in rec['observed_rates']:
            if 'dist_pps_all_protocols' not in group:
                continue
            domains = tuple(sorted(group.get('domains', [])))
            dst = group.get('dst_ip')
            yield ts, domains, dst, group['dist_pps_all_protocols']


def propose_dist_pps_threshold(groups, q=0.999, margin=1.5):
    """groups: iterable of (ts, domains, dst, dist_pps_all_protocols), e.g.
    itertools.chain(*(iter_dist_pps_groups(r) for r in training_runs)).
    Same quantile*margin recipe as propose_thresholds(), for
    DIST_PPS_THRESHOLD -- the protocol-agnostic aggregate
    _classify_distributed() compares against (see that function and
    observed_benign_rates()'s own docstrings in orchestrator-ddos-pucp).
    Returns None if there are zero samples, never a fabricated value."""
    values = [rate for _, _, _, rate in groups]
    if not values:
        return None
    qv = quantile(values, q)
    return dict(n=len(values), quantile=qv, quantile_q=q, margin=margin,
                proposed_threshold=round(qv * margin, 3))


def propose_thresholds(groups, q=0.999, margin=1.5):
    """groups: iterable of (ts, domains, dst, protocol, trigger_pps),
    e.g. itertools.chain(*(iter_cycle_groups(r) for r in training_runs)).
    Returns {protocol: {n, quantile, proposed_threshold}} -- a protocol
    with zero samples is omitted, never given a fabricated value."""
    samples = {p: [] for p in PROTOCOLS}
    for _, _, _, proto, rate in groups:
        if proto in samples:
            samples[proto].append(rate)
    out = {}
    for proto, values in samples.items():
        if not values:
            continue
        qv = quantile(values, q)
        out[proto] = dict(n=len(values), quantile=qv, quantile_q=q, margin=margin,
                           proposed_threshold=round(qv * margin, 3))
    return out


def replay_activation(groups, thresholds, activation_params):
    """groups: iterable of (ts, domains, dst, protocol, trigger_pps),
    ALREADY SORTED by ts (caller's responsibility -- cycles within one
    run are recorded in order; merge carefully if replaying several
    runs' cycles together, which this module never does on its own).

    activation_params: {telemetry_domain_or_'mobile_syn': (min_hits,
    window_s)} -- read from the run's own recorded thresholds snapshot,
    see activation_params_from_snapshot() below.

    Mirrors _activation_domain()/_activated(): hysteresis applies only
    when `domains` is a singleton present in activation_params (mobile's
    SYN gets its own 'mobile_syn' key instead of 'mobile' -- mobile's
    UDP/ICMP never applies here since those protocols already exclude
    mobile from trigger_pps upstream, in Paso 1's own observed_rates).
    A multi-domain group (len(domains) > 1) is reported immediately,
    exactly like a real MULTIDOMAIN_DISTRIBUTED_ATTACK detection.

    Returns a list of (ts, domains, dst, protocol) accepted detections,
    one per cycle a hit was reported (not deduplicated across cycles --
    a sustained flood is expected to report every cycle it's active,
    same as the real engine already does).
    """
    threshold_for = {p: thresholds[p]['proposed_threshold'] for p in thresholds}
    hits = {}  # key -> list of timestamps (for MIN_HITS/WINDOW_S)
    first_hit_at = {}
    accepted = []
    for ts, domains, dst, proto, rate in groups:
        threshold = threshold_for.get(proto)
        if threshold is None or rate <= threshold:
            continue
        activation_key = None
        if len(domains) == 1:
            dom = domains[0]
            if dom == 'mobile' and proto == 'TCP_SYN':
                activation_key = 'mobile_syn'
            elif dom in activation_params:
                activation_key = dom
        if activation_key is None:
            accepted.append((ts, domains, dst, proto))
            continue
        min_hits, window_s = activation_params[activation_key]
        if min_hits <= 1:
            accepted.append((ts, domains, dst, proto))
            continue
        key = (activation_key, dst, proto)
        series = hits.setdefault(key, [])
        first_hit_at.setdefault(key, ts)
        series.append(ts)
        cutoff = ts - window_s
        series[:] = [t for t in series if t >= cutoff]
        if len(series) >= min_hits:
            accepted.append((ts, domains, dst, proto))
    return accepted


def replay_dist_pps_backup(groups, dist_pps_threshold):
    """groups: iterable of (ts, domains, dst, dist_pps_all_protocols), e.g.
    from iter_dist_pps_groups(). Replays ONLY the pps gate of
    _classify_distributed()'s backup criterion (DIST_PPS_THRESHOLD):
    `total_pps < pps_threshold: return None`, i.e. the opposite --
    accepts a cycle when total_pps >= dist_pps_threshold.

    DECLARED SIMPLIFICATION (Paso 4): the real engine also gates on
    DIST_MIN_SOURCES (distinct source IPs) and DIST_ENTROPY_THRESHOLD
    (Shannon entropy of their pps distribution) -- neither is replayable
    from observed_rates/dist_pps_all_protocols, which only carries the
    group's AGGREGATE pps, not its per-source breakdown. This replay is
    therefore an upper bound on how often the real backup criterion could
    fire (the pps gate is necessary but not sufficient for a real engine
    detection) -- useful to confirm the pps gate alone no longer blocks
    benign traffic routinely (see the DIST_PPS_THRESHOLD=300 bug this
    recalibration fixes), not a byte-exact replay of the full criterion.

    Returns a list of (ts, domains, dst, 'DIST_PPS') accepted entries, in
    the same 4-tuple shape fpr_from_replay() expects."""
    return [(ts, domains, dst, 'DIST_PPS') for ts, domains, dst, rate in groups if rate >= dist_pps_threshold]


def activation_params_from_snapshot(thresholds_values):
    """thresholds_values: the `values` dict of any cycle's own recorded
    `thresholds` snapshot (same for every cycle of one run -- policy
    doesn't change mid-run). Returns the activation_params replay_
    activation() needs, reading the exact settings that run actually
    used instead of hardcoding them."""
    out = {}
    for dom, (min_name, window_name) in ACTIVATION_SETTING_NAMES.items():
        if min_name in thresholds_values and window_name in thresholds_values:
            out[dom] = (thresholds_values[min_name], thresholds_values[window_name])
    min_name, window_name = MOBILE_SYN_SETTING_NAMES
    if min_name in thresholds_values and window_name in thresholds_values:
        out['mobile_syn'] = (thresholds_values[min_name], thresholds_values[window_name])
    return out


def fpr_from_replay(plan, run, accepted_detections, domains=('enterprise', 'fixed', 'peering', 'mobile')):
    """Replay-based FPR, benign windows only (this function is only ever
    called on B0 runs -- validated by the caller). `accepted_detections`
    is replay_activation()'s output for this ONE run.

    SIMPLIFICATION, stated explicitly: eligibility is ground_truth.
    windows()'s own 'evaluation' flag (window complete, past warmup) --
    not the full per-domain LAB_AUDIT telemetry-coverage check
    detection_evaluation.evaluate() does. Same documented scope boundary
    as response_metrics.py's compute_availability().
    """
    start = run.get('started_at')
    truth = ground_truth_windows(plan, run)
    by_domain_window_hit = {d: {} for d in domains}
    for ts, raw_domains, dst, proto in accepted_detections:
        if start is None:
            continue
        elapsed = ts - start
        window = int(elapsed // 5)
        affected = {ALIAS.get(d, d) for d in raw_domains} if raw_domains else set()
        for d in affected:
            if d in by_domain_window_hit:
                by_domain_window_hit[d][window] = True
    result = {d: dict(eligible=0, fp=0) for d in domains}
    for w in truth:
        if not w['evaluation'] or w['label'] != 'BENIGN':
            continue
        for d in domains:
            result[d]['eligible'] += 1
            if by_domain_window_hit[d].get(w['window']):
                result[d]['fp'] += 1
    for d in domains:
        e = result[d]['eligible']
        result[d]['fpr'] = result[d]['fp'] / e if e else None
    total_eligible = sum(result[d]['eligible'] for d in domains)
    total_fp = sum(result[d]['fp'] for d in domains)
    result['_global'] = dict(eligible=total_eligible, fp=total_fp,
                              fpr=total_fp / total_eligible if total_eligible else None)
    return result
