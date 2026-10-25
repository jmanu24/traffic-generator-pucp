"""D6: response-time and availability indicators for one attack execution.

Pure computation over already-captured evidence (LAB_AUDIT records, the
attack_runner report, an independently-measured attacker rate series, and
optional per-domain mitigation-installation evidence) -- this module does
not collect anything itself and never touches the lab or the controller.

Definitions (seconds, Unix epoch unless noted):
  tA  -- real attack start (attack_runner's own evidence: the earliest
         actual_start_s among events that actually sent traffic, i.e. the
         SAME window runner.record_attack_evidence() already marks as the
         ATTACK ground truth -- never the planned schedule).
  tF  -- real attack end, same evidence, latest actual_end_s.
  tD  -- first LAB_AUDIT kind=detection record whose src_ip/sources include
         a declared attacker IP (run['attack_source_ips']).
  tD0 -- tD minus that detection's own activation_delay_s: the instant the
         detector FIRST classified the attack, before the activation
         hysteresis (ENTERPRISE_ACTIVATION_*, etc.) held it back. 0 for a
         detection exempt from that hysteresis (core/models.py's own
         DetectionResult.activation_delay_s docstring).
  tO  -- first kind=mitigation_issued record affecting an attacker IP
         (backend dispatch returned true; not a dataplane confirmation).
  tI  -- confirmed dataplane installation, from caller-supplied per-domain
         evidence (installation_evidence); None with reason
         'not_observable' when the domain exposes no such confirmation.
  tE  -- first instant after tO where the attacker's rate, from an
         INDEPENDENT counter (rate_series -- deliberately not derived from
         the detector's own pps), falls to <= (1-R/100) of its mean level
         over [tA, tO] and stays there for S consecutive seconds.
  Service window (5 s): PASS iff delivered benign quota >= D% of planned
         AND p95 latency of events completing in that window <= L ms.
  A   -- 100 x (PASS windows) / (windows with valid domain-telemetry
         coverage), over windows in [tA, tF].
  tS  -- start of the first run of K consecutive PASS windows after tF.
  TR  -- max(0, tS - tF).
  TD = tD-tA, TO = tO-tD, TI = tI-tO (None if tI is None), TM = tE-tD.

Every one of tD, tO, tI, tE that never occurs is reported censored, with
the duration actually observed while waiting for it -- the execution is
never dropped for this (per the brief: conservar ejecuciones fallidas,
nunca borrar evidencia).
"""
import collections
import math
from .ground_truth import windows as ground_truth_windows, overlap
from .detection_evaluation import affected
from .experimental_analytics import finite, percentile, seed_statistics

DEFAULTS = dict(R=80, S=5, D=90, L=150, K=3)
# L=150ms is a PROVISIONAL default, not a measured or confirmed one: the
# brief left it as "L («ms»)" with no number. mobile's own measured RTT is
# ~100-110ms (docs/THESIS_VALIDATION_EXECUTION_PLAN.md Etapa A), so
# anything below that would make mobile fail on latency alone outside any
# attack. 150ms clears that with headroom but is a guess pending
# confirmation, same status as the tE measurement point itself.


def _first(records, predicate):
    for rec in sorted(records, key=lambda x: x.get('timestamp', math.inf)):
        if predicate(rec):
            return rec
    return None


def _censored(value, observed_duration_s, reason=None):
    return dict(value=value, censored=value is None, observed_duration_s=observed_duration_s, reason=reason)


def _attack_window(run):
    """tA/tF from attack_runner's own evidence -- the same entries
    runner.record_attack_evidence() appends, never the planned schedule.
    Returns (relative_tA, relative_tF, absolute_tA, absolute_tF):
    observed_attacks' start_s/end_s are plan-relative seconds (same
    convention as ground_truth.windows()), while LAB_AUDIT records carry
    absolute Unix-epoch timestamps -- both are needed, so both are
    returned rather than silently picking one convention."""
    confirmed = [a for a in run.get('observed_attacks', []) if a.get('annotation_source') == 'attack_runner' and finite(a.get('start_s')) and finite(a.get('end_s'))]
    if not confirmed:
        return None, None, None, None
    rel_a, rel_f = min(a['start_s'] for a in confirmed), max(a['end_s'] for a in confirmed)
    started_at = run.get('started_at')
    abs_a = started_at + rel_a if finite(started_at) else None
    abs_f = started_at + rel_f if finite(started_at) else None
    return rel_a, rel_f, abs_a, abs_f


def compute(plan, run, records, event_states=None, rate_series=None, installation_evidence=None, config=None):
    """One execution's full set of D6 indicators. `rate_series` is
    {domain: [(timestamp, pps), ...]} from an independent counter (see
    docs/RESPONSE_METRICS_DESIGN.md for the proposed, pending-confirmation
    measurement point per domain) -- never required to be present; tE is
    reported censored with reason 'no_independent_rate_series' otherwise.
    `installation_evidence` is {domain: timestamp or None} -- None/absent
    means tI is reported censored with reason 'not_observable'."""
    cfg = dict(DEFAULTS, **(config or {}))
    sources = set(run.get('attack_source_ips', []))
    tA_rel, tF_rel, tA, tF = _attack_window(run)
    run_end = run.get('started_at', 0) + run.get('elapsed_s', 0) if finite(run.get('started_at')) and finite(run.get('elapsed_s')) else None

    detection = _first(records, lambda r: r.get('kind') == 'detection' and r.get('timestamp', -math.inf) >= (tA or -math.inf) and any(ip in sources for _, ip in affected(r.get('detection', {})))) if sources else None
    tD = detection['timestamp'] if detection else None
    activation_delay = (detection.get('detection', {}) or {}).get('activation_delay_s', 0) if detection else None
    tD0 = tD - activation_delay if finite(tD) and finite(activation_delay) else None

    mitigation = _first(records, lambda r: r.get('kind') == 'mitigation_issued' and r.get('timestamp', -math.inf) >= (tD if finite(tD) else (tA or -math.inf)) and any(ip in sources for _, ip in affected(r.get('action', {})))) if sources else None
    tO = mitigation['timestamp'] if mitigation else None
    mitigated_domain = mitigation.get('action', {}).get('domain') if mitigation else None

    tI = None
    tI_reason = 'not_observable'
    if installation_evidence and mitigated_domain and mitigated_domain in installation_evidence:
        tI = installation_evidence[mitigated_domain]
        tI_reason = None if finite(tI) else 'not_observable'

    tE = None
    tE_reason = 'no_independent_rate_series'
    if finite(tO) and rate_series and mitigated_domain in (rate_series or {}):
        series = sorted(rate_series[mitigated_domain])
        baseline = [p for t, p in series if finite(tA) and tA <= t <= tO]
        if baseline:
            threshold = (1 - cfg['R'] / 100) * (sum(baseline) / len(baseline))
            below_since = None
            crossed_at_least_once = False
            for t, p in series:
                if t < tO:
                    continue
                if p <= threshold:
                    crossed_at_least_once = True
                    if below_since is None:
                        below_since = t
                    elif t - below_since >= cfg['S']:
                        tE = below_since
                        tE_reason = None
                        break
                else:
                    below_since = None
            if tE is None:
                tE_reason = 'threshold_crossed_but_not_sustained_for_S' if crossed_at_least_once else 'rate_never_dropped_below_threshold'
        else:
            tE_reason = 'no_samples_in_tA_tO_baseline_window'

    def duration_waited(from_t, found):
        if found is not None:
            return 0.0
        if not finite(from_t):
            return None
        end = run_end if run_end is not None else from_t
        return max(0.0, end - from_t)

    result = dict(
        schema=1,
        attack_source_ips=sorted(sources),
        tA=tA, tF=tF,
        tD=_censored(tD, duration_waited(tA, tD), None if tD is not None else ('no_attack_window' if tA is None else 'no_matching_detection')),
        tD0=tD0,
        tO=_censored(tO, duration_waited(tD if finite(tD) else tA, tO), None if tO is not None else 'no_matching_mitigation'),
        tI=_censored(tI, duration_waited(tO, tI), tI_reason),
        tE=_censored(tE, duration_waited(tO, tE), tE_reason),
        TD=(tD - tA) if finite(tD) and finite(tA) else None,
        TO=(tO - tD) if finite(tO) and finite(tD) else None,
        TI=(tI - tO) if finite(tI) and finite(tO) else None,
        TM=(tE - tD) if finite(tE) and finite(tD) else None,
        mitigated_domain=mitigated_domain,
        config=cfg,
    )
    availability = compute_availability(plan, run, tA_rel, tF_rel, event_states or [], cfg)
    result.update(availability)
    return result


def compute_availability(plan, run, tA, tF, event_states, cfg):
    """A, plus tS/TR: the first K-consecutive-PASS run after tF. Reuses
    ground_truth.windows()'s own 5s grid so window boundaries always match
    what the rest of this codebase already treats as THE window."""
    es = event_states
    truth = ground_truth_windows(plan, run)
    eligible_windows = []
    pass_by_window = {}
    for w in truth:
        a, b = w['start_s'], w['end_s']
        in_attack = finite(tA) and finite(tF) and overlap(a, b, tA, tF) > 0
        planned = sum(e.get('planned_bytes', 0) * overlap(a, b, e['start_s'], e['start_s'] + e['duration_s']) / e['duration_s'] for e in plan.get('events', []) if e.get('duration_s', 0) > 0)
        actual = sum((e.get('bytes_tx', 0) + e.get('bytes_rx', 0)) * overlap(a, b, e['start_s'], e['start_s'] + e['duration_s']) / e['duration_s'] for e in es if e.get('duration_s', 0) > 0)
        delivered_pct = 100 * actual / planned if planned else None
        lateness = [e['lateness_s'] * 1000 for e in es if finite(e.get('lateness_s')) and a <= e.get('actual_end_s', e.get('start_s', -1)) < b]
        p95 = percentile(lateness, .95)
        # SIMPLIFICATION, stated explicitly: "valid coverage" here is the
        # window being complete and past warmup (ground_truth.windows()'s
        # own 'evaluation' flag) -- NOT the full per-domain LAB_AUDIT
        # telemetry-coverage check detection_evaluation.evaluate() does
        # (observed_sources intersecting known IPs in an active cycle).
        # Wiring that in would need this function to also resolve IPs per
        # domain from lab topology, which it does not have here. Flagged
        # in docs/RESPONSE_METRICS_DESIGN.md as a known scope boundary.
        covered = w['evaluation']
        passed = covered and delivered_pct is not None and delivered_pct >= cfg['D'] and (p95 is None or p95 <= cfg['L'])
        # PILOT2_RESULT.md (D7-pilot, resolved 2026-10-24): a run with NO
        # attack window at all (tA/tF both None -- C1, benign-only) has
        # no [tA,tF] to restrict eligible_windows to, which made A
        # formally undefined for it (eligible_windows always empty,
        # availability_pct=None) -- the impact criterion ("A(C2) <=
        # A(C1) - 20pp") could never be computed for ANY benign-only
        # reference condition. For that case, and only that case, every
        # covered window counts as eligible -- A then measures the same
        # thing it always does (fraction of covered windows meeting the
        # D/L SLA jointly), just over the whole run instead of over
        # [tA,tF], because there is no narrower period of interest to
        # restrict to. A run that DOES have an attack window keeps the
        # exact prior behavior (in_attack decides) -- no_attack_window
        # is only ever true when tA is None in the first place.
        no_attack_window = not finite(tA)
        if (in_attack or no_attack_window) and covered:
            eligible_windows.append(w['window'])
            pass_by_window[w['window']] = passed
        elif covered:
            pass_by_window[w['window']] = passed
    availability = 100 * sum(pass_by_window[w] for w in eligible_windows) / len(eligible_windows) if eligible_windows else None
    tS = None
    if finite(tF):
        ordered = sorted(w for w in pass_by_window if w * 5 >= tF)
        streak = 0
        for w in ordered:
            if pass_by_window[w]:
                streak += 1
                if streak >= cfg['K']:
                    tS = (w - cfg['K'] + 1) * 5
                    break
            else:
                streak = 0
    TR = max(0, tS - tF) if finite(tS) and finite(tF) else None
    return dict(availability_pct=availability, eligible_window_count=len(eligible_windows), tS=tS, TR=TR)


def coverage(results):
    """Cross-run proportions: detected / mitigated effective / recovered."""
    n = len(results)
    if n == 0:
        return dict(n=0, detected=None, mitigated=None, recovered=None)
    return dict(
        n=n,
        detected=sum(r['tD']['value'] is not None for r in results) / n,
        mitigated=sum(r['tO']['value'] is not None for r in results) / n,
        recovered=sum(r['TR'] is not None for r in results) / n,
    )


def restricted(value, censored, restriction_s):
    """Restricted-mean substitute for a censored time: cap it at the
    restriction duration (e.g. the attack's own duration) instead of
    treating it as missing. Documented, simple engineering choice -- not
    a Kaplan-Meier estimator."""
    if not censored:
        return value
    if value is None:
        return restriction_s
    return min(value, restriction_s)


def summarize(entries, metric, precision=1):
    """Paired M-I difference by block (seed x scenario), same machinery as
    experimental_analytics.seed_statistics -- entries is
    [{'seed':..., 'condition':'I'|'M', 'value':..., 'censored':bool,
      'restriction_s':...}, ...] for ONE metric (e.g. 'TM')."""
    by_condition = collections.defaultdict(dict)
    for e in entries:
        by_condition[e['condition']][(e['seed'], e.get('block'))] = restricted(e['value'], e.get('censored', False), e.get('restriction_s'))
    summaries = {c: seed_statistics([(k[0], v) for k, v in rows.items()], precision) for c, rows in by_condition.items()}
    pairs = []
    if 'I' in by_condition and 'M' in by_condition:
        shared = set(by_condition['I']) & set(by_condition['M'])
        for key in sorted(shared):
            i, m = by_condition['I'][key], by_condition['M'][key]
            if finite(i) and finite(m):
                pairs.append((key[0], m - i))
    diff = seed_statistics(pairs, precision) if pairs else None
    return dict(metric=metric, by_condition=summaries, mi_difference=diff, restriction_note='Censored observations are restricted-mean substituted (capped at restriction_s), not dropped.')
