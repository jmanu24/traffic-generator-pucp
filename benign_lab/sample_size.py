"""Seed count required for statistical rigor, derived from measured variability.

Reuses the same Student-t, 95% CI framework as experimental_analytics.py
(T975) instead of inventing a second statistical convention. Two uses:

- Prospective (Fase 2 of the instrumentation plan): feed it the variability
  observed during capacity calibration (Fase 1: throughput/delay/jitter/loss
  across repeated probes) and a target precision per metric, to decide how
  many seeds the planned statistical series needs *before* running it.
- Retrospective: experimental_analytics.seed_statistics already does the
  same calculation (additional_seeds_precision_approx) after some runs exist,
  using a normal approximation. required_seeds() here is exact (t-based,
  iterative) and is the function that one should eventually call too.
"""
import math
from .experimental_analytics import T975

Z975 = 1.959963984540054  # two-sided 95% normal critical value


def _t975(df):
    return T975[min(df, 30) - 1]


def required_seeds(sd, precision, minimum=2, maximum=1000):
    """Smallest n with t_{0.975,n-1} * sd / sqrt(n) <= precision.

    precision is the target 95% CI half-width, same unit as sd. Returns None
    when sd<=0 (no observed variability: a sample size cannot be derived from
    it) or precision<=0 (undefined target).
    """
    if sd is None or precision is None or sd <= 0 or precision <= 0:
        return None
    n = max(minimum, math.ceil((Z975 * sd / precision) ** 2))  # normal approx as a starting point
    while n <= maximum:
        if _t975(n - 1) * sd / math.sqrt(n) <= precision:
            return n
        n += 1
    raise ValueError(f'Target precision {precision} needs more than {maximum} seeds (sd={sd})')


def required_seeds_relative(sd, mean, relative_precision, **kwargs):
    """precision expressed as a fraction of the mean, e.g. 0.05 for +-5%."""
    if not mean:
        raise ValueError('Relative precision requires a non-zero mean')
    return required_seeds(sd, abs(mean) * relative_precision, **kwargs)


def plan_sample_size(calibration, precision_by_metric, method='95% CI, Student t, independent seeds'):
    """calibration: {metric: {'mean':.., 'sd':..}} from Fase 1 capacity
    calibration (per domain/metric: throughput_mbps, delay_ms, jitter_ms,
    loss_pct, ...). precision_by_metric: {metric: absolute_precision}.

    Returns the seed count required by the single most demanding metric
    (the statistical series must satisfy every metric's target at once), plus
    the per-metric breakdown so the limiting metric is visible.
    """
    per_metric = {}
    for metric, target in precision_by_metric.items():
        stats = calibration.get(metric)
        if not stats:
            per_metric[metric] = dict(n=None, reason='no_calibration_sample_for_metric')
            continue
        per_metric[metric] = dict(n=required_seeds(stats.get('sd'), target),
                                   sd=stats.get('sd'), mean=stats.get('mean'), precision=target)
    known = [v['n'] for v in per_metric.values() if v.get('n')]
    overall = max(known) if known else None
    limiting = sorted(m for m, v in per_metric.items() if v.get('n') == overall) if overall else []
    return dict(per_metric=per_metric, required_seeds=overall, limiting_metrics=limiting, method=method)
