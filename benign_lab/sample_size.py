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


# Standard normal quantile for power=0.80 (one-sided upper tail of a power
# curve), z such that Phi(z)=0.80. No scipy in this environment -- hardcoded
# the same way Z975 already is, not computed.
Z_POWER_80 = 0.8416212335729143
# z_{0.95}: the ONE-sided 95% critical value, for the non-inferiority margin
# test below (alpha is not split across two tails there).
Z95_ONE_SIDED = 1.6448536269514722


def _phi(z):
    """Standard normal CDF, via math.erf (no scipy available here)."""
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))


def _required_seeds_power_normal_approx(sd, effect, z_alpha, power, minimum, maximum):
    """Smallest n with normal-approximate power >= `power` for a one-sample
    (paired-difference) t-test with critical value z_alpha and a true mean
    difference of `effect`.

    DOCUMENTED APPROXIMATION (brief explicitly allows "aproximacion
    documentada" in place of an exact noncentral-t calculation, which
    would need scipy -- not installed in this environment): power is
    computed as Phi(effect*sqrt(n)/sd - z_alpha), the standard normal
    approximation to the noncentral t distribution's power. This slightly
    OVERSTATES power (equivalently, slightly UNDERSTATES the required n)
    versus the exact noncentral-t calculation, because it ignores the
    extra spread from estimating sd with few degrees of freedom -- the gap
    shrinks as n grows and is typically small already by n=8-10. Flagged
    here and in every caller's docstring; not silently passed off as exact.
    """
    if sd is None or effect is None or sd <= 0 or effect <= 0:
        return None
    z_power = _inverse_phi_power(power)
    n = max(minimum, math.ceil(((z_alpha + z_power) * sd / effect) ** 2))
    while n <= maximum:
        if _phi(effect * math.sqrt(n) / sd - z_alpha) >= power:
            return n
        n += 1
    raise ValueError(f'Power {power} for effect {effect} (sd={sd}) needs more than {maximum} seeds')


def _inverse_phi_power(power):
    if abs(power - 0.80) < 1e-9:
        return Z_POWER_80
    raise ValueError('Only power=0.80 is supported (no scipy available to invert Phi for another value)')


def required_seeds_power(sd, effect, power=0.80, alpha=0.05, minimum=2, maximum=1000):
    """D7-pilot: seeds needed for a two-sided paired t-test (alpha=0.05)
    to detect a true mean paired difference of `effect` (same unit as sd,
    e.g. percentage points of availability_pct) with the given power.
    Normal approximation -- see _required_seeds_power_normal_approx's
    docstring. Only alpha=0.05 (Z975) and power=0.80 are supported, the
    exact values the pilot brief asks for."""
    if alpha != 0.05:
        raise ValueError('Only alpha=0.05 is supported (Z975 is hardcoded, same as required_seeds())')
    return _required_seeds_power_normal_approx(sd, effect, Z975, power, minimum, maximum)


def required_seeds_noninferiority(sd, margin, power=0.80, alpha=0.05, minimum=2, maximum=1000):
    """Seeds needed for a ONE-sided non-inferiority paired test (HE2: M is
    not worse than I by more than `margin`) to reach `power` when the true
    paired difference is exactly `margin` (the standard power-analysis
    convention for a non-inferiority margin: power to detect the boundary
    case, not an arbitrarily larger true effect). One-sided alpha (Z95_ONE_SIDED)
    instead of the two-sided Z975 used by required_seeds_power() -- the
    hypothesis only cares about crossing the margin in one direction.
    Same normal-approximation caveat as required_seeds_power()."""
    if alpha != 0.05:
        raise ValueError('Only alpha=0.05 is supported (Z95_ONE_SIDED is hardcoded)')
    return _required_seeds_power_normal_approx(sd, margin, Z95_ONE_SIDED, power, minimum, maximum)


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
