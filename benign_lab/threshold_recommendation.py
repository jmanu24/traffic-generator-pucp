"""Suggest controller thresholds from measured baseline traffic (Fase 4, #5).

Pure function: no SSH, no live controller state. Takes per-domain baseline
packet-rate statistics (from calibration / false-positive runs, see
docs/FALSE_POSITIVES_CALIBRATION.md) and proposes values for the existing
fields in threshold_control.FIELDS. An operator reviews the recommendation
and applies it with the already-validated ThresholdControl.apply(); this
module never touches the live controller, so it carries none of that path's
risk.

Limitation, stated plainly: SYN_THRESHOLD/UDP_THRESHOLD/ICMP_THRESHOLD/
DECISION_THRESHOLD are global scalars in the deployed controller
(isp-ddos-ryu), not one value per domain — giving every domain its own
threshold needs a controller-side change outside this repository. What this
tool can do today is size those shared thresholds from the combined
calibration evidence, and size DIST_PPS_THRESHOLD (the field that already
exists to catch a distributed attack where no single domain crosses its own
threshold) from the aggregate baseline across domains — the multidomain half
of requirement #5 that this repository can actually deliver.
"""
from .threshold_control import FIELDS

PROTOCOLS = ('syn', 'udp', 'icmp')


def recommend_thresholds(baseline_pps_by_domain, margin=1.5, dist_margin=2.0):
    """baseline_pps_by_domain: {domain: {'syn_pps':.., 'udp_pps':.., 'icmp_pps':..}},
    one or more keys per domain (whichever protocols were measured).

    margin multiplies the worst observed per-domain peak for each shared
    scalar threshold. dist_margin multiplies the baseline summed across every
    domain for DIST_PPS_THRESHOLD. Both must exceed 1: a threshold at or
    below the observed baseline would misfire on legitimate traffic.
    """
    if not baseline_pps_by_domain:
        raise ValueError('At least one domain baseline is required')
    if margin <= 1 or dist_margin <= 1:
        raise ValueError('Margins must be greater than 1 (above the observed baseline)')
    peaks = {proto: [] for proto in PROTOCOLS}
    totals = {proto: 0.0 for proto in PROTOCOLS}
    for domain, stats in baseline_pps_by_domain.items():
        for proto in PROTOCOLS:
            value = stats.get(proto + '_pps')
            if value is not None:
                if value < 0:
                    raise ValueError(f'{domain}.{proto}_pps must be non-negative')
                peaks[proto].append(value)
                totals[proto] += value
    recommended = {}
    field_by_proto = dict(syn='SYN_THRESHOLD', udp='UDP_THRESHOLD', icmp='ICMP_THRESHOLD')
    for proto, field in field_by_proto.items():
        if peaks[proto]:
            recommended[field] = round(max(peaks[proto]) * margin, 1)
    combined_total = sum(totals.values())
    if combined_total > 0:
        recommended['DIST_PPS_THRESHOLD'] = round(combined_total * dist_margin, 1)
    unsupported = set(recommended) - FIELDS
    if unsupported:
        raise AssertionError(f'Internal mismatch with controller fields: {unsupported}')
    return dict(recommended=recommended,
                basis=dict(peaks_by_protocol=peaks, totals_by_protocol=totals,
                           margin=margin, dist_margin=dist_margin,
                           domains=sorted(baseline_pps_by_domain)),
                note=('SYN/UDP/ICMP/DECISION thresholds are global scalars in the deployed '
                      'controller; per-domain thresholds need a controller-side change outside '
                      'this repository. DIST_PPS_THRESHOLD already covers the multidomain-'
                      'distributed case and is sized here from the combined baseline.'))
