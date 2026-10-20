"""Pure, independent reimplementation of the real controller's decision
scoring formula (detection/engine.py::_build_result + decision/engine.py's
weights), used ONLY to predict the expected effective score of a planned
attack composition before running it -- never imported by, and never
driving, anything on the real lab. Mirrors threshold_replay.py's own
stance: an independently re-derived check, not the production code path,
so a bug here can never silently change detection/decision behavior.

Formula (read from the real controller source on 2026-10-20, for the
ATTACK_PLAN_REGENERATION design task):
  - single-source group: score = total_pps / threshold
                          confidence = min(score / 10.0, 1.0)
                          attack_type = f'{VECTOR}_FLOOD', weight from WEIGHTS
  - distributed group (distinct_sources >= DIST_MIN_SOURCES and
    normalized Shannon entropy >= DIST_ENTROPY_THRESHOLD):
                          confidence = min(entropy * (MULTIDOMAIN_BOOST if
                                      sources span >1 domain else 1.0), 1.0)
                          score = total_pps / threshold (same as above)
                          attack_type = MULTIDOMAIN_DISTRIBUTED_ATTACK (>1
                                      domain) or DDOS_DISTRIBUTED (1 domain),
                                      weight from WEIGHTS
  - final_score = score * confidence * weight; decision fires iff
    final_score >= DECISION_THRESHOLD.

Isolated (I) mode evaluates each domain's own sources as a separate group
(the correlator buckets by (domain, dst) instead of just dst); multidomain
(M) mode merges every domain's sources headed to the same dst into one
group. That's the only difference this estimator models between I and M --
it is not a reimplementation of the correlator itself, just of what each
mode hands to the scoring formula once its own grouping is applied.
"""
from __future__ import annotations
import math

DIST_MIN_SOURCES = 5
DIST_ENTROPY_THRESHOLD = 0.7
MULTIDOMAIN_BOOST = 1.3
DECISION_THRESHOLD = 1.5
WEIGHTS = {
    'SYN_FLOOD': 1.0,
    'UDP_FLOOD': 0.9,
    'ICMP_FLOOD': 0.8,
    'DDOS_DISTRIBUTED': 1.3,
    'MULTIDOMAIN_DISTRIBUTED_ATTACK': 1.4,
}
VECTOR_FLOOD_TYPE = {'syn_flood': 'SYN_FLOOD', 'udp_flood': 'UDP_FLOOD', 'icmp_flood': 'ICMP_FLOOD'}


def normalized_entropy(pps_by_source):
    """Shannon entropy of the per-source pps distribution, normalized to
    [0, 1] by log2(n). A single source has entropy 0 (not 1 -- there is
    nothing to be uncertain about)."""
    values = [v for v in pps_by_source if v > 0]
    n = len(values)
    if n <= 1:
        return 0.0
    total = sum(values)
    h = -sum((v / total) * math.log2(v / total) for v in values)
    return h / math.log2(n)


def estimate_group_score(pps_by_source, domains, threshold, vector):
    """pps_by_source: list of per-source pps for one scoring group (one
    domain in isolated mode, or every domain merged in multidomain mode).
    domains: the set of domains contributing sources to this group.
    Returns dict(score, confidence, weight, attack_type, final_score,
    decides) or None if the group never reaches the protocol threshold at
    all (the real engine's _classify() would not even build a result)."""
    total_pps = sum(pps_by_source)
    distinct_sources = len(pps_by_source)
    entropy = normalized_entropy(pps_by_source)
    is_distributed = distinct_sources >= DIST_MIN_SOURCES and entropy >= DIST_ENTROPY_THRESHOLD
    if is_distributed:
        multidomain = len(set(domains)) > 1
        attack_type = 'MULTIDOMAIN_DISTRIBUTED_ATTACK' if multidomain else 'DDOS_DISTRIBUTED'
        confidence = min(entropy * (MULTIDOMAIN_BOOST if multidomain else 1.0), 1.0)
    else:
        if total_pps < threshold:
            return None  # below threshold, single-attacker path never fires either
        attack_type = VECTOR_FLOOD_TYPE[vector]
        confidence = min((total_pps / threshold) / 10.0, 1.0)
    score = total_pps / threshold
    weight = WEIGHTS[attack_type]
    final_score = score * confidence * weight
    return dict(score=score, confidence=confidence, weight=weight, attack_type=attack_type,
                 entropy=entropy, distinct_sources=distinct_sources, total_pps=total_pps,
                 final_score=final_score, decides=final_score >= DECISION_THRESHOLD)


def estimate_isolated_and_multidomain(per_domain_sources, threshold, vector):
    """per_domain_sources: dict(domain -> list of per-source pps). Returns
    dict(isolated=dict(domain -> result_or_None), multidomain=result_or_None)."""
    isolated = {domain: estimate_group_score(sources, [domain], threshold, vector)
                for domain, sources in per_domain_sources.items()}
    all_sources, all_domains = [], []
    for domain, sources in per_domain_sources.items():
        all_sources += sources
        all_domains += [domain] * len(sources)
    multidomain = estimate_group_score(all_sources, all_domains, threshold, vector)
    return dict(isolated=isolated, multidomain=multidomain)
