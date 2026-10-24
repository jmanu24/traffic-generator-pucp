"""ATTACK_PLAN_V2: regenerate the attack plans with the recalibrated
thresholds (docs/THRESHOLD_CALIBRATION_RESULT_V2.md) and corrected
compositions 2 and 3. OFFLINE ONLY -- never touches the real lab. Builds
ATTACK_FLOOD_V1 plans via attack_planner.generate_attack_plan(), predicts
each plan's expected effective decision score in I and M via
benign_lab.decision_score_estimator (independent reimplementation, never
the production code path), and saves everything under
data/attack_plans/ (new files, alongside -- never overwriting -- the V1
ones) + data/attack_plans_manifest_v2.json (the V1 manifest is kept as
data/attack_plans_manifest.json, untouched).

Thresholds (THRESHOLD_CALIBRATION_RESULT_V2.md, applied 2026-10-22):
  SYN_THRESHOLD = 85.238, DECISION_THRESHOLD = 1.5 (unchanged).

D4-A (already decided, same as V1): every composition uses SYN as its
vector, including mobile -- the only vector where mobile's own pps is
comparable to, and combinable with, the other domains' in the scoring
formula (UDP/ICMP exclude mobile by design).

Corrections to V1 (this prompt's own OBJETIVO):
- Composition 2: V1 only used 3 total sources (1 per domain) -- never
  reached DIST_MIN_SOURCES=5, so M's own entropy/source-count gate for
  MULTIDOMAIN_DISTRIBUTED_ATTACK never applied; M only decided via the
  single-attacker SYN_FLOOD path on the over-threshold domain alone,
  with the two under-threshold domains contributing nothing to the
  classification. This version uses >=5 sources across >=3 domains, AND
  splits the over-threshold domain's own aggregate across 2 sources
  (not 1) -- confirmed by hand against decision_score_estimator that a
  single dominant source makes the merged group's entropy top out
  around 0.65 (below DIST_ENTROPY_THRESHOLD=0.7) no matter how close the
  two under-threshold domains are pushed to their own local threshold;
  splitting the over-domain into 2 roughly-equal sources (same
  aggregate, same isolated-mode behavior -- isolated mode's own group
  still has <5 sources so still takes the single-attacker path there)
  pushes entropy comfortably past 0.7, so M genuinely classifies as
  MULTIDOMAIN_DISTRIBUTED_ATTACK instead of degenerating to SYN_FLOOD.
- Composition 3: V1 used a DIFFERENT f per domain in a single plan
  (0.9/0.7/0.5). This prompt asks for the SAME f in all 3 domains, one
  separate plan per f in {0.5, 0.7, 0.9} -- 3 plans instead of 1.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

from benign_lab.attack_planner import generate_attack_plan, save_attack_plan
from benign_lab.decision_score_estimator import estimate_isolated_and_multidomain

SYN_THRESHOLD = 85.238
VECTOR = 'syn_flood'
SEED = 201  # same "semilla de prueba" as V1 -- disjoint from THRESHOLD_CALIBRATION's 101-110
PLAN_DURATION_S = 180
ATTACK_START_S = 60
ATTACK_DURATION_S = 60  # window 60-120s of the 180s plan

OUT_DIR = ROOT / 'data' / 'attack_plans'
MANIFEST_PATH = ROOT / 'data' / 'attack_plans_manifest_v2.json'

# composition 2/3 use enterprise/fixed/mobile (not peering) -- same choice
# V1 made for composition 3 (peering's ~100-simulated-flow aggregate is a
# real feature, not noise, awkward to split evenly into 2 discrete
# sources the way the other 3 domains' real hosts are); kept consistent
# across both multidomain compositions in this version. Composition 1
# (single vector, one plan per domain) still covers peering on its own.
DOMAIN_SOURCES = {
    'enterprise': ['ent-site-1', 'ent-site-2'],
    'fixed': ['fixed1', 'fixed2'],
    'mobile': ['ue1', 'ue2'],
    'peering': ['peer-flow*'],
}


def _flow(domain, sources, rate_pps):
    return dict(domain=domain, sources=sources, destination='victim-web',
                wire_protocol=VECTOR, rate_pps=rate_pps, start_s=ATTACK_START_S,
                duration_s=ATTACK_DURATION_S, packet_size_bytes=64)


def _score_block(per_domain_rates):
    est = estimate_isolated_and_multidomain(per_domain_rates, SYN_THRESHOLD, VECTOR)
    return dict(
        isolated={d: (r and {k: round(v, 4) if isinstance(v, float) else v for k, v in r.items()})
                  for d, r in est['isolated'].items()},
        multidomain=est['multidomain'] and {k: round(v, 4) if isinstance(v, float) else v
                                              for k, v in est['multidomain'].items()},
    )


def build_composition_1():
    """Control, single vector: one source per domain, k=4.75x SYN_THRESHOLD.
    Unchanged design from V1, recomputed with the new threshold."""
    k = 4.75
    rate = round(k * SYN_THRESHOLD, 4)
    plans = []
    for domain, sources in DOMAIN_SOURCES.items():
        source = sources[0]
        per_domain_rates = {domain: [rate]}
        scores = _score_block(per_domain_rates)
        desc = dict(
            composition=1, domain=domain, vector=VECTOR, k=k,
            rate_per_source_pps=rate, sources=[source], num_sources=1,
            aggregate_per_domain_pps=rate, f_effective=k, sum_pps=rate,
            expected_score=scores,
        )
        plan = generate_attack_plan(
            seed=SEED, duration_s=PLAN_DURATION_S,
            flows=[_flow(domain, [source], rate)],
            description=json.dumps(desc, sort_keys=True))
        plans.append((f'composition1_{domain}', plan, desc))
    return plans


def build_composition_2():
    """Multidomain over the local threshold, corrected: >=5 sources across
    >=3 domains, one domain's own aggregate >= 4.5x SYN_THRESHOLD (split
    across 2 sources, for entropy -- see module docstring), the other two
    well under their own local threshold (0.7x, split across 2 sources
    each)."""
    over_k, under_k = 4.5, 0.7
    over_domain, under_domains = 'enterprise', ['fixed', 'mobile']

    rates = {over_domain: round(over_k * SYN_THRESHOLD, 4)}
    rates.update({d: round(under_k * SYN_THRESHOLD, 4) for d in under_domains})

    per_domain_rates, flows, domains_desc = {}, [], {}
    for domain in [over_domain] + under_domains:
        sources = DOMAIN_SOURCES[domain]
        per_source = round(rates[domain] / len(sources), 4)
        per_domain_rates[domain] = [per_source] * len(sources)
        flows.append(_flow(domain, sources, per_source))
        domains_desc[domain] = dict(
            role='over' if domain == over_domain else 'under',
            k=over_k if domain == over_domain else under_k,
            aggregate_pps=rates[domain], rate_per_source_pps=per_source,
            num_sources=len(sources))

    scores = _score_block(per_domain_rates)
    sum_pps = round(sum(rates.values()), 4)
    desc = dict(
        composition=2, vector=VECTOR, domains=domains_desc,
        sum_pps=sum_pps, num_sources=sum(len(v) for v in per_domain_rates.values()),
        expected_score=scores,
    )
    plan = generate_attack_plan(
        seed=SEED, duration_s=PLAN_DURATION_S, flows=flows,
        description=json.dumps(desc, sort_keys=True))
    return [('composition2_multidomain_over_threshold', plan, desc)]


# PILOT2_RESULT.md finding (2026-10-24, live, seed 206 f=0.9/C3): the
# ONE remaining I-coverage violation after the earlier (2026-10-23)
# background-subtraction fix did NOT come from co-located attack+benign
# traffic overlapping in time -- the spurious detection fired 12s AFTER
# the attack window ended, from ent-site-3's own benign SYN rate alone
# (114.49pps measured, no attack active). A dedicated 15-seed pure-C1-I
# experiment (fpr_measurement.json, seeds 301-315) found 0/15 spurious
# detections under benign-only traffic with NO co-located attack in the
# same run, isolating the mechanism to host-level contention: ent-site-3
# was simultaneously a benign-traffic host AND a composition-3 attack
# source, and residual effects from sharing the host (delayed benign
# connection retries, etc.) produced a brief post-attack SYN-rate burst.
# Fix: composition 3's attack sources are now DEDICATED hosts that carry
# ZERO benign traffic at all (excluded from the per-seed benign plan's
# population -- see generate_pilot2b_benign_plans.py), eliminating the
# contention mechanism entirely rather than trying to bound it. This
# also removes the need for a background-pps subtraction: a dedicated
# attack-only source's own measured pps IS the plan's rate (plus
# ordinary measurement jitter), so SAFE_MARGIN alone covers it.
SAFE_MARGIN = 0.85

# PILOT2_RESULT.md finding (2026-10-24), confirmed against a DOCUMENTED,
# pre-existing project issue (memory full-domain-attack-matrix-2026-10-18:
# "hping3 en general también sobre-dispara a intervalos muy chicos" --
# a nominal 60pps measured 216-229pps, ~3.6x): once composition3's
# dedicated sources cleanly sent their requested rate_pps (agent.py's
# own attack_pps_actual confirmed ~1.02x target -- the AGENT's pacing is
# fine), the CONTROLLER's independent flow-stats pps measurement still
# came in at 1.8-4.7x the target (91-169.8pps measured vs 36.2-65.2pps
# targeted) during composition3's real attack window. hping3's -i
# microsecond-interval pacing bursts packets unevenly at these low
# rates; the agent's own packets_sent/duration average hides it, but
# the controller's wire-level sampling catches the real bursts.
# HPING3_OVERSHOOT_MARGIN divides the target rate down to cover the
# worst observed ratio (4.69x) with room to spare -- weakens how much
# of SYN_THRESHOLD composition3 can actually probe per the brief's own
# rejected alternative (replacing hping3 with a software-paced emitter,
# same pattern bng_flood.py already uses for the fixed domain) in favor
# of shipping a working confirmatory design now.
HPING3_OVERSHOOT_MARGIN = 5.0

# 2 dedicated, benign-traffic-free sources per domain (down from 3) --
# chosen from each domain's real extra hosts specifically because they
# are easy to exclude from the benign population without starving the
# domain's calibrated background load: enterprise keeps 3/5 sites
# (ent-site-1/2/3) for benign, fixed keeps 8/10 (fixed1-8), mobile keeps
# 3/5 UEs (ue1/2/3). No background to subtract -> 2/domain is enough for
# M at the SAME f family (per-source rate is much higher now that
# there's no benign floor eating into it -- see build_composition_3's
# own f*SAFE_MARGIN*SYN_THRESHOLD, no subtraction term).
COMPOSITION3_SOURCES = {
    'enterprise': ['ent-site-4', 'ent-site-5'],
    'fixed': ['fixed9', 'fixed10'],
    'mobile': ['ue4', 'ue5'],
}
# 2026-10-24 correction: the 27/27 "hping3: command not found" failures
# in pilot2b were mis-attributed to fixed9/fixed10 from the detection
# record's domain='broadband' field -- the actual failing event_ids
# were mobile/ue4 and mobile/ue5 (event_id is a hash of domain+source,
# identical across plan versions since mobile's sources never changed).
# validate_all_attack_sources.py confirmed hping3 was simply never
# installed on the ue2 VM (10.10.0.16, hosts ue4/ue5) -- fixed9/fixed10
# dispatch correctly and always did. Fixed by installing hping3 there;
# all 20 candidate sources across all 3 domains now validate clean.


def build_composition_3():
    """Multidomain under the local threshold (confirmatoria), corrected
    AGAIN (PILOT2_RESULT.md, 2026-10-24): sources are now dedicated,
    benign-traffic-free hosts (COMPOSITION3_SOURCES' own comment), so f
    simply scales SAFE_MARGIN*SYN_THRESHOLD directly -- no co-located
    background to subtract, because there is none. Still ONE plan per f
    in {0.5, 0.7, 0.9}, same f applied to all 3 domains (enterprise,
    fixed, mobile), 2 sources per domain evenly split."""
    domains = ['enterprise', 'fixed', 'mobile']
    plans = []
    headroom_per_source = SAFE_MARGIN * SYN_THRESHOLD / HPING3_OVERSHOOT_MARGIN
    for f in (0.5, 0.7, 0.9):
        per_domain_rates, flows, domains_desc = {}, [], {}
        for domain in domains:
            sources = COMPOSITION3_SOURCES[domain]
            per_source = round(f * headroom_per_source, 4)
            aggregate = per_source * len(sources)
            per_domain_rates[domain] = [per_source] * len(sources)
            flows.append(_flow(domain, sources, per_source))
            domains_desc[domain] = dict(f=f, aggregate_pps=round(aggregate, 4),
                                         rate_per_source_pps=per_source, num_sources=len(sources))
        scores = _score_block(per_domain_rates)
        sum_pps = round(sum(sum(v) for v in per_domain_rates.values()), 4)
        # AttackPlanRequest.description is capped at 1000 chars server-side
        # -- the full expected_score breakdown doesn't fit alongside 6
        # sources' worth of domain detail, so the HASHED description stays
        # minimal (composition3_f{f}, same role as a plan name) and the
        # rich detail (domains/expected_score) lives only in desc_full,
        # kept OUT of what gets hashed/re-POSTed.
        f_tag = str(f).replace('.', '')
        description = f'composition3_f{f_tag}_v2'
        desc = dict(
            composition=3, vector=VECTOR, f=f, domains=domains_desc,
            sum_pps=sum_pps, sum_over_threshold_ratio=round(sum_pps / SYN_THRESHOLD, 4),
            num_sources=sum(len(v) for v in per_domain_rates.values()),
            expected_score=scores,
        )
        plan = generate_attack_plan(
            seed=SEED, duration_s=PLAN_DURATION_S, flows=flows,
            description=description)
        # flows/description kept OUT of desc's hashed form -- register_*
        # scripts need the raw request body to re-POST /api/attacks/plans
        # server-side and reproduce the identical plan_hash.
        desc_with_flows = dict(desc, flows=flows, hashed_description=description)
        plans.append((f'composition3_f{f_tag}', plan, desc_with_flows))
    return plans


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []
    warnings = []
    all_plans = build_composition_1() + build_composition_2() + build_composition_3()
    for name, plan, desc in all_plans:
        path = OUT_DIR / f'{name}_v2.json'
        save_attack_plan(plan, path)
        m_result = desc['expected_score']['multidomain']
        if not m_result or not m_result.get('decides'):
            warnings.append(f'{name}: multidomain mode does NOT reach DECISION_THRESHOLD '
                             f'(expected_score.multidomain={m_result})')
        if m_result and desc['composition'] == 2 and m_result.get('attack_type') != 'MULTIDOMAIN_DISTRIBUTED_ATTACK':
            warnings.append(f'{name}: multidomain mode classifies as {m_result.get("attack_type")}, '
                             f'not MULTIDOMAIN_DISTRIBUTED_ATTACK (degenerates to single-attacker path)')
        manifest.append(dict(name=name, plan_hash=plan['plan_hash'], seed=SEED,
                              domains=plan['domains'], description=desc,
                              path=str(path.relative_to(ROOT))))
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Wrote {len(manifest)} plans to {OUT_DIR} and manifest to {MANIFEST_PATH}')
    if warnings:
        print('\n*** WARNING ***')
        for w in warnings:
            print(' -', w)
    else:
        print('All compositions reach DECISION_THRESHOLD in M, with the expected attack_type.')


if __name__ == '__main__':
    main()
