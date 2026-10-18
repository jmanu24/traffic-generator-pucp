"""Deterministic attack-plan generation: real flows from real lab clients.

No hping3, no scapy, no spoofing. Each attack event names a real node already
present in lab.yaml (the same inventory benign plans use) and a real target;
dispatch reuses config.resolve()/supervisor transport unchanged, and the
flows are generated client-side by benign_lab.agent.attack_flood (udp_flood,
syn_flood, icmp_flood). An attack plan is a distinct, lighter artifact than a
BENIGN_V1 plan: no capacity/quota model, no profiles, just domain, sources,
destination, protocol, target packet rate and timing.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from .planner import canonical, digest, DOMAINS

PROFILE = 'ATTACK_FLOOD_V1'
PROTOCOLS = ('udp_flood', 'syn_flood', 'icmp_flood')


def _event_id(seed, domain, source, destination, wire_protocol, index):
    raw = f'{seed}:{domain}:{source}:{destination}:{wire_protocol}:{index}'
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _flow_events(seed, flow):
    domain = flow['domain']
    if domain not in DOMAINS:
        raise ValueError(f'Unknown domain: {domain}')
    wire_protocol = flow['wire_protocol']
    if wire_protocol not in PROTOCOLS:
        raise ValueError(f'Unsupported attack protocol: {wire_protocol}')
    sources = flow['sources']
    if not sources:
        raise ValueError('At least one source is required per flow')
    rate_pps = float(flow['rate_pps'])
    if rate_pps <= 0:
        raise ValueError('rate_pps must be positive')
    destination = flow['destination']
    start_s = float(flow.get('start_s', 0))
    duration_s = float(flow['duration_s'])
    packet_size_bytes = int(flow.get('packet_size_bytes', 64))
    if not 8 <= packet_size_bytes <= 1400:
        raise ValueError('packet_size_bytes must be between 8 and 1400')
    return [dict(event_id=_event_id(seed, domain, source, destination, wire_protocol, i),
                 domain=domain, source=source, destination=destination,
                 wire_protocol=wire_protocol, rate_pps=rate_pps,
                 packet_size_bytes=packet_size_bytes, start_s=start_s, duration_s=duration_s)
            for i, source in enumerate(sources)]


def generate_attack_plan(seed, duration_s, flows, description=''):
    """flows: one dict per attack flow (one or many domains; several flows on
    the same or different domains compose a coordinated multidomain attack).
    Each flow: domain, sources (list of lab.yaml node names), destination
    (lab.yaml target name), wire_protocol, rate_pps, start_s, duration_s,
    packet_size_bytes (optional, default 64)."""
    duration_s = float(duration_s)
    if not 1 <= duration_s <= 3600:
        raise ValueError('duration_s must be between 1 and 3600 seconds')
    if not flows:
        raise ValueError('At least one attack flow is required')
    events = []
    for flow in flows:
        events += _flow_events(seed, flow)
    ids = [e['event_id'] for e in events]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate attack event_id; vary domain/source/destination/protocol')
    plan = dict(profile=PROFILE, seed=seed, duration_s=duration_s,
                description=description, domains=sorted({e['domain'] for e in events}),
                events=events)
    plan['plan_hash'] = digest(plan)
    return validate_attack_plan(plan)


def validate_attack_plan(plan):
    if plan.get('profile') != PROFILE:
        raise ValueError('Not an attack plan (expected profile ATTACK_FLOOD_V1)')
    expected = digest({k: v for k, v in plan.items() if k != 'plan_hash'})
    if expected != plan.get('plan_hash'):
        raise ValueError('plan_hash mismatch; plan was edited after materialization')
    if not plan['events']:
        raise ValueError('Attack plan has no events')
    for e in plan['events']:
        if e['wire_protocol'] not in PROTOCOLS:
            raise ValueError(f"Unsupported attack protocol: {e['wire_protocol']}")
        if e['domain'] not in DOMAINS:
            raise ValueError(f"Unknown domain: {e['domain']}")
        if not 0 <= e['start_s'] < e['start_s'] + e['duration_s'] <= plan['duration_s'] + 1e-9:
            raise ValueError(f"Event {e['event_id']} window outside plan duration")
        if e['rate_pps'] <= 0:
            raise ValueError(f"Event {e['event_id']} needs a positive rate_pps")
    return plan


def save_attack_plan(plan, path):
    validate_attack_plan(plan)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = canonical(plan) + b'\n'
    if path.exists():
        if path.read_bytes() != blob:
            raise ValueError(f'Refusing to overwrite a different attack plan: {path}')
    else:
        with path.open('xb') as f:
            f.write(blob)
    return path
