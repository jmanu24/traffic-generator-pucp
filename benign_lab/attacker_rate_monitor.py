"""D7, change 2: independent, detector-agnostic attacker-rate collector for
response_metrics.py's `tE` (see that module's own docstring and
docs/IM_COMPARISON_DESIGN.md §9 for the original, pending-confirmation
proposal this implements, confirmed 2026-10-22).

Point of measurement: `pe`'s own OVS bridge (`br-ent`), the single
convergence point for enterprise, mobile and fixed/broadband traffic
toward the victim (ENT_DC, the same bridge BaselineGuard.enter() already
reads for its own residual-drop-rule check) -- downstream of wherever the
controller's own mitigation rules land on this bridge, so a successful
block is visible here as a real, independent rate drop (never inferred
from the attacker's own, unblocked send rate -- which the generator
already controls and would show nothing). peering is NOT covered here: it
converges on `br`'s own external interface instead (a different physical
point, softflowd-tapped), a separate collector -- not implemented yet,
out of scope for this change (no peering composition in this validation).

Domain/IP attribution comes from the ATTACK PLAN's own domain/source
fields plus the lab config's own node->source_ip mapping -- the
generator's own ground truth, built with ZERO reference to the
controller's detection output (source_domains, sources, etc.), which is
exactly what makes this series independent per the brief.
"""
from __future__ import annotations
import asyncio
import collections
import json
import os
import re
import time

_NW_DST_RE = re.compile(r'nw_dst=([0-9.]+)')
_NW_SRC_RE = re.compile(r'nw_src=([0-9.]+)')
_N_PACKETS_RE = re.compile(r'n_packets=(\d+)')

POLL_INTERVAL_S = 2.0  # independent of COLLECT_INTERVAL (the detector's
# own cadence) on purpose -- this series must stand on its own, not just
# resample the detector's timing.


def domain_sources(attack_plan, cfg):
    """{domain: [ip, ...]} from the attack plan's own events (domain,
    source=a lab.yaml node name) and cfg['nodes'][source]['source_ip'] --
    the generator's own config, never the controller's. A source with no
    resolvable source_ip (misconfigured node) is skipped, not guessed."""
    out = collections.defaultdict(set)
    nodes = cfg.get('nodes', {})
    for e in attack_plan.get('events', []):
        ip = nodes.get(e.get('source'), {}).get('source_ip')
        if ip:
            out[e['domain']].add(ip)
    return {d: sorted(ips) for d, ips in out.items()}


def parse_forwarded_packets(dump_text, victim_ip):
    """{src_ip: n_packets} for flow entries whose nw_dst matches
    victim_ip, EXCLUDING `actions=drop` entries (a block is this IP's
    entry simply disappearing from -- or never growing in -- this dict
    across polls, not a separate counter). Multiple entries can legitimately
    share the same (src, dst) pair (e.g. a TCP_SYN-ACK-specific rule and a
    broader `ip` rule for the rest of that same flow's traffic, confirmed
    in a real `ovs-ofctl dump-flows br-ent` capture) -- summed, since each
    one's own n_packets already only counts the packets that matched THAT
    rule specifically (OpenFlow's own highest-priority-match-wins
    semantics), never double counting the same packet twice."""
    out = collections.defaultdict(int)
    needle = 'nw_dst=' + victim_ip
    for line in dump_text.splitlines():
        if needle not in line or 'actions=drop' in line:
            continue
        src = _NW_SRC_RE.search(line)
        packets = _N_PACKETS_RE.search(line)
        if src and packets:
            out[src.group(1)] += int(packets.group(1))
    return dict(out)


class AttackerRateMonitor:
    """Polls `pe` for as long as `.run()` is awaited (cancel to stop),
    building `rate_series` = {domain: [(timestamp, pps), ...]} straight
    from successive dump-flows deltas -- ready to pass into
    response_metrics.compute(rate_series=...) unchanged."""

    def __init__(self, cfg, attack_plan, victim_ip, known_hosts_file=None):
        self.cfg = cfg
        control = cfg.get('baseline_control', {})
        self.pe_host = control['pe_host']
        self.pe_password_env = control.get('pe_password_env', 'BENIGN_PE_SSH_PASSWORD')
        self.known_hosts_file = known_hosts_file or control['known_hosts_file']
        self.victim_ip = victim_ip
        self.domain_ips = domain_sources(attack_plan, cfg)
        self.ip_domain = {ip: d for d, ips in self.domain_ips.items() for ip in ips}
        self.rate_series = {d: [] for d in self.domain_ips}
        self.samples = []  # raw per-poll records, for the exported .jsonl
        self._previous = None  # (timestamp, {ip: n_packets})

    async def _dump_flows(self):
        env = os.environ.copy()
        password = env.get(self.pe_password_env)
        if not password:
            raise RuntimeError('Attacker-rate monitor SSH credential is unavailable')
        env['SSHPASS'] = password
        argv = ['sshpass', '-e', 'ssh', '-T', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5',
                '-o', 'UserKnownHostsFile=' + self.known_hosts_file, 'root@' + self.pe_host,
                'ovs-ofctl -O OpenFlow13 dump-flows br-ent']
        proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=10)
        if proc.returncode:
            raise RuntimeError('Attacker-rate dump-flows failed on ' + self.pe_host + ': ' + err.decode(errors='replace')[-300:])
        return out.decode()

    def _ingest(self, now, packets_by_ip):
        self.samples.append(dict(timestamp=now, packets_by_ip=packets_by_ip))
        if self._previous is not None:
            prev_ts, prev_packets = self._previous
            dt = now - prev_ts
            if dt > 0:
                by_domain = collections.defaultdict(float)
                for ip, n in packets_by_ip.items():
                    domain = self.ip_domain.get(ip)
                    if domain is None:
                        continue
                    delta = n - prev_packets.get(ip, n)  # a flow entry that
                    # just appeared (first poll that sees it) has no prior
                    # count to diff against -- treated as 0 new packets
                    # this interval, not a spurious spike of its whole
                    # historical total.
                    by_domain[domain] += max(0, delta) / dt
                for domain, pps in by_domain.items():
                    self.rate_series.setdefault(domain, []).append((now, pps))
        self._previous = (now, packets_by_ip)

    async def run(self):
        """Polls until cancelled. Errors from one poll (a transient SSH
        hiccup) are recorded but never stop the loop -- a gap in the
        series is reported as a gap (response_metrics.py's own tE
        censoring already handles sparse/missing data), not a crashed
        collector taking the rest of the run's measurement down with it."""
        while True:
            try:
                dump = await self._dump_flows()
                self._ingest(time.time(), parse_forwarded_packets(dump, self.victim_ip))
            except (RuntimeError, OSError, asyncio.TimeoutError) as exc:
                self.samples.append(dict(timestamp=time.time(), error=str(exc)))
            await asyncio.sleep(POLL_INTERVAL_S)

    def save(self, path):
        with open(path, 'w') as f:
            for row in self.samples:
                f.write(json.dumps(row) + '\n')


def rate_series_from_samples(samples, domain_ips):
    """Rebuilds the SAME rate_series `AttackerRateMonitor.run()` would
    have, from its own persisted samples.jsonl -- used by analytics (read
    long after the run finished, with no live monitor object) exactly the
    way `rows()`/`lines()` already replay other collectors' own on-disk
    history elsewhere in this module. Never reconstructs anything a live
    run did not actually ingest -- same per-interval delta logic, replayed."""
    ip_domain = {ip: d for d, ips in domain_ips.items() for ip in ips}
    series = {d: [] for d in domain_ips}
    previous = None
    for row in samples:
        if 'packets_by_ip' not in row:
            continue
        now = row['timestamp']
        if previous is not None:
            prev_ts, prev_packets = previous
            dt = now - prev_ts
            if dt > 0:
                by_domain = collections.defaultdict(float)
                for ip, n in row['packets_by_ip'].items():
                    domain = ip_domain.get(ip)
                    if domain is None:
                        continue
                    delta = n - prev_packets.get(ip, n)
                    by_domain[domain] += max(0, delta) / dt
                for domain, pps in by_domain.items():
                    series.setdefault(domain, []).append((now, pps))
        previous = (now, row['packets_by_ip'])
    return series
