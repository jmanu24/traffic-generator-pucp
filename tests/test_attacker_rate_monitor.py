"""D7, change 2: pure-function tests against a REAL `ovs-ofctl -O OpenFlow13
dump-flows br-ent` capture from `pe` (2026-10-22) -- not a guessed format."""
import pytest
from benign_lab.attacker_rate_monitor import domain_sources, parse_forwarded_packets, rate_series_from_samples

REAL_DUMP = """OFPST_FLOW reply (OF1.3) (xid=0x2):
 cookie=0x0, duration=101095.485s, table=0, n_packets=0, n_bytes=0, priority=65535,dl_dst=01:80:c2:00:00:0e,dl_type=0x88cc actions=CONTROLLER:65535
 cookie=0x0, duration=5257.238s, table=0, n_packets=1214370, n_bytes=72862200, priority=100,tcp,in_port=3,nw_src=10.70.0.12,nw_dst=10.55.0.100,tp_dst=9001 actions=drop
 cookie=0x0, duration=5245.320s, table=0, n_packets=1211505, n_bytes=72690300, priority=100,tcp,in_port=3,nw_src=10.70.0.11,nw_dst=10.55.0.100,tp_dst=9001 actions=drop
 cookie=0x0, duration=9.353s, table=0, n_packets=1440, n_bytes=86400, idle_timeout=60, hard_timeout=30, priority=11,tcp,nw_src=10.70.0.11,nw_dst=10.55.0.100,tcp_flags=+syn-ack actions=output:5
 cookie=0x0, duration=7.284s, table=0, n_packets=816, n_bytes=48960, idle_timeout=60, hard_timeout=30, priority=11,tcp,nw_src=10.70.0.13,nw_dst=10.55.0.100,tcp_flags=+syn-ack actions=output:5
 cookie=0x0, duration=6.208s, table=0, n_packets=0, n_bytes=0, idle_timeout=60, hard_timeout=30, priority=11,tcp,nw_src=10.55.0.100,nw_dst=10.92.0.2,tcp_flags=+syn-ack actions=output:1
 cookie=0x0, duration=9.353s, table=0, n_packets=1440, n_bytes=86400, idle_timeout=60, hard_timeout=30, priority=10,ip,nw_src=10.70.0.11,nw_dst=10.55.0.100 actions=output:5
 cookie=0x0, duration=7.284s, table=0, n_packets=815, n_bytes=48900, idle_timeout=60, hard_timeout=30, priority=10,ip,nw_src=10.70.0.13,nw_dst=10.55.0.100 actions=output:5
 cookie=0x0, duration=6.208s, table=0, n_packets=948, n_bytes=56880, idle_timeout=60, hard_timeout=30, priority=10,ip,nw_src=10.55.0.100,nw_dst=10.92.0.2 actions=output:1
 cookie=0x0, duration=7289.192s, table=0, n_packets=401, n_bytes=24060, idle_timeout=60, priority=1,arp,in_port=1,dl_src=00:0c:29:ac:84:54,dl_dst=00:0c:29:0b:7c:77 actions=output:5
 cookie=0x0, duration=101095.493s, table=0, n_packets=361637, n_bytes=196643822, priority=0 actions=CONTROLLER:65535
"""


def test_parse_forwarded_packets_sums_non_drop_entries_and_excludes_drop():
    out = parse_forwarded_packets(REAL_DUMP, '10.55.0.100')
    # 10.70.0.11: priority=11 (1440) + priority=10 (1440) -- two distinct
    # rules matching the SAME (src,dst) pair, each counting its own
    # non-overlapping share of that flow's traffic (OpenFlow's own
    # highest-priority-match-wins); summed, not double counted against
    # some single "true" packet count, because there isn't one -- these
    # are each rule's own, already-disjoint n_packets.
    assert out['10.70.0.11'] == 1440 + 1440
    assert out['10.70.0.13'] == 816 + 815
    # 10.70.0.12 has ONLY a drop-rule entry toward the victim -- 0 forwarded,
    # not absent and not counted from the drop rule's own (stale) total.
    assert '10.70.0.12' not in out
    # traffic FROM the victim (nw_src=victim) must never be mistaken for
    # traffic reaching it.
    assert '10.55.0.100' not in out


def test_parse_forwarded_packets_ignores_unrelated_destinations():
    dump = " cookie=0x0, duration=1s, table=0, n_packets=5, n_bytes=1, priority=1,ip,nw_src=10.70.0.11,nw_dst=10.10.0.1 actions=output:1\n"
    assert parse_forwarded_packets(dump, '10.55.0.100') == {}


def test_domain_sources_reads_the_attack_plans_own_domain_and_node_ips():
    attack_plan = dict(events=[
        dict(domain='enterprise', source='ent-site-1'),
        dict(domain='enterprise', source='ent-site-2'),
        dict(domain='mobile', source='ue1'),
    ])
    cfg = dict(nodes={
        'ent-site-1': dict(source_ip='10.70.0.11'),
        'ent-site-2': dict(source_ip='10.70.0.12'),
        'ue1': dict(source_ip='10.45.1.2'),
        'unrelated': dict(source_ip='10.99.0.1'),
    })
    out = domain_sources(attack_plan, cfg)
    assert out == {'enterprise': ['10.70.0.11', '10.70.0.12'], 'mobile': ['10.45.1.2']}


def test_domain_sources_skips_a_source_with_no_resolvable_ip():
    attack_plan = dict(events=[dict(domain='enterprise', source='ghost')])
    out = domain_sources(attack_plan, dict(nodes={}))
    assert out == {}


def test_rate_series_from_samples_computes_pps_from_successive_deltas():
    domain_ips = {'enterprise': ['10.70.0.11']}
    samples = [
        dict(timestamp=100.0, packets_by_ip={'10.70.0.11': 1000}),
        dict(timestamp=102.0, packets_by_ip={'10.70.0.11': 1140}),  # +140 over 2s = 70pps
        dict(timestamp=104.0, packets_by_ip={'10.70.0.11': 1140}),  # blocked: no growth -> 0pps
    ]
    series = rate_series_from_samples(samples, domain_ips)
    assert series['enterprise'] == [(102.0, pytest.approx(70.0)), (104.0, pytest.approx(0.0))]


def test_rate_series_from_samples_ignores_error_rows_without_crashing():
    domain_ips = {'enterprise': ['10.70.0.11']}
    samples = [
        dict(timestamp=100.0, packets_by_ip={'10.70.0.11': 1000}),
        dict(timestamp=101.0, error='SSH timeout'),
        dict(timestamp=102.0, packets_by_ip={'10.70.0.11': 1140}),
    ]
    series = rate_series_from_samples(samples, domain_ips)
    # the error row contributes no sample; the delta is still computed
    # correctly across it from the two real rows on either side.
    assert series['enterprise'] == [(102.0, pytest.approx(70.0))]


def test_rate_series_from_samples_treats_a_newly_appearing_ip_as_zero_not_a_spike():
    domain_ips = {'enterprise': ['10.70.0.11']}
    samples = [
        dict(timestamp=100.0, packets_by_ip={}),
        dict(timestamp=102.0, packets_by_ip={'10.70.0.11': 500}),  # first time this IP's flow appears
    ]
    series = rate_series_from_samples(samples, domain_ips)
    assert series['enterprise'] == [(102.0, pytest.approx(0.0))]
