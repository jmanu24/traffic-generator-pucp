"""D7: BaselineGuard.clear_residual_openflow_drops() -- actively deletes a
residual OVS drop rule from pe instead of only detecting and refusing to
start (the previous behaviour, kept in git history). Extracted out of
enter() so it can be exercised without that method's own lease/mobile/
fixed machinery (see test_baseline.py for enter()'s own, higher-level
tests, which mock BaselineGuard wholesale and never reach this far)."""
import asyncio
import pytest
from benign_lab.baseline import BaselineGuard

REAL_DUMP_WITH_RESIDUAL = """OFPST_FLOW reply (OF1.3) (xid=0x2):
 cookie=0x0, duration=330.602s, table=0, n_packets=63414, n_bytes=4349378, priority=100,tcp,in_port=3,nw_dst=10.55.0.100,tp_dst=9001 actions=drop
 cookie=0x0, duration=9.353s, table=0, n_packets=1440, n_bytes=86400, idle_timeout=60, hard_timeout=30, priority=11,tcp,nw_src=10.70.0.11,nw_dst=10.55.0.100,tcp_flags=+syn-ack actions=output:5
 cookie=0x0, duration=101095.493s, table=0, n_packets=361637, n_bytes=196643822, priority=0 actions=CONTROLLER:65535
"""
REAL_DUMP_CLEAN = """OFPST_FLOW reply (OF1.3) (xid=0x2):
 cookie=0x0, duration=9.353s, table=0, n_packets=1440, n_bytes=86400, idle_timeout=60, hard_timeout=30, priority=11,tcp,nw_src=10.70.0.11,nw_dst=10.55.0.100,tcp_flags=+syn-ack actions=output:5
 cookie=0x0, duration=101095.493s, table=0, n_packets=361637, n_bytes=196643822, priority=0 actions=CONTROLLER:65535
"""


def make_guard():
    return BaselineGuard(dict(baseline_control=dict(pe_host='10.10.0.7')), run_id='r1', duration=180)


def test_returns_zero_and_never_calls_del_flows_when_already_clean():
    guard = make_guard()
    calls = []

    async def fake_ssh(host, user, command, root=False, payload=None, timeout=25):
        calls.append(command)
        return REAL_DUMP_CLEAN
    guard.ssh = fake_ssh

    n = asyncio.run(guard.clear_residual_openflow_drops())
    assert n == 0
    assert calls == ['ovs-ofctl -O OpenFlow13 dump-flows br-ent']  # one dump, no del-flows


def test_deletes_the_residual_rule_with_fields_only_never_the_whole_bridge():
    guard = make_guard()
    calls = []
    dumps = [REAL_DUMP_WITH_RESIDUAL, REAL_DUMP_CLEAN]  # before, after the delete

    async def fake_ssh(host, user, command, root=False, payload=None, timeout=25):
        calls.append(command)
        if command.startswith('ovs-ofctl -O OpenFlow13 dump-flows'):
            return dumps.pop(0)
        return ''
    guard.ssh = fake_ssh

    n = asyncio.run(guard.clear_residual_openflow_drops())
    assert n == 1
    del_flows_calls = [c for c in calls if c.startswith('ovs-ofctl -O OpenFlow13 del-flows')]
    assert len(del_flows_calls) == 1
    # Only the match fields that actually identify the rule -- never
    # cookie/duration/n_packets/n_bytes/priority (those would either not
    # match on a del-flows call or delete far more than this one rule).
    assert del_flows_calls[0] == "ovs-ofctl -O OpenFlow13 del-flows br-ent table=0,tcp,in_port=3,nw_dst=10.55.0.100,tp_dst=9001"
    assert calls[0].startswith('ovs-ofctl -O OpenFlow13 dump-flows')
    assert calls[-1].startswith('ovs-ofctl -O OpenFlow13 dump-flows')  # re-verified after deleting


def test_raises_if_the_rule_survives_its_own_deletion_attempt():
    """Never silently proceeds into a run on dataplane state it could not
    actually confirm clean -- same conservative failure mode the previous,
    detect-only behaviour had, just after actually trying to fix it first."""
    guard = make_guard()

    async def fake_ssh(host, user, command, root=False, payload=None, timeout=25):
        if command.startswith('ovs-ofctl -O OpenFlow13 dump-flows'):
            return REAL_DUMP_WITH_RESIDUAL  # still there, even after the del-flows call below
        return ''
    guard.ssh = fake_ssh

    with pytest.raises(RuntimeError, match='could not be cleared'):
        asyncio.run(guard.clear_residual_openflow_drops())


def test_deletes_multiple_residual_rules_independently():
    guard = make_guard()
    dump_with_two = """OFPST_FLOW reply (OF1.3) (xid=0x2):
 cookie=0x0, duration=5257.238s, table=0, n_packets=1214370, n_bytes=72862200, priority=100,tcp,in_port=3,nw_src=10.70.0.12,nw_dst=10.55.0.100,tp_dst=9001 actions=drop
 cookie=0x0, duration=5245.320s, table=0, n_packets=1211505, n_bytes=72690300, priority=100,tcp,in_port=3,nw_src=10.70.0.11,nw_dst=10.55.0.100,tp_dst=9001 actions=drop
"""
    dumps = [dump_with_two, REAL_DUMP_CLEAN]
    del_flows_calls = []

    async def fake_ssh(host, user, command, root=False, payload=None, timeout=25):
        if command.startswith('ovs-ofctl -O OpenFlow13 dump-flows'):
            return dumps.pop(0)
        del_flows_calls.append(command)
        return ''
    guard.ssh = fake_ssh

    n = asyncio.run(guard.clear_residual_openflow_drops())
    assert n == 2
    assert len(del_flows_calls) == 2
    assert 'nw_src=10.70.0.12' in del_flows_calls[0]
    assert 'nw_src=10.70.0.11' in del_flows_calls[1]
