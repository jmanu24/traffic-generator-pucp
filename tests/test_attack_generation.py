"""Attack generation: real flows from real clients, no receiver cooperation.

syn_flood is the one exception to "no hping3" -- see attack_flood()'s own
docstring and docs/PROTECTED_RESOURCE.md §5/§9 (isp-ddos-ryu) for why a
pure-Python connect() can never produce a real half-open flood here."""
import asyncio
import socket
import time
from unittest import mock
import pytest
from benign_lab.agent import attack_flood, SYN_FLOOD_SPORT_BASE, _icmp_checksum, _icmp_echo_packet
from benign_lab.attack_planner import generate_attack_plan, validate_attack_plan
from benign_lab.attack_runner import run_attack


def test_icmp_echo_packet_checksum_is_self_consistent():
    import struct
    packet = _icmp_echo_packet(1234, 7, 64)
    assert len(packet) == 64
    typ, code, checksum, identifier, seq = struct.unpack('!BBHHH', packet[:8])
    assert (typ, code, identifier, seq) == (8, 0, 1234, 7)
    zeroed = struct.pack('!BBHHH', typ, code, 0, identifier, seq) + packet[8:]
    assert _icmp_checksum(zeroed) == checksum


def test_generate_attack_plan_is_deterministic_by_seed():
    flows = [dict(domain='mobile', sources=['ue1', 'ue2'], destination='victim-web',
                   wire_protocol='udp_flood', rate_pps=50, start_s=60, duration_s=60)]
    a = generate_attack_plan(seed=11, duration_s=180, flows=flows)
    b = generate_attack_plan(seed=11, duration_s=180, flows=flows)
    c = generate_attack_plan(seed=12, duration_s=180, flows=flows)
    assert a['plan_hash'] == b['plan_hash']
    assert a['plan_hash'] != c['plan_hash']
    validate_attack_plan(a)


def test_generate_attack_plan_supports_multidomain_distributed():
    plan = generate_attack_plan(seed=1, duration_s=180, flows=[
        dict(domain='mobile', sources=['ue1'], destination='victim-web', wire_protocol='udp_flood', rate_pps=50, start_s=60, duration_s=60),
        dict(domain='fixed', sources=['fixed1'], destination='victim-web', wire_protocol='udp_flood', rate_pps=50, start_s=60, duration_s=60),
        dict(domain='enterprise', sources=['ent-site-1'], destination='victim-web', wire_protocol='udp_flood', rate_pps=50, start_s=60, duration_s=60),
    ])
    assert plan['domains'] == ['enterprise', 'fixed', 'mobile']
    assert len(plan['events']) == 3


@pytest.mark.parametrize('bad_flow,message', [
    (dict(domain='mobile', sources=['ue1'], destination='v', wire_protocol='hping3', rate_pps=10, duration_s=10), 'protocol'),
    (dict(domain='satellite', sources=['ue1'], destination='v', wire_protocol='udp_flood', rate_pps=10, duration_s=10), 'domain'),
    (dict(domain='mobile', sources=['ue1'], destination='v', wire_protocol='udp_flood', rate_pps=10, start_s=100, duration_s=50), 'window'),
])
def test_generate_attack_plan_rejects_invalid_flows(bad_flow, message):
    with pytest.raises(ValueError):
        generate_attack_plan(seed=1, duration_s=120, flows=[bad_flow])


def test_attack_flood_udp_reaches_a_real_socket_at_the_target_rate():
    async def scenario():
        recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv.bind(('127.0.0.1', 0))
        recv.setblocking(False)
        port = recv.getsockname()[1]
        metrics = {'bytes_tx': 0}
        deadline = time.monotonic() + 1.0
        await attack_flood(dict(wire_protocol='udp_flood', rate_pps=200, packet_size_bytes=64),
                            dict(host='127.0.0.1', udp_port=port), metrics, deadline, {})
        assert metrics['packets_sent'] == 200
        assert 150 <= metrics['attack_pps_actual'] <= 250
        loop = asyncio.get_running_loop()
        received = 0
        try:
            while True:
                await asyncio.wait_for(loop.sock_recv(recv, 2000), 0.05)
                received += 1
        except asyncio.TimeoutError:
            pass
        assert received == 200
    asyncio.run(scenario())


class _FakeProc:
    def __init__(self, returncode=0, stderr=b'', communicate_raises=None):
        self.returncode = returncode
        self._stderr = stderr
        self._communicate_raises = communicate_raises
        self.killed = False
        self.waited = False

    async def communicate(self, *a, **k):
        if self._communicate_raises:
            raise self._communicate_raises
        return b'', self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        self.waited = True


def test_attack_flood_syn_flood_runs_hping3_inside_a_scoped_nft_rule():
    """syn_flood shells out to nft (scoped rule) + hping3 + nft cleanup, in
    that order, and never touches a plain Python socket -- see the branch's
    own comment in agent.py for why a connect()-based flood can't work."""
    calls = []

    async def fake_exec(*args, **kwargs):
        calls.append(args)
        if args[2] == 'nft' and args[3] == 'delete':
            return _FakeProc(returncode=0)
        if args[2] == 'nft':
            return _FakeProc(returncode=0)
        if args[2] == 'pkill':
            return _FakeProc(returncode=0)
        assert args[2] == 'hping3'
        return _FakeProc(returncode=0)

    async def scenario():
        metrics = {'bytes_tx': 0}
        deadline = time.monotonic() + 2.0
        with mock.patch('asyncio.create_subprocess_exec', side_effect=fake_exec):
            await attack_flood(dict(wire_protocol='syn_flood', rate_pps=50, packet_size_bytes=64),
                                dict(host='10.55.0.100', tcp_port=9001), metrics, deadline, {})
        return metrics
    metrics = asyncio.run(scenario())

    # D7: nft_setup, hping, THEN a pkill reap of any surviving hping3 child
    # (hping.kill()'s SIGKILL only reaches the sudo wrapper, never the
    # hping3 grandchild it pty-forks -- confirmed live 2026-10-22), finally
    # the nft cleanup -- the reap runs before the nft table is torn down.
    assert len(calls) == 4
    nft_setup, hping, pkill, nft_cleanup = calls
    assert nft_setup[:3] == ('sudo', '-n', 'nft')
    assert nft_cleanup[:5] == ('sudo', '-n', 'nft', 'delete', 'table')
    assert hping[:3] == ('sudo', '-n', 'hping3')
    assert '-s' in hping and hping[hping.index('-s') + 1] == str(SYN_FLOOD_SPORT_BASE)
    assert '-p' in hping and hping[hping.index('-p') + 1] == '9001'
    assert hping[-1] == '10.55.0.100'
    assert pkill[:5] == ('sudo', '-n', 'pkill', '-9', '-f')
    assert pkill[5] == f'hping3 --syn -p 9001 -s {SYN_FLOOD_SPORT_BASE}'
    assert metrics['packets_sent'] == pytest.approx(100, abs=5)  # ~2s x 50pps
    assert metrics['bytes_tx'] == metrics['packets_sent'] * 64
    assert metrics['attack_pps_target'] == 50


def test_attack_flood_syn_flood_cleans_up_nft_even_when_hping3_fails_at_startup():
    """A startup-time failure (bad sudo rule, missing binary) raises -- but
    the nft cleanup still runs (finally), never leaving a stray table."""
    calls = []

    async def fake_exec(*args, **kwargs):
        calls.append(args)
        if args[2] in ('nft', 'pkill'):
            return _FakeProc(returncode=0)
        return _FakeProc(returncode=1, stderr=b'sudo: a password is required')

    async def scenario():
        metrics = {'bytes_tx': 0}
        deadline = time.monotonic() + 5.0
        with mock.patch('asyncio.create_subprocess_exec', side_effect=fake_exec):
            await attack_flood(dict(wire_protocol='syn_flood', rate_pps=50, packet_size_bytes=64),
                                dict(host='10.55.0.100', tcp_port=9001), metrics, deadline, {})
    with pytest.raises(RuntimeError, match='hping3 failed'):
        asyncio.run(scenario())
    # The pkill reap still runs even on a fast startup failure -- finally
    # covers every exit path, not just the normal/deadline one.
    assert [c[2] for c in calls] == ['nft', 'hping3', 'pkill', 'nft']
    assert calls[-1][3] == 'delete'


def test_attack_flood_syn_flood_treats_the_deadline_kill_as_success_not_failure():
    """hping3 has no native "stop after N seconds" flag independent of -c --
    the normal end-of-event path is this code's own timeout killing a still-
    running process, which must NOT be reported as an error."""
    killed_proc = _FakeProc(returncode=None)
    pkill_calls = []

    async def fake_exec(*args, **kwargs):
        if args[2] == 'nft':
            return _FakeProc(returncode=0)
        if args[2] == 'pkill':
            pkill_calls.append(args)
            return _FakeProc(returncode=0)
        return killed_proc

    async def scenario():
        metrics = {'bytes_tx': 0}
        deadline = time.monotonic() + 0.3
        async def fake_wait_for(coro, timeout):
            coro.close()  # avoid a "coroutine was never awaited" warning
            raise asyncio.TimeoutError

        with mock.patch('asyncio.create_subprocess_exec', side_effect=fake_exec), \
             mock.patch('asyncio.wait_for', side_effect=fake_wait_for):
            await attack_flood(dict(wire_protocol='syn_flood', rate_pps=50, packet_size_bytes=64),
                                dict(host='10.55.0.100', tcp_port=9001), metrics, deadline, {})
        return metrics
    metrics = asyncio.run(scenario())
    assert killed_proc.killed and killed_proc.waited
    assert metrics['packets_sent'] > 0
    # The reap pkill still runs after the deadline-kill path, same as any
    # other exit from the try block -- it is in `finally`, not tied to a
    # particular outcome.
    assert len(pkill_calls) == 1
    assert pkill_calls[0][:5] == ('sudo', '-n', 'pkill', '-9', '-f')


def test_run_attack_reports_resolved_source_ips():
    async def scenario():
        recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv.bind(('127.0.0.1', 0))
        recv.setblocking(False)
        port = recv.getsockname()[1]
        cfg = dict(
            nodes={'nodeA': {'adapter': 'local', 'source_ip': '10.70.0.5'},
                   'nodeB': {'adapter': 'local', 'source_ip': '10.70.0.6'}},
            targets={'victim': {'host': '127.0.0.1', 'tcp_port': 1, 'udp_port': port, 'http_port': 1}},
            allowed_target_cidrs=['127.0.0.0/8'], max_clock_skew_s=2.0, start_lead_s=2.0,
        )
        plan = generate_attack_plan(seed=3, duration_s=10, flows=[
            dict(domain='enterprise', sources=['nodeA', 'nodeB'], destination='victim',
                 wire_protocol='udp_flood', rate_pps=50, start_s=0, duration_s=2),
        ])
        report = await run_attack(plan, cfg)
        assert report['source_ips'] == ['10.70.0.5', '10.70.0.6']
        recv.close()
    asyncio.run(scenario())


def test_run_attack_coordinates_two_local_agents_against_a_real_socket():
    async def scenario():
        recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv.bind(('127.0.0.1', 0))
        recv.setblocking(False)
        port = recv.getsockname()[1]
        cfg = dict(
            nodes={'nodeA': {'adapter': 'local'}, 'nodeB': {'adapter': 'local'}},
            targets={'victim': {'host': '127.0.0.1', 'tcp_port': 1, 'udp_port': port, 'http_port': 1}},
            allowed_target_cidrs=['127.0.0.0/8'], max_clock_skew_s=2.0, start_lead_s=2.0,
        )
        plan = generate_attack_plan(seed=3, duration_s=10, flows=[
            dict(domain='mobile', sources=['nodeA', 'nodeB'], destination='victim',
                 wire_protocol='udp_flood', rate_pps=100, start_s=0, duration_s=3),
        ])
        report = await run_attack(plan, cfg)
        assert all(e['status'] == 'completed' for e in report['events'].values())
        # Tolerant to scheduler jitter under a loaded test machine: the
        # mechanism (coordinated real flows, no hping3) is what's under test,
        # not clock-cycle-exact pacing.
        total_sent = sum(e['packets_sent'] for e in report['events'].values())
        assert 500 <= total_sent <= 700  # target 600 (2 sources x 100pps x 3s)
        loop = asyncio.get_running_loop()
        received = 0
        try:
            while True:
                await asyncio.wait_for(loop.sock_recv(recv, 2000), 0.5)
                received += 1
        except asyncio.TimeoutError:
            pass
        assert received == total_sent
    asyncio.run(scenario())
