"""Attack generation: real flows from real clients, no hping3, no receiver cooperation."""
import asyncio
import socket
import time
import pytest
from benign_lab.agent import attack_flood, _icmp_checksum, _icmp_echo_packet
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
