"""/api/attacks/* endpoints: plan generation/listing (pure) and a real,
local, end-to-end dispatch using config/lab.demo.yaml's loopback targets
(the same mechanism that would run against real lab clients)."""
import socket
from fastapi.testclient import TestClient
from benign_lab.api import create_app
from benign_lab.config import ROOT


def client(tmp_path):
    return TestClient(create_app(tmp_path, ROOT/'config/lab.demo.yaml'))


def test_create_list_and_get_attack_plan(tmp_path):
    with client(tmp_path) as c:
        body = dict(seed=42, duration_s=60, description='test', flows=[
            dict(domain='mobile', sources=['ue1', 'ue2'], destination='victim-web',
                 wire_protocol='udp_flood', rate_pps=50, start_s=0, duration_s=5),
        ])
        created = c.post('/api/attacks/plans', json=body)
        assert created.status_code == 200, created.text
        ph = created.json()['plan_hash']
        assert created.json()['events'] == 2

        listed = c.get('/api/attacks/plans').json()
        assert any(p['plan_hash'] == ph for p in listed)

        fetched = c.get(f'/api/attacks/plans/{ph}').json()
        assert fetched['plan_hash'] == ph and fetched['profile'] == 'ATTACK_FLOOD_V1'


def test_create_attack_plan_rejects_invalid_flows(tmp_path):
    with client(tmp_path) as c:
        body = dict(seed=1, duration_s=60, flows=[
            dict(domain='mobile', sources=['ue1'], destination='victim-web',
                 wire_protocol='udp_flood', rate_pps=50, start_s=100, duration_s=5),
        ])
        r = c.post('/api/attacks/plans', json=body)
        assert r.status_code == 400


def test_start_attack_requires_confirmation(tmp_path):
    with client(tmp_path) as c:
        body = dict(seed=2, duration_s=60, flows=[
            dict(domain='mobile', sources=['ue1'], destination='victim-web',
                 wire_protocol='udp_flood', rate_pps=50, start_s=0, duration_s=1),
        ])
        ph = c.post('/api/attacks/plans', json=body).json()['plan_hash']
        r = c.post('/api/attacks/start', json=dict(plan_hash=ph))
        assert r.status_code == 400


def test_start_attack_dispatches_real_local_flows_end_to_end(tmp_path):
    recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv.bind(('127.0.0.1', 9002))
    recv.settimeout(3)
    try:
        with client(tmp_path) as c:
            body = dict(seed=3, duration_s=60, flows=[
                dict(domain='mobile', sources=['ue1'], destination='victim-web',
                     wire_protocol='udp_flood', rate_pps=100, start_s=0, duration_s=1,
                     packet_size_bytes=64),
            ])
            ph = c.post('/api/attacks/plans', json=body).json()['plan_hash']
            r = c.post('/api/attacks/start', json=dict(plan_hash=ph, confirm=True))
            assert r.status_code == 200, r.text
            report = r.json()
            assert all(e['status'] == 'completed' for e in report['events'].values())
            assert sum(e['packets_sent'] for e in report['events'].values()) > 0
        received = 0
        try:
            while True:
                recv.recvfrom(2000)
                received += 1
        except socket.timeout:
            pass
        assert received > 0
    finally:
        recv.close()


def test_start_attack_blocks_while_an_experiment_is_active(tmp_path):
    with client(tmp_path) as c:
        p = c.post('/api/plans', json=dict(seed=1, duration_s=600, capacity_mbps=dict.fromkeys(
            ['mobile', 'fixed', 'enterprise', 'peering'], 100))).json()
        c.post('/api/runs', json=dict(plan_hash=p['plan_hash'], mode='simulation', speed=100))
        body = dict(seed=4, duration_s=60, flows=[
            dict(domain='mobile', sources=['ue1'], destination='victim-web',
                 wire_protocol='udp_flood', rate_pps=50, start_s=0, duration_s=1),
        ])
        ph = c.post('/api/attacks/plans', json=body).json()['plan_hash']
        r = c.post('/api/attacks/start', json=dict(plan_hash=ph, confirm=True))
        assert r.status_code == 409
