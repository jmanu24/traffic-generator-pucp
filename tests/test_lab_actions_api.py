"""/api/lab/* endpoints: wiring, confirmation guard, busy-experiment guard.

lab_actions itself is mocked here (it would otherwise call the real govc/SSH
tooling, which only makes sense against the real 23-VM lab); see
tests/test_lab_actions.py for the module's own tests.
"""
import json
from fastapi.testclient import TestClient
from benign_lab.api import create_app
from benign_lab.config import ROOT
from benign_lab import lab_actions


def client(tmp_path):
    return TestClient(create_app(tmp_path, ROOT/'config/lab.demo.yaml'))


def test_power_states_is_read_only_and_needs_no_confirmation(monkeypatch, tmp_path):
    monkeypatch.setattr(lab_actions, 'power_states', lambda: {'ue1': 'poweredOn'})
    with client(tmp_path) as c:
        r = c.get('/api/lab/power-states')
        assert r.status_code == 200 and r.json() == {'ue1': 'poweredOn'}


def test_connectivity_check_passes_the_domain_through(monkeypatch, tmp_path):
    seen = {}
    def fake(domain, command='echo ok'):
        seen['domain'] = domain
        return {'n1': {'ok': True}}
    monkeypatch.setattr(lab_actions, 'connectivity_check', fake)
    with client(tmp_path) as c:
        r = c.get('/api/lab/connectivity/mobile')
        assert r.status_code == 200
        assert seen['domain'] == 'mobile'


def test_connectivity_check_maps_unknown_domain_to_400(monkeypatch, tmp_path):
    def fake(domain, command='echo ok'):
        raise ValueError(f'Unknown or empty domain: {domain}')
    monkeypatch.setattr(lab_actions, 'connectivity_check', fake)
    with client(tmp_path) as c:
        assert c.get('/api/lab/connectivity/satellite').status_code == 400


def test_power_domain_requires_explicit_confirmation(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(lab_actions, 'power_domain', lambda d, on: calls.append((d, on)) or {'vm1': True})
    with client(tmp_path) as c:
        r = c.post('/api/lab/power/mobile/off', json={})
        assert r.status_code == 400
        assert not calls
        r = c.post('/api/lab/power/mobile/off', json={'confirm': True})
        assert r.status_code == 200
        assert calls == [('mobile', False)]


def test_power_domain_blocks_while_an_experiment_is_active(monkeypatch, tmp_path):
    with client(tmp_path) as c:
        p = c.post('/api/plans', json=dict(seed=1, duration_s=600, capacity_mbps=dict.fromkeys(
            ['mobile', 'fixed', 'enterprise', 'peering'], 100))).json()
        c.post('/api/runs', json=dict(plan_hash=p['plan_hash'], mode='simulation', speed=100))
        monkeypatch.setattr(lab_actions, 'power_domain', lambda d, on: {'vm1': True})
        r = c.post('/api/lab/power/mobile/on', json={'confirm': True})
        assert r.status_code == 409


def test_recover_domain_requires_confirmation_and_passes_domain(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(lab_actions, 'recover_domain', lambda d: seen.setdefault('domain', d) or {'ok': True})
    with client(tmp_path) as c:
        assert c.post('/api/lab/recover/fixed', json={}).status_code == 400
        r = c.post('/api/lab/recover/fixed', json={'confirm': True})
        assert r.status_code == 200 and seen['domain'] == 'fixed'
