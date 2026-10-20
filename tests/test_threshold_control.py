import asyncio
import json
import pytest
from benign_lab.threshold_control import ThresholdControl, FIELDS


def make_control():
    cfg = {'baseline_control': {'host': '10.10.0.5', 'user': 'ops', 'pe_password_env': 'X', 'password_env': 'Y'}}
    return ThresholdControl(cfg)


def test_read_resolves_settings_path_from_live_systemd_unit_not_a_hardcoded_path():
    control = make_control()
    captured = {}
    async def fake_controller(code, timeout=25):
        captured['code'] = code
        return json.dumps(dict(values={}, config_sha256='x'))
    control.guard.controller = fake_controller
    asyncio.run(control.read())
    # Regression guard for the bug where this targeted a dead, never-imported
    # path (/opt/Tesis_Controller/config/settings.py) instead of the tree
    # ryu-manager's systemd unit actually runs out of.
    assert '/opt/Tesis_Controller' not in captured['code']
    assert "'systemctl','show','ryu-manager','-p','WorkingDirectory'" in captured['code']
    assert "Path(out.strip().split('=',1)[1])/'config'/'settings.py'" in captured['code']
    compile(captured['code'], '<remote>', 'exec')


def test_apply_resolves_settings_path_from_live_systemd_unit_not_a_hardcoded_path():
    control = make_control()
    captured = {}
    async def fake_ssh(host, user, command, root=False, payload=None, timeout=60):
        captured.update(host=host, user=user, command=command, root=root, payload=payload, timeout=timeout)
        return json.dumps(dict(applied={'SYN_THRESHOLD': 76.82}, config_sha256='y', controller_restarted=True))
    control.guard.ssh = fake_ssh
    result = asyncio.run(control.apply({'SYN_THRESHOLD': 76.82}, 'deadbeef'))
    assert result == dict(applied={'SYN_THRESHOLD': 76.82}, config_sha256='y', controller_restarted=True)
    assert captured['host'] == '10.10.0.5'
    assert captured['user'] == 'ops'
    assert captured['root'] is True
    assert '/opt/Tesis_Controller' not in captured['payload']
    assert "'systemctl','show','ryu-manager','-p','WorkingDirectory'" in captured['payload']
    assert "Path(out.strip().split('=',1)[1])/'config'/'settings.py'" in captured['payload']
    compile(captured['payload'], '<remote>', 'exec')


def test_apply_rejects_unsupported_fields_without_touching_ssh():
    control = make_control()
    calls = []
    async def fake_ssh(*a, **k): calls.append((a, k)); return '{}'
    control.guard.ssh = fake_ssh
    with pytest.raises(ValueError, match='Unsupported threshold fields'):
        asyncio.run(control.apply({'NOT_A_FIELD': 1}, 'deadbeef'))
    assert calls == []


def test_apply_rejects_non_finite_or_out_of_range_values_without_touching_ssh():
    control = make_control()
    calls = []
    async def fake_ssh(*a, **k): calls.append((a, k)); return '{}'
    control.guard.ssh = fake_ssh
    for bad in (float('inf'), -1, 0, True, 'x'):
        with pytest.raises(ValueError, match='Thresholds must be finite positive numbers'):
            asyncio.run(control.apply({'SYN_THRESHOLD': bad}, 'deadbeef'))
    assert calls == []


def test_fields_mapping_unchanged():
    assert FIELDS == {'DECISION_THRESHOLD', 'SYN_THRESHOLD', 'UDP_THRESHOLD', 'ICMP_THRESHOLD', 'DIST_PPS_THRESHOLD'}
