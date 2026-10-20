import asyncio
import json
import pytest
from benign_lab.detection_mode_control import DetectionModeControl, MODES


def make_control():
    cfg = {'baseline_control': {'host': '10.10.0.5', 'user': 'ops', 'pe_password_env': 'X', 'password_env': 'Y'}}
    return DetectionModeControl(cfg)


def test_apply_rejects_unknown_mode_without_touching_ssh():
    control = make_control()
    calls = []
    async def fake_ssh(*a, **k): calls.append((a, k)); return '{}'
    control.guard.ssh = fake_ssh
    with pytest.raises(ValueError, match='Unsupported detection mode'):
        asyncio.run(control.apply('both'))
    assert calls == []


@pytest.mark.parametrize('mode,expected_value', [('isolated', 'false'), ('multidomain', 'true')])
def test_apply_targets_configured_host_as_root_with_expected_flag_value(mode, expected_value):
    control = make_control()
    captured = {}
    async def fake_ssh(host, user, command, root=False, payload=None, timeout=25):
        captured.update(host=host, user=user, command=command, root=root, payload=payload, timeout=timeout)
        return json.dumps(dict(applied=mode, controller_restarted=True))
    control.guard.ssh = fake_ssh
    result = asyncio.run(control.apply(mode))
    assert result == dict(applied=mode, controller_restarted=True)
    assert captured['host'] == '10.10.0.5'
    assert captured['user'] == 'ops'
    assert captured['root'] is True
    assert captured['command'] == 'python3 -'
    assert "value='" + expected_value + "'" in captured['payload']
    assert 'DETECTION_CROSS_DOMAIN_CORRELATION=' in captured['payload']
    assert '/run/systemd/system/ryu-manager.service.d' in captured['payload']
    assert 'lease.json' in captured['payload']
    assert "mode='" + mode + "'" in captured['payload']


def test_modes_mapping_covers_isolated_and_multidomain_only():
    assert MODES == {'isolated': 'false', 'multidomain': 'true'}


def test_read_uses_controller_channel_not_root_ssh():
    control = make_control()
    captured = {}
    async def fake_controller(code, timeout=25):
        captured['code'] = code
        return json.dumps(dict(override='multidomain'))
    control.guard.controller = fake_controller
    result = asyncio.run(control.read())
    assert result == dict(override='multidomain')
    assert 'DETECTION_CROSS_DOMAIN_CORRELATION' in captured['code']
