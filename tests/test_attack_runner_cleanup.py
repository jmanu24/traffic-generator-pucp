"""D7: attack_runner.py's pre-flight stale-attack-process sweep -- defense
in depth for leftover `hping3` processes from earlier runs (see
agent.py's own attack_flood() fix and docs/ for the root cause: sudo's
pty monitor doesn't forward SIGKILL to its own hping3 child, so a run
whose own cleanup never got a chance to run can leave it flooding for
hours). Confirmed live 2026-10-22: found on enterprise AND mobile/fixed
attack hosts, hours after the runs that spawned them had finished."""
import asyncio
from unittest import mock
import pytest
from benign_lab.attack_runner import _sweep_stale_attack_processes


def _group(node):
    return dict(node=node, context={}, events=[], sources=set())


class _FakeProc:
    def __init__(self, raises=None):
        self._raises = raises

    async def wait(self):
        if self._raises:
            raise self._raises


def test_sweeps_each_unique_ssh_host_exactly_once(monkeypatch):
    monkeypatch.setenv('BENIGN_SSH_PASSWORD', 'secret')
    groups = {
        'a': _group(dict(adapter='ssh', host='10.10.0.21', user='labadmin', password_env='BENIGN_SSH_PASSWORD', auth_mode='password_env')),
        'b': _group(dict(adapter='ssh', host='10.10.0.21', user='labadmin', password_env='BENIGN_SSH_PASSWORD', auth_mode='password_env')),
        'c': _group(dict(adapter='ssh', host='10.10.0.22', user='labadmin', password_env='BENIGN_SSH_PASSWORD', auth_mode='password_env')),
    }
    calls = []

    async def fake_exec(*args, **kwargs):
        calls.append((args, kwargs.get('env')))
        return _FakeProc()

    async def scenario():
        with mock.patch('asyncio.create_subprocess_exec', side_effect=fake_exec):
            await _sweep_stale_attack_processes(groups)
    asyncio.run(scenario())

    # Two distinct hosts (a/b share one) -> exactly 2 ssh invocations, not 3.
    assert len(calls) == 2
    hosts = {args[-2].split('@')[1] for args, _ in calls}
    assert hosts == {'10.10.0.21', '10.10.0.22'}
    args, env = calls[0]
    assert args[:2] == ('sshpass', '-e')
    assert args[-1] == 'sudo -n pkill -9 -f hping3; true'
    assert env['SSHPASS'] == 'secret'


def test_skips_non_ssh_adapters():
    groups = {'a': _group(dict(adapter='local'))}
    calls = []

    async def fake_exec(*args, **kwargs):
        calls.append(args)
        return _FakeProc()

    async def scenario():
        with mock.patch('asyncio.create_subprocess_exec', side_effect=fake_exec):
            await _sweep_stale_attack_processes(groups)
    asyncio.run(scenario())
    assert calls == []


def test_skips_a_host_with_no_resolvable_password(monkeypatch):
    monkeypatch.delenv('BENIGN_SSH_PASSWORD', raising=False)
    groups = {'a': _group(dict(adapter='ssh', host='10.10.0.21', user='labadmin',
                                password_env='BENIGN_SSH_PASSWORD', auth_mode='password_env'))}
    calls = []

    async def fake_exec(*args, **kwargs):
        calls.append(args)
        return _FakeProc()

    async def scenario():
        with mock.patch('asyncio.create_subprocess_exec', side_effect=fake_exec):
            await _sweep_stale_attack_processes(groups)
    asyncio.run(scenario())
    assert calls == []


@pytest.mark.parametrize('failure', [OSError('unreachable'), asyncio.TimeoutError()])
def test_a_failed_sweep_on_one_host_never_raises(monkeypatch, failure):
    """Unreachable host, no sudo rule, slow connection -- this is a
    best-effort cleanup sweep, not a gate: it must never block the run's
    own, fresh attack dispatch."""
    monkeypatch.setenv('BENIGN_SSH_PASSWORD', 'secret')
    groups = {'a': _group(dict(adapter='ssh', host='10.10.0.21', user='labadmin',
                                password_env='BENIGN_SSH_PASSWORD', auth_mode='password_env'))}

    async def fake_exec(*args, **kwargs):
        if isinstance(failure, OSError):
            raise failure
        return _FakeProc(raises=failure)

    async def scenario():
        with mock.patch('asyncio.create_subprocess_exec', side_effect=fake_exec):
            await _sweep_stale_attack_processes(groups)  # must not raise
    asyncio.run(scenario())


def test_known_hosts_file_is_passed_through_when_configured():
    groups = {'a': _group(dict(adapter='ssh', host='10.10.0.21', user='labadmin',
                                password_env='BENIGN_SSH_PASSWORD', auth_mode='password_env',
                                known_hosts_file='/home/ubuntu/.ssh/known_hosts'))}
    calls = []

    async def fake_exec(*args, **kwargs):
        calls.append(args)
        return _FakeProc()

    async def scenario():
        import os
        os.environ['BENIGN_SSH_PASSWORD'] = 'secret'
        with mock.patch('asyncio.create_subprocess_exec', side_effect=fake_exec):
            await _sweep_stale_attack_processes(groups)
    asyncio.run(scenario())
    assert '-o' in calls[0] and 'UserKnownHostsFile=/home/ubuntu/.ssh/known_hosts' in calls[0]


def test_on_log_reports_the_number_of_hosts_checked(monkeypatch):
    monkeypatch.setenv('BENIGN_SSH_PASSWORD', 'secret')
    groups = {'a': _group(dict(adapter='ssh', host='10.10.0.21', user='labadmin',
                                password_env='BENIGN_SSH_PASSWORD', auth_mode='password_env'))}
    messages = []

    async def fake_exec(*args, **kwargs):
        return _FakeProc()

    async def scenario():
        with mock.patch('asyncio.create_subprocess_exec', side_effect=fake_exec):
            await _sweep_stale_attack_processes(groups, on_log=messages.append)
    asyncio.run(scenario())
    assert any('1 host' in m for m in messages)


def test_no_log_when_there_is_nothing_to_sweep():
    messages = []

    async def scenario():
        await _sweep_stale_attack_processes({}, on_log=messages.append)
    asyncio.run(scenario())
    assert messages == []
