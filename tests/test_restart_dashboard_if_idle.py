import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import restart_dashboard_if_idle as guard


def test_skips_when_an_experiment_is_active(monkeypatch, capsys):
    """The single rule that matters most: never restart mid-run."""
    monkeypatch.setattr(guard, 'load_token', lambda: 'tok')
    monkeypatch.setattr(guard, 'has_active_run', lambda token: True)
    called = []
    monkeypatch.setattr(guard.subprocess, 'run', lambda *a, **k: called.append(a))
    guard.main()
    assert called == []
    assert 'active' in capsys.readouterr().out


def test_skips_when_restarted_too_recently(monkeypatch, capsys):
    monkeypatch.setattr(guard, 'load_token', lambda: 'tok')
    monkeypatch.setattr(guard, 'has_active_run', lambda token: False)
    monkeypatch.setattr(guard, 'seconds_since_last_start', lambda: guard.MIN_INTERVAL_S - 1)
    called = []
    monkeypatch.setattr(guard.subprocess, 'run', lambda *a, **k: called.append(a))
    guard.main()
    assert called == []
    assert 'since last start' in capsys.readouterr().out


def test_restarts_when_idle_and_old_enough(monkeypatch, capsys):
    monkeypatch.setattr(guard, 'load_token', lambda: 'tok')
    monkeypatch.setattr(guard, 'has_active_run', lambda token: False)
    monkeypatch.setattr(guard, 'seconds_since_last_start', lambda: guard.MIN_INTERVAL_S + 1)
    called = []
    monkeypatch.setattr(guard.subprocess, 'run', lambda *a, **k: called.append(a) or type('R', (), dict(returncode=0))())
    guard.main()
    assert called == [(['systemctl', 'restart', 'benign-lab-web'],)]
    assert 'restarting' in capsys.readouterr().out


def test_never_restarts_blind_if_the_active_run_check_itself_fails(monkeypatch, capsys):
    """If we can't confirm the server is idle, the safe default is to do
    nothing -- not to assume it's safe."""
    monkeypatch.setattr(guard, 'load_token', lambda: 'tok')
    def boom(token): raise RuntimeError('API unreachable')
    monkeypatch.setattr(guard, 'has_active_run', boom)
    called = []
    monkeypatch.setattr(guard.subprocess, 'run', lambda *a, **k: called.append(a))
    guard.main()
    assert called == []
    assert 'skip' in capsys.readouterr().out
