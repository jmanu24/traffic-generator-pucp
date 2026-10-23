"""D1 (detection_mode switch+verification) and D5 (integrated attack_runner)
integration tests against Manager.start()/execute(), with the real SSH
(DetectionModeControl, run_attack) and BaselineGuard fully mocked -- these
never touch a network or a real controller."""
import asyncio
import json
import time
import pytest
from benign_lab.config import ROOT, load_lab
from benign_lab.planner import generate, load_profiles, save_plan
from benign_lab.attack_planner import generate_attack_plan, save_attack_plan
from benign_lab.runner import Manager
import benign_lab.runner as runner


class FakeAudit:
    """Minimal stand-in for DetectionAuditMonitor: .enabled + .rows().
    Reports a single kind=cycle record with its timestamp always equal to
    whatever `end` the caller queried with -- avoids a real audit stream's
    actual timing races (apply_detection_mode's polling window moves every
    call) without needing this fake to guess the right wall-clock moment."""
    def __init__(self, enabled=True, value=None):
        self.enabled = enabled
        self.value = value

    def rows(self, start, end, after=0):
        if self.value is None:
            return []
        return [dict(kind='cycle', event_id='e1', timestamp=end,
                     thresholds={'values': {'DETECTION_CROSS_DOMAIN_CORRELATION': self.value}})]


class StaleThenFreshAudit:
    """Reproduces the exact live-lab bug (2026-10-19): a cycle emitted by
    the OLD mode just before a slow restart can still have timestamp >=
    a `since` captured too early, and gets picked up as if it were
    post-restart evidence. stale_at sits strictly between the request
    and SlowControl.apply()'s return -- only correct if `since` is
    captured AFTER apply() returns, not before."""
    def __init__(self, stale_at, stale_value, fresh_value):
        self.enabled = True
        self.stale_at = stale_at
        self.stale_value = stale_value
        self.fresh_value = fresh_value

    def rows(self, start, end, after=0):
        rows = []
        if start <= self.stale_at <= end:
            rows.append(dict(kind='cycle', event_id='stale', timestamp=self.stale_at,
                              thresholds={'values': {'DETECTION_CROSS_DOMAIN_CORRELATION': self.stale_value}}))
        rows.append(dict(kind='cycle', event_id='fresh', timestamp=end,
                          thresholds={'values': {'DETECTION_CROSS_DOMAIN_CORRELATION': self.fresh_value}}))
        return rows


class FakeGuard:
    def __init__(self, cfg, rid, duration): self.rid = rid
    async def enter(self): return {'active': True}
    async def leave(self): return {'restored': True}
    async def monitor(self): await asyncio.Event().wait()
    async def status(self): return {'active': True, 'cleared': True, 'run_id': self.rid}


def base_cfg():
    cfg = load_lab(ROOT / 'config/lab.demo.yaml')
    cfg['baseline_control'] = {'host': 'orchestrator', 'user': 'ops'}
    return cfg


def plan_and_manager(tmp_path, seed=1, duration=5):
    p = generate(load_profiles(ROOT / 'profiles'), seed, duration)
    f = save_plan(p, tmp_path / 'plan.json')
    return p, f, Manager(tmp_path / 'runs')


async def _noop(*a, **k): return None


def bare_run(m, rid, **fields):
    """A minimal run record for exercising a single Manager method
    directly (apply_detection_mode, record_attack_evidence) without going
    through the full start()/execute() pipeline. persist_async() is
    stubbed out since it reads benign_plan.json from a run folder that
    only start() creates -- irrelevant to what these tests check."""
    m.runs[rid] = dict(id=rid, **fields)
    m.logs[rid] = []
    m.events.setdefault(rid, {})
    m.folder(rid).mkdir(parents=True, exist_ok=True)
    m.persist_async = _noop
    return m.runs[rid]


@pytest.mark.parametrize('mode', ['isolated', 'multidomain'])
def test_apply_detection_mode_succeeds_with_matching_audit_evidence(tmp_path, monkeypatch, mode):
    """Both evidences agree -> run proceeds and records verification."""
    m = Manager(tmp_path / 'runs')
    cfg = base_cfg()
    applied = []
    class Control:
        def __init__(self, cfg): pass
        async def read(self): return {'override': None}
        async def apply(self, requested):
            applied.append(requested)
            return dict(applied=requested, controller_restarted=True)
    monkeypatch.setattr(runner, 'DetectionModeControl', Control)
    m.audit = FakeAudit(value=(mode == 'multidomain'))
    bare_run(m, 'x')
    async def run():
        await m.apply_detection_mode('x', cfg, mode)
        return m.runs['x']
    r = asyncio.run(run())
    assert applied == [mode]
    assert r['detection_mode_verification']['requested'] == mode
    assert r['detection_mode_verification']['audit_cycle_evidence']['value'] == (mode == 'multidomain')


@pytest.mark.parametrize('mode', ['isolated', 'multidomain'])
def test_apply_detection_mode_skips_restart_when_already_in_requested_mode(tmp_path, monkeypatch, mode):
    """D7-pilot: a campaign that groups consecutive runs by detection_mode
    (im_campaign.build_schedule) must not restart ryu-manager before every
    single one of them -- only the first run of a mode group should pay
    for the restart. apply() itself must never be called when .read()
    already reports the requested mode; the audit-based second evidence
    is still collected (cheap, no restart)."""
    m = Manager(tmp_path / 'runs')
    cfg = base_cfg()
    applied = []
    class Control:
        def __init__(self, cfg): pass
        async def read(self): return {'override': mode}
        async def apply(self, requested):
            applied.append(requested)
            return dict(applied=requested, controller_restarted=True)
    monkeypatch.setattr(runner, 'DetectionModeControl', Control)
    m.audit = FakeAudit(value=(mode == 'multidomain'))
    bare_run(m, 'x')
    async def run():
        await m.apply_detection_mode('x', cfg, mode)
        return m.runs['x']
    r = asyncio.run(run())
    assert applied == []  # apply() (and its restart) was never called
    assert r['detection_mode_verification']['requested'] == mode
    assert r['detection_mode_verification']['log_evidence'] == dict(applied=mode, controller_restarted=False, already_applied=True)
    assert r['detection_mode_verification']['audit_cycle_evidence']['value'] == (mode == 'multidomain')


def test_apply_detection_mode_still_restarts_when_mode_differs_from_current(tmp_path, monkeypatch):
    """The skip is exact-match only: a different current mode must still
    go through apply()/restart, never silently skipped."""
    m = Manager(tmp_path / 'runs')
    cfg = base_cfg()
    applied = []
    class Control:
        def __init__(self, cfg): pass
        async def read(self): return {'override': 'isolated'}
        async def apply(self, requested):
            applied.append(requested)
            return dict(applied=requested, controller_restarted=True)
    monkeypatch.setattr(runner, 'DetectionModeControl', Control)
    m.audit = FakeAudit(value=True)
    bare_run(m, 'x')
    async def run():
        await m.apply_detection_mode('x', cfg, 'multidomain')
        return m.runs['x']
    r = asyncio.run(run())
    assert applied == ['multidomain']
    assert r['detection_mode_verification']['log_evidence'] == dict(applied='multidomain', controller_restarted=True)


def test_since_is_captured_after_apply_not_before_the_slow_restart(tmp_path, monkeypatch):
    """Live-lab regression (2026-10-19): every one of 4 consecutive real
    calibration runs failed verification, always reading the PREVIOUS
    mode -- not a rare boundary race. Root cause: `since` was captured
    before calling DetectionModeControl.apply(), which is itself the
    slow SSH restart; any old-mode cycle emitted during that restart
    still had timestamp >= that too-early `since` and got picked up as
    if it were post-restart evidence. Fixed by capturing `since` after
    apply() returns. This reproduces it with a deliberately slow apply()
    and a stale cycle timestamped to land squarely in the gap."""
    m = Manager(tmp_path / 'runs')
    cfg = base_cfg()
    t0 = time.time()
    stale_at = t0 + 0.03
    class SlowControl:
        def __init__(self, cfg): pass
        async def read(self): return {'override': None}
        async def apply(self, requested):
            await asyncio.sleep(0.08)  # stale_at falls inside this window
            return dict(applied=requested, controller_restarted=True)
    monkeypatch.setattr(runner, 'DetectionModeControl', SlowControl)
    m.audit = StaleThenFreshAudit(stale_at=stale_at, stale_value=False, fresh_value=True)
    bare_run(m, 'x')
    async def run():
        await m.apply_detection_mode('x', cfg, 'multidomain')
        return m.runs['x']
    r = asyncio.run(run())  # must NOT raise on the stale (False) cycle
    assert r['detection_mode_verification']['audit_cycle_evidence']['value'] is True


def test_isolated_request_cannot_be_verified_against_a_multidomain_audit_record(tmp_path, monkeypatch):
    """The exact failure mode asked for: requesting I (isolated) must not
    silently accept a LAB_AUDIT cycle snapshot that still reports M
    (multidomain) -- e.g. a stale/leftover controller process that never
    actually restarted into the requested mode."""
    m = Manager(tmp_path / 'runs')
    cfg = base_cfg()
    class Control:
        def __init__(self, cfg): pass
        async def read(self): return {'override': None}
        async def apply(self, requested):
            return dict(applied=requested, controller_restarted=True)
    monkeypatch.setattr(runner, 'DetectionModeControl', Control)
    m.audit = FakeAudit(value=True)
    bare_run(m, 'x')
    async def run():
        await m.apply_detection_mode('x', cfg, 'isolated')
    with pytest.raises(RuntimeError, match='DETECTION_CROSS_DOMAIN_CORRELATION'):
        asyncio.run(run())


def test_apply_detection_mode_requires_audit_collector_enabled(tmp_path, monkeypatch):
    m = Manager(tmp_path / 'runs')
    cfg = base_cfg()
    class Control:
        def __init__(self, cfg): pass
        async def read(self): return {'override': None}
        async def apply(self, requested): return dict(applied=requested)
    monkeypatch.setattr(runner, 'DetectionModeControl', Control)
    m.audit = None
    bare_run(m, 'x')
    async def run():
        await m.apply_detection_mode('x', cfg, 'isolated')
    with pytest.raises(RuntimeError, match='LAB_AUDIT'):
        asyncio.run(run())


def test_lab_enabled_run_requires_detection_mode_when_baseline_control_configured(tmp_path):
    p, f, m = plan_and_manager(tmp_path)
    cfg = base_cfg()
    with pytest.raises(ValueError, match='detection_mode is required'):
        asyncio.run(m.start(p, f, cfg, mode='lab', speed=1, pipeline='enabled'))


def test_full_run_fails_in_preparation_on_detection_mode_mismatch(tmp_path, monkeypatch):
    """End-to-end through start()/execute(): a verification mismatch must
    fail the run BEFORE any traffic/agent preparation (real() is never
    called)."""
    monkeypatch.setattr(runner, 'BaselineGuard', FakeGuard)
    real_called = []
    async def real(self, rid, *a, **k): real_called.append(True)
    monkeypatch.setattr(runner.Manager, 'real', real)
    class Control:
        def __init__(self, cfg): pass
        async def read(self): return {'override': None}
        async def apply(self, requested): return dict(applied=requested, controller_restarted=True)
    monkeypatch.setattr(runner, 'DetectionModeControl', Control)
    p, f, m = plan_and_manager(tmp_path)
    cfg = base_cfg()
    m.audit = FakeAudit(value=True)
    async def run():
        r = await m.start(p, f, cfg, mode='lab', speed=1, pipeline='enabled', detection_mode='isolated')
        await m.tasks[r['id']]
        return m.runs[r['id']]
    r = asyncio.run(run())
    assert r['status'] == 'failed'
    assert 'DETECTION_CROSS_DOMAIN_CORRELATION' in r['error']
    assert real_called == []


def test_full_run_verifies_mode_then_proceeds_to_traffic(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, 'BaselineGuard', FakeGuard)
    async def real(self, rid, *a, **k):
        for e in self.events[rid].values(): e['status'] = 'completed'
    monkeypatch.setattr(runner.Manager, 'real', real)
    class Control:
        def __init__(self, cfg): pass
        async def read(self): return {'override': None}
        async def apply(self, requested): return dict(applied=requested, controller_restarted=True)
    monkeypatch.setattr(runner, 'DetectionModeControl', Control)
    p, f, m = plan_and_manager(tmp_path)
    cfg = base_cfg()
    m.audit = FakeAudit(value=False)
    async def run():
        r = await m.start(p, f, cfg, mode='lab', speed=1, pipeline='enabled', detection_mode='isolated')
        await m.tasks[r['id']]
        return m.runs[r['id']]
    r = asyncio.run(run())
    assert r['status'] == 'completed', r.get('error')
    assert r['detection_mode_verification']['requested'] == 'isolated'


def test_record_attack_evidence_marks_window_from_packets_sent_only(tmp_path):
    m = Manager(tmp_path / 'runs')
    rid = 'x'
    bare_run(m, rid, attack_plan_hash='abc123456789', observed_attacks=[])
    report = dict(started_at=100.0, finished_at=110.0, source_ips=['10.70.0.5'], events={
        'e1': dict(packets_sent=50, actual_start_s=1.0, actual_end_s=3.0, attack_pps_target=50, attack_pps_actual=49.5, error=None),
        'e2': dict(packets_sent=0, actual_start_s=None, actual_end_s=None, attack_pps_target=50, attack_pps_actual=None, error='clock skew'),
    })
    m.record_attack_evidence(rid, report)
    r = m.runs[rid]
    assert r['attack_source_ips'] == ['10.70.0.5']
    assert len(r['observed_attacks']) == 1
    window = r['observed_attacks'][0]
    assert window['start_s'] == 1.0 and window['end_s'] == 3.0
    assert window['annotation_source'] == 'attack_runner'
    assert r['attack_runner_report']['events']['e2']['error'] == 'clock skew'


def test_record_attack_evidence_marks_nothing_when_no_event_sent_traffic(tmp_path):
    m = Manager(tmp_path / 'runs')
    rid = 'x'
    bare_run(m, rid, attack_plan_hash='abc', observed_attacks=[])
    report = dict(started_at=100.0, finished_at=110.0, source_ips=[], events={
        'e1': dict(packets_sent=0, actual_start_s=None, actual_end_s=None, attack_pps_target=50, attack_pps_actual=None, error='refused'),
    })
    m.record_attack_evidence(rid, report)
    assert m.runs[rid]['observed_attacks'] == []


def test_integrated_attack_run_end_to_end_marks_attack_window(tmp_path, monkeypatch):
    """D5 full path: start() with an attack_plan, execute() launches a
    (mocked) run_attack synchronized to the benign start, and
    observed_attacks ends up populated automatically -- no manual
    annotate() call anywhere in this test."""
    monkeypatch.setattr(runner, 'BaselineGuard', FakeGuard)
    started_epochs = {}
    async def real(self, rid, plan, cfg, groups, before_start=None, on_start=None):
        if before_start: await before_start()
        epoch = __import__('time').time() + 0.01
        if on_start: on_start(epoch)
        started_epochs[rid] = epoch
        for e in self.events[rid].values(): e['status'] = 'completed'
    monkeypatch.setattr(runner.Manager, 'real', real)
    captured_lead = {}
    async def fake_run_attack(plan, cfg, start_lead_s=None, on_log=None):
        captured_lead['lead'] = start_lead_s
        return dict(started_at=__import__('time').time(), finished_at=__import__('time').time() + 1,
                    source_ips=['10.70.0.9'],
                    events={e['event_id']: dict(packets_sent=10, actual_start_s=0.0, actual_end_s=1.0,
                                                 attack_pps_target=10, attack_pps_actual=10, error=None)
                            for e in plan['events']})
    monkeypatch.setattr(runner, 'run_attack', fake_run_attack)
    p, f, m = plan_and_manager(tmp_path, duration=10)
    cfg = base_cfg()  # pipeline='baseline' requires baseline_control regardless of detection_mode
    attack_plan = generate_attack_plan(seed=1, duration_s=10, flows=[
        dict(domain='enterprise', sources=['ent-site-1'], destination='victim',
             wire_protocol='udp_flood', rate_pps=10, start_s=2, duration_s=3),
    ])
    attack_file = save_attack_plan(attack_plan, tmp_path / 'attack.json')
    async def run():
        r = await m.start(p, f, cfg, mode='lab', scenario='B0+attack', speed=1, pipeline='baseline',
                           attack_plan=attack_plan, attack_plan_file=attack_file)
        await m.tasks[r['id']]
        return m.runs[r['id']]
    r = asyncio.run(run())
    assert r['status'] == 'completed', r.get('error')
    assert r['attack_plan_hash'] == attack_plan['plan_hash']
    assert r['attack_source_ips'] == ['10.70.0.9']
    assert len(r['observed_attacks']) == 1
    assert r['observed_attacks'][0]['annotation_source'] == 'attack_runner'
    assert abs(captured_lead['lead']) < 1  # synchronized to the benign epoch, not cfg's own start_lead_s default
