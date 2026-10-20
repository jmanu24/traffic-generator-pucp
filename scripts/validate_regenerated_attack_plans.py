"""ATTACK_PLAN_REGENERATION -- VALIDACION step (real lab, pipeline
suspended, test seed 201). Runs each of the 6 plans from
scripts/generate_regenerated_attack_plans.py once, with BaselineGuard
suspending actuation (no mitigation ever applies) and
DetectionAuditMonitor capturing the real controller's own LAB_AUDIT
observed_rates for the attack window. detection_mode is switched to
`isolated` for the duration of this script ONLY so observed_rates comes
back per-domain (composition 3's own pass criterion needs each domain's
own aggregate, not a merged multidomain group) -- this changes no
detection/decision/mitigation logic, only the pre-existing, already-used
DETECTION_CROSS_DOMAIN_CORRELATION orthogonal flag (D1,
detection_mode_control.py), and the live mode (multidomain, left over
from THRESHOLD_CALIBRATION's last validation run) is restored at the end
regardless of outcome. No detection-ACTIVE condition is run here --
actuation stays suspended throughout (PUNTO DE CONTROL).
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.config import load_lab
from benign_lab.baseline import BaselineGuard
from benign_lab.detection_mode_control import DetectionModeControl
from benign_lab.detection_audit import DetectionAuditMonitor
from benign_lab.attack_planner import validate_attack_plan
from benign_lab.attack_runner import run_attack

LAB_PATH = ROOT / 'config/lab.connected.yaml'
PRIVATE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab')
PLANS_DIR = ROOT / 'data' / 'attack_plans'
MANIFEST_PATH = ROOT / 'data' / 'attack_plans_manifest.json'
OUT_PATH = PRIVATE / 'calibration' / 'attack_plan_regeneration_validation.json'

ALIAS_GEN_TO_TELEMETRY = {'fixed': 'broadband', 'peering': 'bgp', 'enterprise': 'enterprise', 'mobile': 'mobile'}


async def wait_for_isolated_cycle(audit, since, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        cycle = next((x for x in audit.rows(since, time.time() + 1) if x.get('kind') == 'cycle'), None)
        if cycle is not None:
            return cycle
        await asyncio.sleep(1)
    raise RuntimeError('No LAB_AUDIT cycle observed after the detection_mode restart within the timeout')


def domain_trigger_pps(cycles, telemetry_domain, protocol='TCP_SYN'):
    """Max trigger_pps reported for this single-domain group across the
    given cycles (isolated mode: one group per domain, so 'domains'==[domain])."""
    best = None
    for rec in cycles:
        if rec.get('kind') != 'cycle' or not rec.get('observed_rates'):
            continue
        for group in rec['observed_rates']:
            if tuple(sorted(group.get('domains', []))) != (telemetry_domain,):
                continue
            proto = group.get('protocols', {}).get(protocol)
            if proto is None:
                continue
            rate = proto['trigger_pps']
            if best is None or rate > best:
                best = rate
    return best


async def main():
    secret = json.loads((PRIVATE / 'ssh.json').read_text())['password']
    os.environ['BENIGN_SSH_PASSWORD'] = secret
    os.environ['BENIGN_PE_SSH_PASSWORD'] = 'root'
    cfg = load_lab(LAB_PATH)
    manifest = json.loads(MANIFEST_PATH.read_text())

    dmc = DetectionModeControl(cfg)
    original_mode = (await dmc.read())['override']
    print(f'Current live detection_mode: {original_mode}', flush=True)

    audit = DetectionAuditMonitor(PRIVATE, dict(baseline_control=cfg['baseline_control'],
                                                 detection_audit=dict(enabled=True)))
    rows = []
    run_id = 'attack-plan-regen-validation-' + time.strftime('%Y%m%dT%H%M%S')
    total_duration = sum(json.loads((PLANS_DIR / f"{m['name']}.json").read_text())['duration_s'] for m in manifest)
    guard = BaselineGuard(cfg, run_id, int(total_duration) + 600)

    switched = False
    audit_task = None
    try:
        print('Switching detection_mode to isolated (per-domain observed_rates)...', flush=True)
        await dmc.apply('isolated')
        switched = True
        audit.enabled = True
        audit_task = asyncio.create_task(audit.collect())
        await asyncio.sleep(3)  # let the audit SSH stream connect before relying on it

        print('Suspending pipeline (BaselineGuard.enter())...', flush=True)
        await guard.enter()
        try:
            for m in manifest:
                plan = json.loads((PLANS_DIR / f"{m['name']}.json").read_text())
                validate_attack_plan(plan)
                print(f"--- {m['name']} (domains={plan['domains']}) ---", flush=True)
                since = time.time()
                report = await run_attack(plan, cfg, on_log=lambda s: print('  ' + s, flush=True))
                events = report['events']
                active = [e for e in events.values() if e.get('actual_start_s') is not None]
                window_start = report['started_at'] + min(e['actual_start_s'] for e in active) if active else None
                window_end = report['started_at'] + max(e['actual_end_s'] for e in active) if active else None
                await asyncio.sleep(3)  # let the last cycle(s) covering the window land
                cycles = audit.rows(since, time.time() + 1) if window_start else []
                per_domain = {}
                for e in events.values():
                    domain = e['domain']
                    telem = ALIAS_GEN_TO_TELEMETRY[domain]
                    per_domain.setdefault(domain, dict(
                        planned_per_source_pps=e['rate_pps'], sources=[],
                        attack_pps_target=[], attack_pps_actual=[]))
                    per_domain[domain]['sources'].append(e['source'])
                    per_domain[domain]['attack_pps_target'].append(e.get('attack_pps_target'))
                    per_domain[domain]['attack_pps_actual'].append(e.get('attack_pps_actual'))
                for domain, d in per_domain.items():
                    telem = ALIAS_GEN_TO_TELEMETRY[domain]
                    d['planned_aggregate_pps'] = d['planned_per_source_pps'] * len(d['sources'])
                    d['issued_aggregate_pps'] = sum(v for v in d['attack_pps_actual'] if v is not None)
                    d['observed_controller_trigger_pps'] = domain_trigger_pps(cycles, telem)
                rows.append(dict(name=m['name'], plan_hash=plan['plan_hash'],
                                  window_start=window_start, window_end=window_end,
                                  per_domain=per_domain))
                print('  result:', json.dumps(per_domain, default=str)[:500], flush=True)
                await asyncio.sleep(3)
        finally:
            print('Restoring pipeline (BaselineGuard.leave())...', flush=True)
            print(' ', await guard.leave(), flush=True)
    finally:
        if audit_task:
            audit_task.cancel()
            await asyncio.gather(audit_task, return_exceptions=True)
        audit.db.close()
        if switched and original_mode and original_mode != 'isolated':
            print(f'Restoring detection_mode to {original_mode}...', flush=True)
            await dmc.apply(original_mode)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(dict(seed=201, run_id=run_id, original_mode=original_mode, rows=rows), indent=2, default=str))
    print('Saved:', OUT_PATH)


if __name__ == '__main__':
    asyncio.run(main())
