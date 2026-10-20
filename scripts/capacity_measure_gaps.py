"""Paso 2 follow-up: measure the three gaps left by capacity_measure_attack.py
-- enterprise/peering ICMP (now that CAP_NET_RAW is set on those hosts)
and the full mobile row (ue5 excluded from BaselineGuard's mobile-budget
restoration -- ue1-4 are confirmed connected to the 5G core; ue5 is not,
a pre-existing lab state unrelated to this measurement)."""
import asyncio
import copy
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.config import load_lab
from benign_lab.baseline import BaselineGuard
from benign_lab.attack_planner import generate_attack_plan
from benign_lab.attack_runner import run_attack

LAB_PATH = ROOT / 'config/lab.connected.yaml'
PRIVATE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab')
TARGET_PPS = 50000
DURATION_S = 30
PACKET_SIZE_BYTES = 64

PLAN = [
    ('enterprise', 'ent-site-1', 'icmp_flood'),
    ('peering', 'peer-flow*', 'icmp_flood'),
    ('mobile', 'ue1', 'udp_flood'),
    ('mobile', 'ue1', 'syn_flood'),
    ('mobile', 'ue1', 'icmp_flood'),
]


async def main():
    secret = json.loads((PRIVATE / 'ssh.json').read_text())['password']
    os.environ['BENIGN_SSH_PASSWORD'] = secret
    os.environ['BENIGN_PE_SSH_PASSWORD'] = 'root'
    cfg = load_lab(LAB_PATH)
    # ue5 not in the 5G core session list right now. Only BaselineGuard's
    # mobile-budget restoration needs it excluded (restore_mobile_budgets
    # requires exactly one core session per configured ue1-5); run_attack()
    # uses the UNMODIFIED cfg below, since config.mapping_issues() requires
    # EVERY node to be configured=True regardless of what a given attack
    # plan actually uses -- a blanket inventory-completeness check, not an
    # attack-plan-scoped one. Marking ue5 unconfigured there would wrongly
    # block measuring other domains too.
    cfg_for_guard = copy.deepcopy(cfg)
    cfg_for_guard['nodes']['ue5']['configured'] = False
    run_id = 'capacity-gaps-' + time.strftime('%Y%m%dT%H%M%S')
    guard = BaselineGuard(cfg_for_guard, run_id, DURATION_S * len(PLAN) + 300)
    guard.domains = {'enterprise', 'peering', 'mobile'}
    results = []
    print('Suspending pipeline (BaselineGuard.enter())...', flush=True)
    try:
        preflight = await guard.enter()
        print('Pipeline suspended:', json.dumps(preflight, default=str)[:400], flush=True)
        for domain, source, vector in PLAN:
            print(f'--- {domain} / {vector} / source={source} ---', flush=True)
            plan = generate_attack_plan(
                seed=42, duration_s=DURATION_S,
                flows=[dict(domain=domain, sources=[source], destination='victim-web',
                            wire_protocol=vector, rate_pps=TARGET_PPS, start_s=0,
                            duration_s=DURATION_S, packet_size_bytes=PACKET_SIZE_BYTES)],
                description=f'capacity-gaps {domain}/{vector}')
            try:
                report = await run_attack(plan, cfg, on_log=lambda m: print('  ' + m, flush=True))
                event = next(iter(report['events'].values()))
                row = dict(domain=domain, vector=vector, source=source,
                           attack_pps_target=event.get('attack_pps_target'),
                           attack_pps_actual=event.get('attack_pps_actual'),
                           packets_sent=event.get('packets_sent'), error=event.get('error'))
            except Exception as exc:
                row = dict(domain=domain, vector=vector, source=source, error=str(exc))
            print('  result:', row, flush=True)
            results.append(row)
            await asyncio.sleep(3)
    finally:
        print('Restoring pipeline (BaselineGuard.leave())...', flush=True)
        print('Pipeline restored:', await guard.leave(), flush=True)
    out = PRIVATE / 'calibration' / 'attack_capacity_measurement_gaps.json'
    out.write_text(json.dumps(dict(target_pps=TARGET_PPS, duration_s=DURATION_S,
                                    packet_size_bytes=PACKET_SIZE_BYTES, results=results), indent=2))
    print('Saved:', out)


if __name__ == '__main__':
    asyncio.run(main())
