"""Paso 2 (THRESHOLD_CALIBRATION): measure the real achievable attack_pps
per single source per domain per vector, pipeline suspended (baseline).

Methodology (stated explicitly, confirmed with the user before running):
attack_flood (benign_lab/agent.py) PACES itself to the requested
rate_pps -- it does not run flat-out by default. To measure the true
ceiling (not just "did it hit whatever target I guessed"), this sets an
intentionally unreachable target (TARGET_PPS) for every vector, so
pacing never binds and attack_pps_actual reports the real unthrottled
maximum this one source/process can sustain for DURATION_S seconds.
Single pass per (domain, vector) -- not a probe-then-confirm two-phase
search -- to bound real-lab time; see the written report for why.
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
from benign_lab.attack_planner import generate_attack_plan
from benign_lab.attack_runner import run_attack

LAB_PATH = ROOT / 'config/lab.connected.yaml'
PRIVATE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab')
TARGET_PPS = 50000  # intentionally unreachable -> pacing never binds
DURATION_S = 30
PACKET_SIZE_BYTES = 64

DOMAIN_SOURCES = {
    'fixed': 'fixed1',
    'enterprise': 'ent-site-1',
    'peering': 'peer-flow*',
}
# mobile excluded from THIS run: BaselineGuard.enter()'s mobile-budget
# restoration failed on ue5 (10.45.1.7) -- "Mobile identity missing or
# ambiguous", i.e. ue5 has no (or more than one) matching session in the
# 5G core's session list right now, a pre-existing lab connectivity
# state unrelated to this script. Confirmed independently afterward
# (0 residual OpenFlow drop rules on pe, controller status active=False)
# that the earlier partial enter() left nothing suspended once this
# script's run_id's lease was explicitly released. See the written report.
VECTORS = ['udp_flood', 'syn_flood', 'icmp_flood']


async def main():
    secret = json.loads((PRIVATE / 'ssh.json').read_text())['password']
    os.environ['BENIGN_SSH_PASSWORD'] = secret
    os.environ['BENIGN_PE_SSH_PASSWORD'] = 'root'  # pe's root account uses root/root, not the shared lab password
    cfg = load_lab(LAB_PATH)
    run_id = 'capacity-measure-' + time.strftime('%Y%m%dT%H%M%S')
    guard = BaselineGuard(cfg, run_id, DURATION_S * len(DOMAIN_SOURCES) * len(VECTORS) + 300)
    guard.domains = set(DOMAIN_SOURCES)  # scope to only the domains measured this run
    results = []
    print('Suspending pipeline (BaselineGuard.enter())...', flush=True)
    try:
        preflight = await guard.enter()
        print('Pipeline suspended:', json.dumps(preflight, default=str)[:300], flush=True)
        for domain, source in DOMAIN_SOURCES.items():
            for vector in VECTORS:
                print(f'--- {domain} / {vector} / source={source} ---', flush=True)
                plan = generate_attack_plan(
                    seed=42, duration_s=DURATION_S,
                    flows=[dict(domain=domain, sources=[source], destination='victim-web',
                                wire_protocol=vector, rate_pps=TARGET_PPS, start_s=0,
                                duration_s=DURATION_S, packet_size_bytes=PACKET_SIZE_BYTES)],
                    description=f'capacity-measure {domain}/{vector}')
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
                await asyncio.sleep(3)  # brief settle between bursts
    finally:
        print('Restoring pipeline (BaselineGuard.leave())...', flush=True)
        restoration = await guard.leave()
        print('Pipeline restored:', restoration, flush=True)
    out = PRIVATE / 'calibration' / 'attack_capacity_measurement.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(target_pps=TARGET_PPS, duration_s=DURATION_S,
                                    packet_size_bytes=PACKET_SIZE_BYTES, results=results), indent=2))
    print('Saved:', out)


if __name__ == '__main__':
    asyncio.run(main())
