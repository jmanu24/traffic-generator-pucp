"""Validate that EVERY potential attack-source host in every domain can
actually dispatch hping3 via the orchestrated attack_runner path (not
just manually over SSH) -- triggered by the fixed9/fixed10 finding
(2026-10-24): hping3 worked fine manually in those namespaces but
failed 100% of the time ("command not found") when dispatched through
agent.py's own subprocess path in all 27 pilot2b composition3 blocks.
Low rate (2pps), short duration (8s) -- this is a dispatch capability
check, not a real detection experiment. Uses POST /api/attacks/plans +
POST /api/attacks/start directly (bypasses Manager/baseline -- no real
benign-lab run needed for this)."""
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BASE = 'http://192.168.18.154:8780'
ENV_FILE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/web.env')

HOSTS = {
    'enterprise': ['ent-site-1', 'ent-site-2', 'ent-site-3', 'ent-site-4', 'ent-site-5'],
    'fixed': [f'fixed{i}' for i in range(1, 11)],
    'mobile': ['ue1', 'ue2', 'ue3', 'ue4', 'ue5'],
}
RATE_PPS = 2.0
DURATION_S = 8
PLAN_DURATION_S = 20
START_S = 2


def load_token():
    env = {}
    for line in ENV_FILE.read_text().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()
    return env['BENIGN_API_TOKEN']


def call(token, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                  headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return dict(error=True, status=exc.code, body=exc.read().decode())


def main():
    token = load_token()
    flows = []
    for domain, sources in HOSTS.items():
        flows.append(dict(domain=domain, sources=sources, destination='victim-web',
                           wire_protocol='syn_flood', rate_pps=RATE_PPS,
                           start_s=START_S, duration_s=DURATION_S, packet_size_bytes=64))
    body = dict(seed=999, duration_s=PLAN_DURATION_S,
                description='validate_all_attack_sources', flows=flows)
    result = call(token, 'POST', '/api/attacks/plans', body)
    if result.get('error'):
        print('PLAN CREATE FAILED:', result)
        return
    plan_hash = result['plan_hash']
    print('plan_hash:', plan_hash, 'events:', result['events'])
    start_result = call(token, 'POST', '/api/attacks/start', dict(plan_hash=plan_hash, confirm=True))
    if start_result.get('error'):
        print('ATTACK START FAILED:', start_result)
        return
    events = start_result['events']
    # events is a dict keyed by event_id -- but we need source per event
    plan = call(token, 'GET', f'/api/attacks/plans/{plan_hash}')
    source_by_event = {e['event_id']: (e['domain'], e['source']) for e in plan['events']}
    print(f'\n{"domain":12} {"source":14} {"status":10} {"target":>8} {"actual":>8}  error')
    n_ok, n_fail = 0, 0
    for eid, ev in events.items():
        domain, source = source_by_event.get(eid, ('?', '?'))
        ok = ev.get('error') is None and (ev.get('packets_sent') or 0) > 0
        n_ok += ok
        n_fail += not ok
        target = ev.get('attack_pps_target')
        actual = ev.get('attack_pps_actual')
        print(f'{domain:12} {source:14} {"OK" if ok else "FAIL":10} '
              f'{target if target is not None else "-":>8} {actual if actual is not None else 0:>8.1f}  {(ev.get("error") or "")[:120]}')
    print(f'\n{n_ok} ok, {n_fail} fail')


if __name__ == '__main__':
    main()
