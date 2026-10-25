"""PILOT2 blocker fix: register composition3's 3 new attack plans
(dedicated attack-only sources, see generate_attack_plans_v2.py) on the
dashboard's own server via POST /api/attacks/plans -- unlike benign
plans, attack-plan generation (generate_attack_plan) is pure/explicit
(seed, duration_s, flows, description), no profiles/*.yaml dependency,
so re-POSTing the exact same request body the local generator used
reproduces the identical plan_hash server-side with no import endpoint
needed. Never sends attack traffic or launches a run (create_attack_plan
only stores the plan; /api/attacks/start is separate and requires
confirm=true)."""
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BASE = 'http://192.168.18.154:8780'
TOKEN = os.environ['BENIGN_API_TOKEN']
MANIFEST = json.loads((ROOT / 'data' / 'attack_plans_manifest_v2.json').read_text())


def call(method, path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                  headers={'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return dict(error=True, status=exc.code, body=exc.read().decode())


def main():
    for entry in MANIFEST:
        if entry['description'].get('composition') != 3:
            continue
        desc = entry['description']
        flows = desc['flows']
        body = dict(seed=entry['seed'], duration_s=180.0,
                    description=desc['hashed_description'], flows=flows)
        result = call('POST', '/api/attacks/plans', body)
        status = 'MATCH' if not result.get('error') and result.get('plan_hash') == entry['plan_hash'] else 'MISMATCH/FAILED'
        print(f"{entry['name']}: server={result.get('plan_hash', result)} local={entry['plan_hash']} [{status}]")


if __name__ == '__main__':
    main()
