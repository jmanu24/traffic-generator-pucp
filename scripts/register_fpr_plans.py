"""PILOT2 blocker: register the 15 new FPR-measurement benign plans
(seeds 301-315) on the dashboard's own server. Never sends attack
traffic or launches a run."""
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
MANIFEST = json.loads((ROOT / 'data' / 'fpr_benign_plans_manifest.json').read_text())


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
        result = call('POST', '/api/plans', dict(seed=entry['seed'], duration_s=entry['duration_s']))
        status = 'MATCH' if not result.get('error') and result.get('plan_hash') == entry['plan_hash'] else 'MISMATCH/FAILED'
        print(f"seed={entry['seed']}: server={result.get('plan_hash', result)} local={entry['plan_hash']} [{status}]")


if __name__ == '__main__':
    main()
