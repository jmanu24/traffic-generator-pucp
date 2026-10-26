"""D7 campaign: register the 10 new benign plans (seeds 1-10, attack-only
hosts excluded) on the dashboard's own server, via /api/plans/import
(raw bytes) -- same reasoning as register_pilot2b_plans.py: the
server's own /api/plans handler regenerates from the ON-DISK
profiles/*.yaml (full population), which would NOT reproduce this
excluded-population hash. Never sends attack traffic or launches a run."""
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
MANIFEST = json.loads((ROOT / 'data' / 'campaign_benign_plans_manifest.json').read_text())


def call_import(raw_bytes):
    req = urllib.request.Request(BASE + '/api/plans/import', data=raw_bytes, method='POST',
                                  headers={'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return dict(error=True, status=exc.code, body=exc.read().decode())


def main():
    for entry in MANIFEST:
        raw = Path(entry['path']).read_bytes()
        result = call_import(raw)
        status = 'MATCH' if not result.get('error') and result.get('plan_hash') == entry['plan_hash'] else 'MISMATCH/FAILED'
        print(f"seed={entry['seed']}: server={result.get('plan_hash', result)} local={entry['plan_hash']} [{status}]")


if __name__ == '__main__':
    main()
