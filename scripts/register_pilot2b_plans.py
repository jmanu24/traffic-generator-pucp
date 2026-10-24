"""PILOT2 blocker fix: register the 3 new pilot2b benign plans
(seeds 204-206, attack-only hosts excluded from the population) on the
dashboard's own server. NOTE: unlike register_pilot2_plans.py, this
uses POST /api/plans/import (raw plan bytes), not POST /api/plans
(seed+duration_s) -- the server's own /api/plans handler would
regenerate from the ON-DISK profiles/*.yaml, which still have the full
population, and would reproduce the OLD (non-excluded) hash instead of
this one. /api/plans/import saves the exact bytes under their own
plan_hash with no regeneration. Never sends attack traffic or launches
a run."""
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
MANIFEST = json.loads((ROOT / 'data' / 'pilot2b_benign_plans_manifest.json').read_text())


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
