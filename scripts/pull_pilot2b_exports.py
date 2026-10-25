"""Pull /api/runs/{rid}/export for all 78 PILOT2b runs and extract just
the 4 files response_metrics.compute() needs (benign_plan.json,
run.json, detection_events.jsonl, event_states.json) into a local cache
dir. Same pattern as pull_pilot2_exports.py (the original pilot2),
pointed at pilot2b's own manifest/cache. Read-only against the panel."""
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

BASE = 'http://192.168.18.154:8780'
TOKEN = os.environ['BENIGN_API_TOKEN']
MANIFEST = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/pilot2b_manifest.json')
CACHE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/pilot2b_exports')
NEEDED = ('run.json', 'detection_events.jsonl', 'event_states.json', 'benign_plan.json')


def main():
    manifest = json.loads(MANIFEST.read_text())
    CACHE.mkdir(parents=True, exist_ok=True)
    for i, e in enumerate(manifest):
        rid = e['run_id']
        outdir = CACHE / rid
        if outdir.exists() and all((outdir / f).exists() for f in NEEDED):
            continue
        outdir.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(f'{BASE}/api/runs/{rid}/export', method='GET',
                                      headers={'Authorization': 'Bearer ' + TOKEN})
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            print(f'[{i+1}/{len(manifest)}] {rid} FAILED: {exc.code} {exc.read()[:200]}', flush=True)
            continue
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for name in NEEDED:
                if name in z.namelist():
                    (outdir / name).write_bytes(z.read(name))
        print(f'[{i+1}/{len(manifest)}] {rid} ok ({time.time()-t0:.1f}s)', flush=True)


if __name__ == '__main__':
    main()
