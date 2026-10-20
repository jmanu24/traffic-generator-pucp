"""Paso 3 (THRESHOLD_CALIBRATION): run B0, pipeline=enabled, for each
calibration seed (101-110) under both M (multidomain) and I (isolated),
via the live dashboard's own /api/runs (so there is exactly one Manager
touching the real lab -- this script never instantiates its own)."""
import json
import sys
import time
import urllib.error
import urllib.request

BASE = 'http://192.168.18.154:8780'
TOKEN = 'PWsbuW4Nty10xJ59civhnre6dOaf6OG84pRoiG0HFvg'
SEED_HASHES = {
    101: 'cd7249cda096228dfdb8191c060964f2fb307a4f99966235da641ffd76def84a',
    102: '52d5745453cdc35c1aa53a3ca9b454ddade7f3081f4ee983600dacfbcff435b1',
    103: 'a6671da2c6f9a2bf30fe5e64c1ba3c7540a34e67cd454a0ed76b26493e83d2a4',
    104: 'a68fca713a9f7717a1928535911c30134f7830a1d735fd7e6d7b5dd8b4173508',
    105: 'ff3a6537952698b0519bbe677206ebf683baf5e298ab931d095b835b22984f87',
    106: '219d68aca62d6493d649383530ef6ff4478480c7d7cecffb3e53e041156cc31f',
    107: '65d431df8814587f0ef67ba40204211e510c2f0b3725c02bfb9b87cb33aa2bc9',
    108: 'bddf97c0e10d7b5ebc1fa78c17577b20824581207ec59d4c1af2b7caa7c3d493',
    109: '0f696aa6aaa42ee3f108d6a99c840a508140b79f6b990b76475143ebc2abb8f3',
    110: '1d0cb5cd4db4a561a33efe261b7c5060181ba06eb79cc9c40bbc2238127c86b2',
}
MODES = ['I', 'M']


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                  headers={'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return dict(error=True, status=exc.code, body=exc.read().decode())


def wait_for_completion(rid, timeout=600):
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = call('GET', '/api/runs')
        match = next((r for r in row if r['id'] == rid), None)
        if match and match['status'] in ('completed', 'completed_with_errors', 'failed', 'stopped', 'interrupted'):
            return match
        time.sleep(5)
    raise TimeoutError(f'Run {rid} did not finish within {timeout}s')


def main():
    manifest = []
    for seed, plan_hash in SEED_HASHES.items():
        for mode in MODES:
            print(f'--- seed={seed} mode={mode} ---', flush=True)
            result = call('POST', '/api/runs', dict(plan_hash=plan_hash, mode='lab', scenario='B0',
                                                      pipeline='enabled', speed=1, detection_mode=mode))
            if result.get('error'):
                print('  START FAILED:', result, flush=True)
                manifest.append(dict(seed=seed, mode=mode, plan_hash=plan_hash, start_error=result))
                continue
            rid = result['id']
            print('  started:', rid, flush=True)
            final = wait_for_completion(rid)
            print('  finished:', final['status'], flush=True)
            manifest.append(dict(seed=seed, mode=mode, plan_hash=plan_hash, run_id=rid, status=final['status']))
    out = '/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/calibration_seeds_manifest.json'
    with open(out, 'w') as f:
        json.dump(manifest, f, indent=2)
    print('Saved manifest:', out)
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
