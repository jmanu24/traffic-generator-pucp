"""THRESHOLD_CALIBRATION_V2, Paso 2: B0, pipeline=baseline (deteccion
suspendida -- observed_rates se sigue registrando via LAB_AUDIT kind=cycle,
pero ninguna mitigacion puede alterar el trafico benigno), para cada semilla
de calibracion (101-110) bajo ambos modos de deteccion, I y M.

Diferencia deliberada con scripts/run_calibration_seeds.py (el de la
calibracion V1): ese usaba pipeline=enabled. Repetir con pipeline=baseline
evita que los UMBRALES VIEJOS (SYN=10/UDP=200/ICMP=150, ya bajos de por si)
contaminen la captura de observed_rates con mitigaciones reales sobre
trafico benigno -- ver THRESHOLD_CALIBRATION_RESULT_V2.md.

Via el /api/runs del panel ya corriendo (un solo Manager tocando el
laboratorio real), igual que el script V1."""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = 'http://192.168.18.154:8780'
TOKEN = os.environ['BENIGN_API_TOKEN']
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
# M first -- the controller is live in M right now (confirmed via LAB_AUDIT),
# so the first run needs no restart at all; only one restart total (M->I)
# for the whole 20-run sequence.
MODES = ['M', 'I']


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
        rows = call('GET', '/api/runs')
        match = next((r for r in rows if r['id'] == rid), None)
        if match and match['status'] in ('completed', 'completed_with_errors', 'failed', 'stopped', 'interrupted'):
            return match
        time.sleep(5)
    raise TimeoutError(f'Run {rid} did not finish within {timeout}s')


def main():
    manifest = []
    out = '/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/calibration_seeds_v2_baseline_manifest.json'
    # Grouped by mode (all I, then all M) -- minimizes ryu-manager restarts
    # to at most 1 for the whole run (apply_detection_mode only restarts
    # when the requested mode differs from what the controller already
    # reports), instead of up to 19 if seeds/modes were interleaved.
    for mode in MODES:
        for seed, plan_hash in SEED_HASHES.items():
            print(f'--- seed={seed} mode={mode} pipeline=baseline ---', flush=True)
            result = call('POST', '/api/runs', dict(plan_hash=plan_hash, mode='lab', scenario='B0',
                                                      pipeline='baseline', speed=1, detection_mode=mode))
            if result.get('error'):
                print('  START FAILED:', result, flush=True)
                manifest.append(dict(seed=seed, mode=mode, plan_hash=plan_hash, start_error=result))
                with open(out, 'w') as f:
                    json.dump(manifest, f, indent=2)
                continue
            rid = result['id']
            print('  started:', rid, flush=True)
            final = wait_for_completion(rid)
            print('  finished:', final['status'], flush=True)
            manifest.append(dict(seed=seed, mode=mode, plan_hash=plan_hash, run_id=rid, status=final['status']))
            with open(out, 'w') as f:
                json.dump(manifest, f, indent=2)
            time.sleep(10)
    print('Saved manifest:', out)
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
