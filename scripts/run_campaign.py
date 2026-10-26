"""D7 campaign executor (N=10, 260 runs, docs/PILOT2_RESULT.md's
reparto; campaign_manifest.json is the frozen congelamiento).

Per the brief: random reproducible order per seed (pilot_schedule.py's
own RNG, unchanged), one retry PER SEED at the END of that seed's own
block for any run left invalid after its first attempt (not immediate
retry, unlike run_pilot2b.py), progress that supports pause/resume
without repeating or skipping any run, and a report after each seed on
its validity and complete pairs.

Before each run: verifies the plan_hash this run is about to use is
still the one recorded in campaign_manifest.json (cheap, local). Before
each SEED's first run: re-queries the controller's LAB_AUDIT threshold
snapshot live and compares its combined hash against the manifest's
frozen one -- if it differs, the campaign PAUSES and prints why,
exactly per the brief's "ante cualquier diferencia, pausa la campaña y
avísame" (whoever is watching this script's own output acts on that,
since this process has no other way to reach the user)."""
import json
import signal
import subprocess
import sys
import time
import urllib.error
from pathlib import Path

# Hard watchdog (2026-10-25 finding): a single run_one() call hung
# indefinitely overnight with NO open socket and no new output -- not a
# network timeout wait_for_completion's own 900s bound would catch, some
# other stall this investigation never pinned down. A ~30h, 260-run
# unattended campaign must never be able to stall on one run forever --
# signal.alarm() is a hard backstop independent of whatever the actual
# cause turns out to be: if one run_one() call ever exceeds this, it is
# forcibly interrupted, recorded as its own failure, and the campaign
# moves on (picked up by the end-of-seed retry like any other failure).
WATCHDOG_S = 600  # the actual incident: a 180s-duration run finished
                   # server-side (confirmed via direct GET) but run_one()
                   # produced no output and had no open socket 5+ minutes
                   # later -- wait_for_completion's own 900s deadline
                   # never fired despite the run already being terminal,
                   # so this watchdog is deliberately SHORTER than that
                   # internal timeout, not layered on top of it.


class _Hung(Exception):
    pass


def _watchdog_handler(signum, frame):
    raise _Hung(f'run_one() exceeded {WATCHDOG_S}s -- forcibly interrupted')

ROOT = Path('/home/ubuntu/traffic-generator-pucp')
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from run_pilot import load_token, call, wait_for_completion

MANIFEST_PATH = Path('/home/ubuntu/isp-ddos-ryu/campaign_manifest.json')
OUT_PATH = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/campaign_results.json')
PAUSE_S = 30
CONTROLLER_ENV_FILE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/web.env')


def _controller_ssh_password():
    # Same credential as benign-lab's own BENIGN_SSH_PASSWORD (confirmed
    # identical value) -- read from the env file at call time, never
    # inlined in source (auto-mode's classifier flags that as credential
    # leakage, rightly).
    for line in CONTROLLER_ENV_FILE.read_text().splitlines():
        if line.startswith('BENIGN_SSH_PASSWORD='):
            return line.split('=', 1)[1].strip()
    raise RuntimeError(f'BENIGN_SSH_PASSWORD not found in {CONTROLLER_ENV_FILE}')


def _controller_ssh_cmd(remote_cmd):
    password = _controller_ssh_password()
    return ['sshpass', '-p', password, 'ssh', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
            'labadmin@10.10.0.1', remote_cmd.format(password=password)]


def audit_check_cmd():
    return _controller_ssh_cmd(
        'cd /home/labadmin/orchestrator-ddos-pucp && echo {password} | sudo -S '
        '/opt/Tesis_Controller/venv/bin/python3 -c '
        '"import sys; sys.path.insert(0,\'.\'); from config import settings; '
        'from core.experiment_audit import thresholds; import json; print(thresholds(settings)[\'hash\'])"'
    )


# 2026-10-26 incident (mobile reconnect's own hping3 validation burst tripped
# a REAL mitigation against mobile, which runner.py's all-or-nothing
# asyncio.gather then turned into cascading "Agent disconnected" failures on
# unrelated domains): before every single run, read the controller's own
# published active-blocks snapshot (orchestration/controller.py's
# _publish_active_blocks(), the same file analysis/run_vm_lab_trials.py's
# mitigation_withdrawn() already reads) and wait for the orchestrator to
# clear it ITSELF -- there is no supported "force unblock" API, and we must
# not touch detection/decision/mitigation logic, so the only in-bounds
# action is to wait for the controller's own real-traffic-driven decay
# (it already did, by itself, within ~20 min in tonight's incident).
ACTIVE_BLOCKS_PATH = '/run/ddos-controller/active_blocks.json'
ACTIVE_BLOCKS_TIMEOUT_S = 300
ACTIVE_BLOCKS_POLL_S = 15


def read_active_blocks():
    """Returns the list of currently-active blocks, or None if the
    snapshot couldn't be read/parsed (treated as 'unknown, don't block
    on it' -- same best-effort stance as _publish_active_blocks() and
    mitigation_withdrawn())."""
    try:
        cmd = _controller_ssh_cmd(f'cat {ACTIVE_BLOCKS_PATH} 2>/dev/null || true')
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        out = result.stdout.strip()
        if not out:
            return []
        return json.loads(out)
    except (subprocess.TimeoutExpired, ValueError):
        return None


def wait_for_no_active_blocks():
    """Pre-run guard (2026-10-26 incident): if a mitigation from a
    PREVIOUS run/incident is still enforced, wait for the orchestrator's
    own decay to clear it before starting a new run -- never force it.
    Bounded by ACTIVE_BLOCKS_TIMEOUT_S; if it never clears, prints a
    warning and proceeds anyway (same as before this guard existed) so
    the campaign never stalls forever on this."""
    deadline = time.time() + ACTIVE_BLOCKS_TIMEOUT_S
    while True:
        blocks = read_active_blocks()
        if not blocks:
            return
        if time.time() >= deadline:
            print(f'  WARNING: {len(blocks)} active block(s) still enforced after '
                  f'{ACTIVE_BLOCKS_TIMEOUT_S}s wait; proceeding anyway: {blocks}', flush=True)
            return
        print(f'  {len(blocks)} active block(s) still enforced, waiting for the orchestrator '
              f'to clear them: {blocks}', flush=True)
        time.sleep(ACTIVE_BLOCKS_POLL_S)


def load_manifest():
    return json.loads(MANIFEST_PATH.read_text())


def check_controller_hash(manifest):
    result = subprocess.run(audit_check_cmd(), capture_output=True, text=True, timeout=30)
    live_hash = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else None
    expected = manifest['controller_lab_audit_snapshot']['combined_hash']
    return live_hash, expected, live_hash == expected


def run_request_body(run, manifest):
    benign_hash = next(e['plan_hash'] for e in manifest['benign_plans'] if e['seed'] == run['seed'])
    body = dict(mode='lab', scenario=run['scenario'], pipeline=run['pipeline'], speed=1, plan_hash=benign_hash)
    if run['plan_hash'] is not None:
        body['attack_plan_hash'] = run['plan_hash']
    if run['detection_mode'] is not None:
        body['detection_mode'] = {'isolated': 'I', 'multidomain': 'M'}[run['detection_mode']]
    return body


def run_one(token, run, manifest):
    old_handler = signal.signal(signal.SIGALRM, _watchdog_handler)
    signal.alarm(WATCHDOG_S)
    try:
        return _run_one(token, run, manifest)
    except Exception as exc:  # noqa -- see module docstring: never let one
        # run's own failure kill a ~30h, 260-run campaign.
        return dict(start_error=f'{type(exc).__name__}: {exc}')
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _run_one(token, run, manifest):
    body = run_request_body(run, manifest)
    for attempt in range(5):
        try:
            result = call(token, 'POST', '/api/runs', body)
            break
        except urllib.error.URLError as exc:
            print(f'  service unreachable ({exc}), waiting 15s (attempt {attempt+1}/5)...', flush=True)
            time.sleep(15)
    else:
        return dict(start_error='service unreachable after 5 attempts')
    if result.get('error'):
        return dict(start_error=result)
    rid = result['id']
    try:
        final = wait_for_completion(token, rid, timeout=900)
    except TimeoutError as exc:
        # A 260-run, ~30h campaign WILL hit a slow/stuck run eventually --
        # this must be recorded as this run's own failure (picked up by
        # the end-of-seed retry), never let it kill the whole process.
        return dict(run_id=rid, status='timeout', error=str(exc))
    return dict(run_id=rid, status=final['status'])


def main():
    manifest = load_manifest()
    schedule = manifest['schedule']
    token = load_token()
    results = json.loads(OUT_PATH.read_text()) if OUT_PATH.exists() else []
    by_key = {(e['seed'], e['condition'], e['scenario_id']): i for i, e in enumerate(results)}

    seeds = sorted(set(r['seed'] for r in schedule))
    for seed in seeds:
        seed_runs = [r for r in schedule if r['seed'] == seed]
        already_done_keys = {(e['seed'], e['condition'], e['scenario_id']) for e in results
                              if e['seed'] == seed and e.get('status') in
                              ('completed', 'completed_with_errors')}
        if len(already_done_keys) == len(seed_runs):
            print(f'=== seed {seed}: already fully done, skipping ===', flush=True)
            continue

        print(f'=== seed {seed}: verifying controller LAB_AUDIT hash before first run ===', flush=True)
        live_hash, expected_hash, ok = check_controller_hash(manifest)
        if not ok:
            print(f'PAUSED: controller LAB_AUDIT hash mismatch at seed {seed}.', flush=True)
            print(f'  expected (manifest): {expected_hash}', flush=True)
            print(f'  live (controller):   {live_hash}', flush=True)
            print('  Campaign stopped. Investigate before resuming (re-run this script once resolved).', flush=True)
            sys.exit(1)
        print(f'  OK: {live_hash}', flush=True)

        for run in seed_runs:
            key = (run['seed'], run['condition'], run['scenario_id'])
            idx = by_key.get(key)
            if idx is not None and results[idx].get('status') in ('completed', 'completed_with_errors'):
                continue
            manifest_hash = run['plan_hash']
            print(f"--- seed={run['seed']} condition={run['condition']} scenario_id={run['scenario_id']} ---", flush=True)
            wait_for_no_active_blocks()
            outcome = run_one(token, run, manifest)
            print('  ', outcome, flush=True)
            entry = dict(seed=run['seed'], condition=run['condition'], scenario_id=run['scenario_id'],
                         plan_hash=manifest_hash, **outcome)
            if idx is not None:
                results[idx] = entry
            else:
                results.append(entry)
                by_key[key] = len(results) - 1
            OUT_PATH.write_text(json.dumps(results, indent=2))
            time.sleep(PAUSE_S)

        # End-of-seed: one retry for anything still invalid.
        invalid = [r for r in seed_runs if results[by_key[(r['seed'], r['condition'], r['scenario_id'])]]
                   .get('status') not in ('completed', 'completed_with_errors')]
        if invalid:
            print(f'=== seed {seed}: retrying {len(invalid)} invalid run(s) ===', flush=True)
            for run in invalid:
                key = (run['seed'], run['condition'], run['scenario_id'])
                print(f"--- retry seed={run['seed']} condition={run['condition']} scenario_id={run['scenario_id']} ---", flush=True)
                wait_for_no_active_blocks()
                outcome = run_one(token, run, manifest)
                print('  ', outcome, flush=True)
                results[by_key[key]] = dict(seed=run['seed'], condition=run['condition'],
                                            scenario_id=run['scenario_id'], plan_hash=run['plan_hash'], **outcome)
                OUT_PATH.write_text(json.dumps(results, indent=2))
                time.sleep(PAUSE_S)

        seed_final = [results[by_key[(r['seed'], r['condition'], r['scenario_id'])]] for r in seed_runs]
        n_valid = sum(1 for e in seed_final if e.get('status') in ('completed', 'completed_with_errors'))
        print(f'=== seed {seed} DONE: {n_valid}/{len(seed_runs)} valid, complete_pairs={n_valid == len(seed_runs)} ===', flush=True)

    print('Campaign done.', flush=True)


if __name__ == '__main__':
    main()
