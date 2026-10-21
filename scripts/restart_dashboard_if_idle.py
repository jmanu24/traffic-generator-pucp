"""D7 campaign: restart benign-lab-web.service periodically to bound its
memory growth (docs/PILOT_RESULT.md section 1 -- Manager.__init__ keeps
every run's full event_states.json in memory forever, ~2.5MB/run,
confirmed consistent with the service reaching 3.3GB after ~22h and the
pilot's clock-skew failures concentrated in its last hour).

Intended to run under a systemd timer as root (restart_dashboard_if_idle
.timer/.service, deploy/restart-dashboard-guard/), NOT ad hoc -- a blind
unconditional restart mid-run would corrupt whatever experiment is
active. This script ONLY restarts when:
  1. No active (non-terminal) run is in progress (checked live via the
     API -- never restarts blind).
  2. At least MIN_INTERVAL_S has passed since the service's own last
     start (systemctl's own ActiveEnterTimestamp -- no separate state
     file to go stale or drift from reality).
Logs every decision (restarted / skipped + why) to stdout, which
systemd/journald already captures -- no separate log file needed.
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://192.168.18.154:8780'
ENV_FILE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/web.env')
MIN_INTERVAL_S = 2 * 3600  # restart at most once every 2h
TERMINAL = {'completed', 'completed_with_errors', 'failed', 'stopped', 'interrupted'}


def load_token():
    env = {}
    for line in ENV_FILE.read_text().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()
    token = env.get('BENIGN_API_TOKEN')
    if not token:
        raise RuntimeError(f'BENIGN_API_TOKEN not found in {ENV_FILE}')
    return token


def has_active_run(token):
    req = urllib.request.Request(BASE + '/api/runs', headers={'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(req, timeout=15) as resp:
        rows = json.loads(resp.read())
    return any(r['status'] not in TERMINAL for r in rows)


def seconds_since_last_start():
    out = subprocess.run(['systemctl', 'show', 'benign-lab-web', '-p', 'ActiveEnterTimestampMonotonic'],
                          capture_output=True, text=True, check=True).stdout.strip()
    # e.g. "ActiveEnterTimestampMonotonic=123456789" (microseconds since boot)
    monotonic_us = int(out.split('=', 1)[1])
    boot_s = time.clock_gettime(time.CLOCK_BOOTTIME) if hasattr(time, 'CLOCK_BOOTTIME') else time.monotonic()
    return boot_s - monotonic_us / 1e6


def main():
    try:
        token = load_token()
        active = has_active_run(token)
    except (urllib.error.URLError, OSError, ValueError, RuntimeError) as exc:
        print(f'skip: could not confirm no active run ({exc}) -- never restart blind', flush=True)
        return
    if active:
        print('skip: an experiment is currently active', flush=True)
        return
    uptime_s = seconds_since_last_start()
    if uptime_s < MIN_INTERVAL_S:
        print(f'skip: only {uptime_s:.0f}s since last start (< {MIN_INTERVAL_S}s)', flush=True)
        return
    print(f'restarting benign-lab-web.service (idle, uptime {uptime_s:.0f}s)', flush=True)
    subprocess.run(['systemctl', 'restart', 'benign-lab-web'], check=True)


if __name__ == '__main__':
    main()
