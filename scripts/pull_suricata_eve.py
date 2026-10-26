"""Pull nids's eve.json (Suricata's own alert log, JSON Lines) to a local
cache file, for suricata_adapter.py / response_metrics.compute() to read
offline -- same read-only, no-lab-side-effect pattern as
pull_pilot2b_exports.py. Re-pulling overwrites the cache with the current
(always-growing, append-only) remote file; callers filter by timestamp
for whichever run window they care about, so a stale cache just means
"missing the newest alerts", never wrong ones.

Needs sshpass + the labadmin credential already used throughout this
project's own vm-lab tooling (same convention as benign_lab/
ssh_bridge.py's own --password-env: read from an environment variable,
never hardcoded) -- set NIDS_SSH_PASSWORD before running this."""
import os
import subprocess
import sys
from pathlib import Path

NIDS_HOST = '10.10.0.19'
NIDS_USER = 'labadmin'
REMOTE_PATH = '/var/log/suricata/eve.json'
CACHE_PATH = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/suricata_eve.json')


def main():
    password = os.environ.get('NIDS_SSH_PASSWORD')
    if not password:
        print('Set NIDS_SSH_PASSWORD first', file=sys.stderr)
        sys.exit(1)
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, SSHPASS=password)
    cmd = ['sshpass', '-e', 'ssh', '-o', 'ConnectTimeout=5',
           '-o', 'StrictHostKeyChecking=no', f'{NIDS_USER}@{NIDS_HOST}',
           f'sudo cat {REMOTE_PATH}']
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
    if result.returncode != 0:
        print('FAILED:', result.stderr[-500:], file=sys.stderr)
        sys.exit(1)
    CACHE_PATH.write_text(result.stdout)
    n_lines = result.stdout.count('\n')
    print(f'Pulled {n_lines} lines to {CACHE_PATH}')


if __name__ == '__main__':
    main()
