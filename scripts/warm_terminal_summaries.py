"""One-time cache warm-up for the terminal_summary.json fix (runner.py):
computes and persists every historical terminal run's summary (counts/
bytes/domains/payload_quality/audit_available) to its own small file,
so the NEXT benign-lab-web.service restart (and every one after it)
reads that tiny file instead of re-parsing event_states.json (which can
be several MB per run) for all of them. Pure offline computation --
imports Manager directly, never starts the HTTP server, never touches
the live lab. Safe to run while the service itself is stopped (reads/
writes the same data directory the service uses, no live run active)."""
import sys
import time
from pathlib import Path

ROOT = Path('/home/ubuntu/traffic-generator-pucp')
sys.path.insert(0, str(ROOT))
from benign_lab.runner import Manager

DATA_DIR = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/runs')


def main():
    t0 = time.time()
    print('Constructing Manager (should be fast now -- no event_states.json reads at init)...', flush=True)
    m = Manager(DATA_DIR)
    print(f'  Manager() took {time.time()-t0:.1f}s for {len(m.runs)} runs', flush=True)

    rids = list(m.runs)
    n_warmed, n_already = 0, 0
    for i, rid in enumerate(rids):
        already_cached = rid in m.terminal_metrics
        m.snapshot(rid)
        if already_cached:
            n_already += 1
        else:
            n_warmed += 1
        if (i+1) % 50 == 0:
            print(f'  [{i+1}/{len(rids)}] warmed={n_warmed} already_cached={n_already} ({time.time()-t0:.1f}s elapsed)', flush=True)

    print(f'Done in {time.time()-t0:.1f}s: {n_warmed} newly warmed, {n_already} already had a cached summary.', flush=True)


if __name__ == '__main__':
    main()
