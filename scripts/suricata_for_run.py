"""Filter the local eve.json cache (pull_suricata_eve.py) down to the
alerts relevant to ONE benign-lab run, and hand them to
response_metrics.compute() exactly like the controller's own
detection_events.jsonl records -- a SEPARATE compute() call, not merged
into the controller's own records (mixing the two would make tD/TD mean
"whichever of controller-or-Suricata fired first", losing the
independent per-system comparison this whole adapter exists for).

Suricata sees ALL 4 domains' traffic to the victim (pe's br-ent mirrors
everything -- see nids_suricata/pe_ovs roles), so no domain filtering is
needed here, only a time window. MARGIN_S pads both ends of
[run.started_at, run.finished_at] -- Suricata's own alert emission has
no activation hysteresis to delay it (activation_delay_s=0, by
suricata_adapter.py's own design), but eve.json write/flush and this
script's own pull timing can still land an alert a beat on either side
of the run's own recorded boundaries."""
import json
import sys
from pathlib import Path

ROOT = Path('/home/ubuntu/traffic-generator-pucp')
sys.path.insert(0, str(ROOT))
from benign_lab.suricata_adapter import parse_eve_json

EVE_CACHE = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/suricata_eve.json')
MARGIN_S = 5.0


def records_for_run(run, eve_path=EVE_CACHE):
    """run: a run.json dict (needs started_at, finished_at). Returns a
    list of compute()-ready records, restricted to this run's window."""
    lo = run['started_at'] - MARGIN_S
    hi = run['finished_at'] + MARGIN_S
    return [r for r in parse_eve_json(eve_path) if lo <= r['timestamp'] <= hi]


def main():
    """CLI smoke test: python3 suricata_for_run.py <started_at> <finished_at>
    prints every alert in that window, for validating the pull+filter
    pipeline against real data before wiring it into the campaign."""
    started_at, finished_at = float(sys.argv[1]), float(sys.argv[2])
    run = dict(started_at=started_at, finished_at=finished_at)
    records = records_for_run(run)
    print(f'{len(records)} alerts in [{started_at}, {finished_at}] (+/-{MARGIN_S}s margin)')
    for r in records:
        print(' ', r['timestamp'], r['detection']['src_ip'], r['detection']['signature'])


if __name__ == '__main__':
    main()
