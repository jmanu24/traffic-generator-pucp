"""D7 campaign: correlate Suricata's own custom-rule alerts (sids
9000001-3, "LOCAL SYN/UDP/ICMP Flood Threshold (DDoS thesis comparison)")
against each C3/C4 run's real attack window and attacker source IPs, to
get a THIRD comparison arm (I vs M vs Suricata) for detection coverage
and detection delay. Pure correlation over already-captured data -- never
touches the lab. Suricata alerts pulled once via:
  ssh labadmin@10.10.0.19 "grep '900000[123]' /var/log/suricata/eve.json"
  -> scratchpad/suricata_alerts.jsonl (35296 lines, out of the full
  eve.json's 23M -- the custom rules only, not Suricata's full ruleset)."""
import json
from pathlib import Path

RESULTS = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/campaign_results.json')
RUNS_DIR = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/runs')
ALERTS_PATH = Path('/tmp/claude-1000/-home-ubuntu-isp-ddos-ryu/5e0ade0c-6443-4519-8dc3-a796d4992515/scratchpad/suricata_alerts.jsonl')
OUT = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/d7_suricata.json')


def parse_ts(s):
    # "2026-10-25T05:59:19.553753+0000" -> unix epoch
    import datetime
    s = s.replace('+0000', '+00:00')
    return datetime.datetime.fromisoformat(s).timestamp()


def main():
    alerts = []
    with ALERTS_PATH.open() as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            alerts.append((parse_ts(r['timestamp']), r['src_ip'], r['dest_ip'], r['alert']['signature_id']))
    alerts.sort()
    print(f'Loaded {len(alerts)} custom-rule Suricata alerts, '
          f'span {alerts[0][0]:.0f}..{alerts[-1][0]:.0f}')

    entries = json.loads(RESULTS.read_text())
    results = []
    for e in entries:
        if e['condition'] not in ('C3', 'C4'):
            continue
        rid = e.get('run_id')
        if not rid or e.get('status') not in ('completed', 'completed_with_errors'):
            continue
        d = RUNS_DIR / rid
        run = json.loads((d / 'run.json').read_text())
        attack_windows = run.get('attack_windows', [])
        if not attack_windows:
            continue
        started_at = run.get('started_at')
        sources = set(run.get('attack_source_ips', []))
        if not sources or not started_at:
            continue
        tA = started_at + min(w['start_s'] for w in attack_windows)
        tF = started_at + max(w['end_s'] for w in attack_windows)

        matching = [a for a in alerts if a[1] in sources and tA - 2 <= a[0] <= tF + 5]
        detected = bool(matching)
        tD = matching[0][0] if matching else None
        delay = (tD - tA) if detected else None

        results.append(dict(
            seed=e['seed'], condition=e['condition'], scenario_id=e['scenario_id'],
            run_id=rid, label='I' if e['condition'] == 'C3' else 'M',
            detected=detected, delay_s=delay, n_alerts=len(matching),
        ))

    OUT.write_text(json.dumps(results, indent=2))
    print(f'Saved {len(results)} run correlations to {OUT}')

    for label in ('I', 'M'):
        rows = [r for r in results if r['label'] == label]
        n = len(rows)
        det = sum(1 for r in rows if r['detected'])
        delays = [r['delay_s'] for r in rows if r['delay_s'] is not None]
        mean_delay = sum(delays) / len(delays) if delays else None
        print(f'{label}: n={n} detected={det} ({100*det/n:.1f}%) '
              f'mean_delay_s={mean_delay:.2f}' if mean_delay is not None else
              f'{label}: n={n} detected={det} ({100*det/n:.1f}%) mean_delay_s=None')


if __name__ == '__main__':
    main()
