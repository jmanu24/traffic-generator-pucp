"""D7 campaign: aggregate the official window-level confusion matrix
(benign_lab/scenario_confusion.py's window_confusion(), invoked via
detection_evaluation.evaluate()) across all C3 (I) and C4 (M) runs, plus
C1-I/C1-M (pure benign) for a clean FPR baseline. Pure computation over
already-captured evidence -- never touches the lab."""
import json
import sys
import yaml
from pathlib import Path

ROOT = Path('/home/ubuntu/traffic-generator-pucp')
sys.path.insert(0, str(ROOT))
from benign_lab.detection_evaluation import evaluate

RESULTS = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/campaign_results.json')
RUNS_DIR = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/runs')
OUT = Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/d7_confusion.json')

LAB_CFG = yaml.safe_load((ROOT / 'config/lab.connected.yaml').read_text())


def load_records(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main():
    entries = json.loads(RESULTS.read_text())
    totals = {'C3': dict(VP=0, FN=0, FP=0, VN=0, unknown=0),
              'C4': dict(VP=0, FN=0, FP=0, VN=0, unknown=0)}
    errors = []
    for e in entries:
        if e['condition'] not in ('C3', 'C4'):
            continue
        rid = e.get('run_id')
        if not rid or e.get('status') not in ('completed', 'completed_with_errors'):
            continue
        d = RUNS_DIR / rid
        try:
            plan = json.loads((d / 'benign_plan.json').read_text())
            run = json.loads((d / 'run.json').read_text())
            run['_lab'] = LAB_CFG
            records = load_records(d / 'detection_events.jsonl')
            event_states = list(json.loads((d / 'event_states.json').read_text()).values())
            interfaces = load_records(d / 'interface_metrics.jsonl')
            result = evaluate(plan, run, records, interfaces=interfaces, event_states=event_states)
            cm = result['confusion_matrix']['counts']
        except Exception as exc:  # noqa
            errors.append((e['seed'], e['condition'], e['scenario_id'], rid, f'{type(exc).__name__}: {exc}'))
            continue
        for k in ('VP', 'FN', 'FP', 'VN', 'unknown'):
            totals[e['condition']][k] += cm.get(k, 0)

    print(f'{len(errors)} errors')
    for err in errors[:10]:
        print('  ', err)

    out = {}
    for cond, label in (('C3', 'I'), ('C4', 'M')):
        c = totals[cond]
        vp, fn, fp, vn = c['VP'], c['FN'], c['FP'], c['VN']
        recall = vp / (vp + fn) if (vp + fn) else None
        fpr = fp / (fp + vn) if (fp + vn) else None
        precision = vp / (vp + fp) if (vp + fp) else None
        accuracy = (vp + vn) / (vp + fn + fp + vn) if (vp + fn + fp + vn) else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall and (precision + recall) else None
        out[label] = dict(VP=vp, FN=fn, FP=fp, VN=vn, unknown=c['unknown'],
                           recall=recall, fpr=fpr, precision=precision, accuracy=accuracy, f1=f1)
        print(f"\n=== {label} ({cond}) ===")
        print(f"  VP={vp} FN={fn} FP={fp} VN={vn} unknown={c['unknown']}")
        print(f"  recall={recall:.3f} fpr={fpr:.3f} precision={precision:.3f} accuracy={accuracy:.3f} f1={f1:.3f}"
              if recall is not None and fpr is not None and precision is not None else '  insufficient data')

    OUT.write_text(json.dumps(out, indent=2))
    print('\nSaved:', OUT)


if __name__ == '__main__':
    main()
