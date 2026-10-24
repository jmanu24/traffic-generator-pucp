"""PILOT2 blocker (2026-10-24): measure the SYN_FLOOD single-source
detector's intrinsic false-positive rate under real benign traffic alone
(C1-I showed 0/6 at seeds 204-206, but composition3_f09/C3 found 1 FP
whose detection fired 12s AFTER the attack window ended -- i.e. driven by
benign background alone, unrelated to any attack plan). Generates 15
fresh benign plans (seeds 301-315, disjoint from calibration 101-110,
pilot 201-203, and PILOT2 204-206) to run C1-I repeatedly and get a
usable empirical FPR estimate. Same generator/lab capacities as every
other benign plan in this repo. Pure local computation, never touches
the lab."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.config import load_lab
from benign_lab.planner import generate, load_profiles, save_plan

LAB_PATH = ROOT / 'config/lab.connected.yaml'
PLANS_DIR = ROOT / 'data' / 'plans'
MANIFEST_PATH = ROOT / 'data' / 'fpr_benign_plans_manifest.json'
DURATION_S = 180
FPR_SEEDS = tuple(range(301, 316))


def main():
    PLANS_DIR.mkdir(parents=True, exist_ok=True)
    capacities = load_lab(LAB_PATH)['capacity_mbps']
    profiles = load_profiles(ROOT / 'profiles')
    manifest = []
    for seed in FPR_SEEDS:
        plan = generate(profiles, seed, DURATION_S, capacities)
        path = PLANS_DIR / f"{plan['plan_hash']}.json"
        save_plan(plan, path)
        manifest.append(dict(seed=seed, plan_hash=plan['plan_hash'], duration_s=plan['duration_s'],
                              capacity_mbps=plan['capacity_mbps'], warnings=plan['warnings'], path=str(path)))
        print(f"seed={seed} plan_hash={plan['plan_hash']} warnings={plan['warnings']}", flush=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
    print('Saved manifest:', MANIFEST_PATH)


if __name__ == '__main__':
    main()
