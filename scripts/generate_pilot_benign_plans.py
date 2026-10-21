"""D7 pilot -- generate the 3 benign plans (seeds 201-203) the pilot
schedule needs. Pure local computation (benign_lab.planner.generate),
same deterministic generator and the same lab capacities
(config/lab.connected.yaml's capacity_mbps) already used for the
calibration seeds (101-110) and for the attack-plan validation (which
reused benign plans implicitly via the controller's own baseline) --
no different generation path invented here. Duration fixed at 180s to
match the attack plans already in data/attack_plans/ (ATTACK_PLAN_
REGENERATION), since pilot_schedule.RUN_DURATION_S assumes every plan
used by the pilot is the same length.

Never touches the lab: only writes JSON files under data/plans/ and a
small manifest, exactly like scripts/generate_regenerated_attack_plans.py
already does for attack plans.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.config import load_lab
from benign_lab.planner import generate, load_profiles, save_plan
from benign_lab.pilot_schedule import PILOT_SEEDS

LAB_PATH = ROOT / 'config/lab.connected.yaml'
PLANS_DIR = ROOT / 'data' / 'plans'
MANIFEST_PATH = ROOT / 'data' / 'pilot_benign_plans_manifest.json'
DURATION_S = 180


def main():
    PLANS_DIR.mkdir(parents=True, exist_ok=True)
    capacities = load_lab(LAB_PATH)['capacity_mbps']
    profiles = load_profiles(ROOT / 'profiles')
    manifest = []
    for seed in PILOT_SEEDS:
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
