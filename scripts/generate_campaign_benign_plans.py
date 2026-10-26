"""D7 campaign (N=10, docs/PILOT2_RESULT.md's reparto): generate the 10
per-seed benign plans (seeds 1-10, disjoint from every seed range used
so far: calibration 101-110, pilot 1 201-203, pilot2/pilot2b 204-206,
the FPR measurement 301-315) -- SAME exclusion as
generate_pilot2b_benign_plans.py (composition3's dedicated attack-only
hosts ent-site-4/5, fixed9/10, ue4/5 carry ZERO benign traffic), since
the campaign reuses pilot2b's validated composition3 design unchanged.
Pure local computation, never touches the lab."""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_lab.config import load_lab
from benign_lab.planner import generate, load_profiles, save_plan

LAB_PATH = ROOT / 'config/lab.connected.yaml'
PLANS_DIR = ROOT / 'data' / 'plans'
MANIFEST_PATH = ROOT / 'data' / 'campaign_benign_plans_manifest.json'
DURATION_S = 180
CAMPAIGN_SEEDS = tuple(range(1, 11))

EXCLUDE = {
    'enterprise': {'ent-site-4', 'ent-site-5'},
    'fixed': {'fixed9', 'fixed10'},
    'mobile': {'ue4', 'ue5'},
}


def excluded_profiles(profiles):
    p = copy.deepcopy(profiles)
    p['enterprise']['population']['sites'] = [
        s for s in p['enterprise']['population']['sites'] if s not in EXCLUDE['enterprise']]
    p['mobile']['population']['users'] = [
        u for u in p['mobile']['population']['users'] if u not in EXCLUDE['mobile']]
    p['fixed']['population']['identifiers']['end'] = 8
    return p


def main():
    PLANS_DIR.mkdir(parents=True, exist_ok=True)
    capacities = load_lab(LAB_PATH)['capacity_mbps']
    profiles = excluded_profiles(load_profiles(ROOT / 'profiles'))
    manifest = []
    for seed in CAMPAIGN_SEEDS:
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
