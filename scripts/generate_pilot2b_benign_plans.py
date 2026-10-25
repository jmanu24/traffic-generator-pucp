"""PILOT2 blocker fix (2026-10-24): regenerate the 3 per-seed benign
plans (204-206) EXCLUDING composition3's dedicated attack-only hosts
(ent-site-4/5, fixed9/10, ue4/5) from the benign population entirely --
see generate_attack_plans_v2.py's COMPOSITION3_SOURCES comment for why.
The benign plan is shared by every condition (C1/C2/C3/C4) and every
composition within a seed (same background realization for an
apples-to-apples I-vs-M comparison), so this regeneration invalidates
ALL of pilot2's existing 204-206 data, not just composition 3's -- a
full pilot2 rerun for these 3 seeds follows this. Same deterministic
generator/lab capacities as every other benign plan in this repo; the
only change is the population lists passed in. Pure local computation,
never touches the lab."""
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
MANIFEST_PATH = ROOT / 'data' / 'pilot2b_benign_plans_manifest.json'
DURATION_S = 180
PILOT2_SEEDS = (204, 205, 206)

# Dedicated composition-3 attack-only hosts -- must carry ZERO benign
# traffic (generate_attack_plans_v2.py's COMPOSITION3_SOURCES).
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
    # fixed uses a start/end numeric range (fixed1..fixed10) -- shrink
    # end to 8 so fixed9/fixed10 are outside the population range.
    p['fixed']['population']['identifiers']['end'] = 8
    return p


def main():
    PLANS_DIR.mkdir(parents=True, exist_ok=True)
    capacities = load_lab(LAB_PATH)['capacity_mbps']
    profiles = excluded_profiles(load_profiles(ROOT / 'profiles'))
    manifest = []
    for seed in PILOT2_SEEDS:
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
