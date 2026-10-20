"""D7 pilot: concrete, reproducible run order for the I-vs-M pilot design
(benign seeds 201-203, disjoint from calibration 101-110 and from the
eventual N-seed campaign). Pure, offline: this module only decides WHAT
to run and in WHAT order, exactly like im_campaign.py; it contains no
SSH/API/network code. scripts/run_pilot.py (the executor) drives the
already-running dashboard's /api/runs with this schedule, the same
pattern scripts/run_calibration_seeds.py already uses against the real
lab -- this module never touches the lab itself.

Per the pilot brief: "Bloque = semilla x escenario. En cada semilla: C1-I
y C1-M (benigno), y para cada plan de attack_plans_manifest.json las
condiciones C2, C3 y C4." -- C1-I/C1-M run ONCE per seed (benign-only
traffic has no attack-plan dimension to repeat over); C2/C3/C4 run once
per (seed, scenario) block, one block per attack_plans_manifest.json
entry. This differs deliberately from im_campaign.block_runs(), which
repeats C1-I/C1-M once per scenario_id too -- that module's own, wider
"D7 campaign" discussion in docs/IM_COMPARISON_DESIGN.md predates this
narrower pilot brief and is left untouched; this module is the one that
matches what was actually asked for the pilot.

"Orden aleatorio reproducible dentro de cada semilla, con un RNG cuya
semilla quede registrada" (brief) -> build_pilot_schedule() seeds a
single random.Random once with PILOT_RNG_SEED and shuffles each seed's
20 runs with it, consumed in increasing seed order (201, then 202, then
203) -- the whole schedule is reproducible from that one recorded
integer, and seeds themselves are never reordered (so the lab always
finishes one benign seed's worth of traffic before starting the next).

"60 s de pausa entre ejecuciones; reinicio del controlador solo entre
ejecuciones cuando cambia el modo" (brief) -- the pause is unconditional
(PAUSE_S, applied by the executor between every two consecutive runs);
the restart is NOT unconditional: runner.Manager.apply_detection_mode()
(D7-pilot change, same commit as this module) now calls
DetectionModeControl.read() first and skips .apply()'s restart whenever
the controller is already in the requested mode -- exactly the condition
mode_switches()/estimate_duration_s() below count.
"""
import random
from dataclasses import dataclass
from typing import List, Optional

PILOT_SEEDS = (201, 202, 203)
PILOT_RNG_SEED = 20261020  # arbitrary, recorded here for reproducibility -- not derived from anything


@dataclass(frozen=True)
class PilotRun:
    seed: int
    condition: str  # 'C1-I' | 'C1-M' | 'C2' | 'C3' | 'C4'
    scenario_id: Optional[str]  # None for C1-I/C1-M; manifest 'name' otherwise
    plan_hash: Optional[str]  # None for C1-I/C1-M
    scenario: str  # 'B0' or 'B0+attack'
    pipeline: str  # 'enabled' or 'baseline'
    detection_mode: Optional[str]  # 'isolated' | 'multidomain' | None (C2)


def seed_runs(seed, manifest):
    """The 2 + 3*len(manifest) PilotRuns for one seed: C1-I and C1-M once,
    then C2/C3/C4 for every attack_plans_manifest.json entry."""
    if not manifest:
        raise ValueError('seed_runs requires a non-empty attack plan manifest')
    runs = [
        PilotRun(seed=seed, condition='C1-I', scenario_id=None, plan_hash=None,
                  scenario='B0', pipeline='enabled', detection_mode='isolated'),
        PilotRun(seed=seed, condition='C1-M', scenario_id=None, plan_hash=None,
                  scenario='B0', pipeline='enabled', detection_mode='multidomain'),
    ]
    for entry in manifest:
        runs.append(PilotRun(seed=seed, condition='C2', scenario_id=entry['name'], plan_hash=entry['plan_hash'],
                              scenario='B0+attack', pipeline='baseline', detection_mode=None))
        runs.append(PilotRun(seed=seed, condition='C3', scenario_id=entry['name'], plan_hash=entry['plan_hash'],
                              scenario='B0+attack', pipeline='enabled', detection_mode='isolated'))
        runs.append(PilotRun(seed=seed, condition='C4', scenario_id=entry['name'], plan_hash=entry['plan_hash'],
                              scenario='B0+attack', pipeline='enabled', detection_mode='multidomain'))
    return runs


def build_pilot_schedule(manifest, seeds=PILOT_SEEDS, rng_seed=PILOT_RNG_SEED):
    """All PilotRuns for `seeds` (in the order given -- never shuffled
    across seeds), each seed's own runs shuffled in a reproducible random
    order. A single random.Random(rng_seed) is consumed across seeds in
    sequence, so the entire schedule is reproducible from rng_seed alone."""
    if not seeds:
        raise ValueError('build_pilot_schedule requires at least one seed')
    rng = random.Random(rng_seed)
    schedule = []
    for seed in seeds:
        block = seed_runs(seed, manifest)
        rng.shuffle(block)
        schedule.extend(block)
    return schedule


def mode_switches(schedule):
    """Count of controller detection-mode changes the schedule requires:
    transitions between two consecutive runs that each declare a
    detection_mode and disagree. C2 (detection_mode=None, pipeline
    suspended) never counts as a transition on either side of it -- the
    mode is irrelevant while the pipeline is suspended, same convention
    as im_campaign.mode_switches()."""
    modes = [r.detection_mode for r in schedule if r.detection_mode is not None]
    return sum(1 for a, b in zip(modes, modes[1:]) if a != b)


RUN_DURATION_S = 180  # every data/plans and data/attack_plans plan used by the pilot is this long
PAUSE_S = 60
RESTART_S = 60  # DetectionModeControl's own apply() wait-for-STARTUP-log deadline (detection_mode_control.py)


def estimate_duration_s(schedule, initial_mode_unknown=True):
    """Wall-clock estimate: every run's own duration, PAUSE_S between
    every two consecutive runs, and RESTART_S only where mode_switches()
    would actually trigger a restart (apply_detection_mode skips it when
    the controller already reports the requested mode).

    `initial_mode_unknown` (default True) adds exactly one extra RESTART_S
    for the very first mode-bearing run of the whole schedule: the
    controller's mode before the pilot starts is whatever a previous,
    unrelated run left it in, so it cannot be assumed to already match
    without checking live -- the executor calls DetectionModeControl.read()
    anyway and will skip this restart for real if it turns out to already
    match, same as every other transition."""
    n = len(schedule)
    run_total = n * RUN_DURATION_S
    pause_total = max(0, n - 1) * PAUSE_S
    switches = mode_switches(schedule)
    if initial_mode_unknown and any(r.detection_mode is not None for r in schedule):
        switches += 1
    restart_total = switches * RESTART_S
    return dict(runs=n, run_duration_s=run_total, pause_s=pause_total,
                mode_switches=switches, restart_s=restart_total,
                total_s=run_total + pause_total + restart_total)
