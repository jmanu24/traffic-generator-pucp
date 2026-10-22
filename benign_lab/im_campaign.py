"""Block/condition scheduling for the I-vs-M thesis comparison (C1-C4).

Pure functions only: this module decides WHAT to run and in WHAT order. It
does not execute anything and contains no remote-control code -- the actual
controller mode switch lives in detection_mode_control.py, and launching a
run goes through runner.Manager.start as usual.

Conditions, one block = one (seed, scenario_id) pair:
  C1-I  benign only, detector enabled,    isolated mode     (FP baseline, I)
  C1-M  benign only, detector enabled,    multidomain mode  (FP baseline, M)
  C2    benign + attack, pipeline suspended, mode irrelevant (no-mitigation reference)
  C3    benign + attack, detector enabled, isolated mode     (I treatment)
  C4    benign + attack, detector enabled, multidomain mode  (M treatment)

The primary comparison is the paired M-I difference within each block (same
seed, same scenario): C4 minus C3 during the attack is the main hypothesis;
C1-M minus C1-I is the false-positive-rate counterpart under benign-only
traffic. experimental_analytics.report()/detail() already pair runs sharing
a plan_hash/execution_hash whose grouping differs only by detection_mode.
"""
import random
from dataclasses import dataclass
from typing import Optional, Tuple

CONDITIONS = ('C1-I', 'C1-M', 'C2', 'C3', 'C4')

_SPEC = {
    'C1-I': dict(scenario='B0', pipeline='enabled', detection_mode='isolated', has_attack=False),
    'C1-M': dict(scenario='B0', pipeline='enabled', detection_mode='multidomain', has_attack=False),
    'C2': dict(scenario='B0+attack', pipeline='baseline', detection_mode=None, has_attack=True),
    'C3': dict(scenario='B0+attack', pipeline='enabled', detection_mode='isolated', has_attack=True),
    'C4': dict(scenario='B0+attack', pipeline='enabled', detection_mode='multidomain', has_attack=True),
}


@dataclass(frozen=True)
class RunSpec:
    seed: int
    scenario_id: str
    condition: str
    scenario: str
    pipeline: str
    detection_mode: Optional[str]
    has_attack: bool
    block: Tuple[int, str]


def block_runs(seed, scenario_id):
    """The 5 condition runs for one (seed, scenario_id) block, C1-I..C4."""
    return [
        RunSpec(seed=seed, scenario_id=scenario_id, condition=c, block=(seed, scenario_id), **_SPEC[c])
        for c in CONDITIONS
    ]


IM_CAMPAIGN_RNG_SEED = 20261022  # arbitrary, recorded here for reproducibility
# -- same convention as pilot_schedule.PILOT_RNG_SEED; the value itself has
# no significance, only that it is fixed and this module names it.


def build_schedule(seeds, scenario_ids, rng_seed=IM_CAMPAIGN_RNG_SEED):
    """All blocks (seed x scenario_id), seeds in the given order (never
    reordered), each seed's own runs shuffled in a reproducible random
    order -- the SAME scheme pilot_schedule.build_pilot_schedule() already
    uses for the pilot, not grouped by detection_mode.

    D7: grouping by mode (the previous behaviour) minimized restarts, but
    that is exactly the problem -- it makes "how many seconds since the
    controller last restarted" and "how many runs since a mode switch"
    almost perfectly collinear with detection_mode itself, so any
    difference the campaign measures between I and M can never rule out
    a restart/order confound instead of a real treatment effect (this is
    the mechanism docs/PILOT_DIAGNOSIS.md §4/§7 found live in the pilot:
    reinicio y modo quedaron confundidos al 100%). Shuffling within each
    seed, independent of mode, breaks that collinearity -- restarts and
    runs-since-restart now vary somewhat independently of which mode a
    given run happens to request.

    A single random.Random(rng_seed) is consumed across seeds in
    increasing order, so the whole schedule is reproducible from that one
    recorded integer -- same property pilot_schedule.build_pilot_schedule()
    already has, and for the same reason (a campaign run is real lab time
    that must be exactly replayable from its own log)."""
    if not seeds or not scenario_ids:
        raise ValueError('build_schedule requires at least one seed and one scenario_id')
    rng = random.Random(rng_seed)
    schedule = []
    for seed in seeds:
        block = [run for scenario_id in scenario_ids for run in block_runs(seed, scenario_id)]
        rng.shuffle(block)
        schedule.extend(block)
    return schedule


def mode_switches(schedule):
    """Count of controller detection-mode changes a schedule would require.
    C2 runs (detection_mode is None, pipeline suspended) never require a
    switch -- the mode is irrelevant while the pipeline is suspended."""
    modes = [r.detection_mode for r in schedule if r.detection_mode is not None]
    return sum(1 for a, b in zip(modes, modes[1:]) if a != b)


def required_mode_before(run_spec):
    """The controller mode that must already be applied before launching
    this run, or None if the run is indifferent (C2)."""
    return run_spec.detection_mode
