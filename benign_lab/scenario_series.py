"""Fixed statistical design, separate from immutable benign plans."""
import ipaddress


def interleaved_order(seeds, repeats_per_seed=None):
    """Balanced Latin-square rotation: every seed appears once in every
    relative position across the whole campaign, so execution order never
    confounds a single seed with time-of-day/thermal/network drift.

    Generalizes the fixed 3-seed/6-run design (today hardcoded in
    api.py's comparison_steps as the 6 permutations of (1,2,3)) to any
    number of seeds — the methodological property that matters (balance,
    not exhaustive permutation) holds for any n, while listing every
    permutation would grow factorially and stop being practical past a
    handful of seeds. Fase 2's sample_size.required_seeds() decides len(seeds)
    and this decides the run order for however many seeds that is.
    """
    if not seeds:
        raise ValueError('At least one seed is required')
    seeds = list(seeds)
    repeats = repeats_per_seed if repeats_per_seed is not None else len(seeds)
    if repeats < 1:
        raise ValueError('repeats_per_seed must be at least 1')
    order = []
    for rotation in range(repeats):
        shift = rotation % len(seeds)
        order.extend(seeds[shift:] + seeds[:shift])
    return order
SCENARIOS={'benign_off':('B0','baseline'),'benign_on':('B0','enabled'),'attack_off':('B0+attack','baseline'),'attack_on':('B0+attack','enabled')}
def scenario_steps(reference,scenario,start_s=300,end_s=360,source_ips=None,description=''):
 if scenario not in SCENARIOS:raise ValueError('Unknown experimental scenario')
 attack=scenario.startswith('attack_');sources=[]
 if attack:
  if not 0<=start_s<end_s<=600:raise ValueError('Attack window must be within 0–600 seconds')
  if not source_ips or not description.strip():raise ValueError('Declare attack source IPs and repeatable attack conditions')
  for raw in source_ips:
   ip=ipaddress.ip_address(raw)
   if ip.version!=4 or not ip.is_private:raise ValueError('Attack source must be a private laboratory IPv4 address')
   sources.append(str(ip))
 mode,pipeline=SCENARIOS[scenario]
 return [dict(r,scenario=mode,pipeline=pipeline,attack_windows=[dict(name='external_attack',start_s=start_s,end_s=end_s)] if attack else []) for r in reference],sorted(set(sources))
