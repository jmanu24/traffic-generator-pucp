"""Dispatch an attack plan against the real laboratory.

Reuses the same low-level pipeline already validated for benign traffic:
config.resolve() to group attack events by executor node, one direct
subprocess per group (local/SSH/namespace, exactly like benign_lab.runner's
non-supervisor path), clock_sync.probe_clock for a shared synchronized start,
and benign_lab.agent's existing newline-delimited JSON protocol. The agent
dispatches udp_flood/syn_flood/icmp_flood events through attack_flood()
instead of the cooperative traffic() path; nothing here talks to a receiver.

This module does not touch benign_lab.runner.Manager: an attack run is not a
scientific benign-traffic measurement, has no capacity/quota model, and does
not go through BaselineGuard. It is the thing the external hping3 run used to
be, except internal, precisely timed and coordinated across real clients.
"""
from __future__ import annotations
import asyncio
import json
import time
from .config import resolve
from .clock_sync import probe_clock
from .planner import canonical
from .attack_planner import validate_attack_plan


async def run_attack(plan, cfg, start_lead_s=None, on_log=None):
    """Launch every event in an attack plan and return observed timing.

    Returns dict(started_at, finished_at, events={event_id: {...}}) once every
    agent process has exited or the plan duration has elapsed. Raises on any
    preparation failure (resolve/connect/clock); partial per-event failures
    during the flood itself are reported in events[...]['error'] instead.
    """
    validate_attack_plan(plan)
    log = on_log or (lambda msg: None)
    groups = resolve(cfg, plan)
    if not groups:
        raise ValueError('Attack plan resolved to no executor groups')
    events_by_id = {e['event_id']: dict(e, status='pending', packets_sent=0,
                                         attack_pps_target=None, attack_pps_actual=None,
                                         actual_start_s=None, actual_end_s=None, error=None)
                    for e in plan['events']}
    processes = []

    async def prepare(key, group):
        proc = await asyncio.create_subprocess_exec(
            *group['argv'], stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True, limit=32*1024*1024)
        processes.append(proc)
        payload = dict(events=group['events'], targets=cfg['targets'],
                        duration_s=plan['duration_s'], context=group['context'], execution={})
        proc.stdin.write(canonical(payload)+b'\n')
        await proc.stdin.drain()
        line = await asyncio.wait_for(proc.stdout.readline(), 30)
        if not line:
            err = (await proc.stderr.read(2000)).decode(errors='replace')
            raise RuntimeError(f'Attack agent {key} did not start: {err}')
        reply = json.loads(line)
        if reply.get('type') != 'ready':
            raise RuntimeError(f'Attack agent {key}: {reply.get("error", reply)}')
        log(f'Attack agent ready: {", ".join(sorted(group["sources"]))}')
        return proc, group

    try:
        prepared = await asyncio.gather(*(prepare(k, g) for k, g in groups.items()))
        for key, (proc, group) in zip(groups, prepared):
            clock = await probe_clock(proc, cfg.get('max_clock_skew_s', .5))
            if clock['status'] == 'skewed':
                raise RuntimeError(f'Attack source clock skew exceeds limit: {clock}')
            log(f'Clock {", ".join(sorted(group["sources"]))}: {clock["status"]}')
        start = time.time() + (start_lead_s if start_lead_s is not None else cfg.get('start_lead_s', 3))
        for proc, group in prepared:
            proc.stdin.write(canonical(dict(start_unix=start))+b'\n')
            await proc.stdin.drain()
        log(f'Attack scheduled for epoch {start:.6f}')

        async def read(proc):
            while line := await proc.stdout.readline():
                envelope = json.loads(line)
                if envelope['type'] not in ('event', 'metrics'):
                    continue
                e = events_by_id.get(envelope['event_id'])
                if e is None:
                    continue
                for key in ('status', 'packets_sent', 'attack_pps_target', 'attack_pps_actual',
                            'attack_packets_total', 'actual_start_s', 'actual_end_s', 'error'):
                    if key in envelope:
                        e[key] = envelope[key]
            await proc.wait()

        await asyncio.wait_for(asyncio.gather(*(read(proc) for proc, _ in prepared)),
                                timeout=plan['duration_s']+30)
        finished_at = time.time()
        return dict(started_at=start, finished_at=finished_at, events=events_by_id)
    finally:
        for proc in processes:
            if proc.returncode is None:
                proc.terminate()
        for proc in processes:
            if proc.returncode is None:
                try:
                    await asyncio.wait_for(proc.wait(), 5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
