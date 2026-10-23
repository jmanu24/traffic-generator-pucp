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
import os
import time
from .config import resolve
from .clock_sync import probe_clock
from .planner import canonical
from .attack_planner import validate_attack_plan


async def _sweep_stale_attack_processes(groups, on_log=None):
    """Best-effort kill of any leftover `hping3` syn_flood process on every
    attack-source host this plan is about to use, BEFORE launching this
    run's own attack.

    Defense in depth, not the fix itself: agent.py's attack_flood() now
    also reaps its own hping3 child on cleanup (the actual root cause --
    `hping.kill()`'s SIGKILL only reaches the `sudo` wrapper, never the
    hping3 grandchild it pty-forks, confirmed live 2026-10-22). This sweep
    exists for everything that fix cannot reach: runs from before it
    existed, a run whose own cleanup never got to execute (killed harder
    than SIGKILL, host rebooted mid-flood, etc.), or any future leak this
    narrow fix does not happen to cover. Scoped to `hping3` specifically
    (the only flood vector in agent.py that forks a subprocess at all --
    udp_flood/icmp_flood run in-process, nothing to leak there).

    One host is swept once even if several attack events use it. Never
    raises: a failed sweep on one host (unreachable, no credential, no
    sudo rule) must not block this run's own, fresh attack dispatch --
    it only ever removes stale state, so a no-op here is safe, not silent
    data corruption."""
    log = on_log or (lambda msg: None)
    seen = set()
    for group in groups.values():
        node = group['node']
        host = node.get('host')
        if node.get('adapter') not in ('ssh', 'ssh_netns') or not host or host in seen:
            continue
        seen.add(host)
        password = os.environ.get(node.get('password_env', 'BENIGN_SSH_PASSWORD'))
        if node.get('auth_mode') != 'password_env' or not password:
            continue
        env = dict(os.environ, SSHPASS=password)
        argv = ['sshpass', '-e', 'ssh', '-T', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5']
        if node.get('known_hosts_file'):
            argv += ['-o', 'UserKnownHostsFile=' + node['known_hosts_file']]
        argv += [f"{node.get('user')}@{host}", 'sudo -n pkill -9 -f hping3; true']
        try:
            proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.DEVNULL,
                                                          stderr=asyncio.subprocess.DEVNULL, env=env)
            await asyncio.wait_for(proc.wait(), 10)
        except (OSError, asyncio.TimeoutError):
            pass
    if seen:
        log(f'Stale-attack-process sweep: checked {len(seen)} host(s)')


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
    await _sweep_stale_attack_processes(groups, on_log=log)
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
        # Real resolved attacker addresses -- the same per-group context the
        # agent payload itself was built from (config.resolve), never the
        # plan's logical node names. Ground truth (attack_source_ips) must
        # describe what was actually put on the wire, not what was planned.
        source_ips = sorted({group['context']['source_ip'] for _, group in prepared
                              if group.get('context', {}).get('source_ip')})
        return dict(started_at=start, finished_at=finished_at, events=events_by_id, source_ips=source_ips)
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
