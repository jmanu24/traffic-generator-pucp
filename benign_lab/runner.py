from __future__ import annotations
import asyncio
from asyncio import TimeoutError
import copy
import csv
import io
import json
import os
import signal
import time
import uuid
from collections import Counter
from pathlib import Path
from .config import resolve, supervisor_groups
from .execution import execution_options
from .transport import SupervisorSession
from .clock_sync import probe_clock
from .baseline import BaselineGuard
from .detection_mode_control import DetectionModeControl
from .attack_runner import run_attack
from .attack_planner import validate_attack_plan
from .ground_truth import windows
from .planner import canonical, digest, validate

TERMINAL = {'completed','completed_with_errors','failed','stopped','interrupted'}


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_bytes(canonical(value)+b'\n')
    tmp.replace(path)


def csv_text(rows):
    if not rows: return ''
    out=io.StringIO()
    fields=list(dict.fromkeys(key for row in rows for key in row))
    writer=csv.DictWriter(out,fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


class Manager:
    def __init__(self, root):
        self.root=Path(root)
        self.root.mkdir(parents=True,exist_ok=True)
        self.runs={}
        self.tasks={}
        self.stops={}
        self.processes={}
        self.supervisors={}
        self.events={}
        self.logs={}
        self.origins={}
        self.plan_cache={}
        self.checkpoint_lock=None
        self.terminal_metrics={}
        # Set by the caller (api.py) after construction, same lifetime as
        # this Manager -- the second detection_mode verification evidence
        # (LAB_AUDIT kind=cycle) reads from it. None means "not wired up",
        # which apply_detection_mode treats as verification being
        # impossible, never as an unverified pass.
        self.audit=None
        for file in sorted(self.root.glob('*/run.json')):
            run=json.loads(file.read_text())
            eid=run['id']
            self.runs[eid]=run
            lp=file.parent/'logs.jsonl'
            self.logs[eid]=[json.loads(line) for line in lp.read_text().splitlines()[-200:] if line.strip()] if lp.exists() else []
            if run['status'] not in TERMINAL:
                ep=file.parent/'event_states.json'
                self.events[eid]=json.loads(ep.read_text()) if ep.exists() else {}
                run.update(status='interrupted',error='Orchestrator restarted; no automatic replay',finished_at=time.time())
                for e in self.events[eid].values():
                    if e['status'] in ('pending','running'): e['status']='interrupted'
                self.persist(eid)
                # Deliberately NOT evicted here: a run recovered mid-flight
                # this way can have partial/synthetic event data (e.g. a
                # crash before every field was ever written), and
                # evict_events()'s snapshot() call expects the full event
                # shape. Leaving it in memory is the same (safe) behavior
                # this had before eviction existed -- one recovered run's
                # footprint is not the O(total history) problem below.
            else:
                # D7 campaign finding (2026-10-25): PILOT_RESULT.md section
                # 1's eviction (below) still paid the full cost of reading
                # event_states.json AND recomputing terminal_metrics for
                # EVERY historical terminal run on EVERY process restart --
                # with 576+ accumulated runs (1.16M total events, 9.6GB),
                # that's a 30+ minute synchronous __init__, blocking the
                # whole event loop (and every request) before the server
                # can even start. terminal_summary_path() persists the
                # computed summary to its OWN tiny file the first time
                # it's ever computed (right below, and in snapshot()'s own
                # cache-miss branch) -- __init__ now reads just THAT file
                # when present (near-O(1)) and skips event_states.json
                # entirely; only a run whose summary was never computed
                # before (e.g. ones that predate this fix) falls through
                # to the old lazy-compute-on-first-request path via
                # snapshot()/events_for(), which then persists it too, so
                # the cost is paid at most once per run, ever -- not once
                # per run per restart.
                summary_path=self.terminal_summary_path(eid)
                if summary_path.exists():
                    try:
                        self.terminal_metrics[eid]=json.loads(summary_path.read_text())
                        continue
                    except (OSError,ValueError):pass  # fall through to the lazy path below
                # No cached summary yet -- do NOT read event_states.json
                # here either; leave self.events[eid] unset so events_for()
                # reads it from disk lazily, only if/when something actually
                # requests this run's snapshot (never during __init__ for a
                # restart's whole backlog at once).

    def folder(self, rid): return self.root/rid

    def terminal_summary_path(self,rid): return self.folder(rid)/'terminal_summary.json'

    def events_for(self,rid):
        """Full per-event state for `rid`: from memory if this run is
        still active (evict_events() only clears a TERMINAL run), else
        read once from disk -- a terminal run's event_states.json never
        changes again, so this is always consistent, just not cached
        back into self.events (that would defeat evict_events() -- see
        its own docstring for why total-history memory growth matters)."""
        events=self.events.get(rid)
        if events:return events
        ep=self.folder(rid)/'event_states.json'
        return json.loads(ep.read_text()) if ep.exists() else {}

    def evict_events(self,rid):
        """Drop a TERMINAL run's full event_states from memory, once
        snapshot()'s own derived summaries (terminal_metrics/
        payload_quality) are cached -- those are everything snapshot()
        needs for a terminal run afterward, never self.events[rid]
        itself. A no-op for a run that is not yet terminal (nothing to
        evict: it's still being mutated live). checkpoint() (via
        events_for()) and the few other terminal-run readers
        (/api/runs/{rid}/events, evaluation_dataset) fall back to
        reading event_states.json from disk on demand -- never silently
        missing data, just not held in memory between requests."""
        if self.runs[rid]['status'] not in TERMINAL:return
        self.snapshot(rid)
        self.events[rid]={}

    def elapsed(self,rid):
        r=self.runs[rid]
        if r['status'] in TERMINAL or rid not in self.origins: return r.get('elapsed_s',0)
        return min(r['duration_s'],max(0,(time.monotonic()-self.origins[rid])*(r['speed'] if r['mode']=='simulation' else 1)))

    def snapshot(self,rid):
        r=copy.deepcopy(self.runs[rid])
        r['elapsed_s']=self.elapsed(rid)
        cached=self.terminal_metrics.get(rid) if r['status'] in TERMINAL and r.get('finished_at') else None
        if cached is not None:
            r.update(copy.deepcopy(cached))
        else:
            events=self.events_for(rid)
            r['counts']=dict(Counter(e['status'] for e in events.values()))
            r['bytes_tx']=sum(e.get('bytes_tx',0) for e in events.values())
            r['bytes_rx']=sum(e.get('bytes_rx',0) for e in events.values())
            r['shortfall_bytes']=sum(e.get('shortfall_bytes',0) for e in events.values())
            r['active_planned_mbps']=sum(e['rate_bps'] for e in events.values() if e['status']=='running')/1e6
            r['domains']={}
            for domain in ('mobile','fixed','enterprise','peering'):
                es=[e for e in events.values() if e['domain']==domain]
                r['domains'][domain]=dict(counts=dict(Counter(e['status'] for e in es)),bytes_tx=sum(e.get('bytes_tx',0) for e in es),bytes_rx=sum(e.get('bytes_rx',0) for e in es),active_planned_mbps=sum(e['rate_bps'] for e in es if e['status']=='running')/1e6)
            # PILOT2b finding (2026-10-24): list_runs() used to stat()
            # detection_events.jsonl for every run on every poll -- with
            # hundreds of historical runs, that's hundreds of synchronous
            # disk syscalls per call, blocking the whole event loop long
            # enough to starve the active run's own deadline/agent-sync
            # tasks ("Agents exceeded the experiment deadline" on otherwise
            # healthy runs). A terminal run's audit file never changes
            # again, so compute it once here and cache it like the other
            # terminal metrics below, instead of re-stat'ing it forever.
            path=self.folder(rid)/'detection_events.jsonl'
            r['audit_available']=path.exists() and path.stat().st_size>0
            if r['status'] in TERMINAL and r.get('finished_at'):
                self.terminal_metrics[rid]={k:copy.deepcopy(r[k]) for k in ('counts','bytes_tx','bytes_rx','shortfall_bytes','active_planned_mbps','domains','audit_available')}
        if 'payload_quality' not in r:
            events=self.events_for(rid)
            eligible=[e for e in events.values() if e.get('wire_protocol') in ('tcp','http','udp') and e['status'] not in ('pending','running')]
            r['payload_quality']=dict(eligible=len(eligible),full_local=sum(e.get('bytes_tx',0)+e.get('bytes_rx',0)>=e['planned_bytes'] for e in eligible),partial=sum(0<e.get('bytes_tx',0)+e.get('bytes_rx',0)<e['planned_bytes'] for e in eligible),zero=sum(e.get('bytes_tx',0)+e.get('bytes_rx',0)==0 for e in eligible),receiver_confirmed=sum((e.get('receiver_bytes',0)>=e['planned_bytes'] or e.get('direction')=='dl' and e.get('bytes_rx',0)>=e['planned_bytes']) and e['planned_bytes']>0 for e in eligible) if r.get('mode')=='lab' else 0,interpretation='Observed local quota; UL requires receiver acknowledgement. Historical states are preserved.')
            if r['status'] in TERMINAL and r.get('finished_at'):
                self.terminal_metrics[rid]['payload_quality']=copy.deepcopy(r['payload_quality'])
                # Persist once the full summary (counts/bytes/.../
                # payload_quality) is complete -- see __init__'s own
                # comment for why this is the fix for the 30+ minute
                # restart cost: every future process lifetime reads this
                # tiny file instead of event_states.json (which can be
                # several MB) and never recomputes any of the above.
                # Best-effort: this run's own folder may not exist yet in
                # some in-memory-only call patterns (e.g. tests driving
                # Manager directly without ever creating it on disk) --
                # exactly like LAB_AUDIT's own emit(), a caching write
                # failing here must never break snapshot()'s primary job
                # of returning the correct in-memory metrics.
                try:atomic_json(self.terminal_summary_path(rid),self.terminal_metrics[rid])
                except OSError:pass
        if r.get('purpose')=='domain_benchmark':
            actual=r['bytes_tx']+r['bytes_rx'];planned=r['benchmark_planned_bytes']
            r['benchmark_metrics']=dict(domain=r['benchmark_domain'],planned_bytes=planned,actual_bytes=actual,observed_pct=100*actual/planned,planned_mean_mbps=planned*8/r['duration_s']/1e6,observed_mean_mbps=actual*8/max(r['elapsed_s'],.001)/1e6,failed_events=r['counts'].get('failed',0),final=r['status'] in TERMINAL)
        r['logs']=self.logs[rid][-100:]
        return r

    def log(self,rid,message,level='info'):
        row=dict(timestamp=time.time(),level=level,message=message)
        self.logs[rid].append(row)
        self.logs[rid]=self.logs[rid][-200:]
        with (self.folder(rid)/'logs.jsonl').open('a') as f: f.write(json.dumps(row)+'\n')

    def checkpoint(self,rid):
        self.runs[rid]['elapsed_s']=self.elapsed(rid)
        if rid not in self.plan_cache:
            self.plan_cache[rid]=json.loads((self.folder(rid)/'benign_plan.json').read_text())
        # events_for(), not self.events[rid] directly: a terminal run
        # re-persisted after eviction (e.g. /api/runs/{rid}/export) must
        # never have write_checkpoint() overwrite its already-correct
        # event_states.json with the now-empty in-memory dict.
        return (self.folder(rid),copy.deepcopy(self.runs[rid]),copy.deepcopy(self.events_for(rid)),self.plan_cache[rid])

    @staticmethod
    def write_checkpoint(snapshot):
        folder,r,events,plan=snapshot
        atomic_json(folder/'run.json',r)
        atomic_json(folder/'event_states.json',events)
        for name,rows in (('ground_truth_windows.csv',windows(plan,r)),('generated_events.csv',list(events.values()))):
            target=folder/name;tmp=target.with_suffix('.tmp')
            tmp.write_text(csv_text(rows));tmp.replace(target)

    def persist(self,rid):
        # Synchronous recovery before the event loop starts.
        self.write_checkpoint(self.checkpoint(rid))

    async def persist_async(self,rid,after=None):
        if self.checkpoint_lock is None:self.checkpoint_lock=asyncio.Lock()
        async with self.checkpoint_lock:
            snapshot=self.checkpoint(rid)
            def work():
                self.write_checkpoint(snapshot)
                return after() if after else None
            future=asyncio.get_running_loop().run_in_executor(None,work)
            try:return await asyncio.shield(future)
            except asyncio.CancelledError:
                # Threads cannot be canceled. Keep the lock until the writer
                # has finished so shutdown cannot overlap a newer checkpoint.
                await future
                raise

    async def start(self,plan,plan_file,cfg,mode='simulation',scenario='B0',speed=20,attack_windows=None,pipeline='enabled',execution_profile=None,detection_mode=None,attack_plan=None,attack_plan_file=None):
        validate(plan)
        if detection_mode is not None and detection_mode not in ('isolated','multidomain'):
            raise ValueError('Invalid detection_mode')
        if detection_mode is not None and mode!='lab':
            raise ValueError('detection_mode only applies to laboratory runs')
        if detection_mode is None and mode=='lab' and pipeline=='enabled' and cfg.get('baseline_control'):
            raise ValueError('detection_mode is required for laboratory runs with pipeline=enabled (D1)')
        if attack_plan is not None and (scenario!='B0+attack' or mode!='lab'):
            raise ValueError('attack_plan requires scenario=B0+attack and laboratory mode')
        if attack_plan is not None and attack_windows:
            raise ValueError('Provide either attack_plan or explicit attack_windows, not both')
        if attack_plan is not None:
            validate_attack_plan(attack_plan)
            attack_windows=[dict(name=attack_plan['plan_hash'][:12],
                                  start_s=min(e['start_s'] for e in attack_plan['events']),
                                  end_s=max(e['start_s']+e['duration_s'] for e in attack_plan['events']))]
        if plan.get('purpose')=='domain_benchmark' and (scenario!='B0' or attack_windows or (mode=='lab' and pipeline!='baseline')):
            raise ValueError('Domain benchmark requires B0 without attacks and baseline pipeline for laboratory runs')
        cfg=copy.deepcopy(cfg)
        options=execution_options(cfg,execution_profile)
        cfg['execution_options']=options
        if pipeline not in ('enabled','baseline'): raise ValueError('Invalid pipeline option')
        if pipeline=='baseline' and mode!='lab':
            raise ValueError('Baseline requires laboratory mode')
        if mode=='lab' and cfg.get('require_explicit_mapping') and not cfg.get('baseline_control'):
            raise ValueError('Laboratory block-cleanup controller mapping is not configured')
        if pipeline=='baseline' and not cfg.get('baseline_control'):
            raise ValueError('Baseline controller mapping is not configured')
        if any(r['status'] not in TERMINAL for r in self.runs.values()):
            raise ValueError('An experiment is already active; concurrent runs would contaminate the baseline')
        if mode not in ('simulation','lab') or scenario not in ('B0','B0+attack'):
            raise ValueError('Invalid mode/scenario')
        if mode=='lab' and speed!=1: raise ValueError('Laboratory runs require speed=1')
        if not .1<=speed<=100: raise ValueError('Invalid simulation speed')
        attack_windows=attack_windows or []
        if scenario=='B0' and attack_windows: raise ValueError('B0 cannot contain attack windows')
        for w in attack_windows:
            if not 0<=w['start_s']<w['end_s']<=plan['duration_s']: raise ValueError('Invalid attack window')
        groups=resolve(cfg,plan) if mode=='lab' else {}
        rid=time.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
        folder=self.folder(rid)
        folder.mkdir()
        # Exact byte copy: experiment metadata is never written into the plan.
        (folder/'benign_plan.json').write_bytes(Path(plan_file).read_bytes())
        if attack_plan is not None:
            (folder/'attack_plan.json').write_bytes(Path(attack_plan_file).read_bytes())
        atomic_json(folder/'lab_snapshot.json',cfg)
        r=dict(id=rid,status='preparing',created_at=time.time(),started_at=None,finished_at=None,
               purpose=plan.get('purpose','baseline_plan'),benchmark_domain=plan.get('benchmark_domain'),benchmark_planned_bytes=sum(e['planned_bytes'] for e in plan['events']) if plan.get('purpose')=='domain_benchmark' else None,
               plan_hash=plan['plan_hash'],plan_file_sha256=__import__('hashlib').sha256(Path(plan_file).read_bytes()).hexdigest(),
               lab_hash=digest(cfg),seed=plan['seed'],duration_s=plan['duration_s'],mode=mode,scenario=scenario,speed=speed,
               plan_capacity_mbps=copy.deepcopy(plan['capacity_mbps']),lab_reference_capacity_mbps=copy.deepcopy(cfg.get('capacity_mbps')),
               capacities_differ=cfg.get('capacity_mbps')!=plan['capacity_mbps'],
               elapsed_s=0,attack_windows=attack_windows,observed_attacks=[],error=None,
               attack_plan_hash=attack_plan['plan_hash'] if attack_plan is not None else None,
               pipeline=pipeline,
               # Descriptive only: records which detection mode (isolated vs.
               # multidomain correlation) the real controller was already
               # switched to before this run started -- this field does NOT
               # itself switch anything. Mode switching is a separate,
               # explicit step (see benign_lab/detection_mode_control.py)
               # so that a live restart of the controller is never a
               # side effect of starting a run.
               detection_mode=detection_mode,
               execution_profile=options['profile'],execution_options=options,execution_hash=digest(options),baseline_control={},metrics_kind='simulated_payload' if mode=='simulation' else 'application_payload')
        self.runs[rid]=r
        self.plan_cache[rid]=plan
        atomic_json(folder/'execution_profile.json',dict(execution_hash=r['execution_hash'],options=options,plan_hash=plan['plan_hash']))
        self.events[rid]={e['event_id']:dict(e,status='pending',bytes_tx=0,bytes_rx=0,chunks_tx=0,chunks_rx=0,
                         icmp_replies=0,src_port=None,dst_port=None,actual_start_s=None,actual_end_s=None,
                         start_timestamp=None,stop_timestamp=None,lateness_s=None,error=None) for e in plan['events']}
        self.logs[rid]=[]
        self.stops[rid]=asyncio.Event()
        self.processes[rid]=[]
        self.log(rid,f'{scenario} | {mode} | immutable plan {plan["plan_hash"]}')
        if r['capacities_differ']:
            self.log(rid,'Custom plan capacities (Mbps): '+json.dumps(r['plan_capacity_mbps'],sort_keys=True)+'; unchanged lab reference: '+json.dumps(r['lab_reference_capacity_mbps'],sort_keys=True))
        try:
            await self.persist_async(rid)
        except Exception as exc:
            r.update(status='failed',error=f'Could not initialize artifacts: {exc}',finished_at=time.time())
            raise ValueError(r['error']) from exc
        # Public experimental provenance only; never serialize workstation credentials.
        context=dict(schema=1,captured_at=time.time(),control_python=__import__('platform').python_version(),expected_worker_code_hashes={},probe_storage={n['name']:('ram' if n.get('bootstrap_probe') else 'persistent') for n in cfg.get('traffic_monitor',{}).get('nodes',[])})
        for name in ('agent.py','supervisor.py','runner.py','transport.py','interface_probe.py','resource_probe.py'):
            try:context['expected_worker_code_hashes'][name]=__import__('hashlib').sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            except OSError:context['expected_worker_code_hashes'][name]=None
        context['worker_code_attestation']='expected control copies; remote installation not individually attested'
        for host in cfg.get('host_monitor',{}).get('hosts',[]):
            if host.get('adapter')=='workstation':
                try:
                    workstation=json.loads(Path(host['config_file']).read_text())
                    context['transport']={k:workstation.get(k) for k in ('transport','relay_endpoint','relay_network')}
                    context['workstation_guests']=sorted(workstation.get('vms',{}))
                except (OSError,ValueError,KeyError):context['transport']=None
        r['experiment_context']=context
        await self.persist_async(rid)
        self.tasks[rid]=asyncio.create_task(self.execute(rid,plan,cfg,groups,attack_plan=attack_plan))
        return self.snapshot(rid)

    async def execute(self,rid,plan,cfg,groups,attack_plan=None):
        r=self.runs[rid]
        guard=None
        try:
            if r['mode']=='lab' and r['pipeline']=='enabled' and cfg.get('baseline_control'):
                await self.apply_detection_mode(rid,cfg,r['detection_mode'])
            before_start=None
            if r['mode']=='lab' and (r['pipeline']=='baseline' or cfg.get('baseline_control')):
                cfg=copy.deepcopy(cfg)
                guard=BaselineGuard(cfg,rid,plan['duration_s'])
                if plan.get('purpose')=='domain_benchmark':guard.domains={plan['benchmark_domain']}
                r['block_preparation']=dict(started_at=time.time(),policy='release_previous_blocks_before_every_run_v1',pipeline_requested=r['pipeline'])
                self.log(rid,'Preparation: suspending pipeline and clearing previous controller/actuator restrictions')
                preflight=await guard.enter()
                r['block_preparation']['preflight']=preflight
                groups=resolve(cfg,plan)
                r['lab_hash']=digest(cfg)
                atomic_json(self.folder(rid)/'lab_snapshot.json',cfg)
                await self.persist_async(rid)
                if r['pipeline']=='baseline':
                    r['baseline_control']['preflight']=preflight
                    self.log(rid,'Restrictions cleared; pipeline remains suspended for baseline measurement')
                else:
                    async def activate_pipeline():
                        nonlocal guard
                        state=await guard.status()
                        if not state.get('active') or not state.get('cleared') or state.get('run_id')!=rid:
                            raise RuntimeError('Preparation suspension lost before start; no experimental traffic scheduled')
                        restoration=await guard.leave()
                        r['block_preparation']['pipeline_restoration']=restoration
                        if not restoration.get('restored'):raise RuntimeError('Pipeline activation not confirmed before measurement')
                        guard=None
                        r['block_preparation']['completed_at']=time.time()
                        await self.persist_async(rid)
                        self.log(rid,'All agents ready; cleanup finished and pipeline restored before measurement')
                    before_start=activate_pipeline
            if r['mode']=='simulation':
                await self.simulate(rid,plan)
            else:
                # When an attack plan is integrated (D5), its launch is
                # deferred until the benign plan's own start epoch is
                # known (set by real() via on_benign_start, fired at the
                # exact moment real() computes it -- never polled), then
                # fired with a start_lead_s chosen so attack_runner's own
                # clock-sync schedules its events against that SAME
                # epoch. Everything below this is unchanged when there is
                # no attack_plan (attack_task stays None).
                attack_task=None
                on_benign_start=None
                if attack_plan is not None:
                    loop=asyncio.get_event_loop();benign_start=loop.create_future()
                    def on_benign_start(epoch,_f=benign_start):
                        if not _f.done():_f.set_result(epoch)
                    async def launch_attack():
                        epoch=await benign_start
                        self.log(rid,f'Launching integrated attack plan {attack_plan["plan_hash"][:12]} synchronized to benign epoch {epoch:.6f}')
                        report=await run_attack(attack_plan,cfg,start_lead_s=epoch-time.time(),on_log=lambda m:self.log(rid,'attack: '+m))
                        self.record_attack_evidence(rid,report)
                    attack_task=asyncio.create_task(launch_attack())
                real_kwargs=dict(on_start=on_benign_start) if attack_task else {}
                if guard and r['pipeline']=='baseline':
                    traffic=asyncio.create_task(self.real(rid,plan,cfg,groups,**real_kwargs))
                    monitor=asyncio.create_task(guard.monitor())
                    watch=[traffic,monitor]+([attack_task] if attack_task else [])
                    try:
                        done,_=await asyncio.wait(watch,return_when=asyncio.FIRST_COMPLETED)
                        if monitor in done:await monitor
                        await traffic
                        if attack_task:
                            # traffic/monitor finishing never guarantees
                            # on_benign_start fired (e.g. stopped before
                            # real() ever computed its start epoch) --
                            # awaiting an attack_task still stuck on that
                            # future would hang forever otherwise.
                            if not benign_start.done():attack_task.cancel()
                            try:await attack_task
                            except asyncio.CancelledError:pass
                    finally:
                        for task in watch:
                            if not task.done():task.cancel()
                        await asyncio.gather(*watch,return_exceptions=True)
                elif attack_task:
                    traffic=asyncio.create_task(self.real(rid,plan,cfg,groups,before_start=before_start,**real_kwargs) if before_start else self.real(rid,plan,cfg,groups,**real_kwargs))
                    try:
                        await traffic
                    finally:
                        if not benign_start.done():attack_task.cancel()
                    try:
                        await attack_task
                    except asyncio.CancelledError:
                        pass
                    finally:
                        if not attack_task.done():attack_task.cancel()
                        await asyncio.gather(attack_task,return_exceptions=True)
                else:
                    if before_start:await self.real(rid,plan,cfg,groups,before_start=before_start)
                    else:await self.real(rid,plan,cfg,groups)
            if self.stops[rid].is_set(): r['status']='stopped'
            else:
                r['status']='completed_with_errors' if any(e['status']=='failed' or e.get('error') for e in self.events[rid].values()) else 'completed'
        except Exception as exc:
            r.update(status='failed',error='%s: %s' % (type(exc).__name__,str(exc) or 'Operation timed out during preparation/execution'))
            import traceback
            (self.folder(rid)/'failure_traceback.txt').write_text(traceback.format_exc())
            self.log(rid,r['error'],'error')
        finally:
            # Freeze the elapsed value before removing the monotonic clock.
            if rid in self.origins:
                factor=r['speed'] if r['mode']=='simulation' else 1
                r['elapsed_s']=min(r['duration_s'],max(0,(time.monotonic()-self.origins[rid])*factor))
            await self.kill_processes(rid)
            if guard:
                try:
                    r['baseline_control']['restoration']=await guard.leave()
                    self.log(rid,'Detection and mitigation restored after baseline')
                except Exception as exc:
                    r.update(status='failed',error='Baseline restoration failed: '+str(exc))
                    r['baseline_control']['restoration']=dict(restored=False,error=str(exc))
                    self.log(rid,r['error'],'error')
            for e in self.events[rid].values():
                if e['status'] in ('pending','running'):
                    e['status']='cancelled' if r['status']=='stopped' else 'failed'
                    e['error']='Run ended before event completion'
            for a in r['observed_attacks']:
                if a.get('end_s') is None: a['end_s']=r['elapsed_s']
            if r['status']=='completed' and any(e['status']=='failed' for e in self.events[rid].values()):
                r['status']='completed_with_errors'
            r['payload_mbps']=0
            r['finished_at']=time.time()
            self.log(rid,f'Run {r["status"]}')
            await self.persist_async(rid)
            self.evict_events(rid)

    async def simulate(self,rid,plan):
        r=self.runs[rid]
        speed=r['speed']
        origin=time.monotonic()
        self.origins[rid]=origin
        r.update(status='running',started_at=time.time())
        self.log(rid,'Simulation only: no laboratory traffic is emitted.')
        while True:
            elapsed=min(plan['duration_s'],(time.monotonic()-origin)*speed)
            r['elapsed_s']=elapsed
            for e in self.events[rid].values():
                progress=1.0 if elapsed+1e-6>=e['start_s']+e['duration_s'] else max(0,min(1,(elapsed-e['start_s'])/e['duration_s']))
                if elapsed<e['start_s']: continue
                if e['status']=='pending':
                    e.update(status='running',actual_start_s=e['start_s'],start_timestamp=r['started_at']+e['start_s']/speed,lateness_s=0)
                kind='rx' if e['direction']=='dl' else 'tx'
                e[f'bytes_{kind}']=int(e['planned_bytes']*progress)
                e[f'chunks_{kind}']=math_ceil(e[f'bytes_{kind}']/e['packet_size_bytes'])
                if progress>=1:
                    e.update(status='completed',actual_end_s=e['start_s']+e['duration_s'],stop_timestamp=r['started_at']+(e['start_s']+e['duration_s'])/speed)
            if elapsed>=plan['duration_s'] or self.stops[rid].is_set(): break
            await asyncio.sleep(.1)
        r['elapsed_s']=elapsed

    async def real(self,rid,plan,cfg,groups,before_start=None,on_start=None):
        r=self.runs[rid]
        for group in groups.values():
            context=group['context']
            if context.get('executor_name'):
                for planned in group['events']:
                    self.events[rid][planned['event_id']].update(executor_name=context['executor_name'],source_as=context.get('source_as'))
        options=cfg.get('execution_options',execution_options(cfg))
        sessions=[];channels={}
        if options['supervisor_per_vm']:
            bundles=supervisor_groups(groups)
            async def launch(sid,bundle):
                proc=await asyncio.create_subprocess_exec(*bundle['argv'],stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True,limit=32*1024*1024)
                self.processes[rid].append(proc)
                session=SupervisorSession(proc,[w['key'] for w in bundle['workers']]);sessions.append(session)
                self.supervisors.setdefault(rid,[]).append(session)
                workers=[]
                for worker in bundle['workers']:
                    key,group=worker['key'],worker['group']
                    group['supervisor_id']=sid
                    workers.append(dict(key=key,argv=worker['argv'],config=dict(events=group['events'],targets=cfg['targets'],duration_s=plan['duration_s'],context=group['context'],execution=options)))
                proc.stdin.write(canonical(dict(workers=workers))+b'\n');await proc.stdin.drain()
                channels.update(session.channels)
            results=await asyncio.gather(*(launch(sid,bundle) for sid,bundle in bundles.items()),return_exceptions=True)
            errors=[e for e in results if isinstance(e,Exception)]
            if errors:raise errors[0]
            r['execution_transport']=dict(kind='supervisor_per_vm',sessions=len(bundles),workers=len(groups))
        else:r['execution_transport']=dict(kind='ssh_per_worker',sessions=len(groups),workers=len(groups))
        async def prepare(key,group):
            group['key']=key
            if options['supervisor_per_vm']:
                proc=channels[key]
            else:
                proc=await asyncio.create_subprocess_exec(*group['argv'],stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True,limit=32*1024*1024)
                self.processes[rid].append(proc)
                payload=dict(events=group['events'],targets=cfg['targets'],duration_s=plan['duration_s'],context=group['context'],execution=options)
                proc.stdin.write(canonical(payload)+b'\n');await proc.stdin.drain()
            line=await asyncio.wait_for(proc.stdout.readline(),30)
            if not line:
                err=(await proc.stderr.read(2000)).decode(errors='replace')
                raise RuntimeError(f'Agent {key} did not start: {err}')
            reply=json.loads(line)
            if reply['type']!='ready': raise RuntimeError(f'Agent {key}: {reply.get("error",reply)}')
            if (options['metrics_batch'] or options['connection_reuse']) and reply.get('protocol_version')!=2:
                raise RuntimeError('Worker protocol v2 required; deploy updated agents')
            group['evidence']=reply.get('evidence',{})
            self.runs[rid].setdefault('agents',{})[key]=dict(sources=sorted(group['sources']),context=group['context'],evidence=group['evidence'],status='ready',supervisor_id=group.get('supervisor_id'),python_version=reply.get('python_version'),pid=reply.get('pid'))
            atomic_json(self.folder(rid)/'execution_mapping.json',self.runs[rid]['agents'])
            self.log(rid,f'Agent ready: {", ".join(sorted(group["sources"]))}')
            return proc,group
        # Await all preparations, including failures, so no orphaned launch remains.
        prepared=await asyncio.gather(*(prepare(k,g) for k,g in groups.items()),return_exceptions=True)
        errors=[p for p in prepared if isinstance(p,Exception)]
        if errors: raise errors[0]
        # Probe only after all plan uploads/preflights finish; the ready message
        # may have waited in SSH or in the controller's event loop.
        for key,(proc,group) in zip(groups,prepared):
            if self.stops[rid].is_set(): return
            try:
                clock=await probe_clock(proc,cfg.get('max_clock_skew_s',.5))
            except Exception as exc:
                raise RuntimeError('Clock probe for '+', '.join(sorted(group['sources']))+': '+(str(exc) or type(exc).__name__)) from exc
            r['agents'][key]['clock']=clock
            r['agents'][key]['status']='ready' if clock['status']=='synchronized' else 'clock_'+clock['status']
            atomic_json(self.folder(rid)/'execution_mapping.json',r['agents'])
            sources=', '.join(sorted(group['sources']))
            detail=f"offset={clock['offset_s']:.6f}s, uncertainty={clock['uncertainty_s']:.6f}s, RTT={clock['round_trip_s']:.6f}s"
            self.log(rid,f'Clock {sources}: {clock["status"]}; {detail}')
            if clock['status']=='skewed':
                raise RuntimeError(f'Agent {sources} clock exceeds allowed skew; synchronize NTP ({detail})')
            if clock['status']=='inconclusive':
                raise RuntimeError(f'Agent {sources} clock check inconclusive due to communication latency; retry when load is lower ({detail})')
        if self.stops[rid].is_set(): return
        if before_start:await before_start()
        if self.stops[rid].is_set():return
        start=time.time()+cfg.get('start_lead_s',3)
        if on_start:on_start(start)
        self.origins[rid]=time.monotonic()+start-time.time()
        r.update(status='running',started_at=start)
        for proc,group in prepared:
            proc.stdin.write(canonical(dict(start_unix=start))+b'\n')
            await proc.stdin.drain()
        self.log(rid,f'All agents scheduled for epoch {start:.6f}')
        r['worker_messages']=dict(total=0,metric_batches=0,metrics=0)
        async def read(proc,group):
            done=False
            async def stderr():
                while line:=await proc.stderr.readline():
                    self.log(rid,line.decode(errors='replace')[:1000],'warning')
            errtask=asyncio.create_task(stderr())
            try:
                while line:=await proc.stdout.readline():
                    envelope=json.loads(line)
                    r['worker_messages']['total']+=1
                    if envelope['type']=='metrics_batch':r['worker_messages']['metric_batches']+=1
                    if envelope['type'] in ('metrics','metrics_batch'):
                        r['worker_messages']['metrics']+=len(envelope['items']) if envelope['type']=='metrics_batch' else 1
                    if envelope['type']=='done': done=True
                    if envelope['type']=='worker_stats':
                        r['agents'][group['key']]['connections']=envelope['connections']
                    messages=[dict(type='metrics',**item) for item in envelope['items']] if envelope['type']=='metrics_batch' else [envelope]
                    for msg in messages:
                        if msg['type'] not in ('event','metrics'):continue
                        e=self.events[rid].get(msg['event_id'])
                        if e is None: raise ValueError('Agent returned unknown event')
                        for key in ('status','bytes_tx','bytes_rx','chunks_tx','chunks_rx','icmp_replies','src_port','dst_port','actual_start_s','actual_end_s','start_timestamp','stop_timestamp','lateness_s','error','source_ip','source_interface','shortfall_bytes','receiver_bytes','connections_opened','connection_reused','payload_state','receiver_confirmation','connect_s','connect_start_s','connect_end_s','request_sent_s','payload_start_s','first_payload_s','last_payload_s','ack_s','setup_consumed_s','available_payload_s','required_payload_s','nominal_payload_s','budget_shortfall_s','budget_policy'):
                            if key in msg: e[key]=msg[key]
                        if msg['type']=='event':
                            with (self.folder(rid)/'events.jsonl').open('a') as f: f.write(json.dumps(msg)+'\n')
                            if msg.get('error'): self.log(rid,f'{e["event_id"]}: {msg.get("error")}', 'error' if msg.get('status')=='failed' else 'warning')
                await proc.wait()
                if proc.returncode or not done:
                    raise RuntimeError(f'Agent disconnected (exit={proc.returncode}); run incomplete')
            finally:
                errtask.cancel()
                await asyncio.gather(errtask,return_exceptions=True)
        reads=[asyncio.create_task(read(proc,group)) for proc,group in prepared]
        # 2026-10-26 incident: a single domain's control-path SSH keepalive
        # dying under its own attack-scenario traffic load (confirmed via a
        # dedicated investigation: ~57-90s control-path stalls on
        # Workstation-hosted VMs, with or without a real controller
        # mitigation active) used to take down the OTHER 3 domains as
        # collateral damage -- asyncio.gather(*reads) without
        # return_exceptions=True surfaces the FIRST read() failure the
        # instant it happens, so `joined` was "done" (in the asyncio.wait
        # below) while healthy groups were still mid-run, and the `finally`
        # block's unconditional kill_processes() tore down their still-live
        # SSH sessions too. return_exceptions=True instead makes `joined`
        # wait for every group's own read() to finish (successfully or
        # not) -- a dead group no longer takes a healthy one down with it.
        # (supervisor_per_vm bundles several groups behind one shared
        # process/session -- isolation there is still only as granular as
        # that shared process; this fixes the ssh_per_worker/local
        # transport this incident actually used, where each group owns its
        # own process.)
        joined=asyncio.gather(*reads,return_exceptions=True)
        stop=asyncio.create_task(self.stops[rid].wait())
        # PILOT2b finding (2026-10-24): a 10s grace period was too tight for
        # this lab's real agent-teardown variance -- several otherwise-healthy
        # runs overshot it by only 1-3s ("Agents exceeded the experiment
        # deadline"), e.g. a 180s plan finishing at 192.6s against a 190s
        # deadline. 30s gives real headroom without masking an actual hang
        # (kill_processes() below still runs unconditionally once the
        # deadline/stop/joined race resolves).
        deadline=asyncio.create_task(asyncio.sleep(max(0,start-time.time())+plan['duration_s']+30))
        try:
            done,_=await asyncio.wait([joined,stop,deadline],return_when=asyncio.FIRST_COMPLETED)
            if joined in done:
                results=await joined
                for (proc,group),result in zip(prepared,results):
                    if isinstance(result,Exception):
                        self.fail_group(rid,group,result)
                # A plan with early-ending events still observes the whole interval.
                remaining=max(0,self.origins[rid]+plan['duration_s']-time.monotonic())
                try: await asyncio.wait_for(self.stops[rid].wait(),remaining)
                except TimeoutError: pass
            elif stop not in done:
                raise RuntimeError('Agents exceeded the experiment deadline')
        finally:
            await self.kill_processes(rid)
            for task in reads+[stop,deadline]: task.cancel()
            await asyncio.gather(*reads,stop,deadline,return_exceptions=True)
            if not joined.done(): joined.cancel()
            await asyncio.gather(joined,return_exceptions=True)
            await asyncio.gather(*(session.task for session in sessions),return_exceptions=True)

    def fail_group(self,rid,group,exc):
        """Record one group's own read() failure (e.g. its SSH control
        channel dying under that domain's own traffic load) without
        touching any other group's events -- the isolation half of the
        2026-10-26 fix (see real()'s own comment on `joined`)."""
        error='%s: %s' % (type(exc).__name__,str(exc) or 'Agent group failed')
        self.log(rid,f'{", ".join(sorted(group["sources"]))}: {error}','error')
        for planned in group['events']:
            e=self.events[rid].get(planned['event_id'])
            if e and e['status'] in ('pending','running'):
                e['status']='failed'
                e['error']=error

    async def kill_processes(self,rid):
        live=[p for p in self.processes.get(rid,[]) if p.returncode is None]
        for p in live:
            try:
                p.stdin.write(b'STOP\n')
                await p.stdin.drain()
                p.stdin.close()
            except (OSError,ConnectionError): pass
        for p in live:
            try: await asyncio.wait_for(p.wait(),2)
            except TimeoutError:
                try: os.killpg(p.pid,signal.SIGTERM)
                except ProcessLookupError: pass
                try: await asyncio.wait_for(p.wait(),1)
                except TimeoutError:
                    try: os.killpg(p.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                    await p.wait()
        for session in self.supervisors.get(rid,[]):
            await asyncio.gather(session.task,session.error_task,return_exceptions=True)
        if self.supervisors.get(rid) and rid in self.runs:
            self.runs[rid]['supervisor_transport_stats']=[session.stats for session in self.supervisors[rid]]

    async def stop(self,rid):
        if self.runs[rid]['status'] not in TERMINAL:
            self.stops[rid].set()
            self.log(rid,'Stop requested')
        return self.snapshot(rid)

    async def apply_detection_mode(self,rid,cfg,mode):
        """D1: switch the real controller to `mode` and verify it with TWO
        independent pieces of evidence before any traffic/attack starts.
        Raising here fails the run in preparation -- it never lets a run
        proceed under an unconfirmed (or wrong) detection mode.

        D7-pilot: skips DetectionModeControl.apply() (and therefore the
        ryu-manager restart it performs unconditionally) when .read()
        already reports the requested mode -- a campaign that groups runs
        by mode (im_campaign.build_schedule) would otherwise restart the
        real controller before every single lab-enabled run, including
        consecutive runs that request the SAME mode. The second, audit-based
        evidence is still collected every time (cheap, no restart, confirms
        the mode did not silently drift since the last run)."""
        self.log(rid,f'Applying detection mode: {mode}')
        control=DetectionModeControl(cfg)
        current=await control.read()
        if current.get('override')==mode:
            log_evidence=dict(applied=mode,controller_restarted=False,already_applied=True)
            self.log(rid,f'Detection mode already {mode}; skipping restart')
        else:
            log_evidence=await control.apply(mode)
        # Captured AFTER apply() returns, not before: apply() itself is
        # the SSH round trip that writes the drop-in and restarts
        # ryu-manager, which realistically takes several seconds -- long
        # enough for multiple old-mode cycles to still be emitted after a
        # "before" timestamp. Every cycle this picked up was then
        # guaranteed stale, not a rare boundary race: verified live
        # against the real lab, every run failed the same way (reading
        # the PREVIOUS mode, not a mismatch) until this was moved here.
        since=time.time()
        audit_evidence=await self.verify_detection_mode_in_audit(since,mode)
        self.runs[rid]['detection_mode_verification']=dict(requested=mode,log_evidence=log_evidence,audit_cycle_evidence=audit_evidence)
        await self.persist_async(rid)
        self.log(rid,f'Detection mode verified via STARTUP log and LAB_AUDIT cycle snapshot: {mode}')

    async def verify_detection_mode_in_audit(self,since,mode,timeout=60):
        """Second evidence: DETECTION_CROSS_DOMAIN_CORRELATION in the
        `thresholds` snapshot of the first LAB_AUDIT kind=cycle record
        emitted after the restart requested at `since`. Independent of
        apply()'s own STARTUP-log check (first evidence) -- a different
        code path (the persistent audit SSH stream, not the restart's own
        SSH round trip) reading a different artifact (the detector's own
        per-cycle threshold snapshot, not its startup banner)."""
        if self.audit is None or not getattr(self.audit,'enabled',False):
            raise RuntimeError('detection_mode verification requires the LAB_AUDIT collector (detection_audit.enabled) to be running')
        expected=(mode=='multidomain')
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            cycle=next((x for x in self.audit.rows(since,time.time()+1) if x.get('kind')=='cycle'),None)
            if cycle is not None:
                observed=cycle.get('thresholds',{}).get('values',{}).get('DETECTION_CROSS_DOMAIN_CORRELATION')
                if observed!=expected:
                    raise RuntimeError(f'LAB_AUDIT cycle snapshot reports DETECTION_CROSS_DOMAIN_CORRELATION={observed!r}, expected {expected!r} for detection_mode={mode!r}')
                return dict(event_id=cycle.get('event_id'),timestamp=cycle.get('timestamp'),value=observed)
            await asyncio.sleep(1)
        raise RuntimeError('No LAB_AUDIT cycle record observed after the detection-mode restart within the timeout')

    def record_attack_evidence(self,rid,report):
        """D5: auto-mark the ATTACK ground-truth window from attack_runner's
        own per-event evidence -- never from the planned schedule. A window
        with no event reporting packets_sent>0 gets no observed_attacks
        entry at all (ground_truth.windows() then correctly reports those
        windows as UNKNOWN, never silently promoting a plan to a truth)."""
        r=self.runs[rid]
        events=report.get('events',{})
        r['attack_runner_report']=dict(started_at=report.get('started_at'),finished_at=report.get('finished_at'),
            events={eid:{k:e.get(k) for k in ('packets_sent','attack_pps_target','attack_pps_actual','actual_start_s','actual_end_s','error')} for eid,e in events.items()})
        r['attack_source_ips']=report.get('source_ips',[])
        active=[e for e in events.values() if e.get('packets_sent',0)>0 and e.get('actual_start_s') is not None and e.get('actual_end_s') is not None]
        if active:
            name=(r.get('attack_plan_hash') or 'attack')[:12]
            r['observed_attacks'].append(dict(name=name,start_s=min(e['actual_start_s'] for e in active),end_s=max(e['actual_end_s'] for e in active),annotation_source='attack_runner'))
            self.log(rid,f'Attack window marked from attack_runner evidence: {len(active)} event(s) sent traffic')
        else:
            self.log(rid,'attack_runner reported no packets sent for any event; no ATTACK window marked','warning')

    async def shutdown(self):
        for rid in self.tasks:
            if not self.tasks[rid].done(): self.stops[rid].set()
        await asyncio.gather(*self.tasks.values(),return_exceptions=True)

    def annotate(self,rid,name,action):
        r=self.runs[rid]
        if r['status']!='running' or r['scenario']!='B0+attack': raise ValueError('Requires a running B0+attack experiment')
        elapsed=self.elapsed(rid)
        if action=='start':
            if any(a['name']==name and a.get('end_s') is None for a in r['observed_attacks']): raise ValueError('Attack already marked active')
            r['observed_attacks'].append(dict(name=name,start_s=elapsed,end_s=None,annotation_source='operator_external'))
        elif action=='stop':
            matches=[a for a in r['observed_attacks'] if a['name']==name and a.get('end_s') is None]
            if not matches: raise ValueError('No active attack with this name')
            matches[-1]['end_s']=elapsed
        else: raise ValueError('Invalid annotation action')
        self.log(rid,f'External attack {name}: {action} at {elapsed:.3f} s')
        return self.snapshot(rid)


def math_ceil(x):
    return __import__('math').ceil(x)
