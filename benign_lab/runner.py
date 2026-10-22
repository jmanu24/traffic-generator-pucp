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

# D7, change 4, option B: "tras cada reinicio, esperar un tiempo fijo antes
# del tráfico y comprobar que no quedan bloqueos activos ni reglas
# residuales" -- chosen over option A (restart before EVERY pipeline=enabled
# run, whether or not the mode actually changed) because the mechanism
# docs/PILOT_DIAGNOSIS.md §6 actually found live was residual mitigation
# STATE leaking from the PREVIOUS run into the next one's first cycles
# (confirmed: one real pilot run showed active_blocks={} for ~3s then a
# block appearing at t=3.86s, well before that run's own attack could have
# caused it) -- not restart COUNT itself. Option A would still restart
# unconditionally without checking the thing that actually leaked, and pays
# a ~60s restart on every single pipeline=enabled run (48/60 in the pilot)
# instead of only when a restart really happens. Option B targets that
# exact mechanism directly, for both I and M equally, and is cheaper.
POST_RESTART_SETTLE_S = 5  # same order as COLLECT_INTERVAL (0.5s in the
# pilot's own LAB_AUDIT snapshots) x a few cycles -- enough to observe
# active_blocks settle after a restart, not an arbitrary round number.
POST_RESTART_CHECK_TIMEOUT_S = 30


def _panel_process_memory_kb():
    """D7, change 5: this panel process's own RSS, read the same way any
    `ps`/`top` would (/proc/self/status -- no new dependency). Covariate,
    not a gate: PILOT_RESULT.md already found benign-lab-web.service's own
    memory growing unboundedly over a long session as a confounder
    candidate for the clock-skew failures there; this records it per run
    so a campaign can check for that correlation directly instead of
    reconstructing it after the fact from systemd logs."""
    try:
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1])  # kB, per proc(5)
    except (OSError, ValueError, IndexError):
        pass
    return None


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
        # D7, change 4/5: when the real controller was last confirmed
        # restarted, this Manager's own process lifetime only (never
        # reconstructed from historical runs on an orchestrator restart --
        # the covariate is then None, "unknown this process", not guessed).
        self.last_controller_restart_at=None
        # Instance attributes, not the bare module constants, so tests can
        # override them (e.g. to 0) without a real sleep -- same reason
        # verify_detection_mode_in_audit's own timeout is a parameter, not
        # hardcoded in its body.
        self.post_restart_settle_s=POST_RESTART_SETTLE_S
        self.post_restart_check_timeout_s=POST_RESTART_CHECK_TIMEOUT_S
        for file in sorted(self.root.glob('*/run.json')):
            run=json.loads(file.read_text())
            eid=run['id']
            self.runs[eid]=run
            ep=file.parent/'event_states.json'
            self.events[eid]=json.loads(ep.read_text()) if ep.exists() else {}
            lp=file.parent/'logs.jsonl'
            self.logs[eid]=[json.loads(line) for line in lp.read_text().splitlines()[-200:] if line.strip()] if lp.exists() else []
            if run['status'] not in TERMINAL:
                run.update(status='interrupted',error='Orchestrator restarted; no automatic replay',finished_at=time.time())
                for e in self.events[eid].values():
                    if e['status'] in ('pending','running'): e['status']='interrupted'
                self.persist(eid)

    def folder(self, rid): return self.root/rid

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
            r['counts']=dict(Counter(e['status'] for e in self.events[rid].values()))
            r['bytes_tx']=sum(e.get('bytes_tx',0) for e in self.events[rid].values())
            r['bytes_rx']=sum(e.get('bytes_rx',0) for e in self.events[rid].values())
            r['shortfall_bytes']=sum(e.get('shortfall_bytes',0) for e in self.events[rid].values())
            r['active_planned_mbps']=sum(e['rate_bps'] for e in self.events[rid].values() if e['status']=='running')/1e6
            r['domains']={}
            for domain in ('mobile','fixed','enterprise','peering'):
                es=[e for e in self.events[rid].values() if e['domain']==domain]
                r['domains'][domain]=dict(counts=dict(Counter(e['status'] for e in es)),bytes_tx=sum(e.get('bytes_tx',0) for e in es),bytes_rx=sum(e.get('bytes_rx',0) for e in es),active_planned_mbps=sum(e['rate_bps'] for e in es if e['status']=='running')/1e6)
            if r['status'] in TERMINAL and r.get('finished_at'):
                self.terminal_metrics[rid]={k:copy.deepcopy(r[k]) for k in ('counts','bytes_tx','bytes_rx','shortfall_bytes','active_planned_mbps','domains')}
        if 'payload_quality' not in r:
            eligible=[e for e in self.events[rid].values() if e.get('wire_protocol') in ('tcp','http','udp') and e['status'] not in ('pending','running')]
            r['payload_quality']=dict(eligible=len(eligible),full_local=sum(e.get('bytes_tx',0)+e.get('bytes_rx',0)>=e['planned_bytes'] for e in eligible),partial=sum(0<e.get('bytes_tx',0)+e.get('bytes_rx',0)<e['planned_bytes'] for e in eligible),zero=sum(e.get('bytes_tx',0)+e.get('bytes_rx',0)==0 for e in eligible),receiver_confirmed=sum((e.get('receiver_bytes',0)>=e['planned_bytes'] or e.get('direction')=='dl' and e.get('bytes_rx',0)>=e['planned_bytes']) and e['planned_bytes']>0 for e in eligible) if r.get('mode')=='lab' else 0,interpretation='Observed local quota; UL requires receiver acknowledgement. Historical states are preserved.')
            if r['status'] in TERMINAL and r.get('finished_at'):
                self.terminal_metrics[rid]['payload_quality']=copy.deepcopy(r['payload_quality'])
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
        return (self.folder(rid),copy.deepcopy(self.runs[rid]),copy.deepcopy(self.events[rid]),self.plan_cache[rid])

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
               # D7, change 5: covariates, recorded for every run regardless
               # of mode/pipeline, not just the lab-enabled ones apply_
               # detection_mode() touches. sequence_position is this
               # Manager's own ordinal among every run it has ever started
               # (including ones loaded from disk at __init__, so it
               # survives an orchestrator restart as a real position, not a
               # per-process counter restarting at 0). seconds_since_restart
               # is provisional here -- apply_detection_mode() (lab+enabled
               # runs only) overwrites it with a fresher value once this
               # run's own mode has been confirmed, closer to when traffic
               # actually starts; a baseline/C2 run keeps this value.
               sequence_position=len(self.runs),
               seconds_since_restart=(time.time()-self.last_controller_restart_at) if self.last_controller_restart_at is not None else None,
               panel_process_memory_kb_at_start=_panel_process_memory_kb(),
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
                rate_monitor=None
                rate_monitor_task=None
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
                    # D7, change 2: independent attacker-rate series for
                    # response_metrics.py's tE -- runs for the whole
                    # attack_task lifetime (same guard: only when an
                    # attack_plan actually exists), stopped and persisted
                    # in the SAME finally blocks as attack_task below, so
                    # a stopped/failed run still keeps whatever it
                    # collected (conservar ejecuciones fallidas).
                    if cfg.get('baseline_control',{}).get('pe_host'):
                        from .attacker_rate_monitor import AttackerRateMonitor
                        victim_ip=cfg['targets'][attack_plan['events'][0]['destination']]['host']
                        rate_monitor=AttackerRateMonitor(cfg,attack_plan,victim_ip)
                        rate_monitor_task=asyncio.create_task(rate_monitor.run())
                    else:
                        self.log(rid,'Attacker-rate monitor skipped: baseline_control.pe_host is not configured','warning')
                real_kwargs=dict(on_start=on_benign_start) if attack_task else {}
                if guard and r['pipeline']=='baseline':
                    traffic=asyncio.create_task(self.real(rid,plan,cfg,groups,**real_kwargs))
                    monitor=asyncio.create_task(guard.monitor())
                    watch=[traffic,monitor]+([attack_task] if attack_task else [])+([rate_monitor_task] if rate_monitor_task else [])
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
                        if rate_monitor:rate_monitor.save(self.folder(rid)/'attacker_rate.jsonl')
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
                        if rate_monitor_task:
                            rate_monitor_task.cancel()
                            await asyncio.gather(rate_monitor_task,return_exceptions=True)
                        if rate_monitor:rate_monitor.save(self.folder(rid)/'attacker_rate.jsonl')
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
        joined=asyncio.gather(*reads)
        stop=asyncio.create_task(self.stops[rid].wait())
        deadline=asyncio.create_task(asyncio.sleep(max(0,start-time.time())+plan['duration_s']+10))
        try:
            done,_=await asyncio.wait([joined,stop,deadline],return_when=asyncio.FIRST_COMPLETED)
            if joined in done:
                await joined
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
        # D7, change 4 (option B) + change 5: only when THIS call actually
        # restarted -- a skipped restart changes nothing about the
        # controller's forwarding state, so there is nothing new to settle
        # or re-check (the previous restart's own check already covered
        # it). last_controller_restart_at is Manager-lifetime state (not
        # per-run), so later runs that skip their own restart still see a
        # growing, truthful seconds_since_restart via the same field below.
        if log_evidence.get('controller_restarted'):
            self.last_controller_restart_at=since
            forwarding_state=await self.verify_clean_forwarding_state(rid,since)
            self.runs[rid]['detection_mode_verification']['post_restart_forwarding_state']=forwarding_state
        self.runs[rid]['seconds_since_restart']=(time.time()-self.last_controller_restart_at) if self.last_controller_restart_at is not None else None
        await self.persist_async(rid)
        self.log(rid,f'Detection mode verified via STARTUP log and LAB_AUDIT cycle snapshot: {mode}')

    async def verify_clean_forwarding_state(self,rid,since):
        """D7, change 4 (option B): after a confirmed restart, wait a fixed
        settle time, then require the controller's own next LAB_AUDIT
        cycle to report no active_blocks for any domain -- the exact
        leftover-state mechanism docs/PILOT_DIAGNOSIS.md §6 found live (a
        block from the PREVIOUS run's mitigation, still draining through
        its own release delay -- e.g. BROADBAND_RELEASE_QUIET_S -- visible
        in a run's first cycles well before that run's own attack could
        have caused one). Raises, same posture as the residual-OpenFlow-
        rule check BaselineGuard.enter() already does for C2: never lets a
        run start on top of state it cannot confirm is clear, for I or M."""
        if self.audit is None or not getattr(self.audit,'enabled',False):
            raise RuntimeError('post-restart forwarding-state verification requires the LAB_AUDIT collector (detection_audit.enabled) to be running')
        await asyncio.sleep(self.post_restart_settle_s)
        settled=since+self.post_restart_settle_s
        deadline=time.monotonic()+self.post_restart_check_timeout_s
        while time.monotonic()<deadline:
            cycle=next((x for x in self.audit.rows(since,time.time()+1) if x.get('kind')=='cycle' and x.get('timestamp',0)>=settled),None)
            if cycle is not None:
                residual={k:v for k,v in cycle.get('active_blocks',{}).items() if v>0}
                if residual:
                    raise RuntimeError(f'Residual active_blocks after the post-restart settle wait: {residual!r}; run cannot start on top of unconfirmed mitigation state')
                return dict(event_id=cycle.get('event_id'),timestamp=cycle.get('timestamp'),active_blocks=cycle.get('active_blocks',{}),settle_s=self.post_restart_settle_s)
            await asyncio.sleep(1)
        raise RuntimeError('No LAB_AUDIT cycle record observed after the post-restart settle wait within the timeout')

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
