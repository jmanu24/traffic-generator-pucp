import asyncio
import copy
import json
import time
import sys
import pytest
from benign_lab.agent import receive_client,UDPReceiver
from benign_lab.config import ROOT,load_lab
from benign_lab.planner import generate,load_profiles,plan_hash,save_plan,summarize
from benign_lab.runner import Manager


@pytest.mark.skipif(sys.platform=='win32', reason='Local laboratory worker requires Linux/POSIX')
def test_real_runner_payload_and_persisted_result(tmp_path):
    async def scenario():
        receiver=await asyncio.start_server(receive_client,'127.0.0.1',0)
        port=receiver.sockets[0].getsockname()[1]
        udp,_=await asyncio.get_running_loop().create_datagram_endpoint(UDPReceiver,local_addr=('127.0.0.1',0))
        uport=udp.get_extra_info('sockname')[1]
        cfg=load_lab(ROOT/'config/lab.demo.yaml')
        cfg['start_lead_s']=.1
        cfg['targets']['victim-web'].update(tcp_port=port,http_port=port,udp_port=uport)
        plan=generate(load_profiles(ROOT/'profiles'),7,5)
        prototype=plan['events'][0]
        plan['events']=[]
        for i,(proto,direction) in enumerate((('tcp','ul'),('tcp','dl'),('http','ul'),('http','dl'),('udp','ul'),('udp','dl'))):
            e=dict(prototype,event_id=f'mobile-test{i}',domain='mobile',source='ue1',destination='victim-web',
                   protocol=proto,wire_protocol=proto,direction=direction,start_s=.2,duration_s=.5,
                   rate_bps=19200,rate_fraction=.000192,planned_bytes=1200,packet_size_bytes=200)
            plan['events'].append(e)
        plan['summary']=summarize(plan)
        plan['plan_hash']=plan_hash(plan)
        path=save_plan(plan,tmp_path/'plan.json')
        manager=Manager(tmp_path/'runs')
        try:
            r=await manager.start(plan,path,cfg,mode='lab',speed=1)
            await asyncio.wait_for(manager.tasks[r['id']],15)
            result=manager.snapshot(r['id'])
            assert result['status']=='completed',result
            assert result['bytes_tx']==3600 and result['bytes_rx']==3600
            assert result['elapsed_s']==5
            assert (manager.folder(r['id'])/'benign_plan.json').read_bytes()==path.read_bytes()
            assert all(e['lateness_s'] is not None and e['src_port'] for e in manager.events[r['id']].values())
        finally:
            await manager.shutdown()
            receiver.close()
            await receiver.wait_closed()
            udp.close()
    asyncio.run(scenario())


def test_recovery_marks_pending_events_interrupted(tmp_path):
    p=generate(load_profiles(ROOT/'profiles'),7,5)
    folder=tmp_path/'recover'
    folder.mkdir()
    save_plan(p,folder/'benign_plan.json')
    (folder/'run.json').write_text(json.dumps(dict(id='recover',status='running',elapsed_s=2,attack_windows=[],observed_attacks=[])))
    (folder/'event_states.json').write_text(json.dumps({'a':dict(event_id='a',status='running')}))
    m=Manager(tmp_path)
    assert m.runs['recover']['status']=='interrupted'
    # A run recovered THIS way (interrupted mid-flight, possibly partial/
    # synthetic event data -- see evict_events()'s own comment on why it
    # is skipped here) must still be held fully in memory, same as
    # before eviction existed.
    assert m.events['recover']['a']['status']=='interrupted'


def test_startup_evicts_a_run_that_was_already_terminal_on_disk(tmp_path):
    """PILOT_RESULT.md section 1 (D7/PILOT2, 2026-10-23): a run already
    TERMINAL in its own run.json before this restart has complete,
    well-formed event data -- __init__ never loads its event_states.json
    at all (D7 campaign fix, 2026-10-25: no persisted terminal_summary.json
    exists yet for it, so self.events simply has no entry -- not even
    the old eager {} -- until something actually requests its snapshot,
    unlike the recovered-mid-flight run above). snapshot() must still
    report the exact same derived numbers afterward, computed lazily
    from disk on first request."""
    folder=tmp_path/'already-done'
    folder.mkdir()
    (folder/'run.json').write_text(json.dumps(dict(id='already-done',status='failed',finished_at=1,elapsed_s=5,duration_s=5)))
    (folder/'event_states.json').write_text(json.dumps({'e':dict(domain='fixed',status='failed',rate_bps=8,bytes_tx=3,bytes_rx=4)}))
    m=Manager(tmp_path)
    assert 'already-done' not in m.events
    assert 'already-done' not in m.terminal_metrics
    assert m.snapshot('already-done')['counts']=={'failed':1}
    assert m.snapshot('already-done')['bytes_tx']==3 and m.snapshot('already-done')['bytes_rx']==4


def test_startup_reads_a_persisted_terminal_summary_without_touching_events(tmp_path):
    """The actual D7 campaign fix: once a terminal run's summary has been
    computed and persisted once (terminal_summary.json), a FRESH Manager
    (simulating the next process restart) must read that tiny file alone
    -- never event_states.json -- and report it via snapshot() with no
    further computation."""
    folder=tmp_path/'already-summarized'
    folder.mkdir()
    (folder/'run.json').write_text(json.dumps(dict(id='already-summarized',status='completed',finished_at=1,elapsed_s=5,duration_s=5)))
    summary=dict(counts={'completed':1},bytes_tx=99,bytes_rx=88,shortfall_bytes=0,active_planned_mbps=0.0,
                 domains={d:dict(counts={},bytes_tx=0,bytes_rx=0,active_planned_mbps=0.0) for d in ('mobile','fixed','enterprise','peering')},
                 audit_available=False,payload_quality=dict(eligible=0,full_local=0,partial=0,zero=0,receiver_confirmed=0,interpretation='x'))
    (folder/'terminal_summary.json').write_text(json.dumps(summary))
    # Deliberately NO event_states.json on disk at all -- if snapshot()
    # ever fell back to events_for() instead of the cached summary, this
    # would prove it by returning zeros/empty instead of the asserted
    # values below, not by raising.
    m=Manager(tmp_path)
    assert m.terminal_metrics['already-summarized']==summary
    r=m.snapshot('already-summarized')
    assert r['bytes_tx']==99 and r['bytes_rx']==88
    assert r['payload_quality']['interpretation']=='x'


def test_snapshot_persists_a_terminal_summary_the_first_time_its_computed(tmp_path):
    """The write side of the same fix: the FIRST snapshot() of a terminal
    run with no cached summary yet must write terminal_summary.json (so
    the NEXT Manager() lifetime never re-reads event_states.json for it)."""
    m=Manager(tmp_path);rid='fresh-terminal'
    m.runs[rid]=dict(id=rid,status='completed',finished_at=1,elapsed_s=5,duration_s=5,mode='lab')
    e=dict(domain='fixed',status='completed',rate_bps=8,bytes_tx=10,bytes_rx=20,
           wire_protocol='tcp',planned_bytes=30,shortfall_bytes=0)
    m.events[rid]={'e':e};m.logs[rid]=[]
    m.folder(rid).mkdir(parents=True)
    assert not m.terminal_summary_path(rid).exists()
    r=m.snapshot(rid)
    assert r['bytes_tx']==10 and r['bytes_rx']==20
    assert m.terminal_summary_path(rid).exists()
    persisted=json.loads(m.terminal_summary_path(rid).read_text())
    assert persisted['bytes_tx']==10 and persisted['payload_quality']['full_local']==1


def test_events_for_reads_an_evicted_terminal_runs_events_from_disk(tmp_path):
    m=Manager(tmp_path);rid='evicted'
    m.runs[rid]=dict(id=rid,status='failed',finished_at=1,elapsed_s=5,duration_s=5)
    e=dict(domain='fixed',status='failed',rate_bps=8,bytes_tx=0,bytes_rx=0)
    m.events[rid]={'e':e};m.logs[rid]=[]
    m.folder(rid).mkdir(parents=True)
    m.evict_events(rid)
    assert m.events[rid]=={}
    # Nothing on disk yet (no checkpoint written) -- events_for() must
    # fall back to {} rather than raise, same as a run with no events file.
    assert m.events_for(rid)=={}
    (m.folder(rid)/'event_states.json').write_text(json.dumps({'e':e}))
    assert m.events_for(rid)=={'e':e}


def test_evict_events_is_a_noop_for_a_run_still_in_progress(tmp_path):
    m=Manager(tmp_path);rid='running'
    m.runs[rid]=dict(id=rid,status='running',finished_at=None,elapsed_s=1,duration_s=5)
    e=dict(domain='fixed',status='running',rate_bps=8,bytes_tx=0,bytes_rx=0)
    m.events[rid]={'e':e};m.logs[rid]=[]
    m.evict_events(rid)
    assert m.events[rid]=={'e':e}


def test_checkpoint_never_overwrites_an_evicted_terminal_runs_events_with_empty(tmp_path):
    """The real risk evict_events() must never cause: /api/runs/{rid}/
    export (or any other post-completion persist_async) re-persisting a
    terminal run whose self.events[rid] is now {} must NOT clobber the
    already-correct event_states.json on disk with that empty dict."""
    from benign_lab.planner import generate,load_profiles,save_plan
    m=Manager(tmp_path);rid='export-after-evict'
    m.runs[rid]=dict(id=rid,status='failed',finished_at=1,elapsed_s=5,duration_s=5)
    e=dict(domain='fixed',status='failed',rate_bps=8,bytes_tx=3,bytes_rx=4)
    m.events[rid]={'e':e};m.logs[rid]=[]
    m.folder(rid).mkdir(parents=True)
    p=generate(load_profiles(ROOT/'profiles'),7,5)
    save_plan(p,m.folder(rid)/'benign_plan.json')
    m.write_checkpoint(m.checkpoint(rid))  # as if a normal persist already ran
    m.evict_events(rid)
    assert m.events[rid]=={}
    m.write_checkpoint(m.checkpoint(rid))  # e.g. the export endpoint's persist_async
    assert json.loads((m.folder(rid)/'event_states.json').read_text())=={'e':e}


def test_csv_union_of_protocol_specific_fields():
    from benign_lab.runner import csv_text
    import csv,io
    rows=list(csv.DictReader(io.StringIO(csv_text([{'id':'peer','protocol':'udp'},{'id':'mobile','protocol':'tcp','parent_event':17}]))))
    assert rows[0]['parent_event']==''
    assert rows[1]['parent_event']=='17'
