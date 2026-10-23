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
    assert m.events['recover']['a']['status']=='interrupted'


def test_covariates_recorded_at_start(tmp_path):
    """D7, change 5: sequence_position, panel_process_memory_kb_at_start
    and seconds_since_restart are set for EVERY run, not just lab/enabled
    ones apply_detection_mode() touches -- a simulation-mode run here is
    enough to check start()'s own part of it (seconds_since_restart's
    apply_detection_mode-side update is covered in test_im_integration.py)."""
    async def scenario():
        cfg=load_lab(ROOT/'config/lab.demo.yaml')
        p=generate(load_profiles(ROOT/'profiles'),1,5)
        path=save_plan(p,tmp_path/'plan.json')
        m=Manager(tmp_path/'runs')
        assert m.last_controller_restart_at is None
        first=await m.start(p,path,cfg,mode='simulation',speed=100)
        assert first['sequence_position']==0
        assert first['seconds_since_restart'] is None  # no restart observed this process lifetime
        assert isinstance(first['panel_process_memory_kb_at_start'],int) and first['panel_process_memory_kb_at_start']>0
        await asyncio.wait_for(m.tasks[first['id']],15)
        p2=generate(load_profiles(ROOT/'profiles'),2,5)
        path2=save_plan(p2,tmp_path/'plan2.json')
        second=await m.start(p2,path2,cfg,mode='simulation',speed=100)
        assert second['sequence_position']==1
        await asyncio.wait_for(m.tasks[second['id']],15)
        await m.shutdown()
    asyncio.run(scenario())


def test_sequence_position_continues_across_a_manager_restart(tmp_path):
    """sequence_position must be this Manager's own ordinal among every
    run it has ever started, INCLUDING ones loaded from disk at __init__
    -- a real orchestrator restart must not reset it back to 0."""
    folder=tmp_path/'old'
    folder.mkdir()
    p=generate(load_profiles(ROOT/'profiles'),1,5)
    save_plan(p,folder/'benign_plan.json')
    (folder/'run.json').write_text(json.dumps(dict(id='old',status='completed',elapsed_s=5,attack_windows=[],observed_attacks=[])))
    (folder/'event_states.json').write_text(json.dumps({}))
    async def scenario():
        cfg=load_lab(ROOT/'config/lab.demo.yaml')
        m=Manager(tmp_path)  # reconstructs from the 1 run already on disk
        assert len(m.runs)==1
        p2=generate(load_profiles(ROOT/'profiles'),2,5)
        path2=save_plan(p2,tmp_path/'plan2.json')
        new=await m.start(p2,path2,cfg,mode='simulation',speed=100)
        assert new['sequence_position']==1  # continues from the loaded run, not reset to 0
        await asyncio.wait_for(m.tasks[new['id']],15)
        await m.shutdown()
    asyncio.run(scenario())


def test_csv_union_of_protocol_specific_fields():
    from benign_lab.runner import csv_text
    import csv,io
    rows=list(csv.DictReader(io.StringIO(csv_text([{'id':'peer','protocol':'udp'},{'id':'mobile','protocol':'tcp','parent_event':17}]))))
    assert rows[0]['parent_event']==''
    assert rows[1]['parent_event']=='17'
