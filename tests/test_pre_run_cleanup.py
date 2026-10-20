import asyncio,time
import pytest
from benign_lab.runner import Manager
from benign_lab.config import ROOT,load_lab
from benign_lab.planner import generate,load_profiles,save_plan

class FakeDetectionModeControl:
 def __init__(self,cfg):pass
 async def read(self):return {'override':None}
 async def apply(self,mode):return dict(applied=mode,controller_restarted=True)

class FakeAudit:
 def __init__(self,mode):self.enabled=True;self.mode=mode
 def rows(self,start,end,after=0):return [dict(kind='cycle',timestamp=time.time(),event_id='e1',thresholds={'values':{'DETECTION_CROSS_DOMAIN_CORRELATION':self.mode=='multidomain'}})]

@pytest.mark.parametrize('scenario',['B0','B0+attack'])
def test_enabled_cleanup_remains_suspended_until_agents_ready(tmp_path,monkeypatch,scenario):
 import benign_lab.runner as runner
 flags=[]
 class Guard:
  def __init__(self,cfg,rid,duration):self.rid=rid
  async def enter(self):flags.append('clear');return dict(controller={'cleared':True},mobile={'verified_count':5})
  async def status(self):return dict(active=True,cleared=True,run_id=self.rid)
  async def leave(self):flags.append('enable');return dict(restored=True)
 monkeypatch.setattr(runner,'BaselineGuard',Guard)
 monkeypatch.setattr(runner,'DetectionModeControl',FakeDetectionModeControl)
 async def real(self,rid,plan,cfg,groups,before_start=None):
  assert before_start is not None;flags.append('agents_ready');await before_start();flags.append('measurement')
  assert self.runs[rid]['block_preparation']['pipeline_restoration']['restored']
  for e in self.events[rid].values():e['status']='completed'
 monkeypatch.setattr(Manager,'real',real)
 async def run():
  p=generate(load_profiles(ROOT/'profiles'),1,5);f=save_plan(p,tmp_path/'plan.json');cfg=load_lab(ROOT/'config/lab.demo.yaml');cfg['baseline_control']={'configured':True};m=Manager(tmp_path/'runs');m.audit=FakeAudit('isolated')
  for _ in range(2):
   r=await m.start(p,f,cfg,mode='lab',scenario=scenario,attack_windows=[dict(name='attack',start_s=1,end_s=2)] if scenario!='B0' else [],pipeline='enabled',speed=1,detection_mode='isolated');await m.tasks[r['id']]
   assert m.runs[r['id']]['status']=='completed',m.runs[r['id']].get('error')
 asyncio.run(run());assert flags==['clear','agents_ready','enable','measurement']*2

@pytest.mark.parametrize('stage',['cleanup','activation'])
def test_failed_cleanup_or_activation_never_starts_measurement(tmp_path,monkeypatch,stage):
 import benign_lab.runner as runner
 flags=[]
 class Guard:
  def __init__(self,cfg,rid,duration):self.rid=rid
  async def enter(self):
   flags.append('clear')
   if stage=='cleanup':raise RuntimeError('residual restriction')
   return dict(controller={'cleared':True})
  async def status(self):return dict(active=True,cleared=True,run_id=self.rid)
  async def leave(self):flags.append('restore');return dict(restored=stage!='activation')
 monkeypatch.setattr(runner,'BaselineGuard',Guard)
 monkeypatch.setattr(runner,'DetectionModeControl',FakeDetectionModeControl)
 async def real(self,rid,p,c,g,before_start=None):
  await before_start();flags.append('measurement')
 monkeypatch.setattr(Manager,'real',real)
 async def run():
  p=generate(load_profiles(ROOT/'profiles'),1,5);f=save_plan(p,tmp_path/'plan.json');cfg=load_lab(ROOT/'config/lab.demo.yaml');cfg['baseline_control']={'configured':True};m=Manager(tmp_path/'runs');m.audit=FakeAudit('isolated')
  r=await m.start(p,f,cfg,mode='lab',pipeline='enabled',speed=1,detection_mode='isolated');await m.tasks[r['id']]
  assert m.runs[r['id']]['status']=='failed' and m.runs[r['id']]['started_at'] is None
 asyncio.run(run());assert 'restore' in flags and 'measurement' not in flags
