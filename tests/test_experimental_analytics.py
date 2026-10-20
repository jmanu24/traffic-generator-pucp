import io,json,zipfile,math
from pathlib import Path
from types import SimpleNamespace
import pytest
from benign_lab.experimental_analytics import ExperimentalAnalytics,seed_statistics
from benign_lab.planner import generate,load_profiles
from benign_lab.config import ROOT

def manager(tmp_path):
 root=tmp_path/'runs';root.mkdir();m=SimpleNamespace(runs={},events={},folder=lambda rid:root/rid);return m

def record(m,rid,seed=1,delivery=.9,pipeline='baseline',status='completed',capacity=100,detection_mode=None,hardware=False,attack_plan_hash=None,cycle_correlation_flag=None):
 p=generate(load_profiles(ROOT/'profiles'),seed,5,{d:capacity for d in ('mobile','fixed','enterprise','peering')});folder=m.folder(rid);folder.mkdir()
 r=dict(id=rid,status=status,mode='lab',purpose='baseline_plan',scenario='B0',pipeline=pipeline,detection_mode=detection_mode,attack_plan_hash=attack_plan_hash,seed=seed,plan_hash=p['plan_hash'],execution_hash='exec',execution_profile='coordinated',duration_s=5,elapsed_s=5,created_at=100,started_at=100,finished_at=105,agents={},observed_attacks=[],attack_windows=[],experiment_context={'schema':1,'captured_at':seed,'transport':{'transport':'wired'}})
 es={e['event_id']:dict(e,status='completed',bytes_tx=int(e['planned_bytes']*delivery),bytes_rx=0,lateness_s=.01) for e in p['events']}
 (folder/'run.json').write_text(json.dumps(r));(folder/'benign_plan.json').write_text(json.dumps(p));(folder/'event_states.json').write_text(json.dumps(es));(folder/'lab_snapshot.json').write_text(json.dumps({'nodes':{},'targets':{}}))
 if hardware:
  (folder/'vm_resources.jsonl').write_text(json.dumps(dict(host='h1',platform='linux_guest',timestamp=102,interval_s=5,cpu_pct=1,logical_cpus=2,memory_total_bytes=2*1024**3,memory_pct=1))+'\n')
 if cycle_correlation_flag is not None:
  # Mirrors the real controller: the SAME SYN_THRESHOLD/etc but a different
  # DETECTION_CROSS_DOMAIN_CORRELATION produces a DIFFERENT thresholds.hash
  # (confirmed live, docs/PILOT_RESULT.md section 2) -- not computed by a
  # real digest here, just a distinct literal per flag value, which is all
  # policy_comparability_id's exclusion behavior needs to be exercised.
  values=dict(SYN_THRESHOLD=76.82,DECISION_THRESHOLD=1.5,DETECTION_CROSS_DOMAIN_CORRELATION=cycle_correlation_flag)
  cycle=dict(kind='cycle',timestamp=102,thresholds=dict(values=values,implementation_hashes={'detection/engine.py':'samehash'},hash='hash_for_'+str(cycle_correlation_flag)))
  (folder/'detection_events.jsonl').write_text(json.dumps(cycle)+'\n')
 m.runs[rid]=r;m.events[rid]=es;return folder

def test_seed_balancing_and_no_pseudoreplication():
 s=seed_statistics([(1,80),(1,100),(2,70)]);assert s['n_runs']==3;assert s['n_seeds']==2;assert s['seed_balanced']['mean']==80;assert s['run_weighted']['mean']==pytest.approx(83.3333333)
 assert s['ci95']['df']==1
 assert seed_statistics([(1,80),(1,100)])['ci95'] is None
 assert seed_statistics([(1,100),(2,100)])['ci95'] is None

def test_known_t_interval():
 s=seed_statistics([(1,90),(2,95),(3,100)]);assert s['seed_balanced']['sd']==5;assert s['ci95']['half_width']==pytest.approx(4.303*5/math.sqrt(3))

def test_cohorts_separate_pipeline_capacity_and_aborted(tmp_path):
 m=manager(tmp_path);record(m,'baseline',1,pipeline='baseline');record(m,'enabled',1,pipeline='enabled');record(m,'capacity',2,capacity=200);record(m,'failed',2,status='failed');m.runs['failed']['started_at']=None;m.runs['failed']['elapsed_s']=0
 a=ExperimentalAnalytics(tmp_path,m);r=a.report(list(m.runs));assert len(r['groups'])==3;assert r['excluded'][0]['id']=='failed';assert len(r['pairs'])==1
 assert r['pairs'][0]['context_verified'] is False

def test_repeats_same_seed_not_more_independent_seeds(tmp_path):
 m=manager(tmp_path);record(m,'a',1);record(m,'b',1,delivery=.8);record(m,'c',2,delivery=.7)
 r=ExperimentalAnalytics(tmp_path,m).report(['a','b','c']);assert len(r['groups'])==1;assert r['groups'][0]['statistics']['n_seeds']==2

def test_same_plan_paired_seed_deltas(tmp_path):
 m=manager(tmp_path)
 for seed in [1,2]:record(m,'b'+str(seed),seed,delivery=.95,pipeline='baseline');record(m,'e'+str(seed),seed,delivery=.65,pipeline='enabled')
 r=ExperimentalAnalytics(tmp_path,m).report(list(m.runs));assert len(r['group_comparisons'])==1;comparison=r['group_comparisons'][0];assert comparison['statistics']['n_seeds']==2;assert comparison['statistics']['seed_balanced']['mean']==pytest.approx(-30,abs=.1)

def test_detection_mode_separates_groups_and_is_recognized_as_single_factor(tmp_path):
 m=manager(tmp_path)
 for seed in [1,2]:
  record(m,'i'+str(seed),seed,delivery=.6,pipeline='enabled',detection_mode='isolated',hardware=True)
  record(m,'m'+str(seed),seed,delivery=.8,pipeline='enabled',detection_mode='multidomain',hardware=True)
 a=ExperimentalAnalytics(tmp_path,m);r=a.report(list(m.runs))
 # C3 (isolated) and C4 (multidomain) must not be conflated into one group.
 assert len(r['groups'])==2
 pair=next(p for p in r['pairs'] if p['seed']==1)
 assert pair['differing_conditions']==['detection_mode']
 assert pair['context_verified'] is True
 # M-I framing: comparison-reference reads multidomain minus isolated.
 assert pair['delta']==pytest.approx(20,abs=.1)

def test_detection_mode_group_comparison_pairs_by_seed_and_plan(tmp_path):
 m=manager(tmp_path)
 for seed in [1,2]:
  record(m,'i'+str(seed),seed,delivery=.6,pipeline='enabled',detection_mode='isolated',hardware=True)
  record(m,'m'+str(seed),seed,delivery=.85,pipeline='enabled',detection_mode='multidomain',hardware=True)
 r=ExperimentalAnalytics(tmp_path,m).report(list(m.runs))
 assert len(r['group_comparisons'])==1
 comparison=r['group_comparisons'][0]
 assert comparison['factor']=='detection_mode'
 assert comparison['statistics']['n_seeds']==2
 assert comparison['statistics']['seed_balanced']['mean']==pytest.approx(25,abs=.1)

def test_different_attack_plans_are_never_paired_as_c3_vs_c4(tmp_path):
 # Two runs sharing seed, benign plan, pipeline and hardware but a
 # DIFFERENT attack plan must never be treated as the same C3/C4 block
 # just because detection_mode also differs -- attack_plan_hash gates
 # the pair the same way plan_hash/execution_hash already do.
 m=manager(tmp_path)
 record(m,'c3',1,delivery=.6,pipeline='enabled',detection_mode='isolated',hardware=True,attack_plan_hash='attackA')
 record(m,'other',1,delivery=.8,pipeline='enabled',detection_mode='multidomain',hardware=True,attack_plan_hash='attackB')
 a=ExperimentalAnalytics(tmp_path,m);r=a.report(list(m.runs))
 assert r['pairs']==[]
 assert r['group_comparisons']==[]

def test_same_attack_plan_pairs_c3_and_c4_correctly(tmp_path):
 m=manager(tmp_path)
 for seed in [1,2]:
  record(m,'c3-'+str(seed),seed,delivery=.6,pipeline='enabled',detection_mode='isolated',hardware=True,attack_plan_hash='attackA')
  record(m,'c4-'+str(seed),seed,delivery=.9,pipeline='enabled',detection_mode='multidomain',hardware=True,attack_plan_hash='attackA')
 a=ExperimentalAnalytics(tmp_path,m);r=a.report(list(m.runs))
 assert len(r['group_comparisons'])==1
 comparison=r['group_comparisons'][0]
 assert comparison['factor']=='detection_mode'
 assert all(match['attack_plan_hash']=='attackA' for match in comparison['matches'])
 assert comparison['statistics']['seed_balanced']['mean']==pytest.approx(30,abs=.1)

def test_policy_comparability_ignores_detection_mode_flag_in_threshold_hash(tmp_path):
 """D7-pilot regression (docs/PILOT_RESULT.md section 2): the controller's
 raw threshold_snapshot hash bundles DETECTION_CROSS_DOMAIN_CORRELATION
 with every other threshold value, so an I-vs-M pair that is otherwise
 IDENTICAL would differ in both 'policy' and 'detection_mode' at once --
 two differing grouping fields, which report()'s single-factor pairing
 requires to be exactly one. Confirmed live against the real pilot:
 group_comparisons was 0/60 until policy_comparability_id started
 excluding that one flag."""
 m=manager(tmp_path)
 for seed in [1,2]:
  record(m,'c3-'+str(seed),seed,delivery=.6,pipeline='enabled',detection_mode='isolated',hardware=True,attack_plan_hash='attackA',cycle_correlation_flag=False)
  record(m,'c4-'+str(seed),seed,delivery=.9,pipeline='enabled',detection_mode='multidomain',hardware=True,attack_plan_hash='attackA',cycle_correlation_flag=True)
 r=ExperimentalAnalytics(tmp_path,m).report(list(m.runs))
 assert len(r['group_comparisons'])==1
 comparison=r['group_comparisons'][0]
 assert comparison['factor']=='detection_mode'
 assert comparison['statistics']['n_seeds']==2
 assert comparison['statistics']['seed_balanced']['mean']==pytest.approx(30,abs=.1)

def test_policy_comparability_still_separates_a_genuinely_different_threshold_config(tmp_path):
 """The exclusion is narrow: a DIFFERENT SYN_THRESHOLD (a real
 recalibration, not just the mode flag) must still make two runs
 non-comparable -- this isn't a blanket 'ignore policy' escape hatch."""
 m=manager(tmp_path)
 record(m,'before',1,delivery=.6,pipeline='enabled',detection_mode='isolated',hardware=True,cycle_correlation_flag=False)
 after_folder=record(m,'after',1,delivery=.9,pipeline='enabled',detection_mode='isolated',hardware=True,cycle_correlation_flag=False)
 cycle=json.loads((after_folder/'detection_events.jsonl').read_text())
 cycle['thresholds']['values']['SYN_THRESHOLD']=999.0
 cycle['thresholds']['hash']='different_real_policy_hash'
 (after_folder/'detection_events.jsonl').write_text(json.dumps(cycle)+'\n')
 a=ExperimentalAnalytics(tmp_path,m);r=a.report(list(m.runs))
 assert len(r['groups'])==2
 pair=r['pairs'][0]
 assert pair['differing_conditions']==['policy']
 assert pair['context_verified'] is True  # still a verified single-factor ('policy') pair, just not merged into one group

def test_no_fp_evidence_is_missing_not_zero(tmp_path):
 m=manager(tmp_path);record(m,'old');d=ExperimentalAnalytics(tmp_path,m).detail('old');assert all(x['detection_fpr_pct'] is None for x in d['metrics']);assert d['evaluation']['available'] is False

def test_import_deduplicates_existing_run_and_rejects_paths(tmp_path):
 m=manager(tmp_path);folder=record(m,'existing');a=ExperimentalAnalytics(tmp_path,m)
 def archive(paths):
  buffer=io.BytesIO()
  with zipfile.ZipFile(buffer,'w') as z:
   for name,path in paths:z.writestr(name,path.read_bytes())
  return buffer.getvalue()
 raw=archive([(p.name,p) for p in folder.iterdir()]);assert a.import_archive(raw)['duplicate'] is True
 bad=archive([('../run.json',folder/'run.json')])
 with pytest.raises(ValueError,match='flat'):a.import_archive(bad)


def test_tampered_plan_and_negative_counters_excluded(tmp_path):
 m=manager(tmp_path);folder=record(m,'bad');first=next(iter(m.events['bad'].values()));first['bytes_tx']=-1
 a=ExperimentalAnalytics(tmp_path,m);assert 'invalid_counters' in a.summary('bad')['exclusion_reasons']

def test_manual_attack_annotation_excluded_from_confirmatory_analysis(tmp_path):
 m=manager(tmp_path);record(m,'manual',pipeline='enabled')
 m.runs['manual'].update(scenario='B0+attack',observed_attacks=[dict(name='x',start_s=0,end_s=5,annotation_source='operator_external')])
 a=ExperimentalAnalytics(tmp_path,m);assert 'manual_attack_annotation' in a.summary('manual')['exclusion_reasons']
 # attack_runner-confirmed evidence must NOT trigger the same exclusion.
 second=tmp_path/'second';second.mkdir();m2=manager(second);record(m2,'auto',pipeline='enabled')
 m2.runs['auto'].update(scenario='B0+attack',observed_attacks=[dict(name='x',start_s=0,end_s=5,annotation_source='attack_runner')])
 b=ExperimentalAnalytics(tmp_path,m2);assert 'manual_attack_annotation' not in b.summary('auto')['exclusion_reasons']


def test_api_analytics_auth_and_active_guard(tmp_path):
 from fastapi.testclient import TestClient
 from benign_lab.api import create_app
 app=create_app(data_dir=tmp_path,lab_path=ROOT/'config/lab.demo.yaml',token='test')
 with TestClient(app) as client:
  assert client.get('/api/analytics/catalog').status_code==401
  assert client.get('/api/analytics/catalog',headers={'Authorization':'Bearer test'}).json()['counts']['total']==0
  app.state.manager.runs['active']={'status':'running'}
  result=client.post('/api/analytics/report',headers={'Authorization':'Bearer test'},json={'run_ids':['active']});assert result.status_code==409;app.state.manager.runs.pop('active')
