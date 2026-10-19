"""Conservative 5-second confusion matrix with verified attack identity.

Ground truth for an ATTACK window never depends on what the detector's own
telemetry happened to observe -- that would make the reference the thing
being evaluated is supposed to be judged against. Eligibility only
requires telemetry COVERAGE of all experimental domains (ds[...]['covered'],
already required for every window, BENIGN or ATTACK). Whether the
declared attacker IP was additionally *seen* in an active cycle's
observed_sources is tracked as attacker_observed_by_detector, a separate,
non-gating run-validity diagnostic (reported in bulk, never folded into
VP/FN/FP/VN)."""
from .ground_truth import windows

def window_confusion(plan,run,records,domain_windows):
 from .detection_evaluation import affected
 counts=dict(FP=0,FN=0,VP=0,VN=0,unknown=0);rows=[];start=run.get('started_at');sources=set(run.get('attack_source_ips',[]))
 for w in windows(plan,run):
  relevant=[x for x in records if start is not None and start+w['start_s']<=x.get('timestamp',0)<start+w['end_s']]
  ds=[x for x in domain_windows if x['window']==w['window']]
  eligible=bool(run.get('pipeline')=='enabled' and run.get('mode')=='lab' and w['evaluation'] and w['label'] in ('BENIGN','ATTACK') and ds and all(x['covered'] for x in ds))
  gap=any(x.get('kind')=='capture_gap' and x.get('gap_start',x['timestamp']-5)<start+w['end_s'] and x.get('gap_end',x['timestamp'])>=start+w['start_s'] for x in records) if start is not None else True
  eligible=eligible and not gap
  attacker_observed=None
  if w['label']=='ATTACK':
   observed=set(ip for x in relevant if x.get('kind')=='cycle' and x.get('pipeline_active') for ips in x.get('observed_sources',{}).values() for ip in ips)
   attacker_observed=bool(sources & observed)
   positive=any(x.get('kind')=='detection' and any(ip in sources for _,ip in affected(x.get('detection',{}))) for x in relevant)
  else:positive=any(x['detection_positive'] for x in ds)
  classification=('VP' if positive else 'FN') if eligible and w['label']=='ATTACK' else ('FP' if positive else 'VN') if eligible else 'unknown'
  counts[classification]+=1;rows.append(dict(window=w['window'],truth=w['label'],classification=classification,attacker_observed_by_detector=attacker_observed))
 attack_rows=[r for r in rows if r['truth']=='ATTACK']
 observed_count=sum(1 for r in attack_rows if r['attacker_observed_by_detector'])
 return dict(unit='global 5-second window',counts=counts,windows=rows,
   coverage_policy='All experimental domains must be telemetry-covered for any window, BENIGN or ATTACK, to be eligible. Ground truth for ATTACK windows does NOT additionally require the declared attacker IP to appear in the detector\'s own observed_sources -- that visibility is reported separately below (attacker_observed_by_detector) as a run-validity signal, never as a classification gate. Missing domain coverage is UNKNOWN.',
   attacker_observed_by_detector=dict(windows=len(attack_rows),observed=observed_count,rate=observed_count/len(attack_rows) if attack_rows else None),
   fpr=counts['FP']/(counts['FP']+counts['VN']) if counts['FP']+counts['VN'] else None,recall=counts['VP']/(counts['VP']+counts['FN']) if counts['VP']+counts['FN'] else None)
