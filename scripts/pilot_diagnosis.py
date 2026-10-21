"""Offline diagnosis of the 60-run I-vs-M pilot (seeds 201-203). Reads only
already-captured data (.runtime/benign-lab); writes docs/PILOT_DIAGNOSIS_tables.md
and .runtime/benign-lab/calibration/pilot_diagnosis.json. Never touches the lab."""
import bisect, collections, hashlib, json, math, pathlib, statistics as st, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from pilot_diagnosis_lib import *

OUT_MD = pathlib.Path(__file__).resolve().parent.parent / 'docs' / 'PILOT_DIAGNOSIS_tables.md'
OUT_JSON = ROOT / 'calibration' / 'pilot_diagnosis.json'
DOM_ACTIVE = {'enterprise': 'enterprise', 'fixed': 'broadband', 'mobile': 'mobile', 'peering': 'bgp'}
COMPS = ['composition1_enterprise', 'composition1_fixed', 'composition1_mobile', 'composition1_peering',
         'composition2_multidomain_over_threshold', 'composition3_multidomain_under_threshold']
SHORT = {c: c.replace('composition', 'c').replace('_multidomain', '').replace('_threshold', '') for c in COMPS}
md = []
J = {}


def f(x, n=1):
    return '—' if x is None or (isinstance(x, float) and math.isnan(x)) else f'{x:.{n}f}'


def mean(v):
    v = [x for x in v if x is not None]
    return sum(v) / len(v) if v else None


def med(v):
    v = [x for x in v if x is not None]
    return st.median(v) if v else None


def sd(v):
    v = [x for x in v if x is not None]
    return st.stdev(v) if len(v) > 1 else None


def table(head, rows):
    md.append('| ' + ' | '.join(head) + ' |')
    md.append('|' + '---|' * len(head))
    for r in rows:
        md.append('| ' + ' | '.join(str(c) for c in r) + ' |')
    md.append('')


def h(t):
    md.append(f'\n### {t}\n')


ALL = load()
E = [r for r in ALL if r['eligible']]
for r in ALL:
    run = r['run']; r['t0'] = run.get('started_at')
    r['pipeline_on'] = r['cond'] != 'C2'
    r['mode'] = {'C1-I': 'I', 'C3': 'I', 'C1-M': 'M', 'C4': 'M'}.get(r['cond'], 'none')
    r['dseg'] = {(a, b): {d or 'all': seg_delivery(r['plan'], r['es'], a, b, d) for d in (None,) + DOMAINS} for a, b in SEGMENTS}
    r['dwhole'] = seg_delivery(r['plan'], r['es'], 0, 180)
    r['A'] = availability(r) if r['eligible'] else None
    r['Ad'] = {d: availability(r, d) for d in DOMAINS} if r['eligible'] else {}

# ---------------------------------------------------------------- 0 inventory
h('0. Inventario de las 60 ejecuciones')
c = collections.Counter((r['cond'], r['eligible']) for r in ALL)
table(['condición', 'válidas', 'no válidas (conservadas, excluidas)'], [[k, c[(k, True)], c[(k, False)]] for k in ('C1-I', 'C1-M', 'C2', 'C3', 'C4')])
table(['run', 'pos', 'seed', 'cond', 'escenario', 'estado', 'motivo'], [[r['rid'], r['pos'], r['seed'], r['cond'], SHORT.get(r['scen'], '—'), r['status'], ','.join(r['excl'])] for r in ALL if not r['eligible']])
byte_share = collections.Counter()
for e in E[0]['plan']['events']:
    byte_share[e['domain']] += e['planned_bytes']
tot = sum(byte_share.values())
J['byte_share_pct'] = {d: 100 * byte_share[d] / tot for d in DOMAINS}
md.append('Reparto de bytes planificados por dominio (determina el peso de cada dominio en `delivery_pct` global): ' + ', '.join(f'{d} {f(J["byte_share_pct"][d], 2)}%' for d in DOMAINS) + '.\n')

# ---------------------------------------------------------------- 1 response metrics
h('1. response_metrics.compute() sobre C2/C3/C4 válidas (LAB_AUDIT crudo)')
for r in E:
    if r['cond'] in ('C2', 'C3', 'C4'):
        r['rm'] = rm.compute(r['plan'], r['run'], r['records'], event_states=r['es'])
        r['rel'] = lambda ts, t0=r['t0']: None if ts is None else ts - t0
rows = []
J['response_metrics'] = {}
for cond in ('C2', 'C3', 'C4'):
    for comp in COMPS:
        rs = [r for r in E if r['cond'] == cond and r['scen'] == comp]
        if not rs:
            continue
        n = len(rs)
        As = [r['rm']['availability_pct'] for r in rs]
        TD = [r['rm']['TD'] for r in rs]; TD0 = [(r['rm']['tD0'] - r['rm']['tA']) if r['rm']['tD0'] is not None else None for r in rs]
        TO = [r['rm']['TO'] for r in rs]; TR = [r['rm']['TR'] for r in rs]
        det = sum(x is not None for x in TD); mit = sum(r['rm']['tO']['value'] is not None for x in [0])
        mit = sum(r['rm']['tO']['value'] is not None for r in rs)
        J['response_metrics'][f'{cond}|{comp}'] = dict(n=n, A=As, TD=TD, TD0=TD0, TO=TO, TR=TR)
        rows.append([cond, SHORT[comp], n, f(mean(As)) + ' (' + '/'.join(f(a, 0) for a in As) + ')', f'{det}/{n}', f'{mit}/{n}',
                     f(med(TD)) + f' ({n - det} cens)', f(med(TD0)), f(med(TO)) + f' ({n - mit} cens)', f'{n} cens', f(med(TR)) + f' ({sum(x is None for x in TR)} cens)'])
table(['cond', 'composición', 'n', 'A% media (valores)', 'cobertura detección', 'cobertura mitigación', 'TD mediana s', 'TD0 med s', 'TO med s', 'TM (tE)', 'TR med s'], rows)
md.append('TM/tE: **no calculable** — no existe serie de tasas independiente del atacante en los datos capturados (`rate_series` ausente, motivo `no_independent_rate_series` en las 33/33 ejecuciones con ataque válidas). TI: `not_observable` (sin evidencia de instalación por dominio). Censura: TD censurado = ninguna detección que incluya IP atacante tras tA; TO censurado = ninguna `mitigation_issued` que afecte IP atacante; TR censurado = nunca K=3 ventanas PASS consecutivas tras tF (TR=5 s es el mínimo posible: tF=120 s, ventana de 5 s).\n')
rows = []
for cond in ('C2', 'C3', 'C4'):
    rs = [r for r in E if r['cond'] == cond]
    rows.append([cond, len(rs), f(mean([r['rm']['availability_pct'] for r in rs])), f(sd([r['rm']['availability_pct'] for r in rs])),
                 f'{sum(r["rm"]["tD"]["value"] is not None for r in rs)}/{len(rs)}', f'{sum(r["rm"]["tO"]["value"] is not None for r in rs)}/{len(rs)}'])
table(['cond', 'n', 'A% media (ventana ataque 60–120)', 'sd', 'detección', 'mitigación'], rows)
# C2 pre/post: internal control
# ---------------------------------------------------------------- 2 impact
h('2. Impacto del ataque: C1 vs C2 en 60–120 s, y control interno de C2')
rows = []
for d in ('all',) + DOMAINS:
    def col(cond, seg=(60, 120)):
        return mean([r['dseg'][seg][d] for r in E if r['cond'] == cond])
    Ac = lambda cond: mean([(r['A'] if d == 'all' else r['Ad'][d]) for r in E if r['cond'] == cond])
    rows.append([d, f(col('C1-I')), f(col('C1-M')), f(col('C2')), f(col('C2') - mean([col('C1-I'), col('C1-M')])), f(Ac('C1-I')), f(Ac('C1-M')), f(Ac('C2'))])
table(['dominio', 'entrega% C1-I', 'entrega% C1-M', 'entrega% C2', 'C2 − media(C1)', 'A% C1-I', 'A% C1-M', 'A% C2'], rows)
md.append('Control interno de C2 (pipeline suspendido, mismo plan benigno; n=18): entrega por tramo, dentro de cada ejecución.\n')
rows = []
for d in ('all',) + DOMAINS:
    segs = [[r['dseg'][s][d] for r in E if r['cond'] == 'C2'] for s in SEGMENTS]
    diffs = [a - b for a, b in zip(segs[1], segs[0])]
    diffs2 = [a - b for a, b in zip(segs[1], segs[2])]
    rows.append([d] + [f(mean(s)) for s in segs] + [f(mean(diffs), 2) + ' ± ' + f(sd(diffs) / math.sqrt(len(diffs)), 2), f(mean(diffs2), 2) + ' ± ' + f(sd(diffs2) / math.sqrt(len(diffs2)), 2)])
table(['dominio', '0–60', '60–120 (ataque)', '120–180', '(60–120)−(0–60) media ± ee', '(60–120)−(120–180) media ± ee'], rows)
rowsA = []
for comp in COMPS:
    rs = [r for r in E if r['cond'] == 'C2' and r['scen'] == comp]
    pre = [r['dseg'][(0, 60)]['all'] for r in rs]; dur = [r['dseg'][(60, 120)]['all'] for r in rs]
    A_dur = [r['A'] for r in rs]; A_post = [availability(r, None, (120.002, 180)) for r in rs]
    rowsA.append([SHORT[comp], len(rs), f(mean(pre)), f(mean(dur)), f(mean(dur) - mean(pre), 2), f(mean(A_dur)), f(mean(A_post))])
table(['composición (C2)', 'n', 'entrega% 0–60', 'entrega% 60–120', 'Δ', 'A% 60–120', 'A% 120–180 (sin ataque)'], rowsA)
# A in C2 over [0,60) (warmup bypassed: A only counts windows >= warmup_s by default) vs. attack window, paired
pairsA = []
for r in E:
    if r['cond'] == 'C2':
        pre = rm.compute_availability(dict(r['plan'], warmup_s=0), r['run'], 0.0, 60.0, r['es'], dict(rm.DEFAULTS))['availability_pct']
        post = availability(r, None, (120.002, 180))
        pairsA.append((pre, r['A'], post))
dA = [b - a for a, b, _ in pairsA]; dP = [b - c for _, b, c in pairsA]
md.append(f'A en C2 (n=18), pareada por ejecución: pre-ataque [0,60) (ventanas de 5 s, warmup omitido) {f(mean([a for a, _, _ in pairsA]))}%, ataque [60,120] {f(mean([b for _, b, _ in pairsA]))}%, post-ataque [120,180) {f(mean([c for _, _, c in pairsA]))}%. Δ(ataque−pre) = {f(mean(dA), 2)} ± {f(sd(dA) / math.sqrt(len(dA)), 2)} pp (ee); Δ(ataque−post) = {f(mean(dP), 2)} ± {f(sd(dP) / math.sqrt(len(dP)), 2)} pp.\n')
J['A_c2_paired'] = dict(pre=mean([a for a, _, _ in pairsA]), attack=mean([b for _, b, _ in pairsA]), post=mean([c for _, _, c in pairsA]), d_attack_pre=mean(dA), se_attack_pre=sd(dA) / math.sqrt(len(dA)), d_attack_post=mean(dP), se_attack_post=sd(dP) / math.sqrt(len(dP)))
J['c2_attack_effect_pp_all'] = mean([r['dseg'][(60, 120)]['all'] - r['dseg'][(0, 60)]['all'] for r in E if r['cond'] == 'C2'])
J['A_by_cond'] = {c: mean([r['A'] for r in E if r['cond'] == c]) for c in ('C1-I', 'C1-M', 'C2', 'C3', 'C4')}
A_c2_post = [availability(r, None, (120.002, 180)) for r in E if r['cond'] == 'C2']
J['A_c2_post'] = mean(A_c2_post)

# ---------------------------------------------------------------- 3 M-I by segment
h('3. Diferencia M−I por tramo y dominio (entrega%)')
pairs34 = []
for seed in (201, 202, 203):
    for comp in COMPS:
        a = [r for r in E if r['seed'] == seed and r['scen'] == comp and r['cond'] == 'C3']
        b = [r for r in E if r['seed'] == seed and r['scen'] == comp and r['cond'] == 'C4']
        if a and b:
            pairs34.append((a[0], b[0]))
pairs1 = []
for seed in (201, 202, 203):
    a = [r for r in E if r['seed'] == seed and r['cond'] == 'C1-I']; b = [r for r in E if r['seed'] == seed and r['cond'] == 'C1-M']
    if a and b:
        pairs1.append((a[0], b[0]))
J['n_pairs'] = dict(C4_C3=len(pairs34), C1=len(pairs1))
md.append(f'Pares C4−C3 completos (semilla×escenario con ambas válidas): {len(pairs34)}; pares C1-M−C1-I: {len(pairs1)}. Cada celda: media (n positivos/n).\n')


def diffrow(label, prs, d, extra=lambda r: None):
    row = [label]
    for s in SEGMENTS:
        v = [(m['dseg'][s][d] - i['dseg'][s][d]) for i, m in prs]
        row.append(f'{f(mean(v))} ({sum(x > 0 for x in v)}/{len(v)})')
    return row


for title, prs in (('C4−C3 (todas las composiciones)', pairs34), ('C4−C3 solo composición 1 (control)', [p for p in pairs34 if p[0]['scen'].startswith('composition1')]), ('C1-M − C1-I (sin ataque)', pairs1)):
    md.append(f'**{title}**\n')
    table(['dominio', '0–60', '60–120 (ataque)', '120–180'], [diffrow(d, prs, d) for d in ('all',) + DOMAINS])
md.append('**C4−C3 por composición, entrega% global**\n')
table(['composición', 'n pares', '0–60', '60–120', '120–180', 'whole-run (delivery_pct del piloto)'],
      [[SHORT[comp], len(ps)] + [f(mean([m['dseg'][s]['all'] - i['dseg'][s]['all'] for i, m in ps])) for s in SEGMENTS] + [f(mean([m['dwhole'] - i['dwhole'] for i, m in ps]))]
       for comp in COMPS for ps in [[p for p in pairs34 if p[0]['scen'] == comp]]])
J['MI_all_by_seg'] = {'C4-C3': [mean([m['dseg'][s]['all'] - i['dseg'][s]['all'] for i, m in pairs34]) for s in SEGMENTS],
                      'C1': [mean([m['dseg'][s]['all'] - i['dseg'][s]['all'] for i, m in pairs1]) for s in SEGMENTS]}

# ---------------------------------------------------------------- 4 restart / order
h('4. Reinicio de ryu-manager, orden y hora')
last_restart = None
for r in ALL:
    ver = [l['timestamp'] for l in r['logs'] if l['message'].startswith('Detection mode verified')]
    app = [l['timestamp'] for l in r['logs'] if l['message'].startswith('Applying detection mode')]
    r['restarted'] = bool(r['run'].get('detection_mode_verification', {}).get('log_evidence', {}).get('controller_restarted')) if r['run'].get('detection_mode_verification') else False
    if r['restarted'] and ver:
        last_restart = ver[0]
    r['t_since_restart'] = (r['t0'] - last_restart) if (r['t0'] and last_restart) else None
    r['restart_apply_ts'] = app[0] if app else None
    r['hour'] = (r['run']['created_at'] - ALL[0]['run']['created_at']) / 3600
# previous run mode for "immediately before"
rows = []
for r in ALL:
    prev_mode = next((x['mode'] for x in reversed(ALL[:r['pos']]) if x['mode'] != 'none'), None)
    r['prev_mode'] = prev_mode
cnt = collections.Counter()
for r in ALL:
    if r['mode'] != 'none':
        cnt[(r['mode'], r['restarted'])] += 1
cnt_e = collections.Counter()
for r in E:
    if r['mode'] != 'none':
        cnt_e[(r['mode'], r['restarted'])] += 1
table(['modo', 'reinicio inmediatamente antes (60 ejec.)', 'sin reinicio', 'reinicio (34 válidas)', 'sin reinicio (válidas)'],
      [[m, cnt[(m, True)], cnt[(m, False)], cnt_e[(m, True)], cnt_e[(m, False)]] for m in ('I', 'M')])
J['restart_counts'] = {f'{m}|{k}': v for (m, k), v in cnt.items()}
rows = []
for r in ALL:
    rows.append([r['pos'], r['seed'], r['cond'], SHORT.get(r['scen'], '—'), r['mode'], 'sí' if r['restarted'] else 'no', f(r['t_since_restart'], 0), f(r['hour'], 2),
                 'sí' if r['eligible'] else 'no', f(r['dwhole']), f(r['dseg'][(0, 60)]['all']), f(r['dseg'][(60, 120)]['all']), f(r['A'])])
table(['pos', 'semilla', 'cond', 'esc.', 'modo', 'reinicio antes', 's desde reinicio al inicio del tráfico', 'hora (h desde 1ª)', 'válida', 'entrega% run', 'entrega% 0–60', 'entrega% 60–120', 'A%'], rows)


def ols(X, y, names):
    n, k = len(y), len(X[0])
    XtX = [[sum(X[i][a] * X[i][b] for i in range(n)) for b in range(k)] for a in range(k)]
    Xty = [sum(X[i][a] * y[i] for i in range(n)) for a in range(k)]
    # invert XtX via Gauss-Jordan
    M = [row[:] + [1.0 if i == j else 0.0 for j in range(k)] for i, row in enumerate(XtX)]
    for i in range(k):
        p = max(range(i, k), key=lambda r: abs(M[r][i])); M[i], M[p] = M[p], M[i]
        piv = M[i][i]; M[i] = [v / piv for v in M[i]]
        for r in range(k):
            if r != i:
                fac = M[r][i]; M[r] = [a - fac * b for a, b in zip(M[r], M[i])]
    inv = [row[k:] for row in M]
    beta = [sum(inv[a][b] * Xty[b] for b in range(k)) for a in range(k)]
    res = [y[i] - sum(X[i][a] * beta[a] for a in range(k)) for i in range(n)]
    s2 = sum(e * e for e in res) / (n - k)
    ybar = sum(y) / n; sst = sum((v - ybar) ** 2 for v in y)
    se = [math.sqrt(s2 * inv[a][a]) for a in range(k)]
    return dict(n=n, r2=1 - sum(e * e for e in res) / sst if sst else None, coef={nm: (b, s, b / s if s else None) for nm, b, s in zip(names, beta, se)})


def reg(label, runs, y, regs):
    rr = [r for r in runs if y(r) is not None and all(g(r) is not None for _, g in regs)]
    X = [[1.0] + [g(r) for _, g in regs] for r in rr]
    try:
        o = ols(X, [y(r) for r in rr], ['intercepto'] + [n for n, _ in regs])
    except ZeroDivisionError:
        return [label, len(rr), '—', 'matriz singular (regresor sin variación o colineal)']
    J.setdefault('regressions', {})[label] = o
    return [label, o['n'], f(o['r2'], 3)] + [f'{nm}={f(b, 2)} (t={f(t, 1)})' for nm, (b, s, t) in o['coef'].items()]


PO = [r for r in E if r['pipeline_on']]
tsr = lambda r: r['t_since_restart'] / 60 if r['t_since_restart'] is not None else None
mm = lambda r: 1.0 if r['mode'] == 'M' else 0.0
atk = lambda r: 0.0 if r['cond'].startswith('C1') else 1.0
rst = lambda r: 1.0 if r['restarted'] else 0.0
pos = lambda r: r['pos'] / 10
hour = lambda r: r['hour']
y_seg0 = lambda r: r['dseg'][(0, 60)]['all']
y_whole = lambda r: r['dwhole']
y_att = lambda r: r['dseg'][(60, 120)]['all']
md.append('\nRegresión OLS (solo ejecuciones válidas con pipeline activo: C1-I, C1-M, C3, C4; n=34; error estándar clásico; sin corrección por semilla). Coeficientes en pp de entrega (o pp de A) con su t.\n')
rows = []
for label, y in (('entrega 0–60 (pre-ataque)', y_seg0), ('entrega run completo', y_whole), ('entrega 60–120', y_att), ('A 60–120', lambda r: r['A'])):
    rows.append(reg(f'{label} ~ modo M', PO, y, [('M', mm)]))
    rows.append(reg(f'{label} ~ modo M + ataque', PO, y, [('M', mm), ('ataque', atk)]))
    rows.append(reg(f'{label} ~ M + ataque + s_desde_reinicio(min) + reinicio_antes', PO, y, [('M', mm), ('ataque', atk), ('min_desde_reinicio', tsr), ('reinicio_antes', rst)]))
    rows.append(reg(f'{label} ~ M + ataque + posición(/10) + hora(h)', PO, y, [('M', mm), ('ataque', atk), ('pos/10', pos), ('hora', hour)]))
table(['modelo', 'n', 'R²', 'intercepto', 'coef 1', 'coef 2', 'coef 3', 'coef 4', ][:3] + ['coeficientes'], [[r[0], r[1], r[2], ' · '.join(r[3:])] for r in rows])
md.append('Entrega 0–60 s y reinicio, solo ejecuciones C3/C4 (pre-ataque, comparables), media por grupo:\n')
rows = []
for m in ('I', 'M'):
    for rs_ in (True, False):
        g = [r for r in PO if r['mode'] == m and r['restarted'] == rs_]
        rows.append([m, 'reinicio antes' if rs_ else 'sin reinicio', len(g), f(mean([r['dseg'][(0, 60)]['all'] for r in g])), f(mean([r['dwhole'] for r in g])), f(mean([r['t_since_restart'] for r in g]), 0)])
table(['modo', 'grupo', 'n', 'entrega% 0–60', 'entrega% run', 's desde reinicio (media)'], rows)
# order: by hour tertile
rows = []
for lab, lo, hi in (('1/3 inicial (pos 0–19)', 0, 20), ('1/3 medio (20–39)', 20, 40), ('1/3 final (40–59)', 40, 60)):
    for m in ('I', 'M'):
        g = [r for r in PO if r['mode'] == m and lo <= r['pos'] < hi]
        rows.append([lab, m, len(g), f(mean([r['dseg'][(0, 60)]['all'] for r in g])), f(mean([r['dwhole'] for r in g]))])
table(['tramo del piloto', 'modo', 'n', 'entrega% 0–60', 'entrega% run'], rows)
# C2 vs time (pipeline off)
rows = []
for lab, lo, hi in (('pos 0–19', 0, 20), ('pos 20–39', 20, 40), ('pos 40–59', 40, 60)):
    g = [r for r in E if r['cond'] == 'C2' and lo <= r['pos'] < hi]
    rows.append([lab, len(g), f(mean([r['dwhole'] for r in g])), f(mean([r['A'] for r in g]))])
md.append('Control sin pipeline (C2) a lo largo del piloto:\n')
table(['tramo', 'n', 'entrega% run', 'A%'], rows)

def blocked_frac(r, dom, a, b):
    if not r['t0']:
        return None
    cy = [c for c in r['cycles'] if a <= c['timestamp'] - r['t0'] < b]
    if not cy:
        return None
    return 100 * sum(1 for c in cy if c.get('active_blocks', {}).get(DOM_ACTIVE[dom], 0) > 0) / len(cy)



# restart should have been skipped for consecutive same-mode runs (pilot design)
seq = [r for r in ALL if r['mode'] != 'none']
same = [(a, b) for a, b in zip(seq, seq[1:]) if a['mode'] == b['mode']]
md.append(f'\nSecuencia de las {len(seq)} ejecuciones con modo (C2 excluidas): {len(same)} pares consecutivos con el mismo modo; el diseño del piloto preveía **omitir** el reinicio en esos pares. Reinicios observados en esos {len(same)} pares: {sum(1 for a, b in same if b["restarted"])}. Ejecuciones con modo que reiniciaron: {sum(r["restarted"] for r in seq)}/{len(seq)} (PILOT_DESIGN preveía 27 reinicios). Mensajes "Applying detection mode" en logs: 1 por cada una de las {len(seq)}.\n')
J['same_mode_pairs'] = dict(pairs=len(same), restarted=sum(1 for a, b in same if b['restarted']), mode_runs=len(seq), restarted_mode_runs=sum(r['restarted'] for r in seq))
# clean-start test: delivery before the first block/mitigation vs seed-matched C2 over the same interval
def first_block_t(r):
    c = [x['timestamp'] - r['t0'] for x in r['records'] if x['kind'] == 'mitigation_issued']
    ab = [x['timestamp'] - r['t0'] for x in r['cycles'] if sum(x.get('active_blocks', {}).values()) > 0 and x['timestamp'] >= r['t0']] if 'cycles' in r else []
    return min(c + ab + [60.0])
for r in ALL:
    r['cycles'] = [x for x in r['records'] if x['kind'] == 'cycle']
def contained_delivery(r, T1):
    """Delivery of events that END before T1 only (an event cut by a later block would otherwise
    smear its shortfall over the pre-block interval)."""
    ids = {e['event_id'] for e in r['plan']['events'] if e['start_s'] + e['duration_s'] <= T1}
    planned = sum(e['planned_bytes'] for e in r['plan']['events'] if e['event_id'] in ids)
    got = sum(e.get('bytes_tx', 0) + e.get('bytes_rx', 0) for e in r['es'] if e['event_id'] in ids)
    return 100 * got / planned if planned else None
rows = []; clean = []
for r in PO:
    T1 = first_block_t(r)
    if T1 < 5:
        continue
    d = contained_delivery(r, T1)
    base = [contained_delivery(c, T1) for c in E if c['cond'] == 'C2' and c['seed'] == r['seed']]
    r['n_contained'] = sum(1 for e in r['plan']['events'] if e['start_s'] + e['duration_s'] <= T1)
    clean.append((r, T1, d, mean(base)))
rows = [[r['pos'], r['seed'], r['cond'], r['mode'], f(T1), f(d), f(b), f(d - b), r['n_contained'], f(r['t_since_restart'], 0)] for r, T1, d, b in clean]
md.append('\n**Prueba de arranque limpio**: entrega de los eventos que TERMINAN antes de T1 (los eventos cortados por un bloqueo posterior no se cuentan, para no arrastrar su pérdida al intervalo previo), con T1 = primer bloqueo/mitigación de la propia ejecución (o 60 s), solo ejecuciones con pipeline activo y T1≥5 s, contra la media de C2 de la misma semilla (mismo plan benigno) en el mismo intervalo. Si el reinicio (~40 s antes) degradara el reenvío, esta diferencia sería negativa aun sin bloqueos.\n')
table(['pos', 'semilla', 'cond', 'modo', 'T1 s', 'entrega% [0,T1)', 'C2 misma semilla', 'Δ pp', 'eventos contenidos', 's desde reinicio'], rows)
J['clean_start'] = [dict(pos=r['pos'], cond=r['cond'], T1=T1, d=d, base=b) for r, T1, d, b in clean]
for m_ in ('I', 'M'):
    g = [(r, T1, d, b) for r, T1, d, b in clean if r['mode'] == m_]
    md.append(f'Modo {m_}: n={len(g)}, Δ media {f(mean([d - b for _, _, d, b in g]), 2)} pp, mediana {f(med([d - b for _, _, d, b in g]), 2)} pp; T1 mediana {f(med([T1 for _, T1, _, _ in g]))} s; eventos contenidos (mediana) {f(med([r["n_contained"] for r, _, _, _ in g]), 0)}.\n')
J['clean_start_by_mode'] = {m_: dict(n=len([1 for r, *_ in clean if r['mode'] == m_]), d=mean([d - b for r, T1, d, b in clean if r['mode'] == m_])) for m_ in ('I', 'M')}
# time to first block/mitigation by mode over ALL pipeline-on valid runs
rows = []
for m_ in ('I', 'M'):
    t1s = [first_block_t(r) for r in PO if r['mode'] == m_]
    t1s = [t for t in t1s if t < 60]
    rows.append([m_, len(t1s), f(min(t1s)), f(med(t1s)), f(max(t1s))])
md.append('Tiempo hasta el primer bloqueo/mitigación (s desde el inicio del tráfico), ejecuciones válidas con pipeline activo, todas sin ataque hasta t=60:\n')
table(['modo', 'n', 'mín', 'mediana', 'máx'], rows)
J['t_first_block'] = {r[0]: r[1:] for r in rows}
# enterprise events: delivery vs. block state at event start, by mode
def block_at(r, dom, t):
    best = None
    for c in r['cycles']:
        if c['timestamp'] - r['t0'] <= t:
            best = c
        else:
            break
    return bool(best and best.get('active_blocks', {}).get(DOM_ACTIVE[dom], 0) > 0)
md.append('Eventos enterprise (pipeline activo): entrega por evento según si había bloqueo enterprise activo al inicio del evento, por modo.\n')
rows = []
plan_ev = {e['event_id']: e for e in PO[0]['plan']['events']}
for m_ in ('I', 'M'):
    for blk in (False, True):
        pl = got = n = 0
        for r in PO:
            if r['mode'] != m_:
                continue
            pe = {e['event_id']: e for e in r['plan']['events']}
            for e in r['es']:
                if e.get('domain') != 'enterprise':
                    continue
                if block_at(r, 'enterprise', pe[e['event_id']]['start_s']) != blk:
                    continue
                pl += pe[e['event_id']]['planned_bytes']; got += e.get('bytes_tx', 0) + e.get('bytes_rx', 0); n += 1
        rows.append([m_, 'bloqueo activo' if blk else 'sin bloqueo', n, f(100 * got / pl) if pl else '—'])
table(['modo', 'estado al inicio del evento', 'eventos', 'entrega% (bytes)'], rows)
J['enterprise_event_delivery'] = rows

# M effect after controlling for blocked fraction, per domain
md.append('Efecto del modo tras controlar por fracción bloqueada (OLS por dominio, pares ejecución×tramo, pipeline activo): entrega ~ bloqueo(0–1) + M.\n')
rows = []
for dom in ('enterprise', 'fixed', 'mobile', 'peering'):
    pts = []
    for r in PO:
        for sg in SEGMENTS:
            bfv = blocked_frac(r, dom, *sg) if r['t0'] else None
            dv = r['dseg'][sg][dom]
            if bfv is not None and dv is not None:
                pts.append((bfv / 100, 1.0 if r['mode'] == 'M' else 0.0, dv))
    try:
        o = ols([[1.0, a, b] for a, b, _ in pts], [c for _, _, c in pts], ['i', 'bloqueo', 'M'])
        rows.append([dom, len(pts), f(o['coef']['bloqueo'][0]) + f' (t={f(o["coef"]["bloqueo"][2], 1)})', f(o['coef']['M'][0]) + f' (t={f(o["coef"]["M"][2], 1)})', f(o['r2'], 2)])
        J.setdefault('mode_given_block', {})[dom] = o['coef']
    except ZeroDivisionError:
        rows.append([dom, len(pts), '—', '—', '—'])
table(['dominio', 'n', 'coef bloqueo (pp por 100%)', 'coef M (pp)', 'R²'], rows)

# ---------------------------------------------------------------- 5 detector activity
h('5. Actividad del detector')
TH = E[0]['records'][0]['thresholds']['values']
thr = {'TCP_SYN': TH['SYN_THRESHOLD'], 'UDP': TH['UDP_THRESHOLD'], 'ICMP': TH['ICMP_THRESHOLD']}
J['thresholds'] = TH
for r in ALL:
    cyc = [x for x in r['records'] if x['kind'] == 'cycle']; ts = [x['timestamp'] for x in cyc]
    r['cycles'] = cyc
    dets = []
    for x in r['records']:
        if x['kind'] != 'detection':
            continue
        d = x['detection']
        # a protocol-threshold crossing may precede the detection by up to its activation delay
        # (hysteresis), so look at every cycle in [t_det - delay - 6 s, t_det], not just the last one
        lo = x['timestamp'] - (d.get('activation_delay_s') or 0) - 6
        i0, i1 = bisect.bisect_left(ts, lo), bisect.bisect_right(ts, x['timestamp'])
        over = []
        for cy_ in cyc[i0:i1]:
            for g in cy_.get('observed_rates', []):
                if g['dst_ip'] == d['dst_ip']:
                    for p_, v in g['protocols'].items():
                        if p_ in thr and v['trigger_pps'] > thr[p_]:
                            over.append(p_)
        origin = 'umbral_protocolo:' + ','.join(sorted(set(over))) if over else 'respaldo_distribuido(DIST_PPS=300)'  # no protocol over its threshold anywhere in the look-back window
        dets.append(dict(t=x['timestamp'] - r['t0'] if r['t0'] else None, type=d['attack_type'], domain=d['domain'], origin=origin, pps=d['pps'], n_sources=len(d.get('sources', [])), delay=d.get('activation_delay_s'), kpm=bool(d.get('kpm'))))
    r['dets'] = dets
    r['decisions'] = [x for x in r['records'] if x['kind'] == 'decision']
    r['mits'] = [x for x in r['records'] if x['kind'] == 'mitigation_issued']
    r['rels'] = [x for x in r['records'] if x['kind'] == 'mitigation_release']
md.append('**C1 (benigno puro, sin ataque): toda detección, decisión y mitigación es sobre tráfico benigno.**\n')
rows = []
for r in ALL:
    if r['cond'].startswith('C1') and r['eligible']:
        tc = collections.Counter(d['type'] for d in r['dets']); org = collections.Counter(d['origin'] for d in r['dets'])
        acc = sum(1 for x in r['decisions'] if x.get('accepted'))
        mc = collections.Counter((x['action']['domain'], x['action']['action']) for x in r['mits'])
        srcs = {x['action']['src_ip'] for x in r['mits']}
        rows.append([r['seed'], r['cond'], len(r['dets']), dict(tc), dict(org), f'{acc}/{len(r["decisions"])}', len(r['mits']), dict(mc), len(srcs), sum(d['kpm'] for d in r['dets'])])
table(['semilla', 'cond', 'detecciones', 'tipos', 'origen del criterio', 'decisiones aceptadas/total', 'mitigaciones emitidas', 'por dominio/acción', 'fuentes únicas bloqueadas', 'detecciones KPM'], rows)
agg = collections.defaultdict(lambda: collections.Counter())
for r in E:
    if r['cond'].startswith('C1'):
        for d in r['dets']:
            agg[r['cond']][('det', d['type'], d['origin'])] += 1
        for x in r['mits']:
            agg[r['cond']][('mit', x['action']['domain'], x['action']['action'])] += 1
J['c1_activity'] = {c: {'|'.join(k): v for k, v in cn.items()} for c, cn in agg.items()}
# blocked fraction per domain/segment
md.append('\nFracción del tiempo con bloqueos activos (`active_blocks>0` en los ciclos LAB_AUDIT) por dominio y tramo; media sobre ejecuciones válidas.\n')


for r in E:
    r['bf'] = {(dom, s): blocked_frac(r, dom, *s) for dom in DOMAINS for s in SEGMENTS}
rows = []
for cond in ('C1-I', 'C1-M', 'C2', 'C3', 'C4'):
    g = [r for r in E if r['cond'] == cond]
    rows.append([cond, len(g)] + [f'{dom[:3]} ' + '/'.join(f(mean([r['bf'][(dom, s)] for r in g]), 0) for s in SEGMENTS) for dom in DOMAINS])
table(['cond', 'n', 'enterprise 0-60/60-120/120-180 (%)', 'fixed', 'mobile', 'peering'], rows)
# relationship delivery vs blocked fraction, per domain
md.append('Relación entrega% ↔ fracción bloqueada (pares ejecución×tramo, ejecuciones con pipeline activo; OLS entrega ~ bloqueo%):\n')
rows = []
for dom in DOMAINS:
    pts = [(r['bf'][(dom, s)], r['dseg'][s][dom]) for r in PO for s in SEGMENTS if r['bf'][(dom, s)] is not None and r['dseg'][s][dom] is not None]
    X = [[1.0, p[0] / 100] for p in pts]; o = ols(X, [p[1] for p in pts], ['intercepto', 'bloqueo(0→100%)'])
    lo = mean([p[1] for p in pts if p[0] == 0]); hi = mean([p[1] for p in pts if p[0] >= 50])
    J.setdefault('delivery_vs_block', {})[dom] = dict(n=len(pts), coef=o['coef'], r2=o['r2'])
    rows.append([dom, len(pts), f(o['coef']['intercepto'][0]), f(o['coef']['bloqueo(0→100%)'][0]) + f' (t={f(o["coef"]["bloqueo(0→100%)"][2], 1)})', f(o['r2'], 2), f(lo), f(hi), sum(1 for p in pts if p[0] == 0), sum(1 for p in pts if p[0] >= 50)])
table(['dominio', 'n', 'entrega% con 0% bloqueo (intercepto)', 'pendiente por 100% bloqueado (pp)', 'R²', 'media entrega% sin bloqueo', 'media entrega% con ≥50% bloqueo', 'n sin bloqueo', 'n con ≥50%'], rows)
# 0-60 only, pre-attack, C3/C4 + C1
md.append('Mitigaciones antes de tA (t<60 s) en C3/C4 — por definición no responden al ataque de la ejecución:\n')
rows = []
for cond in ('C3', 'C4'):
    g = [r for r in E if r['cond'] == cond]
    pre_m = [sum(1 for x in r['mits'] if x['timestamp'] - r['t0'] < 60) for r in g]
    pre_d = [sum(1 for d in r['dets'] if d['t'] is not None and d['t'] < 60) for r in g]
    rows.append([cond, len(g), f(mean(pre_d), 1), f(mean(pre_m), 1), sum(x > 0 for x in pre_m), f(mean([r['dseg'][(0, 60)]['all'] for r in g]))])
table(['cond', 'n', 'detecciones pre-ataque (media/ejec.)', 'mitigaciones pre-ataque (media)', 'ejec. con ≥1', 'entrega% 0–60'], rows)

md.append('Tasa máxima observada (`trigger_pps` por ciclo, cualquier destino) antes de t=60 s y umbral del protocolo (máximo sobre todos los ciclos y destinos; un cruce aislado de un ciclo no basta para detectar por la histéresis de activación, y la columna «origen» de las tablas de detección sólo marca «umbral_protocolo» si el destino detectado cruzó el umbral en la ventana previa a la detección):\n')
rows = []
for cond in ('C1-I', 'C1-M', 'C3', 'C4'):
    mx = collections.defaultdict(float)
    for r in E:
        if r['cond'] != cond:
            continue
        for cy_ in r['cycles']:
            if r['t0'] <= cy_['timestamp'] < r['t0'] + 60:
                for g in cy_.get('observed_rates', []):
                    for p_, v in g['protocols'].items():
                        mx[p_] = max(mx[p_], v['trigger_pps'])
    rows.append([cond] + [f(mx[p_], 1) + f' / {thr[p_]}' for p_ in ('TCP_SYN', 'UDP', 'ICMP')])
table(['cond', 'TCP_SYN máx / umbral', 'UDP máx / umbral', 'ICMP máx / umbral'], rows)
J['max_trigger_pps_pre60'] = rows
# per-run totals by condition: mitigations on non-attacker IPs
rows = []
for cond in ('C1-I', 'C1-M', 'C3', 'C4'):
    g = [r for r in E if r['cond'] == cond]
    ben = []
    for r in g:
        atk_ips = set(r['run'].get('attack_source_ips', []))
        ben.append(sum(1 for x in r['mits'] if x['action']['src_ip'] not in atk_ips))
    rows.append([cond, len(g), f(mean([len(r['mits']) for r in g])), f(mean(ben)), f(mean([len(r['dets']) for r in g])),
                 f(mean([sum(1 for d in r['dets'] if d['origin'].startswith('respaldo')) for r in g])),
                 f(mean([sum(1 for x in r['mits'] if x['action']['domain'] == 'bgp') for r in g]))])
table(['cond', 'n', 'mitigaciones/ejec.', 'sobre IP no atacante (incl. "*")', 'detecciones/ejec.', 'de ellas, por respaldo distribuido', 'flowspec bgp/ejec.'], rows)
# C3/C4 detection types
md.append('Detecciones por tipo y origen, todas las ejecuciones válidas con pipeline activo:\n')
cc = collections.Counter()
for r in PO:
    for d in r['dets']:
        cc[(r['cond'], d['type'], d['origin'])] += 1
table(['cond', 'tipo', 'origen', 'n'], [[*k, v] for k, v in sorted(cc.items())])
J['detections_by_origin'] = {'|'.join(k): v for k, v in cc.items()}

# ---------------------------------------------------------------- 6 forwarding state
h('6. Estado de reenvío')
rows = []
for r in E:
    c0 = [c for c in r['cycles'] if r['t0'] <= c['timestamp'] < r['t0'] + 5]
    pk = max([sum(c.get('active_blocks', {}).values()) for c in c0] or [0])
    prep = r['run'].get('block_preparation', {})
    r['init_blocks'] = pk
    r['resid'] = prep.get('preflight', {}).get('openflow_residual_drops')
    r['errs'] = collections.Counter(e.get('error', '') and ('reset' if 'reset' in e['error'].lower() else 'bind' if 'bind' in e['error'].lower() or 'assign' in e['error'].lower() else 'unreach' if 'unreachable' in e['error'].lower() else 'deadline' if 'Deadline' in e['error'] or 'deadline' in e['error'] else 'shortfall' if 'shortfall' in e['error'] else 'otro') for e in r['es'] if e.get('status') == 'failed')
rows = []
for cond in ('C1-I', 'C1-M', 'C2', 'C3', 'C4'):
    g = [r for r in E if r['cond'] == cond]
    ne = sum(len(r['es']) for r in g)
    ec = collections.Counter(); [ec.update(r['errs']) for r in g]
    rows.append([cond, len(g), f(mean([r['init_blocks'] for r in g])), sum(1 for r in g if r['init_blocks'] > 0), f(mean([r['resid'] for r in g if r['resid'] is not None])),
                 f(100 * sum(ec.values()) / ne), *(f(100 * ec[k] / ne, 2) for k in ('shortfall', 'deadline', 'reset', 'bind', 'unreach'))])
table(['cond', 'n', 'bloqueos activos en 1ros 5 s (media)', 'ejec. con bloqueos al inicio', 'openflow_residual_drops previo (media)', 'eventos fallidos %', 'shortfall %', 'deadline %', 'reset %', 'bind %', 'unreachable %'], rows)
rows = []
for m in ('I', 'M'):
    for rs_ in (True, False):
        g = [r for r in PO if r['mode'] == m and r['restarted'] == rs_]
        ne = sum(len(r['es']) for r in g) or float('nan'); ec = collections.Counter(); [ec.update(r['errs']) for r in g]
        rows.append([m, 'reinicio antes' if rs_ else 'sin reinicio', len(g), f(mean([r['init_blocks'] for r in g])), f(100 * sum(ec.values()) / ne), f(100 * ec['reset'] / ne, 2), f(100 * ec['deadline'] / ne, 2)])
table(['modo', 'grupo', 'n', 'bloqueos iniciales media', 'fallidos %', 'reset %', 'deadline %'], rows)
# deployed code hashes
hs = collections.defaultdict(set)
for r in ALL:
    for x in r['records'][:1]:
        for k, v in x['thresholds']['implementation_hashes'].items():
            hs[k].add(v)
J['implementation_hashes_distinct'] = {k: sorted(v) for k, v in hs.items()}
md.append('Hashes de implementación del controlador registrados por LAB_AUDIT: ' + ', '.join(f'`{k}` → {len(v)} valor(es) distinto(s) en las 60 ejecuciones' for k, v in hs.items()) + '.\n')
# write
OUT_MD.write_text('\n'.join(md))
json.dump(J, open(OUT_JSON, 'w'), indent=1, default=str)
print('\n'.join(md))
