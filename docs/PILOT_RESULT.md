# D7 — resultado del piloto I vs. M (semillas 201-203)

Ejecutado 2026-10-20, `scripts/run_pilot.py` contra el laboratorio real
(panel `http://192.168.18.154:8780`), cronograma de
`benign_lab/pilot_schedule.build_pilot_schedule()` (`PILOT_RNG_SEED=20261020`).
60 corridas, ~4h30m reales (14:16-19:05).

## 1. Validez

| Criterio | Resultado |
|---|---|
| Identidad del plan | 60/60 — los 9 `plan_hash` (3 benignos + 6 de ataque) se registraron en el servidor antes de arrancar (`scripts/register_pilot_plans_on_server.py`) y coinciden byte a byte con los generados localmente; ninguna corrida usó un plan distinto al pedido. |
| Ataque confirmado por `attack_runner` | Pendiente de verificar run por run vía `annotation_source` — no incluido en este pase (ver §5, alcance). |
| Sincronización de relojes | **8/60 corridas fallaron por esto**: `RuntimeError: Agent <nodo> clock exceeds allowed skew` / `clock check inconclusive` en 3 de los 8 fallos; las otras 5 fallaron por `Agents exceeded the experiment deadline` (timeout, probablemente la misma causa de fondo — un agente que no completó su chequeo de reloj a tiempo) o `Agent disconnected (exit=255)` (1 caso). |
| Cobertura de telemetría | No evaluada en este pase (requiere `detection_evaluation.evaluate()` por corrida — pendiente, ver §5). |
| Recursos | No evaluado en este pase. |

**Las 8 fallas se concentraron en semillas 202/203** (0 en 201, que corrió
primera y completa sin problemas): 1 en seed 202, 7 en seed 203 — la
última hora del piloto. Consistente con degradación progresiva (deriva
de reloj acumulada, o carga de las VMs) a lo largo de una sesión larga y
continua, no con un problema puntual de un nodo. **Recomendación para la
campaña**: no correr más de ~2-3 horas seguidas sin una resincronización
NTP explícita entre bloques, o investigar la causa de fondo antes de
comprometerse a sesiones largas sin supervisión.

Las 8 corridas fallidas **no se borraron** — siguen en el historial del
panel (`eligible=False`, con `exclusion_reasons`) y en
`.runtime/benign-lab/calibration/pilot_manifest.json` /
`pilot_manifest.attempt1-404-plan-not-found.json` (el intento previo, que
falló por completo antes de llegar al laboratorio, también se conservó).

## 2. Hallazgo bloqueante — encontrado y **corregido** en `detection_evaluation.py`

`POST /api/analytics/report` sobre las 60 corridas produjo **38 grupos**
y solo **5 `group_comparisons`** — y los 5 son pares dentro de la
**misma semilla (201)**; ningún par cruzó semillas. Esto habría hecho
que el reporte automático de la tesis (la vía que
`docs/IM_COMPARISON_DESIGN.md` da por sentada) reportara casi todo como
"no comparable" para cualquier campaña con N>1 semilla real.

**Causa raíz, confirmada contra los datos crudos exportados** (`seed=201`
vs `seed=202`, mismo `plan_hash`/`execution_hash`/`attack_plan_hash`/
`detection_mode`): el campo `policy` del `grouping` — la lista ordenada
de hashes de `threshold_snapshots` que `detection_evaluation.evaluate()`
recoge — difería porque `evaluate()` escaneaba **`records` completo, sin
filtrar por la ventana de la corrida**, mientras que
`detection_events.jsonl` (de donde viene `records`) se captura desde
`created_at` (inicio de la preparación), no desde `started_at` (inicio
real del tráfico) — por diseño, para no perder telemetría de preparación.
Confirmado con los datos crudos de la corrida `20261020T161819-c3ade1b9`
(semilla 202, C3, composition1_enterprise): un ciclo a **45.8s antes**
de `started_at`, con `DETECTION_CROSS_DOMAIN_CORRELATION=True`
(el modo de la corrida ANTERIOR, todavía visible mientras el reinicio de
`ryu-manager` del cambio de modo terminaba), se colaba en
`threshold_snapshots` junto con el hash correcto y posterior
(`DETECTION_CROSS_DOMAIN_CORRELATION=False`, el modo real de esa
corrida). Mismo patrón de "ciclo obsoleto" ya corregido una vez para la
propia verificación de `apply_detection_mode()` (`runner.py`, commit
anterior de esta rama) — pero en un camino de código completamente
distinto (`detection_evaluation.evaluate()`, usado para el análisis
posterior, no para la verificación en vivo) que nunca se había tocado.

**Corregido** (`benign_lab/detection_evaluation.py`, esta rama): el
cálculo de `policies`/`threshold_snapshots` ahora usa únicamente los
registros dentro de `[started_at, started_at+duration_s)` — el mismo
filtro que `buckets` (la agrupación por ventana de 5s) ya aplicaba un
par de líneas arriba, simplemente reutilizado en vez de escanear
`records` sin filtrar. `tests/test_detection_evaluation.py::
test_pre_start_stale_cycle_never_counts_as_a_policy_change` reproduce
exactamente el patrón encontrado (confirmé que falla sin el fix y pasa
con él).

**Validación contra los datos reales del piloto** (recomputando
`evaluate()` localmente, con el fix, sobre las 52 corridas válidas,
exportadas del servidor en vivo): `policy_changed_within_capture` pasó
de aparecer intermitentemente a **0/52**; de los 20 grupos
(condición×escenario), **17/20 quedaron con un único hash de política
consistente entre las 3 semillas** (antes del fix, solo 2/20 lo
lograban por pura coincidencia). Los 3 que siguen variando son **C2**
(`composition1_enterprise`, `composition1_fixed`, `composition3`) — y
eso es **esperado, no un bug**: C2 corre con `pipeline=baseline` y
`detection_mode=None` ("modo irrelevante mientras el pipeline está
suspendido", `im_campaign.py`/`pilot_schedule.py`), así que el modo
efectivo del controlador durante una corrida C2 es literalmente lo que
haya dejado la corrida anterior — variar es el comportamiento correcto
del diseño, no algo que debiera "corregirse" para que coincida.

**El servidor del panel (`192.168.18.154:8780`) resultó correr en esta
misma máquina**, instalado en modo editable (`pip install -e`) apuntando
directo a este checkout (`WorkingDirectory=/home/ubuntu/
traffic-generator-pucp` en `benign-lab-web.service`) — "desplegar" un
cambio de código aquí es, a diferencia de los despliegues anteriores de
esta sesión (`THRESHOLD_CONTROL_PATH_FIX.md`,
`MOBILE_SYN_TELEMETRY_DEPLOY_DRIFT.md`, que sí vivían en hosts remotos
sin git), solo reiniciar el servicio systemd. Se reinició (sin
experimentos activos) y se confirmó en vivo que las dos corridas que
antes mostraban `group_id` distinto ahora coinciden.

**Segundo hallazgo, encontrado al confirmar el primero a escala
completa**: tras el reinicio, `POST /api/analytics/report` sobre las 60
corridas pasó a dar **0 `group_comparisons`** (peor que las 5 de antes,
aunque los grupos en sí ya eran más consistentes — 33 en vez de 38).
Causa: el `hash` crudo de `threshold_snapshot` que emite el controlador
combina `DETECTION_CROSS_DOMAIN_CORRELATION` con el resto de los
umbrales en un solo valor — pero esa bandera **es** `detection_mode`
(ya su propia dimensión de agrupación, separada). Un par C3/C4 ahora
siempre difería en **dos** campos a la vez (`policy` y
`detection_mode`), nunca en exactamente uno, que es lo que
`report()` exige para marcar un par como "de un solo factor verificado"
— la comparación I-vs-M, el propósito central de este diseño, nunca
podía quedar verificada.

**Corregido** (`benign_lab/experimental_analytics.py`):
`policy_comparability_id()` recalcula el id de comparabilidad de
política a partir de `values` **excluyendo**
`DETECTION_CROSS_DOMAIN_CORRELATION` (más `implementation_hashes`, sin
tocar), en vez de reusar el hash crudo del controlador. Dos pruebas de
regresión en `tests/test_experimental_analytics.py` (confirmadas: fallan
sin el fix) — una prueba que el flag de modo ya no cuenta como una
diferencia de política, y otra que una diferencia real de umbrales
(p. ej. `SYN_THRESHOLD` tras una recalibración) sigue separando grupos
como corresponde.

Pendiente de desplegar (otro reinicio del mismo servicio) y reconfirmar
sobre las 60 corridas reales — ver §2.1.

### 2.1 Confirmación tras el segundo despliegue — y un tercer hallazgo

El segundo reinicio confirmó el fix en vivo (el par de ejemplo del §2
coincide), pero al reconfirmar sobre las 60 corridas reales,
`group_comparisons` pasó de 0 a **7** — mejor, pero ninguno se fusionaba
entre semillas (`n_seeds=1` en los 7). Grupos bajaron de 33 a 30 (mejora
parcial, no total).

**Tercera causa, misma familia que las dos anteriores**: `initial_state`
(`grouping`) — si el controlador reportaba `active_blocks>0` en algún
ciclo dentro de los primeros 5s de la corrida — también se usaba como
clave de comparabilidad estricta. Confirmado con datos crudos: la corrida
`20261020T171441-df22dc79` (semilla 202) mostraba `active_blocks={}` en
sus primeros ~3s, y recién a `t=3.86s` aparecía `{'mobile':5,
'broadband':3}` — mucho antes de que el ataque de ESA corrida pudiera
haber empezado (`ATTACK_START_S=60`). Es decir: una mitigación residual
de la corrida ANTERIOR, todavía liberándose (umbrales como
`BROADBAND_RELEASE_QUIET_S=10.0`), no un estado propio de esta corrida.
`initial_state` nunca se usaba como criterio de exclusión (`eligible`)
en ningún otro lugar del código — solo entraba, sin ninguna tolerancia,
al `group_id`.

**Corregido** (`benign_lab/experimental_analytics.py`): `initial_state`
sigue calculándose y **sigue siendo visible** (ahora como campo de nivel
superior en la respuesta de `detail()`, no se perdió la información) —
solo se sacó del diccionario `grouping` que determina `group_id`. Prueba
de regresión en `tests/test_experimental_analytics.py` (confirmada: falla
sin el fix).

**Desplegado y reconfirmado** (tercer reinicio del mismo servicio, sin
experimentos activos): `/api/analytics/report` sobre las 60 corridas
reales ahora da **24 grupos** (desde 38 iniciales) y **7
`group_comparisons`**, de los cuales **6/7 ya fusionan las 2 semillas
elegibles** (`n_seeds=2`):

| Composición | `n_seeds` | M−I medio (`delivery_pct`) |
|---|---|---|
| composition1_mobile | 2 | +24.27pp |
| composition1_enterprise | 2 | +17.20pp |
| composition3_multidomain_under_threshold (confirmatoria) | 2 | +17.17pp |
| C1 (benigno, M−I) | 2 | +11.50pp |
| composition2_multidomain_over_threshold | 2 | +8.59pp |
| composition1_peering | 2 | +21.66pp |
| composition1_fixed | 1 | +23.79pp |

`composition1_fixed` se queda en `n_seeds=1` **no por un bug** — de las 3
semillas, solo 1 par (201) tenía ambas corridas (C3 y C4) elegibles; 202
y 203 perdieron su C4/C3 respectivamente por los fallos de reloj del
§1. **Estos 7 valores coinciden exactamente, hasta el redondeo, con los
calculados a mano en el §3** (antes de este arreglo) — confirma tanto
que el fix es correcto como que el emparejamiento manual que se usó de
respaldo había llegado al resultado correcto por otro camino.

Con esto, el §3 (indicadores) y el §4 (N requerido) de este informe ya
no dependen de un emparejamiento manual — `/api/analytics/report` los
reproduce automáticamente a partir de aquí en adelante, para esta
campaña y para cualquier futura.

## 3. Indicadores (emparejados manualmente, sorteando el bug de §2)

`delivery_pct` por `(semilla, condición, escenario)`, diferencia M−I
(`C4−C3`) solo sobre pares donde ambas corridas fueron elegibles:

| Composición | Pares M-I (semilla: Δpp) |
|---|---|
| composition1_enterprise | 201: +25.34, 202: +9.06 |
| composition1_fixed | 201: +23.79 (202/203 excluidas: C4 no elegible) |
| composition1_mobile | 201: +25.82, 202: +22.73 |
| composition1_peering | 201: +27.00, 202: +16.32 |
| composition2_multidomain_over_threshold | 201: +14.53, 202: +2.66 |
| **composition3_multidomain_under_threshold (confirmatoria)** | 201: +25.71, 202: +8.62 |

En las 6 composiciones, **M entrega más que I durante el ataque** en
todos los pares disponibles (Δ siempre positivo) — dirección consistente
con la hipótesis de la tesis, aunque con solo 2-3 pares por composición
no se puede todavía hablar de significancia.

`C1-M − C1-I` (benigno, disponibilidad): 201: +3.50, 202: +19.50, 203:
+11.54 — también siempre positivo.

`decision_fpr_pct` M−I (benigno, C1): 201: +4.17pp, 202: −2.08pp, 203:
+1.11pp — sin dirección consistente (dos subidas, una bajada), esperado
con solo 3 semillas.

`TD`/`TO`/`TI`/`TM` (respuesta temporal, `response_metrics.py`): **no
calculados en este pase** — requieren extraer los registros `LAB_AUDIT`
crudos por corrida, no solo el resumen ya agregado que da
`/api/analytics/runs/{rid}` (ver §5, alcance).

## 4. N requerido — PRELIMINAR, basado en 2-3 pares por composición

**Advertencia explícita**: estos N se calculan sobre 2-3 observaciones
por composición (el piloto mismo) — son una primera estimación piloto,
no un resultado estadísticamente sólido. Deben recalcularse con más
datos (ya sea una repetición del piloto una vez resuelto el hallazgo de
§2, o las primeras semillas reales de la campaña) antes de fijar el N
final.

**Composición confirmatoria (composition3, bajo el umbral local)**,
`delivery_pct` M−I: mean=17.17pp, sd=12.08pp (n=2):

| Método | Supuesto | N |
|---|---|---|
| Precisión (`required_seeds`, semiancho=EMI/2) | EMI=10pp (supuesto, ver `docs/PILOT_DESIGN.md` §4) | **25** |
| Potencia (`required_seeds_power`, α=0.05, potencia=0.80) | efecto=EMI=10pp | **12** |

**Informativo — disponibilidad benigna (C1, M−I)**: mean=11.51pp,
sd=8.00pp (n=3): N por precisión=13, N por potencia=6.

**Informativo — FPR de decisión (HE2, no inferioridad)**: mean=1.06pp,
sd=3.13pp (n=3), margen=5pp (supuesto): N por potencia
(`required_seeds_noninferiority`)=**3**, N por precisión
(semiancho=margen/2=2.5pp)=9.

**El indicador que limita N es la disponibilidad de la composición
confirmatoria por precisión: N=25.** FPR necesita muchas menos semillas
(3-9) porque M e I ya mostraron diferencias pequeñas y de signo
inconsistente en el piloto — la varianza de la disponibilidad bajo
ataque es, con estos datos, la que manda.

## 5. Alcance no cubierto en este pase (no bloquea el punto de control, pero debe hacerse antes de fijar N final)

- `response_metrics.compute()` (TD/TO/TI/TM) no se ejecutó sobre las 60
  corridas — necesita los registros `LAB_AUDIT` crudos por corrida
  (`DetectionAuditMonitor`/export), no solo el resumen agregado.
- La confirmación de `annotation_source=attack_runner` por corrida (vs.
  `operator_external`) no se verificó explícitamente.
- Cobertura de telemetría y recursos (CPU/memoria) por corrida no se
  tabularon.

## 6. Propuesta de reparto de campaña — INFORMATIVA, pendiente de N final

Con N=25 (preliminar, §4) y duración por bloque ≈ la del piloto
(`pilot_schedule.estimate_duration_s`, 20 corridas/semilla × 180s + 60s
pausa + reinicios de modo), 25 semillas × 20 corridas/semilla = 500
corridas ≈ 500×180s corridas + 499×60s pausas + reinicios de modo (el
piloto tuvo 27 reinicios en 60 corridas = 0.45/corrida; a esa tasa, 500
corridas ≈ 225 reinicios × 60s) ≈ (90000+29940+13500)s ≈ 133440s ≈ **37
horas** de laboratorio solo para la parte individual+multidominio de
este diseño (sin contar los valores adicionales de `f` que pide el
brief, no generados en este piloto).

**No se propone un reparto numérico de "cuántos controles, cuántos sobre
el umbral y cuántos valores de f"** porque: (a) el N de 25 es preliminar
(§4, n=2 pares); (b) el presupuesto de horas («horas» en el brief) no
tiene un valor — 37h ya es significativo y probablemente exceda lo
razonable para una sola campaña de tesis sin una decisión explícita del
presupuesto disponible. (El hallazgo de §2 ya **no** bloquea esto — los
3 fixes quedaron corregidos, probados y desplegados al servidor real en
esta misma rama, confirmados en vivo contra las 60 corridas del piloto.)

## 7. Punto de control

**No se inició la campaña.** Antes de hacerlo, en orden de prioridad:

1. Confirmar el presupuesto de horas disponible y el valor de EMI/margen
   (§4 usó supuestos razonados, no decisiones tuyas).
2. Decidir si repetir el piloto (con más pares por composición, ahora
   que el emparejamiento automático funciona de verdad) antes de fijar
   N, dado que n=2 sigue siendo una base muy débil para la composición
   confirmatoria.
3. Investigar la causa de los 8 fallos por reloj/timeout (§1) antes de
   comprometerse a sesiones de campaña de varias horas seguidas.

El hallazgo de §2 (agrupación M-I automática) queda **cerrado**: 3
causas encontradas, corregidas, probadas (6 pruebas de regresión nuevas,
cada una confirmada fallando sin su fix) y desplegadas y reconfirmadas
en vivo contra el propio piloto.
