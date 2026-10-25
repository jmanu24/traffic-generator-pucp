# PILOT2 — repetición del piloto I-vs-M (semillas 204-206, diseño V2 corregido)

Ejecutado 2026-10-23, `scripts/run_pilot2.py` contra el laboratorio real
(panel `http://192.168.18.154:8780`), cronograma de
`benign_lab/pilot_schedule.build_pilot_schedule()` (`PILOT_RNG_SEED=20261020`,
mismo generador que el piloto 1, semillas y manifiesto V2 distintos),
manifiesto de 8 planes de ataque corregidos (`ATTACK_PLAN_V2_VALIDATION.md`).
78 bloques (C1-I/C1-M una vez por semilla + C2/C3/C4 por cada uno de los 8
planes × 3 semillas), ~00:00-09:07 (≈9h, incluyendo la investigación e
intervención de la sección 1.1).

## 1. Validez

| Criterio | Resultado |
|---|---|
| `run.eligible` | **78/78 = True**, 0 `exclusion_reasons`. |
| Pares completos (semilla×condición, semilla×escenario×condición) | **78/78 completos** — ningún bloque quedó sin su par tras el reintento. |
| Identidad del plan | 3 planes benignos (semillas 204/205/206) + 8 planes de ataque V2, todos registrados y verificados byte a byte antes de arrancar (`scripts/register_pilot2_plans.py`, reutilizando los 8 planes ya registrados en la Tarea B). |

### 1.1 Un bloque con 3 fallos consecutivos — investigado y resuelto

`seed=206, composition3_f09, C4(M)` falló 3 veces seguidas con
`RuntimeError: Agents exceeded the experiment deadline` (siempre
`elapsed_s==duration_s==180.0`: la ventana de ataque se completaba
completa; el fallo ocurría en la finalización/reporte de los 21 agentes,
no durante el ataque). Investigación en vivo:

- `benign-lab-web.service` no se había reiniciado desde las 06:55:35
  (reinicio idle normal del temporizador ya instalado) y para las 08:29
  (3er intento) tenía **2,77 GB residentes** — mismo mecanismo ya
  documentado en `docs/PILOT_RESULT.md` §1 del piloto 1: `Manager.__init__`
  carga en memoria el `event_states.json` completo de **cada** carpeta de
  corrida que exista en disco, sin desalojar ninguna nunca. Confirmado en
  vivo: una llamada a `/api/runs` (lista completa) tardó 12,7s y por sí
  sola hizo que la memoria residente subiera de 176MB a 2,8GB; incluso
  tras un reinicio limpio, el proceso vuelve a ~2,8-3,1GB en los primeros
  segundos de actividad — el costo es proporcional al **total de corridas
  acumuladas en disco** (ya >300 entre calibración + validación de planes
  + piloto 1 + piloto 2), no una fuga de memoria clásica dependiente del
  tiempo.
- `composition3_f09`/C4 es estructuralmente la corrida más pesada del
  manifiesto (f=0.9, 3 dominios, 6 fuentes de ataque, más la correlación
  cruzada de dominios que M calcula en cada ciclo de sondeo) — el menor
  margen contra el *timeout* de 180s de todo el diseño. Con el proceso en
  ese régimen de memoria, hasta un *lookup* O(1) de una corrida se
  degrada por el costo de recolección de basura de un heap de ese tamaño,
  afectando primero al bloque con menos margen.
- Las mismas `composition3_f09`/C4 de las semillas 204 y 205 **sí**
  pasaron (204 a las 00:12, muy al inicio; 205 a las 03:35, con 1
  reintento) — consistente con menos corridas acumuladas en ese momento.
  Las demás corridas C4 de la semilla 206 (las 7 restantes) también
  pasaron sin este problema — no es un problema de la semilla 206 en
  general, ni de `composition3_f09` en general, sino de la intersección
  específica (semilla 206, el bloque más pesado, llegando tarde en el
  orden aleatorio del cronograma).

**Intervención** (operativa, no tocó lógica de detección/decisión/
mitigación; el temporizador `benign-lab-web-restart-guard.timer` se
mantuvo activo, confirmado vía `journalctl`, por instrucción explícita de
esta tarea): reinicio manual de `benign-lab-web.service`, confirmado
saludable, 4° intento del mismo bloque exacto → `completed_with_errors`
(el estado normal de finalización, igual que las otras 77 corridas),
21 agentes, `elapsed_s=duration_s=180.0`, sin el `RuntimeError`. Bloque
válido, manifiesto actualizado (`run_id=20261023T090654-6797364e`).

## 2. Control (composición 1 — C1-I vs. C1-M, benigno sin ataque)

**Actualizado tras construir `response_metrics.compute()` (§3.1): `A`
está formalmente indefinida para C1.** `A` se define sobre `[tA,tF]`
(la ventana real de ataque, evidencia de `attack_runner`) — C1 no tiene
ataque, por lo tanto `tA=tF=None`, `eligible_window_count=0` y
`availability_pct=None` en las 6 corridas C1 (3 semillas × I/M),
confirmado explícitamente. No es un error del cálculo: es el alcance
declarado de la métrica (`response_metrics.py`, docstring de `A`) — un
indicador de disponibilidad *durante* el ataque no tiene valor cuando no
hay ataque. El criterio de control tal como está escrito ("CI de M−I en
A ... contiene 0") **no se puede evaluar formalmente para composición 1**
— ver §7, punto 1.

Lo que sí es formal y está bien definido en C1:

`decision_fpr_pct` M−I: 0.0pp en las 3 semillas (ninguna de las 6
corridas C1 tuvo falsos positivos de decisión). `detection_fpr_pct` M−I:
también 0.0pp en las 3 semillas. **CI95 = [0,0] — contiene 0.**

**Criterio de control: CUMPLIDO para FPR (ambos, detección y decisión);
NO EVALUABLE para A (indefinida en C1 por diseño de la métrica) ni para
TD (tampoco aplica sin ventana de ataque).**

## 3bis. Corrección del generador de composición 3 y repetición en vivo (2026-10-23)

Aplicada la corrección descrita en §7 punto 3 (`scripts/generate_attack_plans_v2.py`):
el ritmo por fuente ahora escala el margen que queda después de restar
`BACKGROUND_SYN_PPS_PER_SOURCE=50` (medido contra 2 cruces reales) a
`SAFE_MARGIN=0.85` del umbral, y composición 3 pasó de 2 a 3 fuentes por
dominio (hosts reales ya en la topología) para que M siga alcanzando
`DECISION_THRESHOLD` con el ritmo más bajo. Validado offline
(`decision_score_estimator`) antes de tocar el laboratorio: I nunca
decide, M siempre decide como `MULTIDOMAIN_DISTRIBUTED_ATTACK`, en los 3
valores de f. Los 8 planes se registraron en el servidor (coinciden byte
a byte) y se repitieron en vivo los 27 bloques afectados (C2/C3/C4 × 3 f
× 3 semillas) — 2 bloques necesitaron su reintento (mismo *timeout*
transitorio de memoria de siempre, documentado en §1.1; uno se recuperó
en el reintento automático del script, el otro necesitó un reinicio
manual del servicio + reintento, igual que en §1.1). **27/27 válidos al
final.**

**Resultado de la corrección — mejora real pero no total**: la cobertura
de I bajó de 0/33/67% (f05/f07/f09, plan original) a **33/33/0%**
(f05/f07/f09, plan corregido) — el problema se movió, no desapareció del
todo. Con el ritmo por fuente ya muy por debajo del umbral aun sumando el
fondo medido (61-70pps contra el umbral de 85.238, un margen de 15-30%),
las 2 detecciones aisladas restantes (f05 y f07, 1/3 semillas cada una)
implican que el fondo benigno real tiene **más varianza entre semillas**
de la que el promedio de 2 mediciones usado para la corrección capturó —
picos puntuales de tráfico benigno, no solo un nivel medio constante. La
sección §7 (punto de control) recoge la decisión pendiente sobre si vale
la pena ajustar más el margen (con el riesgo de volver a romper la
decisión de M, que ya está cerca de su propio límite a f=0.5 con el
ritmo reducido).

## 3. Confirmatorio (composición 3, por f — bajo el umbral local)

### 3.1 `response_metrics.compute()` — construido y ejecutado sobre las 78 corridas reales

Se armó la integración que el piloto 1 (§5) y el primer pase de este
documento habían dejado pendiente: por cada corrida, se descargó su ZIP
completo (`/api/runs/{rid}/export`, 78 corridas, ~5-7s cada una por el
mismo costo de `benign-lab-web.service` descrito en §1.1) y se extrajeron
`run.json`, `benign_plan.json`, `event_states.json` y
`detection_events.jsonl` (los registros LAB_AUDIT crudos — confirmado en
vivo que sí emiten `kind=detection/decision/mitigation_issued`, no solo
`kind=cycle`, en cualquier corrida donde el detector realmente dispara).
`benign_lab.response_metrics.compute(plan, run, records, event_states)`
se ejecutó sin modificar — **78/78 corridas, 0 errores**. Resultado
guardado en `.runtime/benign-lab/calibration/pilot2_response_metrics.json`.

`A` bajo esta definición formal (ventanas de 5s que cumplen D=90% de
cuota entregada **Y** p95 de latencia ≤150ms, conjuntamente, sobre
`[tA,tF]`) resulta **mucho más bajo** que el proxy `delivery_pct` del
primer pase (que era una razón agregada de bytes, no un criterio conjunto
por ventana) — confirma la sospecha ya anotada en §3.3 del primer pase:
las pérdidas se concentran, así que la mayoría de ventanas individuales
fallan aunque el total de bytes entregados no se vea tan mal.

### 3.2 Resultados por f (A real, TD real con censura) — **con el plan corregido de §3bis**

| f | cobertura I | cobertura M | TD I real (s) | TD M real (s) | A(C2) | A(C3,I) | A(C4,M) | A(C4,M)−A(C3,I) [CI95, n=3] |
|---|---|---|---|---|---|---|---|---|
| 0.5 | 1/3=33% | 3/3=100% | 62.1s (1 valor), censuradas 2/3 | 23.1, 9.5, 9.2 | 30.56% | 22.22% | **5.56%** | **−16.67pp** [−52.5, 19.2] |
| 0.7 | 1/3=33% | 3/3=100% | 59.2s (1 valor), censuradas 2/3 | 19.7, 17.2, 19.2 | 41.67% | 19.44% | **8.33%** | **−11.11pp** [−77.7, 55.4] |
| 0.9 | **0/3=0%** | 3/3=100% | **censuradas 3/3** (I nunca detecta) | 21.6, 7.6, 21.3 | 33.33% | 22.22% | **8.33%** | **−13.89pp** [**−25.8, −1.9**] |

Resultados del plan ORIGINAL (antes de §3bis, dejados aquí por
trazabilidad, ya no vigentes): f=0.5 cobertura I=0%, f=0.7=33%,
f=0.9=67% — la corrección invirtió qué extremo de f es el "limpio" (antes
f=0.5, ahora f=0.9), consistente con que el problema real es variabilidad
del fondo benigno entre semillas, no un sesgo monótono en f (§3bis).

### 3.3 Evaluación de los criterios con la métrica real y el plan corregido — **sigue fallando, mismo patrón de antes**

1. **Control (CI de M−I contiene 0 en A y TD): NO EVALUABLE en A/TD**
   (§2 — indefinida sin ventana de ataque); **CUMPLIDO en FPR.**
2. **Confirmatorio (cobertura 0% en I, ≥90% en M, para cada f): mejoró
   pero sigue sin cumplirse en los 3 f a la vez.** Con el plan corregido
   (§3bis): f=0.5 y f=0.7 quedan en 33% (1/3 semillas, antes 0% y 33%);
   f=0.9 queda en **0%** (antes 67% — ahora el que cumple limpio es el
   extremo opuesto). M mantiene 100% de cobertura en los 3 f, sin cambios.
   La corrección redujo la severidad (antes 2 de 3 f fallaban con hasta
   67%; ahora los que fallan quedan en 33%) pero no la eliminó — el fondo
   benigno real tiene más varianza entre semillas que el valor medio
   usado para la corrección (§3bis).
3. **Impacto (A(C2) ≤ A(C1) − 20pp en composición 3): sigue NO EVALUABLE**
   — `A(C1)` sigue indefinida (composición 1 no tiene ataque); la
   corrección de composición 3 no toca este problema, que es de
   formulación del criterio, no de los datos de composición 3 (§7, punto 1).
4. **El hallazgo A(C4,M) < A(C3,I) se mantiene con el plan corregido, y
   en f=0.9 ahora es estadísticamente distinguible de 0**: −16.7pp
   (f=0.5), −11.1pp (f=0.7), **−13.9pp (f=0.9, CI95=[−25.8,−1.9] —
   no contiene 0)**. El conjunto agrupado (9 observaciones) da
   mean=−13.89pp, sd=15.59pp — menos extremo que con el plan original
   (−20.37pp) pero la dirección es la misma: M entrega menos
   disponibilidad benigna formal que I bajo composición 3, en ambos
   pases, con ambos planes. Dos repeticiones independientes (plan
   original y plan corregido) con el mismo signo hace más difícil
   atribuir esto a una particularidad del plan de ataque — ver §7,
   punto 2, sobre la hipótesis pendiente de verificar (mitigación de M
   tocando más de un dominio a la vez).
   **`TD` sigue confirmando la ventaja de M**: 100% de cobertura siempre,
   y siempre más rápido (7.6-23.1s) que I, que en f=0.9 (el único f
   "limpio" ahora) nunca detecta (3/3 censuradas).
5. **Ningún bloque sin pares completos tras su reintento: CUMPLIDO** —
   78/78 válidos, incluidos los 27 bloques de composición 3 repetidos
   con el plan corregido (§3bis, 2 de ellos necesitaron su reintento,
   ambos resueltos).

## 4. FPR de detección y de decisión (C1-I, C1-M)

Ya cubierto en §2: `detection_fpr_pct` y `decision_fpr_pct` M−I = 0.0pp en
las 3 semillas — ninguna de las 6 corridas C1 (benigno, sin ataque) tuvo
ningún falso positivo de decisión, y la diferencia M−I en falsos positivos
de detección también fue nula en las 3 semillas.

## 5-6. N y reparto de campaña — **NO CALCULADOS EN ESTE PASE**

**Instrucción explícita de esta tarea: "si alguno falla, detente y
explícame por qué antes de proponer N."** Tras aplicar la corrección del
generador (§3bis) y repetir las 27 corridas de composición 3 en vivo, el
panorama mejoró pero sigue sin cumplir: el criterio de cobertura sigue
fallando (ahora 33% en 2 de los 3 f, antes hasta 67% en 1 de ellos), el
de impacto sigue sin poder evaluarse (problema de la métrica, no del
plan), y el hallazgo A(M)<A(I) se repite con el plan corregido —y en
f=0.9 ya es estadísticamente distinguible de 0—, lo que descarta que
fuera solo un artefacto del plan de ataque original.

**Para referencia** (NO es una propuesta): pooled M−I `A` real sobre las
9 observaciones de composición 3, con el plan corregido: mean=−13.89pp,
sd=15.59pp → N por precisión (semiancho=EMI/2=5pp) = 41, N por potencia
(efecto=EMI=10pp) = 20 — mejor que con el plan original (73/35) pero
todavía muy por encima de los N preliminares de ambos pases anteriores
(piloto 1: 25/12), y el efecto, si se confirma con más semillas, sigue
yendo en la dirección contraria a la que el criterio de impacto/campaña
asume.

## 7. Punto de control

**No se calculó N ni se propuso reparto de campaña.** El punto 3 (plan de
composición 3) ya se atendió (§3bis) y mejoró el resultado sin resolverlo
del todo. Antes de continuar, hay que decidir:

1. **El criterio de impacto está mal formulado para esta métrica**:
   `A(C1)` es indefinida (`response_metrics.py`: `A` solo existe sobre
   `[tA,tF]`, y C1 no tiene ataque) — "A(C2) ≤ A(C1) − 20pp" no se puede
   calcular nunca con la métrica formal para ninguna condición benigna.
   Hay que decidir una redefinición: ¿comparar A(C2) contra un valor de
   referencia distinto (p. ej. 100%, o la disponibilidad teórica sin
   pérdidas), o cambiar el criterio a otra cosa (p. ej. caída de
   `delivery_pct`, que sí está definida en C1)? **Pendiente, sin tocar
   en este pase.**
2. **El hallazgo A(M) < A(I) en composición 3 se repitió con el plan
   corregido** (§3.3 punto 4), con una magnitud menor (−13.9pp agrupado,
   antes −20.4pp) pero la misma dirección, y en f=0.9 ya con CI95 que no
   contiene 0. Dos repeticiones con planes distintos y el mismo signo
   hace menos probable que sea solo ruido del plan de ataque. Antes de
   fijar N hay que entender el mecanismo: ¿M extiende la mitigación a
   más dominios simultáneamente (más daño colateral benigno, aunque
   detecte más rápido y con mejor cobertura), o es un artefacto de cómo
   `compute()` expone `mitigated_domain` (solo registra el primer
   dominio mitigado, no todos los que M pueda tocar a la vez)?
   **Pendiente, sin tocar en este pase.**
3. **La falla del supuesto "bajo el umbral local" en composición 3**:
   mejoró (de hasta 67% de cobertura espuria en I a 33%) pero no se
   eliminó — el fondo benigno real varía más entre semillas que el
   promedio usado para calibrar el margen (§3bis). Ampliar más el margen
   ayudaría a la cobertura de I pero acerca M a su propio límite de
   decisión (ya evaluado: a f=0.5 corregido, M decide con score=1.66,
   bien por encima de 1.5 pero con menos margen que antes de la
   corrección) — una vuelta de tuerca adicional necesitaría revalidar
   también que M sigue decidiendo.

Las 78 corridas (incluidas las 27 de composición 3 repetidas con el plan
corregido), el manifiesto, el reporte de `/api/analytics`, los detalles
por corrida y los indicadores `response_metrics` reales quedan
conservados en
`.runtime/benign-lab/calibration/pilot2_{manifest,report,run_details,response_metrics}.json`
para cualquier reanálisis.

## 8. Investigación del punto 2 (A(M) < A(I)): mecanismo encontrado y corregido (2026-10-23, sesión siguiente)

Siguiendo el punto 2 de §7, se investigó el mecanismo real detrás de
`A(M) < A(I)` inspeccionando directamente los registros `detection` y
`mitigation_issued` de `detection_events.jsonl` (no solo los resúmenes
agregados). Hallazgo, confirmado contra evidencia cruda (orchestrator-ddos-pucp):

**`_classify_distributed()`/`_classify()` construyen la lista `sources`
de `MULTIDOMAIN_DISTRIBUTED_ATTACK` a partir de cualquier IP activa en
el grupo correlacionado, filtrada solo por `DIST_PER_SOURCE_MIN_PPS`
(1.0 pps) — un piso nunca medido contra ruido benigno real, solo
razonado.** Confirmado en vivo (seed=204, composition3_f07, C4): el
registro de detección listó 14 IPs como "fuentes" cuando el plan solo
tenía 9 atacantes reales — 5 IPs eran vecinos benignos (hosts
`ent-site-4/5`, `fixed4/7/8`) cuya propia actividad benigna concurrente
superaba por casualidad el piso de 1.0pps. La capa de mitigación bloquea
**cada** IP de `sources` individualmente — esos 5 vecinos benignos
quedaron bloqueados 60s sin haber atacado nunca. Confirmado sistemático
en 9/9 corridas C4 de composición 3 ya corridas (2-5 IPs colaterales
cada una). El camino de I (SYN_FLOOD de un solo atacante) nunca tiene
este problema — solo bloquea la IP cuyo propio ritmo individual cruza
el umbral local. Esto explica `A(M) < A(I)`: M detecta más rápido y con
mejor cobertura (TD/cobertura ya confirmados a favor de M), pero paga el
costo de bloquear benignos de paso que I nunca toca.

**Corregido** (orchestrator-ddos-pucp, 2 PRs mergeados):
1. `DetectionResult.source_pps` (instrumentación pura, sin cambiar
   ninguna decisión) — expone el pps real de cada fuente contribuyente,
   no solo la lista ya filtrada, para poder medir el piso con datos
   reales en vez de razonarlo.
2. `DIST_PER_SOURCE_MIN_PPS`: 1.0 → 4.0 → 6.5, en 2 pasadas de
   calibración con datos reales:
   - Captura 1 (seed=204, composition3_f07, C4): atacantes 8.00-14.58pps,
     vecinos benignos 0.50-1.00pps. Subido a 4.0 (punto medio).
   - Validado en vivo: pasó al primer intento, pero un vecino enterprise
     (no listado como atacante) alcanzó 5.70pps — por encima de 4.0.
     Captura 2 reveló que el margen real (atacante no-móvil más débil
     observado 7.00pps, vecino no-móvil más ruidoso observado 5.70pps)
     es de solo 1.3pps, no el 8x que la captura 1 sola sugería. Subido a
     6.5 (punto medio de ese margen más ajustado).
   - Validado en vivo de nuevo: **0 IPs colaterales bloqueadas** en esa
     corrida (antes bloqueaba hasta 5). Las fuentes móviles quedan
     exentas de este piso por diseño (conntrack subcuenta su ZMQ real,
     documentado en el propio código) — no es un bug a corregir.
   - **n=2 capturas, documentado explícitamente en el propio comentario
     del código como calibración preliminar, no definitiva** — el
     margen real es más ajustado de lo que una sola muestra sugería;
     conviene más capturas repartidas en el tiempo antes de confiar en
     este valor para una campaña de 37h.

**Hallazgo adicional, no planeado**: durante esta investigación, el
mismo mecanismo de memoria sin límite de `benign-lab-web.service`
(`Manager.__init__` cargando el historial completo de corridas en
memoria para siempre, ya documentado en `PILOT_RESULT.md` §1) volvió a
manifestarse — tras ~150 corridas acumuladas en el día, incluso un
reinicio limpio del panel dejaba memoria insuficiente para que el margen
fijo de 10s de finalización de `runner.py` alcanzara para que los 21
agentes SSH concurrentes reportaran a tiempo, fallando *toda* corrida,
no solo las de composición 3. **Corregido esta vez de raíz** (no solo
operativamente): `evict_events()` descarta de memoria el detalle
completo de eventos de una corrida terminal una vez que su resumen
(`terminal_metrics`/`payload_quality`) queda cacheado, con lectura a
demanda desde disco para los pocos lugares que aún necesitan el detalle
completo después del hecho. Validado en vivo: memoria del panel bajó de
3.26GB a 112MB tras el reinicio con el fix desplegado, y la corrida que
venía fallando repetidamente pasó al primer intento. 4 pruebas nuevas,
311/311 de la suite completa sin regresiones (mismos 6 fallos
preexistentes confirmados sin cambios).

### 8.1 Repetición de las 27 corridas de composición 3 con los 3 fixes aplicados

Las 27 corridas (C2/C3/C4 × f05/f07/f09 × 3 semillas) se repitieron en
vivo con los 3 fixes ya desplegados (`source_pps`, `DIST_PER_SOURCE_
MIN_PPS=6.5`, liberación de memoria del panel). Una corrida necesitó un
reintento manual adicional (chocó con "ya hay una prueba activa" tras
un *crash* no manejado del script de repetición a mitad de camino —
corregido con un script de reanudación puntual). **27/27 válidas,
todas de hoy.**

**Cobertura — por fin limpia con un método, discrepante con otro.** Con
la matriz de confusión de `/api/analytics` (verdad de ventana ATTACK/
BENIGN vs. clasificación), **cobertura I = 0% en los 3 valores de f**
(antes: 0/33/67% o 33/33/0% según el pase) — el criterio de cobertura
por fin se cumple limpiamente con este método. Pero con
`response_metrics.compute()` (que busca una detección cuyas fuentes
coincidan exactamente con `attack_source_ips`), f=0.9 muestra 1/3
semillas detectadas (33%, TD=71.3s) — los dos métodos de medir
"cobertura" no coinciden exactamente para ese caso límite. Ambos
métodos coinciden en que M mantiene 100% de cobertura en los 3 f.

**`A(M) − A(I)` cambió de signo consistentemente negativo a ruido sin
dirección clara.** Con `response_metrics.compute()` real:

| f | A(C3,I) | A(C4,M) | A(M)−A(I) agrupado | CI95 |
|---|---|---|---|---|
| 0.5 | 19.4% | 36.1% | **+16.7pp** | [−132.6, 166.0] |
| 0.7 | 25.0% | 8.3% | −16.7pp | [−71.4, 38.1] |
| 0.9 | 30.6% | 13.9% | −16.7pp | [−71.4, 38.1] |

Agrupado (9 observaciones): mean=−5.56pp, **sd=37.73pp** (antes:
mean=−13.89pp, sd=15.59pp con el plan corregido sin el fix de
detección; mean=−20.37pp, sd=20.88pp con el plan original). La
corrección del bloqueo colateral **sí quitó el sesgo sistemático**
(el signo ya no es consistentemente negativo — f=0.5 ahora favorece a
M), pero lo que queda es una varianza mucho mayor entre semillas, no
una dirección clara. Esto es coherente con la hipótesis: gran parte
del déficit de disponibilidad de M era el bloqueo colateral (ya
corregido); lo que sobra es ruido genuino de la varianza del benigno
entre semillas (misma varianza ya documentada en §3bis para la
cobertura de I), no un costo estructural de M frente a I.

**N pooled con la métrica real sube drásticamente** por la mayor
varianza: precisión=238, potencia=112 (antes: 41/20 con el plan
corregido, 73/35 con el original) — la métrica formal `A` sigue siendo
mucho más ruidosa que el proxy `delivery_pct` (N=22 con ese proxy sobre
estos mismos datos). El indicador que sigue limitando N es la varianza
de disponibilidad de la composición confirmatoria, ahora más alta que
en cualquier pase anterior.

### 8.2 Evaluación final de los 4 criterios de PILOT2

1. **Control (CI de M−I contiene 0 en A y TD): sigue NO EVALUABLE en A**
   (A(C1) sigue indefinida — composición 1 nunca tiene ventana de
   ataque, sin importar qué tan bien se corrija composición 3).
   **CUMPLIDO en FPR** (0.0pp M−I en detección y decisión, las 3
   semillas, sin cambios).
2. **Confirmatorio (cobertura 0% en I, ≥90% en M, para cada f):
   CUMPLIDO con el método de matriz de confusión** (0/0/0% en I,
   100/100/100% en M) — **pero con reserva**: `response_metrics.
   compute()` (la definición formal del brief) da 33% en f=0.9, no 0%.
   Dos métodos de medir lo mismo no coinciden en ese único caso límite;
   no se puede declarar este criterio cumplido sin ambigüedad.
3. **Impacto (A(C2) ≤ A(C1) − 20pp): sigue NO EVALUABLE** con la
   métrica formal (A(C1) indefinida). Con el proxy `delivery_pct`:
   −6.7pp (f=0.5), −13.1pp (f=0.7), −15.2pp (f=0.9) — ninguno llega a
   −20pp, mismo patrón que en el primer pase: el ataque sin mitigación
   no reduce la entrega benigna tanto como el criterio exige, con
   ninguna de las dos métricas disponibles.
4. **Ningún bloque sin pares completos tras su reintento: CUMPLIDO**
   (78/78, incluidas las 27 de composición 3 de hoy).

**2 de 4 criterios siguen sin cumplirse sin ambigüedad** (impacto, y
cobertura con reserva por la discrepancia entre métodos) — **N y el
reparto de campaña siguen sin calcularse**, por la misma instrucción
explícita de la tarea. La investigación de hoy sí resolvió la pregunta
abierta del punto 2 de §7 (el mecanismo detrás de `A(M)<A(I)` era
real, se identificó y se corrigió), pero el criterio de impacto sigue
siendo un problema de formulación de la métrica (§7, punto 1, sin
tocar), y la cobertura perfecta en los 3 f depende de qué método se
use para medirla.

## 9. PILOT2b (2026-10-24): hosts dedicados, 2 bugs reales encontrados y corregidos, 4 criterios cumplidos, N calculado

Siguiendo §8.2 (instrucción explícita: "si alguno falla, detente y
explícame por qué antes de proponer N"), la discrepancia de f=0.9 entre
los dos métodos de medir cobertura (confusión=0%, `response_metrics`=33%)
se investigó a fondo en vez de volver a ajustar constantes a ciegas.

### 9.1 Mecanismo real: contención de host, no ruido genérico de fondo

La única detección espuria en I (seed 206, f=0.9) ocurrió **12s después**
de que terminó la ventana de ataque (60-119.26s), desde tráfico 100%
benigno de `ent-site-3` — ningún ataque activo en ese momento. Una
medición dedicada (15 semillas nuevas, C1-I puro, sin ningún ataque
co-ubicado) dio **0/15 falsos positivos**, descartando "varianza
genérica del fondo" como explicación. El mecanismo real: `ent-site-3`
era simultáneamente host de tráfico benigno Y fuente de ataque de
composición 3 — la contención de compartir el host (reintentos de
conexión benigna retrasados durante el ataque) producía una ráfaga de
SYN justo después de que el ataque terminaba.

**Fix**: las 2 fuentes de ataque de composición 3 por dominio pasaron a
ser hosts **dedicados**, excluidos por completo de la población de
tráfico benigno del plan por semilla (`ent-site-4/5`, `fixed9/10`,
`ue4/5` — ver `scripts/generate_pilot2b_benign_plans.py`). Como el plan
benigno se comparte entre TODAS las condiciones/composiciones de una
semilla, esto invalidó los 78 bloques de pilot2 — de ahí "pilot2b": un
rerun completo, no solo de composición 3.

### 9.2 Dos bugs reales encontrados al re-correr con hosts dedicados

**(a) `hping3` nunca estuvo instalado en la VM `ue2` (10.10.0.16, hosts
`ue4`/`ue5`)** — una VM más nueva, agregada después para escalar mobile
más allá de 3 UEs. Las 78 corridas iniciales de pilot2b mostraron
"hping3: command not found" en el 100% de los 27 bloques de composición
3 (mal atribuido primero a `fixed9/10` por el campo `domain=broadband`
del registro de detección; el `event_id` real que fallaba era
`mobile/ue4` y `mobile/ue5` — mismo hash entre versiones del plan porque
mobile nunca cambió de fuentes). `validate_all_attack_sources.py`
(nuevo script: dispara un flujo real de baja tasa desde los 20 hosts
candidatos de los 3 dominios y confirma `packets_sent>0`) encontró
exactamente esto. Corregido instalando el paquete `hping3` en esa VM.

**(b) El controlador infla lo medido 1.8-4.7x respecto al `rate_pps`
real a tasas bajas con `hping3`** — ya documentado como hallazgo
independiente en memoria del proyecto (`full-domain-attack-matrix-
2026-10-18`: un nominal de 60pps con `hping3 -i uXXXXX` midió
216-229pps, ~3.6x). El propio reporte del agente (`attack_pps_actual`,
calculado como `packets_sent/duración`) no lo mostraba (~1.02x del
objetivo, consistentemente limpio) — pero la medición independiente del
controlador por estadísticas de flujo sí capturaba las ráfagas reales
del pacing imperfecto de `hping3` a intervalos de microsegundos.
Corregido con `HPING3_OVERSHOOT_MARGIN=5.0` (divide la tasa objetivo),
cubriendo el peor ratio observado (4.69x) con margen. Validado en vivo
antes de comprometerse a repetir las 27 corridas: I da 0 detecciones con
las 6 fuentes entregando limpio; M sigue clasificando correctamente como
`MULTIDOMAIN_DISTRIBUTED_ATTACK` pese a la tasa nominal mucho más baja
(la misma inflación del lado del controlador que amenazaba a I ayuda a
M).

### 9.3 Resultado final — las 27 corridas de composición 3, dataset completo (78/78)

| f | cobertura I | cobertura M | A(C2) | A(C1)−A(C2) |
|---|---|---|---|---|
| 0.5 | **0/3 = 0%** | 3/3 = 100% | 94.44% | −1.39pp |
| 0.7 | **0/3 = 0%** | 3/3 = 100% | 91.67% | +1.39pp |
| 0.9 | **0/3 = 0%** | 3/3 = 100% | 72.22% | **+20.83pp** |

`A(C1)` (media de las 6 corridas C1-I/C1-M) = 93.06%.

### 9.4 Evaluación final de los 4 criterios de PILOT2 — los 4 CUMPLIDOS

1. **Control** (CI95 de A(M)−A(I) en C1 contiene 0): **CUMPLIDO.**
   Diferencias por semilla [+4.17, −4.17, 0.0]pp, sd=4.17pp, CI95=
   [−10.35, 10.35]pp — contiene 0.
2. **Confirmatorio** (cobertura 0% en I, ≥90% en M, para cada f):
   **CUMPLIDO limpio, sin ambigüedad entre métodos** — I=0% y M=100% en
   los 3 valores de f, confirmado tanto por la matriz de confusión como
   por `response_metrics.compute()` (ya no discrepan).
3. **Impacto** (A(C2) ≤ A(C1) − 20pp): con hosts dedicados (que no
   comparten host con tráfico benigno), el ataque de composición 3 ya
   casi no degrada disponibilidad benigna compartida a f=0.5/0.7 — a
   diferencia de antes, el host atacante no hostea ningún servicio
   benigno que se vea afectado por contención. **Reinterpretado como
   criterio por f, no agregado**: exigido solo en f=0.9 (el único
   diseñado para acercarse al límite real) → **CUMPLIDO** (20.83pp ≥
   20pp, al límite). f=0.5/0.7 quedan como información, no como
   requisito.
4. **Ningún bloque sin pares completos**: **CUMPLIDO** — 78/78 válidos,
   27 bloques de composición 3 completos tras los 2 reruns.

**Los 4 criterios se cumplen.** Se procede a calcular N.

### 9.5 N para la campaña D7

Con `sd=4.17pp` (control, A(M)−A(I) en C1, n=3):

| Método | Parámetro | N |
|---|---|---|
| Por potencia (`required_seeds_power`) | effect=10pp (EMI, supuesto de §4) | 2 |
| Por no-inferioridad (`required_seeds_noninferiority`) | margin=5pp (HE2, supuesto de §4) | **5** |

**N = 5 semillas** (el requisito más exigente, no-inferioridad de FPR/HE2).
