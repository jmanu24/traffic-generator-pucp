# Diseño I vs. M (comparación de tratamientos del controlador)

Este documento describe un diseño experimental **distinto y más amplio**
que `THESIS_VALIDATION_EXECUTION_PLAN.md` (que ya corre su propia campaña
con el detector siempre en modo multidominio). Aquí se comparan **dos
tratamientos del mismo controlador**:

- **I** (protección independiente): `DETECTION_CROSS_DOMAIN_CORRELATION=false`
- **M** (coordinación multidominio): `DETECTION_CROSS_DOMAIN_CORRELATION=true`

El indicador principal es **disponibilidad durante el ataque**
(`delivery_pct` en `experimental_analytics.py`, agregado dominio×ventana).
Las hipótesis son diferencias **M − I emparejadas por bloque**, donde
**bloque = semilla × escenario**.

## 1. Qué ya existía (confirmado leyendo el código, no asumido)

- `DETECTION_CROSS_DOMAIN_CORRELATION` ya existe en
  `orchestrator-ddos-pucp/config/settings.py` y es, por diseño documentado
  ahí mismo, **ortogonal** a la lógica de detección/decisión/mitigación:
  solo cambia si `correlation/correlator.py` agrupa telemetría de varios
  dominios antes de que `detection/engine.py` la vea. No se modificó nada
  de esa lógica para este diseño.
- El controlador ya emite al iniciar una línea de log parseable:
  `[controller] STARTUP: DETECTION_MODE=isolated|multidomain`
  (`controller/ryu_controller_2.py:206-207`), suficiente para verificar
  desde afuera qué modo quedó activo tras un restart.
- `benign_lab/threshold_control.py` ya tiene el patrón completo para
  cambiar una configuración del controlador real por SSH con candado
  (`/run/benign-baseline/lease.json`), respaldo/rollback y restart de
  `ryu-manager` — se reutilizó esa misma forma, no se inventó una nueva.
- `benign_lab/experimental_analytics.py` ya soporta comparaciones
  genéricas de grupos pareadas por semilla y por `plan_hash` (ver
  `report()`), y ya distinguía single-factor A/B verificado para
  `pipeline`/`policy`. No existía ningún concepto de modo de detección.
- Un harness *distinto y más antiguo*
  (`isp-ddos-ryu/analysis/run_vm_lab_trials.py`, `Lab.set_detection_mode`)
  ya hace exactamente este mismo toggle, pero para medir **detección**
  (TrialResult: detectado/no detectado), no **disponibilidad pareada por
  bloque** como pide este diseño — se usó como referencia de que el
  mecanismo (drop-in systemd transitorio + restart + verificación por
  log) ya está validado en producción, no se copió su código.

## 2. Qué se agregó (esta rama, `im-comparison-design`)

Todo instrumentación/orquestación — **ninguna línea de detección, decisión
o mitigación del controlador fue tocada**.

**Actualización (D1/D5/D6, misma rama):** lo que en la primera versión de
este documento era *solo descriptivo* (`detection_mode` se registraba pero
no se aplicaba) ahora **sí se aplica y se verifica** automáticamente al
arrancar una corrida — ver §7. También se integró `attack_runner` dentro
del ciclo de vida de una corrida (D5, §8) y se agregó el módulo de
indicadores de respuesta (D6, §9).

| Archivo | Qué hace |
|---|---|
| `benign_lab/detection_mode_control.py` | `DetectionModeControl.apply('isolated'\|'multidomain')`: SSH al orquestador, candado de lease de baseline, drop-in systemd transitorio sobre `DETECTION_CROSS_DOMAIN_CORRELATION`, restart de `ryu-manager`, verificación contra la línea `DETECTION_MODE=` del log, rollback automático si no coincide. `.read()` lee el valor efectivo actual. Escrito y probado con `tests/test_detection_mode_control.py` (SSH mockeado; nunca se ejecutó contra el laboratorio real). |
| `benign_lab/im_campaign.py` | Funciones puras (sin red): `block_runs(seed, scenario_id)` devuelve las 5 corridas de condición C1-I..C4 de un bloque; `build_schedule(seeds, scenario_ids)` devuelve todos los bloques agrupados por modo de detección para minimizar restarts del controlador; `mode_switches()` cuenta cuántos cambios de modo requeriría un cronograma. |
| `benign_lab/runner.py` | `Manager.start(..., detection_mode=None)`: obligatorio cuando `pipeline=enabled` y el laboratorio está configurado de verdad (`cfg['baseline_control']`). `Manager.execute()` llama `apply_detection_mode()` **antes de cualquier tráfico** — ver §7. |
| `benign_lab/experimental_analytics.py` | `detection_mode` (y ahora también `attack_plan_hash`) viajan en `summary()` y en `grouping`/`group_id`, y se agregaron a la lista de factores únicos que un par A/B puede verificar (antes solo `pipeline`/`policy`). C3 (I) y C4 (M) del mismo bloque ya no se confunden en el mismo grupo, y su diferencia pareada se reporta como candidato A/B verificado (M−I), igual que ya pasaba con baseline/enabled. |

## 3. Matriz de condiciones

Un **bloque** = una semilla × un escenario (mismo plan benigno + mismo plan
de ataque, si lo hay). Cada bloque corre las 5 condiciones:

| Condición | Tráfico | `pipeline` | `detection_mode` | Qué mide |
|---|---|---|---|---|
| **C1-I** | benigno solo | `enabled` | `isolated` | falsos positivos / disponibilidad benigna bajo I |
| **C1-M** | benigno solo | `enabled` | `multidomain` | falsos positivos / disponibilidad benigna bajo M |
| **C2** | benigno + ataque | `baseline` (pipeline suspendido) | — (irrelevante) | referencia sin mitigación |
| **C3** | benigno + ataque | `enabled` | `isolated` | tratamiento I |
| **C4** | benigno + ataque | `enabled` | `multidomain` | tratamiento M |

**Comparación principal: C4 − C3 (M − I) durante el ataque**, por bloque,
en `delivery_pct`. **Comparación secundaria: C1-M − C1-I (M − I) en
benigno**, la contraparte de tasa de falsos positivos/disponibilidad sin
ataque. C2 es la referencia de "qué tan mal estaría sin ningún tratamiento"
— no se empareja con C3/C4 como A/B de un solo factor porque difiere en
`pipeline` **y** no tiene `detection_mode` aplicable a la vez.

`experimental_analytics.report()` ya construye estos pares automáticamente
siempre que las corridas comparten `plan_hash`/`execution_hash` (mismo
plan materializado) y difieren en exactamente un factor reconocido
(`pipeline`, `policy` o, ahora, `detection_mode`); el `delta` siempre se
reporta como comparación−referencia, y para `detection_mode` el código
ordena explícitamente para que se lea M−I (nunca I−M).

## 4. Orden de ejecución y por qué

`im_campaign.build_schedule(seeds, scenario_ids)` agrupa todas las
corridas por `detection_mode` (C2 primero —modo irrelevante—, luego todo
I, luego todo M) en vez de ir bloque por bloque. Con N semillas × E
escenarios, ir condición-por-condición dentro de cada bloque exigiría
hasta 2 restarts de `ryu-manager` por bloque (I→M→I al pasar al siguiente
bloque); agrupar por modo lo reduce a **un solo restart en toda la
campaña** (`mode_switches()==1`, probado en
`tests/test_im_campaign.py::test_schedule_minimizes_controller_mode_switches`
con 11 semillas × 13 escenarios = 143 bloques). Un restart de
`ryu-manager` es una interrupción real del plano de control del
laboratorio productivo — minimizarlos no es una optimización cosmética.

## 5. Lo que falta y por qué no se hizo en esta sesión

- **No se tocó el laboratorio real.** Ninguna corrida C1-C4, ningún
  restart de `ryu-manager`, ningún ataque — todo lo de esta rama es código
  y pruebas unitarias contra datos simulados/sintéticos.
- **No se escribió un orquestador de campaña ejecutable end-to-end**
  (el que recorrería `build_schedule()` y lanzaría cada corrida vía
  `/api/runs`, incluyendo el cambio de modo cuando corresponda). Es el
  siguiente paso natural; `im_campaign.py` ya deja la parte pura (qué y en
  qué orden) lista y probada para que ese orquestador sea un envoltorio
  fino, y ahora `/api/runs` ya acepta `detection_mode`/`attack_plan_hash`
  directamente (§7-§8), así que el orquestador solo necesita invocar la
  API, no reimplementar la lógica.

## 6. Supuestos

- El N de semillas y el repertorio de escenarios de este diseño son
  independientes de los de `THESIS_VALIDATION_EXECUTION_PLAN.md` (N=11,
  13 escenarios) — se puede reusar esa misma generación de planes
  (`sample_size.py`, `attack_planner.py`), pero es una decisión aparte
  del usuario, no asumida aquí.
- Se asume que, igual que con los umbrales (`threshold_control.py`), un
  cambio de `detection_mode` requiere que no haya un lease de baseline
  activo ni un experimento en curso — mismo candado, mismo motivo
  (evitar una carrera entre dos cambios de configuración del controlador
  real).
- Se asume que un restart de `ryu-manager` (≤60s de indisponibilidad del
  plano de control, no del plano de datos ya instalado) es aceptable
  fuera de una ventana de medición activa — igual que ya lo asume
  `threshold_control.py` para la recalibración de umbrales.

## 7. D1 — aplicación y verificación doble del modo de detección

`Manager.start()` ahora **exige** `detection_mode` cuando `mode=lab`,
`pipeline=enabled` **y** el laboratorio está configurado de verdad
(`cfg['baseline_control']` presente) — una corrida local sin esa
configuración (usada por varias pruebas existentes para ejercitar solo el
tráfico) sigue sin necesitarlo, igual que antes.

Antes de que `Manager.execute()` arranque cualquier agente o tráfico
(incluido el preflight de `BaselineGuard`), llama
`apply_detection_mode(rid, cfg, detection_mode)`:

1. **Primera evidencia**: `DetectionModeControl.apply(mode)` (ya descrito
   en §2) — compara contra la línea `STARTUP: DETECTION_MODE=` del log
   del controlador, con rollback automático si no coincide.
2. **Segunda evidencia, independiente**: `verify_detection_mode_in_audit()`
   lee el *stream* persistente de LAB_AUDIT (`Manager.audit`, el mismo
   `DetectionAuditMonitor` que ya alimenta `detection_events.jsonl`) y
   busca el primer registro `kind=cycle` emitido **después** del restart;
   compara su `thresholds.values.DETECTION_CROSS_DOMAIN_CORRELATION`
   contra lo pedido.

Si cualquiera de las dos evidencias falta o no coincide, la corrida falla
en preparación — nunca llega a lanzar tráfico. Esto es exactamente el caso
de prueba que pedía el prompt ("una ejecución en modo I que no puede
producir un registro con modo M"): `tests/test_im_integration.py::
test_isolated_request_cannot_be_verified_against_a_multidomain_audit_record`
y `test_full_run_fails_in_preparation_on_detection_mode_mismatch`.

`Manager.audit` es `None` por defecto; `api.py` lo asigna después de
construir tanto `Manager` como `DetectionAuditMonitor`. Si el colector de
auditoría no está habilitado (`detection_audit.enabled=false`), la
verificación es imposible por diseño y la corrida falla con un mensaje
explícito — nunca se asume "sin evidencia, está bien".

`RunRequest`/`ScenarioSeriesRequest` exponen esto en la API pública como
`detection_mode: "I"|"M"` (la ortografía de las condiciones de la tesis),
traducido a `isolated`/`multidomain` justo antes de llamar
`Manager.start()`. `/api/jobs` y `/api/scenario-series` lo heredan sin
cambios adicionales: `ExperimentJobs` ya persiste y relanza el `dict`
completo de la solicitud original.

## 8. D5 — `attack_runner` integrado en la ejecución

Una corrida `B0+attack` en modo `lab` ahora puede recibir un plan de
ataque completo (`attack_plan_hash` en `/api/runs`) en vez de depender
de que el operador lance `hping3`/`attack_runner` por fuera y marque la
ventana a mano (`POST /api/runs/{rid}/attack`, que sigue existiendo como
respaldo — ver más abajo).

- `Manager.start()` deriva `attack_windows` automáticamente de los
  eventos del plan de ataque (uno por evento), y guarda el plan como
  `attack_plan.json` en la carpeta de la corrida — misma política de
  nunca borrar evidencia que `benign_plan.json`.
- `Manager.execute()` lanza `run_attack()` en una tarea concurrente,
  **sincronizada al instante exacto en que `real()` calcula el inicio del
  plan benigno** (`on_start`, un callback de una sola vez, nunca
  *polling*) — el `start_lead_s` que recibe `attack_runner` se calcula
  contra ESE mismo instante, no contra el de `cfg['start_lead_s']`.
- Al terminar, `record_attack_evidence()` marca la ventana ATTACK
  **desde la evidencia real de `attack_runner`** (`packets_sent>0`,
  `actual_start_s`/`actual_end_s` por evento) — nunca desde el horario
  planeado. Si ningún evento envió tráfico, no se marca ninguna ventana
  (la verdad de referencia queda `UNKNOWN`, nunca se promueve lo
  planeado a observado).
- `ground_truth.windows()` ahora reporta `annotation_source` por entrada
  (`attack_runner` | `operator_external`), no un valor único inferido de
  "si hubo algo observado". `Manager.annotate()` (la marca manual) sigue
  existiendo intacta como respaldo, etiquetada explícitamente.
- `scenario_confusion.window_confusion()`: la elegibilidad de una ventana
  ATTACK **ya no exige** que la IP atacante declarada aparezca en
  `observed_sources` del detector — eso haría que la verdad de referencia
  dependiera de lo que el propio detector observó. La cobertura de
  telemetría de todos los dominios (`covered`) sigue exigiéndose igual
  para toda ventana, ATTACK o BENIGN. La visibilidad de la IP atacante se
  reporta aparte, sin afectar la clasificación, como
  `attacker_observed_by_detector` (ventanas/observadas/tasa).
- `experimental_analytics.py`: una corrida cuya única evidencia de ataque
  sea `operator_external` se excluye del análisis confirmatorio
  (`manual_attack_annotation`, sin borrar nada — sigue en el catálogo);
  una confirmada por `attack_runner` no se excluye por esto.
- `attack_plan_hash` ahora es parte del emparejamiento C3/C4 en
  `experimental_analytics.py` (§2) — dos corridas con distinto plan de
  ataque nunca se confunden como el mismo bloque aunque compartan semilla
  y plan benigno.

## 9. D6 — `benign_lab/response_metrics.py`

Módulo nuevo, de solo cómputo (no colecta nada, no toca el laboratorio).
Ver el docstring del módulo para las definiciones completas de
`tA,tF,tD,tD0,tO,tI,tE,TD,TO,TI,TM`, la ventana de servicio (5 s: entrega
≥D% y latencia p95 ≤L ms) y la disponibilidad `A`/recuperación
(`tS`,`TR`). `coverage()` da proporciones cruzadas entre corridas
(detectado/mitigado/recuperado); `summarize()` empareja M−I por bloque
reusando `experimental_analytics.seed_statistics`, con una sustitución de
media restringida (documentada, no un estimador de supervivencia
completo) para los tiempos censurados.

**Dos decisiones quedaron deliberadamente abiertas, no resueltas en
silencio:**

- **El punto de medición independiente para `tE`** (`rate_series`): el
  módulo recibe la serie `{dominio: [(timestamp, pps), ...]}` ya
  extraída por quien lo llame — no asume ni implementa de dónde viene.
  La propuesta (pendiente de tu confirmación) es:
  - **enterprise/mobile/broadband**: contador de paquetes/bytes de
    `ovs-ofctl dump-flows`/`dump-ports` en `pe`, en el puerto/flujo más
    cercano a la víctima — aguas abajo de donde se instalan las reglas
    de bloqueo, para que un bloqueo exitoso sea visible como una caída
    real de tasa en ese punto (medir en la fuente nunca mostraría nada,
    la fuente sigue enviando al mismo ritmo configurado). El mecanismo de
    acceso ya existe: `BaselineGuard.enter()` ya hace
    `ovs-ofctl -O OpenFlow13 dump-flows br-ent` contra `pe`.
  - **peering**: el contador de la interfaz externa de `br`
    (`PEERING_DIST_BR_EXTERNAL_IFACE`, lo que ya husmea `softflowd` para
    la telemetría de ese dominio) — mismo punto físico que ya alimenta al
    controlador, pero leído directamente por el generador, independiente
    del cómputo de pps del detector.
  - Ninguno de estos está todavía conectado a `response_metrics.py`;
    conectar uno requiere decidir primero si es aceptable, antes de
    escribir el *collector* correspondiente.
- **`L` (umbral de latencia de la ventana de servicio)**: el prompt lo
  dejó como `L («ms»)`, sin número. El valor por defecto en el código es
  **150 ms**, elegido porque el RTT medido de `mobile` ya es ~100-110 ms
  (`docs/THESIS_VALIDATION_EXECUTION_PLAN.md`, Etapa A) — cualquier `L`
  menor haría que `mobile` fallara por latencia aun sin ataque. Es una
  suposición razonada, no una medición; está marcado como provisional en
  `response_metrics.DEFAULTS` y en su docstring.

No se wireó ningún endpoint de API para este módulo — es, por ahora, una
librería de análisis como `detection_evaluation.py`, consistente con "no
generes planes nuevos ni calibres umbrales" del punto de control.

- El N de semillas y el repertorio de escenarios de este diseño son
  independientes de los de `THESIS_VALIDATION_EXECUTION_PLAN.md` (N=11,
  13 escenarios) — se puede reusar esa misma generación de planes
  (`sample_size.py`, `attack_planner.py`), pero es una decisión aparte
  del usuario, no asumida aquí.
- Se asume que, igual que con los umbrales (`threshold_control.py`), un
  cambio de `detection_mode` requiere que no haya un lease de baseline
  activo ni un experimento en curso — mismo candado, mismo motivo
  (evitar una carrera entre dos cambios de configuración del controlador
  real).
- Se asume que un restart de `ryu-manager` (≤60s de indisponibilidad del
  plano de control, no del plano de datos ya instalado) es aceptable
  fuera de una ventana de medición activa — igual que ya lo asume
  `threshold_control.py` para la recalibración de umbrales.
