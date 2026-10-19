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

| Archivo | Qué hace |
|---|---|
| `benign_lab/detection_mode_control.py` | `DetectionModeControl.apply('isolated'\|'multidomain')`: SSH al orquestador, candado de lease de baseline, drop-in systemd transitorio sobre `DETECTION_CROSS_DOMAIN_CORRELATION`, restart de `ryu-manager`, verificación contra la línea `DETECTION_MODE=` del log, rollback automático si no coincide. `.read()` lee el valor efectivo actual. Escrito y probado con `tests/test_detection_mode_control.py` (SSH mockeado; nunca se ejecutó contra el laboratorio real). |
| `benign_lab/im_campaign.py` | Funciones puras (sin red): `block_runs(seed, scenario_id)` devuelve las 5 corridas de condición C1-I..C4 de un bloque; `build_schedule(seeds, scenario_ids)` devuelve todos los bloques agrupados por modo de detección para minimizar restarts del controlador; `mode_switches()` cuenta cuántos cambios de modo requeriría un cronograma. |
| `benign_lab/runner.py` | `Manager.start(..., detection_mode=None)`: nuevo parámetro **solo descriptivo** — registra en `run.json` qué modo tenía el controlador antes de arrancar la corrida. **No dispara ningún SSH ni restart**; el cambio de modo es un paso aparte y explícito (`DetectionModeControl.apply()`), exactamente como ya pasa con la recalibración de umbrales (Etapa E del otro documento) — nunca un efecto secundario silencioso de iniciar una corrida. |
| `benign_lab/experimental_analytics.py` | `detection_mode` ahora viaja en `summary()` y en `grouping`/`group_id`, y se agregó a la lista de factores únicos que un par A/B puede verificar (antes solo `pipeline`/`policy`). C3 (I) y C4 (M) del mismo bloque ya no se confunden en el mismo grupo, y su diferencia pareada se reporta como candidato A/B verificado (M−I), igual que ya pasaba con baseline/enabled. |

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
  (el que recorrería `build_schedule()`, llamaría `DetectionModeControl`
  cuando el modo cambia, y lanzaría cada corrida vía `/api/runs`). Es el
  siguiente paso natural una vez exista `detection_mode_control.py` en el
  entorno correcto; `im_campaign.py` ya deja la parte pura (qué y en qué
  orden) lista y probada para que ese orquestador sea un envoltorio fino.
- **No se wireó un endpoint de API ni panel** para `DetectionModeControl`
  (el panel de `threshold_control.py` sí tiene uno) — se dejó fuera para
  no ampliar el alcance sin que el módulo que envuelve exista todavía.

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
