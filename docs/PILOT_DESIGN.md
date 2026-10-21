# D7 — piloto I vs. M (semillas 201-203)

Requiere los prompts 1-3 ya terminados: `docs/ATTACK_PLAN_REGENERATION.md`
(3 composiciones, 6 planes en `data/attack_plans_manifest.json`),
`docs/THRESHOLD_CALIBRATION_RESULT.md` (umbrales recalibrados y ya
aplicados al controlador real, `docs/THRESHOLD_CONTROL_PATH_FIX.md`) y el
diseño I/M (`docs/IM_COMPARISON_DESIGN.md`, condiciones C1-I/C1-M/C2/C3/C4,
D1 aplicación+verificación de modo, D5 `attack_runner` integrado, D6
indicadores de respuesta en `benign_lab/response_metrics.py`).

## 1. Qué se agregó esta rama

Todo instrumentación/orquestación — ninguna línea de detección, decisión
ni mitigación del controlador fue tocada.

| Archivo | Qué hace |
|---|---|
| `benign_lab/pilot_schedule.py` | Puro, sin red: `seed_runs(seed, manifest)` da las 2+3×6=20 corridas de un bloque de semilla (C1-I/C1-M una sola vez; C2/C3/C4 por cada una de las 6 composiciones del manifiesto); `build_pilot_schedule(manifest, seeds, rng_seed)` da el cronograma completo, semilla por semilla en el orden dado (201→202→203, nunca entremezcladas), con las 20 corridas de cada semilla en un orden aleatorio reproducible (`random.Random(rng_seed).shuffle`, `rng_seed` por defecto `PILOT_RNG_SEED=20261020`, documentado y fijo); `mode_switches()`/`estimate_duration_s()` calculan el calendario. |
| `benign_lab/runner.py` | `Manager.apply_detection_mode()` ahora llama `DetectionModeControl.read()` primero y **omite** `.apply()` (y por tanto el reinicio de `ryu-manager` que `.apply()` siempre hace) cuando el controlador ya reporta el modo pedido — necesario para que "reinicio solo cuando cambia el modo" sea real y no una coincidencia: antes de este cambio, **toda** corrida con `detection_mode` (C1-I, C1-M, C3, C4 — 48 de las 60 del piloto) reiniciaba el controlador real sin condición alguna, incluso corridas consecutivas con el mismo modo. La segunda evidencia (auditoría LAB_AUDIT) se sigue pidiendo siempre, con o sin reinicio. |
| `benign_lab/sample_size.py` | `required_seeds_power(sd, effect, power=0.80, alpha=0.05)`: N por potencia para una prueba t emparejada bilateral (aproximación normal a la t no central, documentada — no hay `scipy` en este entorno para el cálculo exacto). `required_seeds_noninferiority(sd, margin, power=0.80, alpha=0.05)`: igual pero unilateral (para HE2, margen de no inferioridad). |
| `scripts/run_pilot.py` | Ejecutor contra el laboratorio real: recorre `build_pilot_schedule()` y llama `/api/runs` del panel ya corriendo (mismo patrón que `scripts/run_calibration_seeds.py`, un solo `Manager` tocando el laboratorio). **No se ejecutó todavía** —`PLAN_HASHES` de las 3 semillas benignas (201-203) está vacío a propósito; generarlos y confirmarlos es el primer paso real, no algo que este script asuma. |

Pruebas nuevas: `tests/test_pilot_schedule.py` (11), `tests/test_sample_size.py`
(+7, cubriendo `required_seeds_power`/`required_seeds_noninferiority`),
`tests/test_im_integration.py` (+2, el salto/no-salto del reinicio;
los 6 fakes de `DetectionModeControl` existentes se actualizaron con un
`.read()` para no cambiar su comportamiento ya probado).

## 2. Diseño del piloto

**Bloque = semilla × escenario.** En cada una de las 3 semillas benignas
(201, 202, 203 — disjuntas de calibración 101-110 y de la campaña):

- **C1-I, C1-M** (una sola vez por semilla, sin dimensión de escenario —
  el tráfico benigno no depende de qué plan de ataque exista): B0,
  `pipeline=enabled`, `detection_mode=isolated`/`multidomain`.
- **C2, C3, C4** (una vez por cada una de las 6 composiciones del
  manifiesto): B0+attack; C2 `pipeline=baseline` (sin mitigación,
  referencia); C3 `detection_mode=isolated`; C4 `detection_mode=multidomain`.

20 corridas por semilla × 3 semillas = **60 corridas**.

Orden: semillas en secuencia (201 completa, luego 202, luego 203); dentro
de cada semilla, las 20 corridas en un orden aleatorio reproducible (RNG
sembrado con `PILOT_RNG_SEED=20261020`, un solo `random.Random` consumido
semilla tras semilla). 60 s de pausa entre toda corrida consecutiva.
Reinicio de `ryu-manager` solo cuando el modo efectivamente cambia entre
dos corridas consecutivas que lo usan (ver §1, `runner.py`).

## 3. Calendario estimado — PUNTO DE CONTROL, esperando confirmación

Calculado por `pilot_schedule.estimate_duration_s()` sobre el cronograma
real (`build_pilot_schedule()` con la semilla de RNG por defecto):

| Componente | Cantidad | Duración |
|---|---|---|
| Corridas | 60 (20/semilla × 3) | 60 × 180 s = 10 800 s |
| Pausas entre corridas | 59 | 59 × 60 s = 3 540 s |
| Reinicios de `ryu-manager` | 27 (incluye 1 por el modo inicial desconocido) | 27 × 60 s = 1 620 s |
| **Total estimado** | | **15 960 s ≈ 4 h 26 min** |

(180 s es la duración de cada plan benigno/de ataque usado — `data/plans`
y `data/attack_plans` de este diseño, ambos a 180 s; 60 s por reinicio es
el propio tope de espera de `DetectionModeControl.apply()`.) El número de
reinicios (27 de 48 corridas con `detection_mode`) depende del orden
aleatorio exacto que produce `PILOT_RNG_SEED` — es menor que 48 gracias a
rachas fortuitas del mismo modo consecutivo, no a ninguna optimización
deliberada del orden (a diferencia de `im_campaign.build_schedule()`, que
sí agrupa por modo a propósito; este piloto usa el orden que pide el
propio brief, aleatorio dentro de cada semilla).

**No se ha tocado el laboratorio real para este piloto.**

**Paso 1 completado** (puro, local, sin tocar el laboratorio):
`scripts/generate_pilot_benign_plans.py` generó los 3 planes benignos
(semillas 201-203, 180 s, mismas capacidades de
`config/lab.connected.yaml` que usó la calibración) —
`data/pilot_benign_plans_manifest.json` tiene el registro completo.
`PLAN_HASHES` en `scripts/run_pilot.py` ya está lleno:

| Semilla | `plan_hash` |
|---|---|
| 201 | `5c54495dec246a16d3f5a6ab3e4f46c337ce35f10fdee8f420be28bb6e9e0d80` |
| 202 | `5fd659158e42df8495033d6033f552a55f8f9dd814b8458547580630ddfb76eb` |
| 203 | `c974d7454f21a33953a92b2e10d392ed3783905c837cf6c03dfc29639113aceb` |

Antes de ejecutar `scripts/run_pilot.py` contra el laboratorio real falta,
y requiere tu confirmación aparte en el momento de hacerlo:

1. Confirmar que el panel (`http://192.168.18.154:8780`) está arriba y
   que ningún otro experimento está activo (`Manager.start()` ya rechaza
   corridas concurrentes, pero vale confirmarlo antes de lanzar ~4.5 h de
   corridas desatendidas).
2. Confirmar el modo efectivo actual del controlador antes de empezar
   (afecta solo el primer reinicio, no el resultado).

## 4. Análisis — qué falta y qué supuestos quedan abiertos

El análisis de validez/indicadores/N (§ANÁLISIS del brief) se calcula
**después** de correr el piloto, sobre datos reales — no se puede
anticipar sin ellos. Lo que sí queda resuelto, listo para ese momento:

- **Validez**: `response_metrics.compute()`/`coverage()` y
  `detection_evaluation.evaluate()` ya distinguen ejecuciones válidas por
  cada criterio pedido (identidad del plan vía `plan_hash`, ataque
  confirmado por `attack_runner` vía `annotation_source`, cobertura de
  telemetría vía `covered`); sincronización de relojes y recursos se leen
  de `clock_sync.py`/`host_monitor.py`/`vm_resource_monitor` ya existentes.
- **Indicadores por condición/composición**: `response_metrics.summarize()`
  ya empareja M−I por bloque; falta solo invocarlo sobre los runs reales.
- **N por precisión**: `sample_size.required_seeds()` (ya existía).
- **N por potencia**: `sample_size.required_seeds_power()` (nuevo, §1) —
  necesita `effect` = «EMI» (el brief deja ese valor entre comillas
  angulares, sin número). **Supuesto tomado**: EMI = 10 puntos
  porcentuales de `availability_pct`, el mismo orden de magnitud que la
  precisión ±10% relativa ya usada para throughput en
  `THESIS_VALIDATION_EXECUTION_PLAN.md` — a confirmar o ajustar una vez
  que el piloto dé una `sd` real con la que recalcular.
- **FPR / HE2 (no inferioridad)**: `sample_size.required_seeds_noninferiority()`
  (nuevo, §1) — necesita `margin` = «margen p.p.» del brief, también sin
  número. **Supuesto tomado**: margin = 5 puntos porcentuales de FPR,
  la mitad del EMI de disponibilidad (razonado, no medido) — mismo
  estado provisional que el `L=150ms` ya asumido en
  `response_metrics.DEFAULTS`.
- **Reparto D7**: depende del N resultante del piloto y de un presupuesto
  de horas que el brief deja como «horas» sin número — no se puede
  calcular todavía.

Ninguno de estos pendientes requiere tocar el laboratorio real antes del
piloto; se resuelven con el mismo código ya escrito y probado en cuanto
existan los 60 runs.

## 5. Supuestos

- `PILOT_RNG_SEED=20261020` es arbitrario — cualquier entero fijo serviría;
  se documentó aquí y en el módulo para que el orden sea reproducible, no
  porque el valor en sí tenga significado.
- 180 s por corrida (duración de cada plan benigno/de ataque) se toma de
  los planes ya generados — no se generó ningún plan nuevo de distinta
  duración para el piloto.
- El reinicio de `ryu-manager` (≤60 s de indisponibilidad del plano de
  control) se asume aceptable fuera de una ventana de medición activa,
  igual que ya lo asumía `docs/IM_COMPARISON_DESIGN.md` §6 para el mismo
  mecanismo.
- EMI=10pp y margin=5pp (§4) son supuestos razonados, no medidos — el
  piloto mismo es la entrada para reemplazarlos por una decisión informada
  antes de la campaña.
