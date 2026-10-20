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

## 2. Hallazgo bloqueante: la agrupación automática de `experimental_analytics.py` no empareja casi ninguna semilla

`POST /api/analytics/report` sobre las 60 corridas produjo **38 grupos**
y solo **5 `group_comparisons`** — y los 5 son pares dentro de la
**misma semilla (201)**; ningún par cruzó semillas. Esto habría hecho
que el reporte automático de la tesis (la vía que
`docs/IM_COMPARISON_DESIGN.md` da por sentada) reportara casi todo como
"no comparable" para cualquier campaña con N>1 semilla real.

**Causa, aislada comparando el campo `grouping` de dos corridas que
deberían haber emparejado** (`seed=201` vs `seed=202`, mismo
`plan_hash`/`execution_hash`/`attack_plan_hash`/`detection_mode`): el
único campo que difiere es `policy` — la lista ordenada de hashes de
`threshold_snapshots` que `detection_evaluation.evaluate()` recoge de
los ciclos `LAB_AUDIT` dentro de la ventana de la corrida. Una corrida
vio **un solo** hash de política durante toda su ventana; la otra vio
**dos** (uno de ellos coincide con el de la primera). Es decir: durante
al menos una corrida, el controlador reportó dos snapshots de
configuración distintos dentro de la misma ventana de 180s — ya sea un
ciclo residual justo después de un reinicio de `ryu-manager` (el mismo
patrón de "ciclo obsoleto" ya corregido una vez para
`apply_detection_mode`'s propia verificación, pero aquí dentro de
`detection_evaluation.evaluate()`, un camino de código distinto que
nunca se tocó), o un reinicio genuino ocurriendo más cerca del inicio
de la corrida de lo esperado.

**No se investigó más a fondo ni se corrigió en esta sesión** — toca
`detection_evaluation.py`/`experiment_audit.py` (posiblemente
`orchestrator-ddos-pucp`), y el punto de control original pedía
reportar el piloto, no iterar sobre él. **Se señala aquí explícitamente
como el problema más importante que debe resolverse antes de la
campaña**: sin esto, cada comparación M-I tendría que emparejarse a
mano (como se hizo para este informe, ver §3) en vez de confiar en
`/api/analytics/report`.

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
presupuesto disponible; (c) el hallazgo de §2 debe resolverse antes de
que cualquier N calculado automáticamente sea confiable.

## 7. Punto de control

**No se inició la campaña.** Antes de hacerlo, en orden de prioridad:

1. Investigar y corregir el hallazgo de §2 (agrupación `policy`
   inestable en `experimental_analytics.py`/`detection_evaluation.py`).
2. Confirmar el presupuesto de horas disponible y el valor de EMI/margen
   (§4 usó supuestos razonados, no decisiones tuyas).
3. Decidir si repetir el piloto (con más pares por composición) antes de
   fijar N, dado que n=2 es una base muy débil.
4. Investigar la causa de los 8 fallos por reloj/timeout (§1) antes de
   comprometerse a sesiones de campaña de varias horas seguidas.
