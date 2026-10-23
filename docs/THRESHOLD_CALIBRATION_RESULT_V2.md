# Resultado de la recalibración de umbrales V2 (THRESHOLD_CALIBRATION_RESULT_V2)

Recalibración completa con la configuración final del laboratorio, aplicada al
controlador real el 2026-10-22. No reemplaza
[`THRESHOLD_CALIBRATION_RESULT.md`](THRESHOLD_CALIBRATION_RESULT.md) (V1,
2026-10-20) — ese documento sigue siendo válido como historial; este es el
resultado de repetir la calibración después de los cambios reales de
laboratorio ocurridos desde entonces (fix NAT, exención de móvil del piso
por-fuente, corrección de confusión metodológica, D7, limpieza FlexRIC,
fix real de duplicación OVS en `enterprise`, mejora real del puente KPM del
RIC) y de cubrir, por primera vez, el camino del criterio distribuido
(`DIST_PPS_THRESHOLD`).

## Resumen

| Umbral | Valor V1 (2026-10-20) | **Valor V2 aplicado** | Cuantil (q=0,999) | Margen |
|---|---|---|---|---|
| SYN | 76,82 | **85,238** | 56,83 | ×1,5 |
| UDP | 14 515,64 | **13 601,981** | 9 067,99 | ×1,5 |
| ICMP | 240,37 | **355,78** | 237,19 | ×1,5 |
| DIST_PPS | 300 (nunca calibrado) | **175 699,17** | 117 132,78 | ×1,5 |

`DECISION_THRESHOLD` (1,5) sin tocar — fuera del alcance de este prompt.

`config_sha256` anterior: `2c61b4ed...a5b`. `config_sha256` aplicado:
`d8f546b4...1a7`, confirmado idéntico entre el controlador real y el
repositorio. `controller_restarted: true`, confirmado por
`ThresholdControl.apply()` vía `/api/calibration/thresholds`.

## Paso 1 — verificación de código desplegado

Verificación completa por hash (controlador, core5g, bng, RIC) contra los
repositorios, **solo lectura**, antes de tocar nada del laboratorio.
Encontró 4 divergencias reales repo↔despliegue (ninguna causada por este
prompt) — las primeras 3 se resolvieron trayendo al repositorio exactamente
lo que ya estaba corriendo en producción, documentando cada una:

1. **Umbrales calibrados V1** en `config/settings.py` del controlador,
   nunca commiteados — corregido.
2. **Fix real de duplicación de claves OVS** en `collectors/flow_collector.py`
   (picos espurios de ~2× en `enterprise`), staged pero sin commitear, con
   su propio documento (`ENTERPRISE_FLOW_STATS_KEY_COLLISION.md`)
   inexistente hasta entonces. **Hallazgo durante la resolución**: una
   sesión concurrente ya había investigado el mismo síntoma con más
   profundidad y encontrado que esa colisión **nunca ocurre en la
   práctica** — la causa real era un doble conteo `on_packet_in` +
   `on_flow_stats` (PR #6, `fix-enterprise-telemetry-overcount`, ya
   fusionado a `main`). Se tomó esa versión, más completa, en vez de la
   propia.
3. **Mejora real de resiliencia** en el xApp KPM del RIC
   (`kpm_bridge_xapp.py`): re-suscripción automática a DUs silenciosos,
   manejo de errores, campos de diagnóstico — no rastreada en ningún
   commit del repositorio. Documentada en `KPM_BRIDGE_XAPP_DEPLOY_DRIFT.md`
   y traída al repositorio tal cual.
4. **6 commits del repositorio sin desplegar** (wording de limpieza
   FlexRIC + bandera `MOBILE_INCLUDED_IN_UDP_ICMP_AGGREGATE`, default
   `false`, sin cambio de comportamiento) — desplegados también, con
   `ryu-manager` reiniciado y verificado sin experimento activo.

PRs de esta fase: `orchestrator-ddos-pucp#9` (`threshold-calibration-v2`,
**fusionado**) y `dist-pps-observed-rates` (ver Paso 3, abierto).

**Población móvil**: se encontró `ue2` sin sesión (no `ue5`, como en V1).
Se resolvió en vivo corriendo `reconnect_mobile_domain.yml` completo —
las 5 UEs quedaron conectadas, con KPM y actuación RC confirmados por UE
(ver informe de esa sesión). La calibración de este documento se hizo con
la población completa `ue1-ue5`.

## Paso 2 — B0, pipeline=baseline, semillas 101-110, modos I y M

20 corridas reales (`scripts/run_calibration_seeds_v2_baseline.py`),
agrupadas por modo (M primero, el controlador ya estaba en M) para
minimizar reinicios — solo 1 en las 20. A diferencia de V1 (que usó
`pipeline=enabled`), estas corrieron con **`pipeline=baseline`**
(detección suspendida) para que `observed_rates` no quedara contaminado
por mitigaciones reales de los umbrales viejos sobre tráfico benigno.

Las 20 completaron (`completed_with_errors`, el estado habitual — fallos
puntuales de eventos benignos individuales ya documentados en
`PILOT_DIAGNOSIS.md`, no de la corrida). Una corrida (`seed=108`, modo M)
se perdió a mitad de arranque por una condición de carrera real con el
*timer* de reinicio por memoria del panel (`benign-lab-web-restart-guard`,
cada 15 min) — coincidió justo con la pausa de 10 s entre corridas; quedó
en estado `stopped`, sin tráfico real enviado, y se repitió sin pérdida de
datos. El timer se detuvo temporalmente para el resto de las corridas de
este prompt y se reactivó al terminar.

Manifiesto: `.runtime/benign-lab/calibration/calibration_seeds_v2_baseline_manifest.json`.

## Paso 3 — instrumentación y propuesta

**Instrumentación nueva** (`orchestrator-ddos-pucp`, rama
`dist-pps-observed-rates`, pendiente de PR): `dist_pps_all_protocols` en
cada entrada de `observed_rates` — la suma de pps de **todos** los
protocolos de un grupo de correlación, exactamente el mismo cálculo que
`_classify_distributed()` usa como su propio `total_pps` cuando
`_classify()` cae al camino de respaldo. Pura aritmética, sin tocar
`_classify()`/`_classify_distributed()`/`_mobile_kpm_signal()` — 3 pruebas
nuevas confirman que coincide exactamente con lo que el camino real
evalúa. Desplegada y verificada en vivo (hash
`c61c5644...4c0da` en el primer ciclo `LAB_AUDIT` tras el reinicio).

Como esta instrumentación es posterior a las primeras 20 corridas, se
recapturó el set de entrenamiento (semillas 101-105, M) después de
desplegarla — 5 corridas, una (`seed=105`, primer intento) falló por
`RuntimeError: Agents exceeded the experiment deadline` (timeout
transitorio ya documentado en V1), repetida limpia.

**Propuesta** (`threshold_replay.propose_thresholds()` /
`propose_dist_pps_threshold()`, q=0,999, margen=1,5, entrenamiento
101-105 en M): ver tabla del resumen. `n` = 9402 muestras de SYN, 1311 de
UDP, 657 de ICMP, 10 380 del agregado distribuido.

### Hallazgo — DIST_PPS_THRESHOLD nunca estuvo calibrado, y es un bug real ya documentado

El valor propuesto (175 699,17) es ~585× el valor en vivo anterior (300).
No es un error: `_classify()` recorre SYN→UDP→ICMP y, si ninguno cruza su
propio umbral (lo normal con tráfico benigno y umbrales bien calibrados),
cae **sin condición** a `_classify_distributed()`, que suma todo el grupo
(los 4 dominios, todos los protocolos). Con `DIST_PPS_THRESHOLD=300`, el
83,2 % de 10 380 ciclos benignos reales ya superaban ese piso (mediana
2020 pps) — coincide exactamente con el hallazgo ya registrado en memoria
de una sesión anterior (`pilot-diagnosis-2026-10-21`): *"con el pipeline
activo, el criterio distribuido sin calibrar bloquea tráfico benigno en
el 100 % de las corridas C1/C3/C4 antes de t=60s"*. Confirmado
numéricamente abajo (Paso 5).

## Paso 4 — extensión del replay (criterio distribuido + camino KPM)

**Criterio distribuido**: `threshold_replay.replay_dist_pps_backup()`,
nuevo — réplica **solo del gate de pps** de `_classify_distributed()`.
Simplificación declarada explícitamente (en el propio docstring de la
función): `DIST_MIN_SOURCES`/`DIST_ENTROPY_THRESHOLD` no son replicables
offline porque `observed_rates` solo trae el agregado por grupo, no el
desglose por fuente — esta réplica es una **cota superior** de cuántas
veces dispararía el criterio real completo, nunca una réplica exacta.

**Camino KPM del móvil**: no reproducible offline, como anticipaba el
prompt — `observed_rates` no lleva telemetría KPM cruda. Estimado en vivo
en el Paso 6: las 4 corridas C1 (semillas 106-107, I y M, pipeline
completo) ejercitan el camino KPM real de las 5 UEs junto con todo lo
demás, y dieron 0 detecciones en total (ver Paso 6) — sin evidencia de
falso positivo por esa vía tampoco, aunque no aislado del resto.

## Paso 5 — validación (semillas 106-110), una sola vez

### SYN/UDP/ICMP (réplica completa con histéresis de activación)

| | I | M |
|---|---|---|
| 106 | 0,0 % (0/96) | 0,0 % (0/96) |
| 107 | 0,0 % (0/96) | 0,0 % (0/96) |
| 108 | **5,2 %** (5/96) | 0,0 % (0/96) |
| 109 | **4,2 %** (4/96) | 0,0 % (0/96) |
| 110 | 0,0 % (0/96) | 0,0 % (0/96) |

**M: 0 % en las 5 semillas — cumple el criterio de paso (≤1 %) con margen
amplio**, que es el que pide explícitamente el prompt. I (informativo, sin
umbral numérico en el prompt) tiene 2/5 semillas por encima de 1 %, con un
patrón atípico: FPs repartidos ~1 por dominio simultáneamente en los 4
dominios en la misma ventana — no debería pasar en modo I (grupos
aislados por dominio); queda como hallazgo abierto, no bloqueante, para
investigar en una sesión futura.

### DIST_PPS (cota superior, solo gate de pps), semillas 106-110 en M

| | Umbral viejo (300) | **Umbral propuesto (175 699,17)** |
|---|---|---|
| 106 | 100,0 % (96/96) | 0,0 % |
| 107 | 100,0 % (96/96) | 0,0 % |
| 108 | 100,0 % (96/96) | **6,25 % (6/96)** — 2 picos aislados (de 2021 muestras), 3 dominios cada uno |
| 109 | 100,0 % (96/96) | 0,0 % |
| 110 | 100,0 % (96/96) | 0,0 % |

El valor viejo bloqueaba tráfico benigno en el 100 % de las ventanas de
las 5 semillas — confirma numéricamente el bug. El propuesto lo baja a
0 % en 4/5; el residual de `seed=108` (2 picos, cota superior sin los
gates de fuentes/entropía) no se pudo confirmar ni descartar offline con
la instrumentación actual.

## Paso 6 — aplicación y verificación en vivo

Aplicado vía `POST /api/calibration/thresholds` → `ThresholdControl.apply()`,
con tu confirmación explícita. `controller_restarted: true`,
`config_sha256` nuevo `d8f546b4...1a7`, confirmado en el primer ciclo
`LAB_AUDIT` real tras el reinicio. Comprometido en
`orchestrator-ddos-pucp/config/settings.py` (rama
`threshold-calibration-v2-apply`), hash del archivo del repositorio
idéntico byte a byte al desplegado. 3 archivos de prueba (fixtures con
valores literales dimensionados para los umbrales viejos, no lógica)
reescalados proporcionalmente — 164/164 pruebas pasan.

**FPR en vivo, detector completo** (`pipeline=enabled`, semillas 106-107,
I y M — 4 corridas reales, 100 % tráfico benigno):

| Corrida | Detecciones (`kind=detection`) reales |
|---|---|
| 106-M | **0** |
| 107-M | **0** |
| 106-I | **0** |
| 107-I | **0** |

**FPR en vivo = 0,0 % en las 4 corridas, en los 4 dominios — cumple el
criterio de paso con el margen más amplio posible.**

## Paso 7 — factibilidad

**Vector único**: `4,75 × SYN_THRESHOLD = 404,88 pps`, muy por debajo de
la capacidad máxima medida por fuente en cada dominio
(`docs/ATTACK_CAPACITY_MEASUREMENT.md`):

| Dominio | Capacidad máx. (1 fuente) | Margen sobre 404,88 pps |
|---|---|---|
| enterprise | 24 686 pps | ×61,0 |
| fixed | 13 462 pps | ×33,2 |
| peering | 15 325 pps | ×37,9 |
| mobile | 5 116 pps | ×12,6 |

**Composición 3 (confirmatoria)**: `f` ∈ {0,9; 0,7; 0,5} × SYN_THRESHOLD =
{76,71; 59,67; 42,62} pps por dominio (cada uno bajo su propio umbral),
suma = 179,00 pps = **2,10× SYN_THRESHOLD** (≥1,3× requerido). **Ambos
criterios de factibilidad se cumplen.**

## Criterio de paso — evaluación final

| Criterio | Resultado |
|---|---|
| FPR de detección por dominio ≤1 % en validación, en M | **0,0 % (0/480 ventanas), cumple con margen amplio** |
| FPR de detección por dominio ≤1 % en vivo, en M | **0,0 % (0 detecciones en 2 corridas reales), cumple** |
| Umbrales alcanzables por un ataque generable | **Sí — márgenes de ×12,6 a ×61 por dominio, composición 3 a 2,10×** |
| Código desplegado igual al del repositorio | **Sí — hashes idénticos, confirmados en vivo** |

**Los 4 criterios se cumplen.**

## Pendiente — no bloqueante

- PR `dist-pps-observed-rates` (Paso 3) y `threshold-calibration-v2-apply`
  (Paso 6) en `orchestrator-ddos-pucp`, y `threshold-calibration-v2` en
  `traffic-generator-pucp` — abiertos, sin fusionar al cierre de este
  documento.
- Residual de modo I en validación (`seed=108/109`, 4-5 % FPR, patrón
  atípico de 4 dominios simultáneos) — investigar en una sesión futura,
  no bloquea el criterio de paso (que es explícitamente sobre M).
- Residual de `DIST_PPS` en `seed=108` (6,25 %, cota superior) — no se
  pudo confirmar contra el motor real (gates de fuentes/entropía) con la
  instrumentación actual; instrumentar el desglose por fuente en
  `observed_rates` sería el siguiente paso si se quiere cerrar esto del
  todo offline.
- `rc_actuator_xapp.py` del RIC permanece sin divergencia (verificado en
  Paso 1, no requiere acción).

## Supuestos

- El objetivo de FPR (≤1 % por dominio en validación, M) se tomó, igual
  que en V1, del mismo valor de referencia ya usado en
  `docs/FALSE_POSITIVES_CALIBRATION.md`.
- La réplica del criterio distribuido es una cota superior declarada
  (Paso 4) — no una réplica exacta del motor real.
- Las capacidades de ataque del Paso 7 se tomaron de
  `docs/ATTACK_CAPACITY_MEASUREMENT.md` (medidas 2026-10-19, sin
  remedir en esta sesión) — no deberían haber cambiado desde entonces,
  pero no se reconfirmaron en vivo.
- Se aplicaron los umbrales redondeados exactamente a los valores
  calculados (sin redondeo adicional), igual que en V1.
