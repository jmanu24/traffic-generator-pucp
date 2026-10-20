# Resultado de la calibración de umbrales (THRESHOLD_CALIBRATION)

Calibración completa, aplicada al controlador real el 2026-10-20.

## Resumen

| Protocolo | Umbral anterior | **Umbral aplicado** | Cuantil (q=0,999) | Margen |
|---|---|---|---|---|
| SYN | 10 | **76,82** | 51,21 | ×1,5 |
| UDP | 200 | **14 515,64** | 9 677,10 | ×1,5 |
| ICMP | 150 | **240,37** | 160,24 | ×1,5 |

`DECISION_THRESHOLD` (1,5) y `DIST_PPS_THRESHOLD` (300) quedaron sin
tocar — fuera del alcance de este prompt (solo pidió calibrar
SYN/UDP/ICMP).

`config_sha256` anterior: `ad625cfe...fba59`. `config_sha256` aplicado:
`e95d70ec...c7e7b`. `controller_restarted: true`, confirmado por
`ThresholdControl.apply()` vía `/api/calibration/thresholds`.

## Semillas y datos de base

- **Entrenamiento**: semillas 101-105 (benigno, `pipeline=enabled`, B0,
  180 s, misma configuración que la campaña — `config/lab.connected.yaml`).
- **Validación**: semillas 106-110, misma configuración.
- Cada semilla se corrió en **ambos tratamientos**, I (`detection_mode=
  isolated`) y M (`detection_mode=multidomain`) — 20 corridas en total,
  cada una con verificación doble de `detection_mode` (D1) exitosa.
- La propuesta usa **solo las 5 corridas de entrenamiento en M** (el
  tratamiento que suma la tasa de todos los dominios, el que más falsas
  alarmas puede producir, por diseño del prompt).

## Paso 1 — observación (instrumentación, sin cambiar decisión)

`orchestrator-ddos-pucp`, rama `benign-rate-instrumentation` (ahora
desplegada en el controlador real): `observed_rates` en cada
`LAB_AUDIT kind=cycle`, la tasa agregada por protocolo/destino/dominio
tal como la evalúa el motor de detección (incluida la exclusión de
mobile en UDP/ICMP), sin tocar `_classify()`/`_mobile_kpm_signal()`/
`_activated()`. Probado en vivo que no cambia ninguna detección ni
decisión (`detection/test_observed_benign_rates.py`, 7 pruebas).

**Bug real encontrado y corregido en el camino** (con tu confirmación):
`collectors/peering_flow_collector.py` calculaba `pps = packets /
max(nfdump_td, 0.001)` — un flujo NetFlow corto (`td≈0`) se convertía en
~1000 pps por un solo paquete, y `detection/engine.py` suma esas tasas
por ciclo — las semillas de entrenamiento mostraron hasta **~29 000
"pps" de SYN** benignos de `peering`, antes de corregir el piso a
`COLLECT_INTERVAL` (0,5 s). Ver
`orchestrator-ddos-pucp/docs/PEERING_DURATION_FLOOR_BUG.md`. Las 20
corridas se repitieron contra el controlador ya corregido.

## Paso 2 — capacidad de ataque alcanzable

Ver `docs/ATTACK_CAPACITY_MEASUREMENT.md` (medido en vivo, pipeline
suspendido): enterprise SYN 24 686/UDP 330 224/ICMP 102 830 pps; fixed
13 462/29 253/23 677; peering 15 325/35 733/25 755; mobile 5 116/34 825
/13 096 (UDP/ICMP de mobile no participan en `trigger_pps` por diseño
del motor — solo su SYN es relevante aquí).

## Paso 3 — ejecuciones de calibración

Ver `docs/CALIBRATION_SEEDS_RESULT.md` para el detalle completo de las
20 corridas y los problemas reales encontrados en el camino (ue5,
wiring de `manager.audit`, carrera de tiempos en la verificación de
`detection_mode`, una regla de bloqueo OpenFlow residual, un timeout
transitorio) — todos corregidos o resueltos antes de usar los datos
aquí. Las 20 corridas se **repitieron una segunda vez completa** después
de corregir el bug de `peering_flow_collector.py`, para que los datos de
este documento vengan todos del controlador ya corregido.

## Paso 4 — propuesta, replay y validación

### Propuesta (cuantil × margen, entrenamiento en M)

`benign_lab/threshold_replay.py::propose_thresholds()`, q=0,999,
margen=1,5, sobre 6 605 muestras de SYN, 1 354 de UDP y 641 de ICMP
(cada muestra = un grupo de correlación × ciclo × protocolo, de las 5
corridas de entrenamiento en M).

### Criterio de paso — factibilidad

1. **Vector único** (4,5×umbral ≤ tasa máxima de una fuente, Paso 2):

   | Protocolo | 4,5×umbral | Dominio(s) que lo superan |
   |---|---|---|
   | SYN | 345,7 | los 4 (mínimo: mobile, 5 116) |
   | UDP | 65 320,4 | enterprise (330 224); fixed y peering no alcanzan por sí solos, pero no hace falta — basta uno |
   | ICMP | 1 081,7 | los 3 no-mobile (mínimo: fixed, 23 677) |

2. **Composición multidominio** (≥3 dominios, cada uno ≤0,9×umbral,
   suma ≥1,3×umbral): para SYN hay 4 dominios disponibles; para UDP/ICMP
   hay exactamente 3 (mobile excluido del `trigger_pps` de esos dos
   protocolos) — los 3 alcanzan de sobra la fracción del umbral
   necesaria sin acercarse a su propio límite individual.

**Los tres protocolos pasan ambos criterios.**

### FPR por repetición (replay con persistencia de activación)

`benign_lab/threshold_replay.py::replay_activation()` +
`fpr_from_replay()`, con los `MIN_HITS`/`WINDOW_S` leídos de la propia
captura de cada corrida (nunca hardcodeados):

| | Entrenamiento I | Entrenamiento M | **Validación I** | **Validación M** |
|---|---|---|---|---|
| Por dominio (los 4, idéntico) | 0,0 % | 1,67 % (2/120) | **0,0 %** | **0,0 %** |
| Global | 0,0 % | 1,67 % (8/480) | **0,0 %** | **0,0 %** |

Objetivo confirmado: FPR de detección por dominio ≤ 1 % en validación,
en M. **Validación en M = 0,0 % ≤ 1 %** — pasa con margen amplio.
Entrenamiento en M mostró 2 falsos positivos (de 120 ventanas/dominio,
8 globales) — el mismo evento de correlación cruzada afecta a los 4
dominios por igual (de ahí la tasa idéntica), consistente con cómo
`MULTIDOMAIN_DISTRIBUTED_ATTACK` atribuye un solo evento a todos los
dominios contribuyentes.

Nunca se usaron las semillas de validación para retocar el candidato —
se evaluó una sola vez, después de fijar la propuesta con entrenamiento.

## Aplicado

```
SYN_THRESHOLD = 76.82
UDP_THRESHOLD = 14515.64
ICMP_THRESHOLD = 240.37
```

Vía `POST /api/calibration/thresholds` → `ThresholdControl.apply()`,
con tu confirmación explícita. `controller_restarted: true`,
`config_sha256` nuevo `e95d70ec...c7e7b`, controlador verificado activo
después del reinicio.

## Supuestos

- El objetivo de FPR de detección (≤1 % por dominio en validación, M)
  se tomó del valor ya usado como referencia en
  `docs/FALSE_POSITIVES_CALIBRATION.md` (el mismo documento que pide
  leer el prompt), no un número nuevo inventado aquí.
- La replay-FPR es una **simplificación declarada**: elegibilidad de
  ventana = `ground_truth.windows()`'s propio flag `evaluation`
  (completa y pasado el calentamiento), no la cobertura completa de
  telemetría por dominio que usa `detection_evaluation.evaluate()` — la
  misma frontera de alcance que ya declaran
  `benign_lab/response_metrics.py` y el propio `threshold_replay.py`.
- Las tasas UDP/ICMP de `peering` siguen siendo notablemente más altas
  que las de otros dominios incluso después de corregir el bug de
  duración — se trató como una característica real de `peer-flow*`
  (representa ~100 flujos simulados, un volumen agregado legítimamente
  mayor que un solo cliente), no como contaminación, porque el patrón
  de contaminación (duración casi cero, un solo dominio dominando TODOS
  los protocolos simultáneamente) solo coincidía con SYN antes del fix;
  después del fix, SYN se normalizó mientras UDP/ICMP se mantuvieron en
  el mismo orden de magnitud, consistente con ser una señal real.
- Se aplicaron los umbrales redondeados exactamente a los valores
  calculados (sin redondeo adicional) para que el `config_sha256`
  resultante sea reproducible desde los datos de este documento.
