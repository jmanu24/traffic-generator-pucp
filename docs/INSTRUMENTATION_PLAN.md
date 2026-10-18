# Plan de instrumentación — alcance consolidado

Este documento fija el alcance funcional que la herramienta debe cubrir (los
10 puntos acordados), mapea cada uno contra lo que ya existe en el código, y
propone qué conservar, qué consolidar y qué retirar. Es la referencia para
priorizar el trabajo; no describe implementación detallada de cada módulo.

## Principio rector

No reinventar lo que ya funciona y está validado. Donde exista automatización
probada en `isp-ddos-ryu` (roles Ansible de bring-up/reconexión/mitigación,
`deploy/vm-lab/webtool`), BENIGN-LAB la **invoca** (subprocess/API), no la
duplica. Donde ya exista un módulo propio que cubra el requisito, se
**consolida y se documenta**, no se reescribe desde cero.

## 1. Mapa de requisitos → estado actual

| # | Requisito | Estado | Módulos/activos relevantes |
|---|---|---|---|
| 1 | Medir capacidad máxima por dominio (throughput, utilización, delay, jitter, pérdida) | **Parcial** | `scripts/calibrate_capacity.py`, `scripts/capacity_probe.py`, `docs/CAPACITY_CALIBRATION.md`. Mide goodput TCP; **no mide delay/jitter/pérdida** todavía. |
| 2 | Fijar capacidad medida → derivar semillas con rigor estadístico | **Parcial** | `docs/PLAN_CAPACITIES.md`, `scripts/apply_capacity_results.py` fijan capacidad de referencia. El *tamaño de muestra* (nº de semillas/réplicas) no está derivado formalmente de la capacidad medida ni de un criterio de potencia estadística. |
| 3 | Usar las semillas para generar planes de prueba | **Existe** | `benign_lab/planner.py`, `cli.py generate-plan`, `/api/plans`. Determinístico, con `plan_hash`. |
| 4 | Ejecutar las pruebas según la cantidad requerida para rigor estadístico | **Existe (parcial)** | `benign_lab/scenario_series.py`, `/api/scenario-series/*` (18 corridas fijas). Está cableado a un diseño fijo (6 semillas × classic), no a un tamaño de muestra derivado del paso 2. |
| 5 | Fijar umbrales de detección por dominio y multidominio con esta información | **Existe** | `benign_lab/threshold_control.py`, `/api/calibration/thresholds`, `docs/FALSE_POSITIVES_CALIBRATION.md`. Cubre dominio individual; falta el lazo explícito "capacidad medida → umbral sugerido" y el caso multidominio. |
| 6 | Obtener parámetros para el análisis estadístico de los escenarios | **Existe** | `benign_lab/experimental_analytics.py`, `detection_evaluation.py`, `scenario_confusion.py`, `/api/analytics/*`. Produce medias, IC (t de Student), matriz de confusión por ventana. |
| 7 | Acciones sobre el laboratorio (on/off VMs/dominios, validación de conectividad, recuperación) | **No existe aquí** | Vive hoy en `isp-ddos-ryu/deploy/vm-lab/webtool` (topología, power-any-VM, bring-up) y en los playbooks Ansible (`reconnect_fixed_domain.yml`, etc.). BENIGN-LAB no tiene esta capa. |
| 8 | Monitoreo de VMs y hosts del laboratorio | **Existe** | `benign_lab/vm_resources.py`, `host_monitor.py`, `resource_probe.py`, `interface_monitor.py`/`interface_probe.py`. CPU, memoria, disco, red, CPU Ready ESXi. |
| 9 | Monitoreo de telemetría propia de cada dominio | **Parcial** | Interfaces (`interface_monitor.py`) cubre tráfico; Peering tiene nfcapd (`docs/WATCHDOG_PEERING.md`). Falta telemetría propia homogénea para Mobile (KPM E2) y Fixed/Enterprise si no pasa por interfaces. |
| 10 | Monitoreo de registros/acciones (detección, mitigación) | **Existe** | `benign_lab/detection_audit.py` (SSH stream autenticado → sqlite), `audit_probe.py` (tail de `ryu-manager.log`), `/api/detection-audit/status`, `/runs/{rid}/detection-evaluation`. |

**Conclusión del mapeo:** 7 de los 10 puntos ya tienen una base real en el
código. El trabajo nuevo grande es el **#7** (acciones sobre el laboratorio,
hoy fuera de este repo) y cerrar los lazos faltantes en **#1, #2, #5, #9**.
El resto es consolidar, documentar y exponer mejor lo que ya existe, no
construir de cero.

## 2. Qué sobra (candidatos a retirar o archivar)

Son artefactos de pilotos/depuraciones puntuales, no funcionalidad central.
Mover a `docs/archive/` (se conservan como bitácora, dejan de mantenerse) y
evaluar si el código asociado sigue usándose en producción:

- `docs/BURST_DURATION_PILOT.md`, `docs/PAYLOAD_QUALITY_V2.md`,
  `docs/REFERENCE_RESTORATION.md`, `docs/REFERENCE_OCT6.md`,
  `docs/PREPARATION_FAILURE_FIX.md`, `docs/PRE_RUN_BLOCK_CLEANUP.md`,
  `docs/CPU_FORWARDER_EXPANSION.md`, `docs/CPU_PARALLEL_RECEIVER.md`,
  `docs/OPTIMIZATION_VALIDATION.md` + `.json`,
  `docs/WORKSTATION_WIFI_MIGRATION.md` (ya no aplica, VM migrada),
  `docs/WORKSTATION_MIGRATION_VALIDATION.json`.
- ~~`benign_lab/burst_variants.py`~~ — **retirado** (Fase 0): los endpoints
  `/api/burst-pilot/*` ya devolvían 409 "Piloto retirado" en el código; se
  eliminó el módulo, los tres endpoints y `tests/test_burst_variants.py`.
  El frontend ya no lo referenciaba.
- Revisar si `clock_sync.py` sigue siendo necesario fuera de la ejecución
  (si ya está integrado al arranque coordinado, no hace falta exponerlo
  como feature aparte).

No se toca nada de esto sin tu confirmación explícita por archivo: esta es
una lista propuesta, no una ejecución.

## 3. Arquitectura objetivo (4 capas, alineadas a los 10 puntos)

```
┌─ Capa de laboratorio (nueva, #7, #8, #9) ───────────────────────────┐
│ Acciones (power on/off, bring-up, recuperación) + monitoreo VM/host │
│ + telemetría por dominio. Envuelve Ansible/govc/webtool existentes. │
└───────────────────────────────────────────────────────────────────┘
┌─ Capa de calibración (#1, #2) ───────────────────────────────────────┐
│ Medición de capacidad (throughput/util/delay/jitter/pérdida) →       │
│ cálculo de tamaño de muestra (nº semillas) con criterio estadístico  │
└───────────────────────────────────────────────────────────────────┘
┌─ Capa de generación y ejecución (#3, #4) ────────────────────────────┐
│ planner.py (semillas → planes) + scenario_series.py (ejecución con   │
│ el nº de réplicas que exige la capa de calibración)                  │
└───────────────────────────────────────────────────────────────────┘
┌─ Capa de umbrales y análisis (#5, #6, #10) ──────────────────────────┐
│ threshold_control.py (por dominio y multidominio) +                  │
│ experimental_analytics.py / detection_audit.py (parámetros, auditoría)│
└───────────────────────────────────────────────────────────────────┘
```

## 4. Roadmap por fases

**Fase 0 — Poda (1 sesión corta)**
Archivar los docs listados en §2, confirmar contigo caso por caso el
código candidato a retirar (`burst_variants.py` y su endpoint). Sin esto,
cada fase siguiente arrastra más superficie de la necesaria.

**Fase 1 — Cerrar medición de capacidad (#1)**
Extender `calibrate_capacity.py`/`capacity_probe.py` para registrar, por
dominio, no solo goodput sino delay (RTT), jitter y pérdida de paquetes
(usar los agentes ya desplegados o ping/UDP con secuencia para pérdida).
Persistir junto a lo que ya guarda `CAPACITY_MEASUREMENTS.json`.

**Fase 2 — Tamaño de muestra con rigor estadístico (#2)**
Nuevo módulo (p.ej. `sample_size.py`) que, a partir de la variabilidad
observada en la calibración (Fase 1), calcule el número de semillas/
réplicas necesario para una potencia/IC objetivo (ya existe `T975` y la
lógica de IC en `experimental_analytics.py`: se reutiliza el mismo marco
en lugar de crear uno nuevo). Expone el resultado como insumo directo de
`scenario_series.py`.

**Fase 3 — Generación y ejecución dirigidas por el tamaño de muestra (#3, #4)**
Parametrizar `scenario_series.py`/`/api/scenario-series/*` para que el
número de semillas/corridas venga de la Fase 2 en vez de estar fijo a 18.
`planner.py` no cambia de contrato, solo cómo se invoca.

**Fase 4 — Umbrales por dominio y multidominio desde la calibración (#5)**
Extender `threshold_control.py` para sugerir umbrales a partir de la
capacidad medida (Fase 1) y de los resultados de falsos positivos
(`FALSE_POSITIVES_CALIBRATION.md`), y para fijar/registrar un umbral o
regla multidominio explícita (hoy el control es por dominio).

**Fase 5 — Capa de acciones sobre el laboratorio (#7)**
La pieza nueva más grande. Definir si se integra como cliente del
`webtool` de `isp-ddos-ryu` (llamando su API) o si se replican acciones
mínimas (power on/off por VM/dominio, prueba de conectividad, disparo de
los playbooks de recuperación) directamente desde BENIGN-LAB. Recomendado:
**envolver el webtool/Ansible existente**, no reimplementar el control de
VMware/accel-ppp/FlexRIC que ya está validado en `isp-ddos-ryu`.

**Fase 6 — Telemetría homogénea por dominio (#9)**
Completar lo que falta para que Mobile (KPM vía E2), Fixed y Enterprise
reporten telemetría propia con el mismo formato que ya usa Peering
(nfcapd) e Interfaces, para que la capa de análisis (#6) y auditoría
(#10) los traten de forma uniforme.

**Fase 7 — Consolidación de análisis y auditoría (#6, #10)**
Con todo lo anterior en su lugar, revisar `experimental_analytics.py` y
`detection_audit.py` para que expongan exactamente los parámetros que la
tesis necesita (ya están cerca; es más documentación/reporte que código
nuevo) y retirar cualquier endpoint de analítica que haya quedado huérfano
tras la Fase 0.

## 5. Decisiones que necesito de ti antes de tocar código

1. **Fase 0:** ¿confirmo el archivado de los docs listados en §2.1 ahora,
   o prefieres revisarlos uno por uno primero?
2. **Fase 5 (#7):** ¿integrar llamando al `webtool` de `isp-ddos-ryu`, o
   quieres que las acciones de laboratorio vivan directamente dentro de
   `traffic-generator-pucp` (duplicando la capa de actuación)?
3. **Orden:** ¿seguimos el roadmap en este orden (0→7), o hay un punto de
   los 10 que es bloqueante para tu cronograma de tesis y debe ir primero
   (por ejemplo, si necesitas #7 antes que el resto para poder calibrar)?
