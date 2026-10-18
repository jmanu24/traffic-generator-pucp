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
| 11 | Generar ataques reales desde cada cliente, sin hping3 (añadido 2026-10-18) | **Implementado y probado localmente** | `benign_lab/attack_planner.py`, `benign_lab/attack_runner.py`, flood primitives en `benign_lab/agent.py`. Ver §6. |

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

**Fase 2 — Tamaño de muestra con rigor estadístico (#2) — implementada y probada**
`benign_lab/sample_size.py`: `required_seeds(sd, precision)` (exacta,
iterativa, basada en `T975` de `experimental_analytics.py`, no en la
aproximación normal que ya traía `additional_seeds_precision_approx`), y
`plan_sample_size(calibration, precision_by_metric)` que, dado un
diccionario de variabilidad por métrica (throughput/delay/jitter/pérdida de
la Fase 1), calcula el número de semillas que exige la métrica más
demandante — todas las métricas deben cumplir su precisión objetivo a la
vez. 5 pruebas unitarias pasan. Falta conectarlo con datos reales de
calibración (Fase 1 en el laboratorio) y con `scenario_series.py` (Fase 3).

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

## 5. Requisito #11 — generación de ataques reales (sin hping3)

Hasta ahora el ataque era siempre externo: `scenario_series.py` solo registra
una ventana (`attack_windows: [{'name':'external_attack', start_s, end_s}]`)
y espera a que el operador lo dispare manualmente (históricamente hping3) y
confirme inicio/fin reales. Esto es impreciso (la memoria del proyecto ya
registraba que hping3/nfcapd sobreestiman tasas bajas y que hubo que escribir
un emisor Python ad-hoc para la prueba multidominio sub-umbral del 18 de
octubre). El pedido es llevar esa capacidad a la herramienta misma, generando
los flujos **desde cada cliente real de la topología**, no desde un proceso
externo.

### Diseño (reutiliza la infraestructura ya validada, no la duplica)

`config.resolve()` ya es agnóstico al contenido de cada evento: solo necesita
`source`, `domain`, `destination` y que `targets` tenga los puertos. Por eso
un "plan de ataque" puede fluir por el mismo `resolve()`/`command()`/
`supervisor_groups()`/transporte SSH que ya usan los planes benignos, sin
tocar esas funciones.

- **`benign_lab/agent.py`**: nuevo `wire_protocol` ∈ `{udp_flood, syn_flood,
  icmp_flood}`, despachado por `attack_flood()` antes de la ruta cooperativa
  de `traffic()`. Sin receptor cómplice: UDP es *fire-and-forget* (no manda
  el prefijo `BLDL:` ni espera eco), TCP abre conexiones medio-abiertas y las
  cierra con `SO_LINGER(1,0)` para forzar RST antes de completar el
  *handshake* de aplicación (no es spoofing, es tráfico real desde la IP real
  del cliente), ICMP usa un socket raw con un paquete *echo request*
  construido a mano (checksum incluido) en vez de invocar `ping` (evita su
  límite de intervalo). Nada de hping3, nada de scapy, cero dependencias
  nuevas — mismo espíritu *dependency-free* del resto del proyecto.
- **`benign_lab/attack_planner.py`**: plan determinista y liviano
  (`profile: ATTACK_FLOOD_V1`, hash SHA-256 igual que los planes benignos,
  pero sin el modelo de capacidad/cuota de `BENIGN_V1`). Cada "flow" declara
  dominio, lista de clientes reales (nombres de `lab.yaml`), destino,
  protocolo, `rate_pps`, ventana y tamaño de paquete. Varios *flows* en un
  mismo plan —incluso de distintos dominios— componen un ataque multidominio
  coordinado, reproduciendo exactamente la receta ya validada (`5 fuentes/3
  dominios a ~50 pps UDP`) pero ahora como una función reutilizable y
  determinista por semilla en vez de un script manual.
- **`benign_lab/attack_runner.py`**: despacha el plan contra el laboratorio
  real reutilizando `resolve()` + un subproceso por grupo (mismo patrón que
  `runner.Manager.real()` en su variante sin supervisor) + `clock_sync.
  probe_clock` para un arranque sincronizado entre todos los clientes. No
  toca `runner.Manager`: un ataque no es una medición científica de tráfico
  benigno, no tiene modelo de cuota/capacidad y no pasa por `BaselineGuard`.
  Devuelve `started_at`/`finished_at` reales y, por evento, paquetes
  enviados y pps logrado — exactamente la precisión de tiempos que hoy falta
  (hoy el operador "marca" el inicio/fin a mano).
- **CLI**: `generate-attack-plan`, `validate-attack-plan`, `run-attack`
  (simétrico a `generate-plan`/`validate-plan`).

### Probado en este entorno (sin acceso al laboratorio real)

- Construcción y checksum del paquete ICMP echo.
- `udp_flood` y `syn_flood` contra un socket/listener TCP real en loopback:
  tasa objetivo vs. real dentro de ±1 pps, paquetes recibidos = paquetes
  enviados.
- `run_attack()` extremo a extremo con dos procesos agente locales
  independientes, reloj sincronizado, arranque coordinado: 400/400 paquetes
  recibidos (2 fuentes × 200 paquetes a 100 pps × 2 s).
- Generación de plan multidominio distribuido, determinismo por semilla,
  rechazo de protocolo/dominio/ventana inválidos.
- `icmp_flood` falla limpiamente sin privilegios de root (`PermissionError`
  explícito) — en el laboratorio real los agentes ya corren con `sudo`/en
  namespaces, así que debería funcionar sin cambios; **pendiente de
  validación en el nodo real**.
- Suite completa de pytest: 165 passed, 5 failed (las mismas 5 fallas
  preexistentes del entorno, confirmadas también en el commit anterior a
  todo este trabajo — ver §0). Las 13 pruebas nuevas (`test_attack_
  generation.py`, `test_sample_size.py`) pasan.

### Pendiente (siguiente incremento, requiere el laboratorio real)

1. Validar `icmp_flood`/`syn_flood` contra VMs reales (privilegios, rutas,
   que el SYN medio-abierto efectivamente dispare `SYN_THRESHOLD`).
2. Enganchar `scenario_series.py`/`api.py`: hoy `scenario_steps(...,
   source_ips, description)` asume un ataque externo manual. Añadir un modo
   `attack_source='internal'` que, en vez de esperar al operador, genere un
   `attack_plan` y llame `run_attack()` exactamente en la ventana declarada,
   y vuelque `started_at`/`finished_at` reales en `observed_attacks` del
   `run.json` (mejora directa de precisión del ground truth, que hoy depende
   de que el operador confirme a mano).
3. Endpoints `/api/attacks/plan` y `/api/attacks/start` en `api.py`, y una
   vista mínima en el panel para componerlos (dominio, fuentes, protocolo,
   pps, ventana) en vez de editar JSON a mano por CLI.

## 6. Decisiones que necesito de ti antes de seguir

**Hecho hasta ahora (2026-10-18), todo en el working tree, sin commit:**
Fase 0 completa (docs archivados, `burst_variants` retirado — commiteado y
pusheado antes de esta corrección de proceso). Requisito #11 (ataques):
primitivas de flood en `agent.py`, `attack_planner.py`, `attack_runner.py`,
CLI, 13 pruebas nuevas, todo probado en este entorno salvo `icmp_flood`
contra VMs reales. Fase 2 (`sample_size.py`): implementada y probada con
datos sintéticos.

**No hecho todavía, porque necesita decisiones o el laboratorio real:**

1. **Fase 1 (#1):** extender `calibrate_capacity.py`/`capacity_probe.py`
   para medir delay/jitter/pérdida además de goodput. Solo puedo escribir el
   código; validarlo requiere correrlo en el nodo orquestador contra las VMs
   reales (igual que el resto de calibraciones del proyecto).
2. **Fase 3 (#3/#4):** conectar `sample_size.py`/el `attack_runner` con
   `scenario_series.py` para que el número de corridas y el disparo del
   ataque dejen de ser fijos/manuales. Es la pieza que más toca el flujo
   existente; prefiero hacerlo con calibración real en la mano (Fase 1), no
   con números de ejemplo.
3. **Fase 4 (#5):** umbrales por dominio y multidominio derivados de la
   capacidad medida — depende de la Fase 1.
4. **Fase 5 (#7):** ¿integro llamando al `webtool` de `isp-ddos-ryu`, o las
   acciones de laboratorio viven directamente dentro de
   `traffic-generator-pucp`? Sigue pendiente de tu confirmación.
5. **Fases 6-7 (#9/#6/#10):** telemetría homogénea por dominio y
   consolidación de analítica — son las de menor riesgo pero también las que
   menos cambian el comportamiento actual; las dejo para el final salvo que
   prefieras otro orden.

¿Seguimos en este orden, o priorizamos algo distinto (por ejemplo, llevar el
requisito #11 al laboratorio real antes de avanzar con las fases 1/3/4)?
