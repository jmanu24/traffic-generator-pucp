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

## 4. Roadmap por fases — estado al 2026-10-18

Todo lo marcado "implementado" está en el working tree de
`traffic-generator-pucp`, probado en este entorno (sin acceso al
laboratorio real salvo donde se indica), y pendiente de tu decisión sobre
cuándo commitear/pushear. Nada de esto se ha validado todavía contra las
23 VMs reales.

**Fase 0 — Poda — completa (commiteada y pusheada: `f48aafc`, `ada5efd`)**
Docs de pilotos archivados, `burst_variants.py` y su endpoint retirados.

**Fase 1 — Cerrar medición de capacidad (#1) — código añadido, no validado en el lab**
`scripts/capacity_probe.py`: nuevo modo `path` (RTT min/avg/max, jitter
`mdev`, % pérdida vía `ping`, reutilizando el mismo patrón ICMP que ya usa
`agent.py` — sin hping3). Probado localmente contra `127.0.0.1` y contra una
IP inalcanzable (100 % pérdida parseada correctamente).
`scripts/calibrate_capacity.py`: paso aditivo por dominio que llama al modo
`path` desde cada cliente y agrega `report['path_quality'][domain]`
(pérdida/RTT/jitter medios y máximos); envuelto en `try/except` para que un
fallo en la medición de latencia **nunca** aborte la campaña de throughput
ya validada. No toca la lógica existente de capacidad/firewall/mitigación.
**Pendiente:** correr en el nodo orquestador contra el laboratorio real.

**Fase 2 — Tamaño de muestra con rigor estadístico (#2) — implementada y probada**
`benign_lab/sample_size.py`: `required_seeds(sd, precision)` (exacta,
iterativa, basada en `T975` de `experimental_analytics.py`), y
`plan_sample_size(calibration, precision_by_metric)`, que dado
`{métrica: {mean, sd}}` (lo que produce la Fase 1) devuelve el número de
semillas que exige la métrica más demandante. 5 pruebas unitarias.

**Fase 3 — Ejecución dirigida por el tamaño de muestra y ataques internos (#3, #4) — parcial**
`benign_lab/scenario_series.interleaved_order(seeds, repeats_per_seed)`:
generaliza el diseño fijo de 3 semillas/18 corridas (hoy hardcoded en
`api.py:comparison_steps`, con 3 hashes de plan fijos) a cualquier número de
semillas mediante un Latin square balanceado (cada semilla aparece una vez
en cada posición relativa de la campaña — la propiedad que importa
metodológicamente, no la permutación exhaustiva, que solo es práctica para
n pequeño). 4 pruebas unitarias. **Pendiente (requiere el laboratorio
real):** sustituir el orden fijo de `comparison_steps()` por esta función
alimentada por `sample_size.plan_sample_size()`, lo que exige tener N planes
calibrados reales en el nodo orquestador, no solo 3. El requisito #11
(generación de ataques, ver §5) ya da la pieza para que el disparo del
ataque dentro de un escenario deje de ser manual; conectarla a
`scenario_series`/`api.py`/`runner.Manager` para que quede 100% automática
es el siguiente incremento, documentado también en §5.

**Fase 4 — Umbrales por dominio y multidominio desde la calibración (#5) — recomendación implementada, aplicación sin tocar**
`benign_lab/threshold_recommendation.py`: `recommend_thresholds(baseline_pps_by_domain, margin, dist_margin)`,
función pura (sin SSH, sin tocar el controlador en vivo) que sugiere
`SYN_THRESHOLD`/`UDP_THRESHOLD`/`ICMP_THRESHOLD` a partir del pico de
dominio más alto, y `DIST_PPS_THRESHOLD` (el campo que ya existe para el
caso multidominio distribuido) a partir de la suma de líneas base de todos
los dominios. 5 pruebas unitarias. El operador revisa la sugerencia y la
aplica con `ThresholdControl.apply()`, que no se tocó. **Limitación real,
no de esta herramienta:** `SYN_THRESHOLD`/`UDP_THRESHOLD`/`ICMP_THRESHOLD`/
`DECISION_THRESHOLD` son escalares globales en el controlador desplegado
(`isp-ddos-ryu`), no uno por dominio; un umbral por dominio de verdad
requiere un cambio del lado del controlador, fuera de este repositorio.

**Fase 5 — Capa de acciones sobre el laboratorio (#7) — implementada, decisión ya tomada**
Investigué `isp-ddos-ryu`: el antiguo `webtool` (puerto 8070) fue retirado
(working tree de `isp-ddos-ryu` en plena refactorización); sus primitivas de
actuación reales viven ahora en `deploy/vm-lab/vmlab_common/` (`govc_ops`,
`ssh_ops`, `inventory`), exactamente el mismo paquete que
`scripts/calibrate_capacity.py` ya importa. Decisión: **envolver
`vmlab_common`, no reimplementar.** `benign_lab/lab_actions.py`:
`power_states()`, `power_domain(domain, on)`, `connectivity_check(domain,
command)`, `recover_domain(domain)` (dispara los playbooks Ansible
`reconnect_{mobile,fixed,peering}_domain.yml` ya validados). No hay
playbook de reconexión para `enterprise` todavía.

**Validado en vivo el 2026-10-18** (este mismo control node, 192.168.18.154,
es el que corre `benign-lab-web.service`; sin experimento activo en ese
momento — `data/runs/` vacío):
- `power_states()`: 45 VMs reales vía `govc`, solo lectura.
- `connectivity_check('enterprise','echo ok')` y `('mobile','echo ok')`:
  16/16 nodos reales responden. **Bug real encontrado y corregido:** el
  código leía `result.returncode`, pero `vmlab_common.ssh_ops.SshResult`
  usa `.rc` — la prueba en vivo marcaba `ok=False` en nodos que en realidad
  respondían bien. Corregido, con una prueba unitaria nueva que fija el
  nombre real del campo para que no vuelva a pasar inadvertido.
- **Segundo hallazgo, no es un bug de inventario, es vocabulario distinto
  entre repos:** `fixed`/`peering` (nombres de `benign_lab.planner.DOMAINS`)
  no son `0 nodos` en `isp-ddos-ryu` — ese repo llama a esos mismos dominios
  `broadband`/`bgp` (`vmlab_common.inventory.ROLE_TO_DOMAIN`). Confirmado:
  `nodes_by_domain('broadband')` → `bng`, `suscriptor`;
  `nodes_by_domain('bgp')` → `br`, `peer-router`, `peer-router-2`, todos
  responden. Corregido con `lab_actions.DOMAIN_ALIASES = {'fixed':
  'broadband', 'peering': 'bgp'}`, aplicado solo donde se llama a
  `nodes_by_domain` (los playbooks de reconexión ya se llaman
  `fixed`/`peering`, no hacía falta tocarlos). 9 pruebas en total (las que
  no tocan red pasan siempre; las que sí, se saltan si no hay checkout de
  `isp-ddos-ryu` al lado).
- `scripts/capacity_probe.py path` contra `10.55.0.100` desde este control
  host: 100% pérdida — **esperado**, el control host está en la red de
  gestión (10.10.0.x), sin ruta al plano de datos de la víctima
  (10.55.0.x); confirma que no hay un atajo de red inesperado. La medición
  real debe correr desde un cliente (`ue1`, etc.), como ya hace
  `calibrate_capacity.py`.
- `config.resolve()` con un plan `ATTACK_FLOOD_V1` real contra
  `config/lab.connected.yaml`: genera el comando SSH correcto hacia `ue1`
  (namespace real, host real) sin ningún cambio en `resolve()`.
- `inspect-mapping` sobre `lab.connected.yaml`: mapeo completo, sin
  parámetros faltantes.
- **Hallazgo operativo importante:** el agente remoto vive en
  `/opt/benign-lab/agent.py` en cada VM, una copia separada sincronizada por
  `scripts/install_execution_agents.py` (ya existente, ya verifica que no
  haya experimentos activos antes de instalar). Mis cambios en `agent.py`
  (flood de ataque) **no tienen efecto en el laboratorio real hasta correr
  ese script** — pendiente, requiere tu confirmación explícita porque
  escribe en VMs reales y reinicia receptores.

**Fase 6 — Telemetría homogénea por dominio (#9) — mecanismo implementado, adaptadores parciales**
`benign_lab/domain_telemetry.py`: un esquema canónico de registro
(`domain, source, element, metric, value, unit, timestamp`) y
`from_interface_sample(...)`, adaptador real y probado para el formato que
ya usa `interface_monitor.py`. `from_mapping(...)` es el mecanismo
generalizado para los adaptadores que faltan (Peering/nfcapd, Mobile/KPM vía
E2): no necesitan arquitectura nueva, solo un diccionario de
`{campo_nativo: (métrica, unidad)}` una vez confirmado el formato exacto
contra el colector real — que no pude confirmar desde este entorno. 4
pruebas unitarias.

**Fase 7 — Consolidación de análisis y auditoría (#6, #10) — sin cambios de código, como se previó**
`experimental_analytics.py` y `detection_audit.py` ya exponen lo que la
tesis necesita (medias por semilla, IC 95%, matriz de confusión por
ventana, auditoría SSH autenticada); tras la Fase 0 no quedó ningún
endpoint de analítica huérfano. No hay nada más que hacer aquí hasta que
las Fases 1/3/4/5/6 estén validadas en el laboratorio real y se sepa qué
campos nuevos (path_quality, domain_telemetry, lab_actions) vale la pena
sumar a los reportes — prematuro antes de esa validación.

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

### Validado en el laboratorio real (2026-10-18)

Instalados `agent.py`/`supervisor.py`/`connection_pool.py` actualizados en
los 10 nodos reales vía `scripts/install_execution_agents.py` (`ue`, `ue2`,
`suscriptor`, `peer-router`, `ent-site-1..5`; receptor de `victim`
reiniciado, sin errores). Sin experimento activo antes y después.

Ataques reales contenidos vía CLI (`run-attack`) contra el laboratorio
real, mismo origen/destino/tasa/ventana (`ue1` → `victim-web`
10.55.0.100:9002, 50 pps objetivo, 5 s), uno por protocolo, el 2026-10-18 y
19 (sin experimento activo antes/después de cada corrida):

| Protocolo | Paquetes enviados | pps real | Estado |
|---|---|---|---|
| `udp_flood` | 250 | 49.98 | `completed`, sin error |
| `syn_flood` | 250 | 49.98 | `completed`, sin error |
| `icmp_flood` | 250 | 50.00 | `completed`, sin error |

`icmp_flood` confirma que el socket raw funciona con los privilegios reales
del namespace `ue1` (root dentro del namespace vía `ip netns exec`), sin
necesitar ningún cambio de permisos. Los tres protocolos de ataque de la
herramienta (udp_flood/syn_flood/icmp_flood) quedan validados de extremo a
extremo contra la topología real — primer tráfico de ataque generado por
la herramienta misma (no hping3).

### Confirmado contra la telemetría real del controlador (2026-10-19)

`detection_audit.sqlite` (captura continua en vivo, ya corriendo desde el
reinicio del servicio) registra para la ventana del `syn_flood`: el
umbral de referencia en el orquestador real es 10; la fuente de `ue1`
queda marcada como observada bajo `mobile` desde ~3.3 s de iniciado el
flujo, pero el registro de restricciones activas permanece vacío en los
31 ciclos revisados (±40 s) — ningún evento de decisión, solo muestreo
periódico. Consistente con la histéresis ya documentada (mínimo de
coincidencias dentro de una ventana corta antes de actuar): una sola
fuente, 5 s, detectada pero sin acumular suficientes coincidencias para
pasar a la etapa siguiente. Primera confirmación, con el flujo generado
por la herramienta misma (no hping3), del comportamiento sub-umbral ya
conocido de pruebas anteriores.

### Pendiente (siguiente incremento, requiere el laboratorio real)

1. ~~Validar `icmp_flood`/`syn_flood` contra VMs reales~~ — **resuelto**, ver
   la tabla arriba (los tres protocolos, `completed` sin error).
   Comportamiento de detección para `syn_flood` ya confirmado arriba.
2. Enganchar `scenario_series.py`/`api.py`: hoy `scenario_steps(...,
   source_ips, description)` asume un ataque externo manual. Añadir un modo
   `attack_source='internal'` que, en vez de esperar al operador, genere un
   `attack_plan` y llame `run_attack()` exactamente en la ventana declarada,
   y vuelque `started_at`/`finished_at` reales en `observed_attacks` del
   `run.json` (mejora directa de precisión del ground truth, que hoy depende
   de que el operador confirme a mano).
3. ~~Endpoints `/api/attacks/plan` y `/api/attacks/start`, vista en el
   panel~~ — **resuelto**, ver la sección "Exposición en el panel" en §6.

## 6. Estado y lo que falta

**Hecho (2026-10-18):** Fase 0 completa y pusheada (`f48aafc`, `ada5efd`).
Requisito #11 (ataques sin hping3) y Fase 2 (`sample_size.py`) pusheados
(`67b2928`). Fases 1, 3 (parcial), 4, 5 y 6 pusheadas (`e53a680`, `23d7822`,
`0412204`) — ver el detalle y lo probado/pendiente de cada una en §4.

**Exposición en el panel (2026-10-18, sin commitear todavía):** `api.py`
gana `/api/lab/power-states`, `/api/lab/connectivity/{domain}`,
`/api/lab/power/{domain}/{on|off}`, `/api/lab/recover/{domain}`,
`/api/attacks/plans` (crear/listar/leer), `/api/attacks/start`. Todo lo que
cambia estado real (power/recover/start) exige `confirm:true` en el cuerpo
Y se bloquea con 409 mientras haya un experimento activo (`manager.runs`
no terminal) — dos guardas independientes, no solo el `confirm()` de la
UI. Nueva vista **"Acciones de laboratorio"** en el panel
(`index.html`/`lab-actions.js`): estado de energía (solo lectura),
conectividad/encendido/apagado/recuperación por dominio con diálogo de
confirmación explícito, y un compositor de ataques (formulario simple +
JSON avanzado para multidominio) con lista de planes guardados y botón
"Lanzar" por plan. 11 pruebas nuevas (`test_lab_actions_api.py` con
`lab_actions` mockeado, `test_attacks_api.py` con un ataque real local de
extremo a extremo vía HTTP). 203 passed en el suite completo. **El servicio
en producción no se ha reiniciado:** nada de esto es visible en
`http://192.168.18.154:8780` hasta que se reinicie `benign-lab-web.service`
(ver §0 de esta sección).

**Lo único que de verdad falta y requiere el laboratorio real, no más
código a ciegas:**

1. Correr la Fase 1 (medición de delay/jitter/pérdida) en el nodo
   orquestador y confirmar que no rompe la campaña de throughput existente.
2. Con datos reales de la Fase 1, alimentar `sample_size.plan_sample_size()`
   y sustituir el orden fijo de 3 semillas en `comparison_steps()` por
   `interleaved_order()` con el N que resulte (Fase 3).
3. Con datos reales de falsos positivos, correr
   `threshold_recommendation.recommend_thresholds()` y aplicar con
   `ThresholdControl.apply()` (Fase 4).
4. ~~Arreglar que `nodes_by_domain('fixed')`/`('peering')` devuelven 0
   nodos~~ — **resuelto:** no era un dato faltante, era vocabulario distinto
   entre repos (`fixed`/`peering` aquí vs. `broadband`/`bgp` en
   `isp-ddos-ryu`); `lab_actions.DOMAIN_ALIASES` lo traduce, validado en
   vivo contra los 5 nodos reales de ambos dominios (Fase 5).
5. Confirmar el formato real de telemetría de Peering (nfcapd) y Mobile
   (KPM/E2) para escribirles un adaptador `from_mapping(...)` en
   `domain_telemetry.py` (Fase 6).
6. Conectar `attack_runner.py` con `scenario_series.py`/`api.py` para que el
   disparo del ataque en un escenario `attack_on`/`attack_off` deje de
   depender de que el operador lo confirme a mano (cierre de Fase 3, ya
   diseñado en §5 del requisito #11).

Ninguno de estos seis puntos se puede terminar bien desde este entorno:
todos necesitan el laboratorio real o datos que solo él produce.
