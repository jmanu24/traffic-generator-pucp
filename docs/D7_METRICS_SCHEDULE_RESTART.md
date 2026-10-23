# D7: A como indicador principal, tE independiente, orden sin confundir modo,
# estado inicial equiparado entre I y M

Rama `d7-metrics-schedule-restart` (generador; sin push). Controlador
(`orchestrator-ddos-pucp`) sin cambios — ninguno de los 5 cambios tocaba
lógica de detección/decisión/mitigación.

## 0. Qué cambió

1. **`response_metrics.py`'s A como indicador principal** en
   `experimental_analytics.report()`/`detail()`, con el mismo mecanismo
   genérico de emparejamiento M−I que ya usaba cualquier otra métrica
   (`METRICS['availability_pct']`); `delivery_pct` queda como indicador
   complementario, sin tocar. `response_metrics.json` se exporta en cada
   ZIP (`benign_lab/api.py`).
2. **`tE` independiente del detector** (`benign_lab/attacker_rate_monitor.py`,
   nuevo): cuenta en `pe` (`ovs-ofctl dump-flows br-ent`), aguas abajo de
   las reglas de bloqueo, para enterprise/mobile/fixed (peering usa la
   interfaz externa de `br`, no implementado, fuera de alcance de esta
   validación). Atribución de dominio/IP desde el propio plan de ataque +
   `cfg['nodes']`, nunca desde la salida del detector.
3. **Orden del esquema**: `im_campaign.build_schedule()` usa el mismo
   esquema que el piloto (`pilot_schedule.py`): semillas en el orden dado,
   orden aleatorio reproducible (semilla de RNG registrada) dentro de cada
   semilla — ya no agrupado por `detection_mode`.
4. **Estado inicial equiparado (Opción B)**: tras cada reinicio del
   controlador por cambio de modo, `runner.py` espera
   `POST_RESTART_SETTLE_S=5s` y verifica vía LAB_AUDIT que
   `active_blocks` esté vacío antes de permitir que la ejecución continúe
   (`verify_clean_forwarding_state()`); si no, la ejecución falla en vez
   de arrancar sobre un bloqueo residual sin confirmar.
5. **Covariables en `run.json`**: `seconds_since_restart`,
   `sequence_position` (sobrevive un reinicio del panel — se calcula de
   `len(self.runs)` cargado de disco), `panel_process_memory_kb_at_start`
   (`VmRSS` de `/proc/self/status`).

## 1. Pruebas unitarias

```
python3 -m pytest tests/ -q --ignore=tests/test_api.py --ignore=tests/test_attacks_api.py \
  --ignore=tests/test_batch_delete.py --ignore=tests/test_benchmark.py \
  --ignore=tests/test_lab_actions_api.py --ignore=tests/test_lifecycle_api.py \
  --ignore=tests/test_plan_cache.py --ignore=tests/test_plan_capacities.py \
  --ignore=tests/test_preparation_resources.py
# 296 passed, 10 failed
```
Los 10 fallos son preexistentes y no relacionados (9 por `fastapi` no
instalado en este entorno, 1 fixture de manifiesto obsoleta en
`test_pilot_schedule.py`) — confirmado comparando contra el mismo conjunto
de pruebas en el commit base (`5c7d33a`, antes de cualquier cambio de esta
rama), que da exactamente los mismos 10 fallos.

Pruebas nuevas por cambio: `test_experimental_analytics.py` (A como
métrica genérica, con/sin ventana de ataque confirmada, por dominio),
`test_response_metrics.py` (`compute_domain_availability`, integración
`attacker_rate_monitor`→`compute()` de punta a punta), `test_attacker_rate_monitor.py`
(parseo contra una captura real de `dump-flows`), `test_im_campaign.py`
(orden no agrupado por modo, reproducible, semillas nunca reordenadas),
`test_im_integration.py` (verificación post-reinicio, bloqueo residual
detectado y bloqueante), `test_runner.py` (covariables, `sequence_position`
sobrevive un reinicio del `Manager`).

## 2. Hashes del código desplegado

El panel (`benign-lab-web.service`, `192.168.18.154:8780`) corre en modo
editable directamente desde este checkout — no hay paso de despliegue
separado para el propio panel, solo reinicio del servicio para recargar el
proceso Python. `agent.py` SÍ se despliega por separado a cada VM de
ataque (ver §4).

| Archivo | SHA-256 |
|---|---|
| `benign_lab/api.py` | `82930c37...95a9f6d9c` |
| `benign_lab/experimental_analytics.py` | `e5f46c86...188d252bf` |
| `benign_lab/im_campaign.py` | `e72b794f...0d30a4dcf43` |
| `benign_lab/response_metrics.py` | `4a55c51b...39d7025` |
| `benign_lab/runner.py` | `d0aa8656...f222889fbf069cc9` |
| `benign_lab/attacker_rate_monitor.py` | `530d91a8...d634df5c3f7164d3` |
| `benign_lab/agent.py` | `c6dba7ff...e39cff49ff314ea` |
| `benign_lab/attack_runner.py` | `d5ce6e35...2b642c09e2b00108781b` |
| `benign_lab/baseline.py` | `7c4b2cad...632dd25d4b` |

`agent.py` confirmado idéntico en `ent-site-1` (`/opt/benign-lab/agent.py`,
mismo SHA-256) tras `scripts/install_execution_agents.py`.

## 3. Validación en vivo: C3 y C4, composición 1 enterprise, semilla 201

Ejecutor: `scripts/run_d7_c3c4_validation.py` (nuevo, basado en el mismo
patrón de `run_pilot.py`/`run_calibration_seeds.py` — un único `Manager`
real vía `/api/runs`, nunca uno propio). Resultado completo en
`.runtime/benign-lab/calibration/d7_c3c4_validation.json`.

**Intentos 1–3 (descartados, no borrados — ver `.runtime/benign-lab/data/runs/`
de los IDs citados): fallaron por un bug preexistente, no relacionado con
estos 5 cambios**, encontrado durante esta validación:
`agent.py`'s `syn_flood` mata el proceso `sudo -n hping3 -...` con
`SIGKILL` esperando que eso termine también al propio `hping3` — pero con
`use_pty` activo, `sudo` bifurca un monitor en vez de reemplazarse con
`exec()`, y `SIGKILL` (no capturable) mata al monitor sin que este pueda
reenviar nada a su hijo, dejando `hping3` huérfano, floodeando
indefinidamente. Confirmado en vivo: 8+ procesos `hping3` de ejecuciones
pasadas (algunas de días atrás, de las composiciones 2/3 multidominio)
seguían corriendo en `ent-site-1`, `ent-site-2`, `ue` y `suscriptor`.

**Corregido** (mismos 3 archivos, con pruebas — §1, §2):
- `agent.py`: tras matar el wrapper `sudo`, remata explícitamente cualquier
  `hping3` sobreviviente con el mismo patrón de puerto/sport (`pkill -9 -f`).
- `attack_runner.py`: barrido preventivo (`_sweep_stale_attack_processes`)
  que mata cualquier `hping3` residual en cada host de ataque antes de
  lanzar el propio ataque de la ejecución — nunca bloqueante (mejor
  esfuerzo).
- `baseline.py`: `BaselineGuard.clear_residual_openflow_drops()` borra
  activamente (no solo detecta) cualquier regla de drop residual en `pe`
  con la forma exacta `priority=100,...,actions=drop` antes de permitir
  que una ejecución arranque; sigue fallando si una regla sobrevive su
  propio intento de borrado.

Confirmado en vivo tras el fix: barrido completo en los 9 hosts de ataque
(`ent-site-1..5`, `ue`, `ue2`, `suscriptor`, `br`/`peer-router`) y en `pe` —
cero procesos, cero reglas residuales — y el siguiente par C3/C4
(`20261022T015052-aa942db2`/`20261022T015651-a10720b3`) corrió sin ese
problema. Ese par sí quedó afectado por la ráfaga de §3.1 (todavía en curso
en ese momento) y se descarta como resultado final por eso, no por el bug
ya corregido; se repitió una vez más (§3.2) con el entorno ya confirmado
limpio también de la ráfaga.

### 3.1. Hallazgo adicional durante la investigación: ráfaga de
mitigación lab-wide

Entre los intentos, un reinicio del controlador (disparado por el cambio
de modo I→M) hizo que `active_blocks` se reportara vacío (proceso nuevo,
sin historial) mientras el tráfico de ataque huérfano de `fixed1`
(`10.20.0.201`, fuente real en las composiciones 2/3) seguía activo —
el controlador lo "redescubrió" de inmediato y disparó mitigación real
contra prácticamente todas las IPs benignas de mobile/broadband/bgp en
simultáneo (confirmado: `fixed1`/`ue1`/`ue2` son fuentes de ataque
reales en esas composiciones, no falsos positivos). Se disipó por
completo al limpiar los procesos huérfanos (§ anterior) — confirmado:
cero eventos de detección/mitigación durante 20+ minutos antes del
intento 4.

### 3.2. Resultados finales (par repetido con el entorno ya confirmado
limpio antes y durante, sin la ráfaga de §3.1)

| | C3 (I) `20261022T044905-d2321715` | C4 (M) `20261022T045458-e55d4e2d` |
|---|---|---|
| estado | `completed_with_errors`* | `completed_with_errors`* |
| A (availability_pct) | 0,0 % | 0,0 % |
| tD (censurado) | sí — `no_matching_detection` | no — TD=3,29 s |
| tO (censurado) | sí — `no_matching_mitigation` | no — TO=0,008 s |
| tE (censurado) | sí — `no_independent_rate_series` (sin tO no hay ventana base) | sí — `no_samples_in_tA_tO_baseline_window` (TO casi instantáneo, sin margen para muestrear la base) |
| dominio mitigado | — | enterprise |
| `sequence_position` | 190 | 191 |
| `seconds_since_restart` | 13,97 s | 15,69 s |
| `panel_process_memory_kb_at_start` | 1 554 436 | 1 608 180 |
| `detection_mode_verification.controller_restarted` | true | true |
| `detection_mode_verification.post_restart_forwarding_state.active_blocks` | `{}` | `{}` |

\* `completed_with_errors`: eventos individuales con un pequeño déficit de
bytes planeados vs entregados (`Scheduled payload shortfall`), no un fallo
de la ejecución en sí — mismo patrón ya visto en ejecuciones piloto previas.

**tE con un valor real (no censurado) se obtuvo en el intento previo
(entorno todavía con la ráfaga residual, descartado por eso del resultado
final pero válido como prueba de que el mecanismo funciona)**:
`20261022T015651-a10720b3` (C4), TD=12,2 s, TO=1,66 s, `tE.reason`=
`threshold_crossed_but_not_sustained_for_S` tras cruzar el umbral pero sin
sostenerlo los S=5 s completos — causa identificada: la entrada de la
regla de reenvío del atacante en `pe` (`idle_timeout=60s`) desaparece de
`dump-flows` una vez bloqueada (sin tráfico nuevo que la refresque), así
que la serie de tasa simplemente deja de producir muestras en vez de
confirmar explícitamente una base sostenida en cero — una limitación real
y ahora documentada del punto de medición elegido (recuento por presencia/
ausencia de la regla de reenvío), no un error de `attacker_rate_monitor.py`.
El colector en sí funcionó sin un solo error en sus 43 muestras durante
los 202 s de esa ejecución.

### 3.3. Por qué A = 0,0 % en ambas condiciones (no es un bug de D7)

Inspeccionando `detection_events.jsonl` del intento 4 se encuentra una
corrección cruzada entre dominios activa en C4 (modo M,
`DETECTION_CROSS_DOMAIN_CORRELATION=true`): el mismo evento de detección
de `enterprise` incluye como "sources" IPs de `mobile`/`broadband`/`bgp`
no involucradas en este plan de ataque (`composition1_enterprise` solo usa
`ent-site-1`), y dispara `mitigation_issued`/`mitigation_release` cíclicos
contra ellas cada ~10-20 s durante toda la ventana de ataque.

Pero el `delivered_pct` por ventana de 5 s, calculado directamente con
`compute_domain_availability('enterprise', ...)` sobre los eventos propios
de enterprise, es **plano en ~84-85 % en TODAS las ventanas del run — antes,
durante y después del ataque, con o sin mitigación activa**
(`TD=3,29s`/`TO=0,008s`, casi instantáneo). Esto descarta que el ataque o
la mitigación expliquen A=0%: la propia entrega benigna base de esta
composición/semilla para enterprise nunca alcanza el umbral D=90% definido
en el diseño, con o sin ataque. **A no puede discriminar I de M en esta
combinación particular (semilla 201, composition1_enterprise) porque el
umbral D=90% nunca es alcanzable por este plan benigno**, exactamente la
misma conclusión que `docs/PILOT_DIAGNOSIS.md` §0/§7 ya documentó para C3/C4
del piloto completo ("A no puede discriminar I de M mientras el detector
bloquee tráfico benigno"; A=0,0% en C3 y 3,2% en C4 allí también). No es un
hallazgo nuevo introducido por estos 5 cambios — es una reconfirmación en
vivo, con datos frescos, de un límite de diseño ya conocido y ya atribuido
(criterio distribuido de respaldo sin calibrar, `DIST_PPS_THRESHOLD=300`).

## 4. Supuestos

- `agent.py`'s reap vía `pkill -9 -f 'hping3 --syn -p {port} -s {sport_base}'`
  es seguro porque port/sport_base son constantes fijas de esta rama de
  código (no por-ejecución) — cualquier proceso que calce ese patrón
  exacto fue lanzado por este mismo agente, nunca por otra cosa en esas VMs.
- `baseline.py`'s borrado activo asume que CUALQUIER regla
  `priority=100,...,actions=drop` en `br-ent` es mitigación de este
  arnés contra tráfico de ataque propio — nunca una restricción externa
  real que debiera persistir. Mismo supuesto que ya hacía el chequeo
  anterior (solo detectaba), ahora además actúa sobre él.
- El hallazgo de A=0% se limita a esta semilla/composición; no se generaliza
  a otras semillas/composiciones del futuro experimento completo sin
  repetir este mismo análisis por cada una.

## 5. Criterio de la VALIDACIÓN

El punto de control pedía *mostrar* A, tE y las covariables en una
ejecución real de C3 y una de C4 — no un umbral numérico de aprobación
(a diferencia de D7/4.4.2). **Mostrado**: ambos indicadores y las 3
covariables aparecen con valores reales (o censura explícita con motivo)
en ambas ejecuciones del intento 4, y tE con un valor numérico real se
confirmó en una ejecución previa bajo las mismas 3 piezas de código. El
mecanismo de los 5 cambios está validado en vivo de punta a punta; el
resultado sustantivo de A en esta combinación particular está limitado
por un factor de diseño preexistente y ya documentado, no por estos
cambios.

## 6. Pendiente

Commit/push: no realizado — pendiente de confirmación.
