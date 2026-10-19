# Plan de ejecución — validación de la tesis

Este documento secuencia cómo llevar la herramienta (ya construida y
validada pieza por pieza) a una campaña de validación con rigor
estadístico para la tesis. Responde directamente la pregunta: **sí, las
tres fases que faltan del roadmap (1, 3, 4) no son trabajo aparte — son
las entradas de esta campaña.** Sin ellas, la campaña se puede correr
igual, pero con un tamaño de muestra arbitrario en vez de uno derivado, y
con los umbrales actuales en vez de unos sustentados en datos propios.

## 0. Qué ya está listo (no bloquea nada de esto)

- Generación determinista de planes benignos (`planner.py`) y de ataque
  (`attack_planner.py`, 3 protocolos validados en vivo: `udp_flood`,
  `syn_flood`, `icmp_flood`).
- Ejecución real contra el laboratorio, con ground truth de 5 s
  (`runner.Manager`, `attack_runner.py`).
- Análisis estadístico (`experimental_analytics.py`: medias por semilla,
  IC 95% con t de Student, matriz de confusión por ventana).
- Acciones de laboratorio (`lab_actions.py`): estado de energía,
  conectividad, recuperación por dominio — los 4 dominios tienen playbook.
- Panel con todo lo anterior expuesto (`/api/lab/*`, `/api/attacks/*`).

## 1. Decisiones ya tomadas (2026-10-19)

| Decisión | Resuelto |
|---|---|
| Alcance | **Matriz factorial completa**: 3 vectores (udp/syn/icmp_flood) × 4 dominios = 12 escenarios individuales + multidominio distribuido |
| Precisión objetivo | **Default propuesto** (tabla en §3), a confirmar antes de ejecutar |
| Umbrales | **Recalibrar con datos propios** — la Fase 4 entra en el camino crítico, no en paralelo |
| Repertorio de ataque | **Recetas ya validadas** (tabla en §4) |

Como se eligió recalibrar umbrales, la Fase 4 deja de ser paralela: las
corridas `B0` con pipeline activo (que miden la línea base de falsos
positivos) tienen que terminar **antes** de aplicar los umbrales nuevos, y
las corridas de ataque-con-mitigación tienen que correr **después**, ya
con los umbrales recalibrados. El orden queda así:

```
Fase 1 (calibración real: throughput/delay/jitter/pérdida)
   ▼
Fase 2 (sample_size.py, YA HECHA) → N semillas
   ▼
Generación de N planes benignos + planes de ataque (receta validada)
   ▼
Corridas B0 + B0-pipeline-activo (× N semillas, los 4 dominios)
   │  → produce baseline_pps_by_domain (falsos positivos)
   ▼
Fase 4: recommend_thresholds() → aplicar con ThresholdControl.apply()
   ▼
Corridas B0+attack sin mitigación + B0+attack con mitigación
   │  (ya con los umbrales recalibrados; usa attack_runner, manual por
   │    ahora — Fase 3b es la única pieza opcional de todo esto)
   ▼
Análisis (Fase 7, YA HECHA) → reporte final
```

## 2. Etapas

**Etapa A — Calibración real (Fase 1) — completada 2026-10-19.**
`calibrate_capacity.py --without-mitigation --fresh` contra el
laboratorio real. 28 rounds de throughput, `path_quality` sin errores en
los 4 dominios; mitigación suspendida durante la corrida y confirmada
restaurada después (`pipeline_active: true`, `active_blocks: {}`,
verificado independientemente del mensaje del propio script).

| Dominio | Throughput (ref.) | RTT medio | Jitter medio | Pérdida |
|---|---|---|---|---|
| enterprise | 1241.91 Mbps | 2.95 ms | 7.27 ms | 0% |
| peering | 900.68 Mbps | 3.27 ms | 3.76 ms | 0% |
| mobile | 5.18 Mbps | 104.49 ms | 32.00 ms | 0% |
| fixed | 114.16 Mbps | 2.02 ms | 3.89 ms | 0% |

Mobile tiene un RTT ~35× mayor que el resto — coherente con la pila de
radio real (5G/O-RAN), no un error de medición. Pérdida 0% en los cuatro
(muestra pequeña, 30 probes por fuente a 0.2s de intervalo — no descarta
pérdida bajo carga sostenida, solo en el patrón de sondeo usado aquí).
Datos crudos en `.runtime/benign-lab/calibration/measurements.json`
(`probe_sha256` `0bbe3657...`); pendiente copiar la revisión final a
`docs/CAPACITY_MEASUREMENTS.json` cuando se confirme (paso manual, no
automático, según `docs/CAPACITY_CALIBRATION.md`).

**Hallazgo: throughput DL de `fixed` es inestable (183/30/227/114/28 Mbps
en las 5 repeticiones) — causa raíz confirmada con monitoreo en vivo de la
tabla de flujos de OpenFlow en `pe` (no es ruido de muestreo).** La regla
que el controlador instala reactivamente para el flujo `fixed`↔víctima
tiene `hard_timeout=2`: se elimina a los 2 segundos sin importar si el
flujo sigue activo, forzando una re-aprendizaje (vuelta a *table-miss*)
cada vez. Reproducido dos veces con un solo suscriptor y un solo stream
(sin concurrencia): reset a los ~2.3-2.4 s en ambas, coincidiendo
exactamente con el `hard_timeout`. El bypass temporal que `enterprise` ya
recibe durante su calibración usa `hard_timeout=900` (15 min) — por eso
enterprise es estable y fixed no. **Es un problema del controlador real
(`orchestrator-ddos-pucp`), no de esta herramienta ni de esta
calibración**: cualquier conexión larga y de alto throughput en `fixed`
se vería afectada igual, dentro o fuera de un experimento de calibración.
No se modificó nada del controlador ni de `pe`; la reproducción fue de
solo lectura/observación (un receptor temporal en `victim`, un flujo de
prueba desde `fixed1`, un *poller* de `ovs-ofctl dump-flows` en `pe`),
todo limpiado al terminar.

**Fix aplicado y recalibración — 2026-10-19.** El bug de validación de
flujos NAT'd (`fixed`/`mobile`, ver hallazgo arriba) se corrigió en
`orchestrator-ddos-pucp`. Se repitió exactamente la misma calibración
(`calibrate_capacity.py --without-mitigation --fresh`) contra el
laboratorio real para confirmar la resolución:

| Dominio | Throughput (ref.) | RTT medio | Jitter medio | Pérdida |
|---|---|---|---|---|
| enterprise | 1259.58 Mbps | 3.18 ms | 8.02 ms | 0% |
| peering | 1165.72 Mbps | 2.13 ms | 3.79 ms | 0% |
| mobile | 5.50 Mbps | 109.06 ms | 32.71 ms | 0% |
| fixed | 1048.49 Mbps | 1.11 ms | 0.35 ms | 0% |

`fixed` DL: **1214.8 / 1022.2 / 1210.9 Mbps** en las 3 repeticiones
iniciales (máx/mín = 1.19, por debajo del umbral 1.3 que dispara
repeticiones extra) — ya no activa el camino de inestabilidad. Pasó de
necesitar N=246 semillas (Etapa B, antes del fix) a un comportamiento
estable comparable a `enterprise`/`peering`. `mobile` se mantiene bajo
(~5.5 Mbps UL) por la pila de radio real, no por el bug — esperado y sin
cambios respecto a la primera corrida.

Queda un `ConnectionResetError` residual, aislado y de menor escala (5
ocurrencias desde `10.92.0.2`, la IP NAT'd de `fixed`, durante toda la
corrida de ~28 rounds) — no relacionado con el bug de `hard_timeout=2`
corregido (no coincide con el patrón de ~2.3-2.4s por conexión, y no
impidió que ninguna repetición de `fixed` necesitara reintentos). Se dejó
registrado, no bloquea continuar a la Etapa B.

Datos crudos de esta segunda corrida en el mismo
`.runtime/benign-lab/calibration/measurements.json` (misma `probe_sha256`
`0bbe3657...`, corrida sobrescrita tras archivar la anterior con
`--fresh`); la tabla de la primera corrida arriba queda como evidencia
histórica del hallazgo, no como referencia vigente para la Etapa B.

**Etapa B — Tamaño de muestra — completada 2026-10-19.**
`sample_size.required_seeds()` aplicado por dominio/dirección/métrica
sobre la segunda corrida de calibración (post-fix), con la precisión
objetivo de §3 (throughput ±10%, RTT ±15%, jitter ±20%, pérdida ±1pp
absoluto):

| Dominio | N (máx. entre métricas) | Métrica limitante |
|---|---|---|
| enterprise | 11 | jitter |
| fixed | 7 | throughput DL |
| mobile | 10 | throughput UL |
| peering | 8 | throughput UL y DL (empate) |

**N global de la campaña = 11** (el máximo entre dominios, para que la
misma serie de semillas satisfaga la precisión objetivo en los cuatro
dominios a la vez; limitante: jitter de `enterprise`). Desglose completo
por métrica:

| Dominio | throughput UL | throughput DL | RTT | Jitter | Pérdida |
|---|---|---|---|---|---|
| enterprise | 2 | 3 | 6 | 11 | sin variabilidad (0% en las 5 muestras) |
| fixed | 3 | 7 | 5 | 5 | sin variabilidad |
| mobile | 10 | 4 | 4 | 4 | sin variabilidad |
| peering | 8 | 8 | — (1 sola fuente, sin réplicas) | — | sin variabilidad |

Pérdida no genera N en ningún dominio porque las 5 corridas de
`path_quality` midieron 0% de pérdida sin variabilidad — no hay señal
para derivar un tamaño de muestra de esa métrica con los datos actuales;
se mantiene el objetivo de §3 (±1pp) como validación posterior, no como
insumo de N. `peering` no tiene RTT/jitter por dominio porque solo hay
una fuente (`peer-flow*`), no una muestra de fuentes distintas como en
los otros tres.

**Comparación con el N=246 previo al fix**: antes de corregir el bug NAT,
`fixed` DL era la métrica limitante de toda la campaña (N=246,
impracticable). Tras el fix, `fixed` DL baja a N=7 y la métrica limitante
pasa a ser `enterprise` jitter (N=11) — un orden de magnitud menor y ya
viable para ejecutar la campaña completa.

**Etapa C — Generación de planes — completada 2026-10-19.** 11 planes
benignos (`generate-plan`, semillas 1-11, 180s, `config/lab.connected.yaml`)
guardados en `data/plans/benign-seed{1..11}.json`. 13 planes de ataque
(`generate-attack-plan`): los 12 escenarios factoriales (tabla en §4,
fuente única por dominio, 50 pps, ventana 60-120s dentro de un plan de
180s) en `data/attack_plans/factorial-{dominio}-{protocolo}.json`, más el
multidominio (`ue1`+`ue2`, `fixed1`+`fixed2`, `ent-site-1`; 5 fuentes/3
dominios, `udp_flood` ~50pps c/u) en
`data/attack_plans/multidomain-distributed.json`. El `seed` de cada plan
de ataque solo determina el hash de `event_id` (no hay aleatoriedad en
tasa/tiempos, que vienen explícitos por flow) — por eso un solo plan por
escenario basta; en la Etapa F cada uno se repite junto con cada una de
las 11 semillas benignas, no se genera una variante de ataque por
semilla. Hashes de planes de ataque:

| Escenario | `plan_hash` (12 primeros hex) |
|---|---|
| mobile / udp_flood | `938cfc684438` |
| mobile / syn_flood | `c087eb23a721` |
| mobile / icmp_flood | `7ab72b68dc1b` |
| fixed / udp_flood | `5d43102a870b` |
| fixed / syn_flood | `907e87476d8f` |
| fixed / icmp_flood | `ada136d0d2f7` |
| enterprise / udp_flood | `444a6b786e37` |
| enterprise / syn_flood | `71cf31b2871c` |
| enterprise / icmp_flood | `f8215ed8063e` |
| peering / udp_flood | `a29d2320d7a3` |
| peering / syn_flood | `417fede93d3b` |
| peering / icmp_flood | `5f02e3e3d0e1` |
| multidominio distribuido | `d09e1eadbcc7` |

**Etapa D — Línea base de falsos positivos.** Correr `B0` (pipeline
suspendido) y `B0` con pipeline activo para los N × 4 dominios. La
segunda produce `baseline_pps_by_domain` para la Etapa E.

**Etapa E — Recalibración de umbrales (Fase 4).**
`threshold_recommendation.recommend_thresholds(baseline_pps_by_domain,
margin, dist_margin)` → revisar la sugerencia → aplicar con
`ThresholdControl.apply()`. Los márgenes (`margin`, `dist_margin`) son
otra decisión de tesis (cuánto margen sobre la línea base antes de
considerar ataque) — pendiente, ver §3.

**Etapa F — Campaña de ataque.** `B0+attack` sin mitigación y
`B0+attack` con mitigación (umbrales ya recalibrados), × N semillas, orden
intercalado (`interleaved_order`), para los 12 escenarios individuales
(matriz factorial, §4) + el multidominio. Ataque disparado con
`attack_runner` (manual, CLI o panel).

**Etapa G — Análisis (Fase 7, ya existe).** `experimental_analytics.py`:
medias, IC 95%, matriz de confusión por ventana; exportar reporte.

## 3. Precisión objetivo — confirmada (2026-10-19)

| Métrica | Precisión objetivo | Razón |
|---|---|---|
| Throughput | ±10 % relativo a la media | Margen típico para capacidad medida con generadores de software, no hardware dedicado (ver `docs/METHODOLOGY.md`) |
| Delay (RTT) | ±15 % relativo | RTT en LAN/VM tiene más ruido relativo que el throughput agregado |
| Jitter | ±20 % relativo | Es la métrica más ruidosa típicamente; exigir más precisión dispararía N sin aportar |
| Pérdida | ±1 punto porcentual absoluto | Pérdida suele estar cerca de 0%; un objetivo relativo no tiene sentido ahí |

Margen de los umbrales recalibrados (Etapa E): `margin=1.5` (umbral por
dominio = 1.5× el pico observado), `dist_margin=2.0` (DIST_PPS = 2.0× la
suma de líneas base) — confirmados.

## 4. Repertorio de ataque — confirmado

| Escenario | Dominio(s) | Fuente(s) | Protocolo | Tasa | Estado |
|---|---|---|---|---|---|
**Matriz factorial completa (2026-10-19): los 3 vectores en los 4 dominios,
12 escenarios individuales** — no un protocolo representativo por
dominio. Misma tasa (50 pps) y misma fuente única por dominio en los tres,
para que sean comparables entre sí.

| Dominio | `udp_flood` | `syn_flood` | `icmp_flood` |
|---|---|---|---|
| **mobile** (`ue1`) | Diseño listo, sin correr formalmente (hubo una corrida de validación técnica 2026-10-18, no parte de esta campaña) | **Validado en vivo** 2026-10-19: detectado, no mitigado (sub-umbral de hits) | **Validado en vivo** 2026-10-19: `completed`, 250 paquetes, sin error |
| **fixed** (1 suscriptor) | Diseño listo, sin correr | Diseño listo, sin correr | Diseño listo, sin correr |
| **enterprise** (1 sitio) | Diseño listo, sin correr | Diseño listo, sin correr | Diseño listo, sin correr |
| **peering** (1 fuente) | Diseño listo, sin correr | Diseño listo, sin correr | Diseño listo, sin correr |

12 escenarios individuales × N semillas (Etapa B) × 2 condiciones
(sin/con mitigación, Etapa F) = 24 × N corridas solo para la parte
individual, antes del multidominio y de B0/B0-pipeline-activo (Etapa D).
Con N=11 (Etapa B, resuelto 2026-10-19): **264 corridas** para la parte
individual de la Etapa F, más el multidominio y las N×4 de la Etapa D.

| Escenario multidominio | Dominios | Fuentes | Protocolo | Tasa |
|---|---|---|---|---|
| Distribuido | **mobile+fixed+enterprise** | ~5 fuentes/3 dominios | `udp_flood` | ~50 pps cada una |

El multidominio queda con un solo vector (`udp_flood`, receta ya conocida
de pruebas anteriores) — la matriz factorial de §4 es para los escenarios
individuales; extenderla al multidominio (otros vectores, incluir
`peering`) sería una ampliación aparte, no parte de esta campaña.

## 5. Diseño cerrado — listo para ejecutar

Todas las decisiones de diseño quedaron confirmadas en §1, §3 y §4. El
siguiente paso es empezar la ejecución por la Etapa A (calibración real)
cuando se decida tocar el laboratorio.
