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

**Etapa B — Tamaño de muestra.** `sample_size.plan_sample_size()` con la
salida de A y la precisión objetivo de §3 → N semillas, con la métrica
limitante documentada.

**Etapa C — Generación de planes.** N planes benignos
(`generate-plan`) + planes de ataque por escenario (`generate-attack-plan`,
tabla en §4).

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
Dimensiona el tiempo total de la campaña — vale la pena tenerlo presente
al fijar N en la Etapa B.

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
