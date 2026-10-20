# Regeneración de planes de ataque sobre umbrales calibrados

Tres composiciones de la tesis, con tasas expresadas como múltiplos de
`SYN_THRESHOLD = 76.82` (`docs/THRESHOLD_CALIBRATION_RESULT.md`).
`DECISION_THRESHOLD` (1,5) sin tocar. Generado con
`scripts/generate_regenerated_attack_plans.py` (offline: solo calcula y
guarda planes, nunca toca el laboratorio real). Planes en
`data/attack_plans/*.json`, manifiesto en `data/attack_plans_manifest.json`.

## Decisión D4 (móvil en la agregación): A + B

El prompt pedía A **y, además**, B — ambos se hicieron:

- **A (documentado aquí)**: `detection/engine.py`'s `_protocol_rate()`
  excluye a mobile de `trigger_pps` para UDP/ICMP (solo su señal KPM
  cuenta ahí); SYN siempre incluye a mobile. **Por eso las tres
  composiciones de este documento usan SYN en los 4 dominios** — es el
  único vector donde la tasa de mobile es comparable y combinable con la
  de los otros tres dominios en la fórmula de puntuación. Una composición
  UDP/ICMP que quisiera incluir a mobile no podría, con el motor como
  está, salvo que mobile cruce su propio umbral de KPM de forma
  independiente.
- **B (preparado, NO aplicado)**: rama `mobile-udp-icmp-aggregation-option`
  en `orchestrator-ddos-pucp` (commit `f96df1f`), flag
  `MOBILE_INCLUDED_IN_UDP_ICMP_AGGREGATE` (default `false`, comportamiento
  idéntico al actual) en `config/settings.py`, que de activarse sumaría la
  tasa de mobile en `trigger_pps` de UDP/ICMP también. 7 pruebas en
  `detection/test_mobile_udp_icmp_aggregate_option.py`, las 180 de la
  suite completa sin romperse. Pendiente de tu decisión de usarlo o no.

## Vector

**SYN en los cuatro dominios**, por defecto, en las tres composiciones
(no solo en la composición 1, que es donde el prompt lo menciona
explícitamente) — necesario para que mobile participe de forma uniforme
en las composiciones 2 y 3 también (ver D4-A).

## Semilla de prueba

El prompt pide validar "sobre la semilla de prueba" sin nombrarla.
**Supuesto**: semilla **201**, elegida por no haber sido usada en ninguna
corrida de `THRESHOLD_CALIBRATION` (que usó 101-110) — evita cualquier
contaminación cruzada entre la calibración y esta validación.

## Las tres composiciones

Puntuación efectiva estimada con `benign_lab/decision_score_estimator.py`
(reimplementación independiente y pura de la fórmula real del motor
— `score × confianza × peso`, nunca el camino de producción — con 11
pruebas unitarias, `benign_lab/test_decision_score_estimator.py`).

### Composición 1 — control, vector único (una por dominio)

k = 4,75× `SYN_THRESHOLD` = 364,895 pps, 1 fuente, 1 dominio por plan (4
planes independientes: enterprise/fixed/mobile/peering).

| Dominio | Fuente | pps/fuente | Agregado | f | Σ | #fuentes | score | confianza | peso | final (I=M) | decide |
|---|---|---|---|---|---|---|---|---|---|---|---|
| enterprise | ent-site-1 | 364,895 | 364,895 | 4,75 | 364,895 | 1 | 4,75 | 0,475 | 1,0 | 2,256 | sí |
| fixed | fixed1 | 364,895 | 364,895 | 4,75 | 364,895 | 1 | 4,75 | 0,475 | 1,0 | 2,256 | sí |
| mobile | ue1 | 364,895 | 364,895 | 4,75 | 364,895 | 1 | 4,75 | 0,475 | 1,0 | 2,256 | sí |
| peering | peer-flow* | 364,895 | 364,895 | 4,75 | 364,895 | 1 | 4,75 | 0,475 | 1,0 | 2,256 | sí |

Un solo dominio por plan ⇒ I y M dan exactamente el mismo resultado
(nada que correlacionar entre dominios). Capacidad real verificada
(`ATTACK_CAPACITY_MEASUREMENT.md`): mobile SYN máximo 5 116 pps, el menor
de los cuatro — 364,9 pps está muy por debajo, factible de sobra.

### Composición 2 — multidominio sobre el umbral local

1 dominio ≥1,5× (elegido 4,5×, con margen: el límite de
score²/10≥1,5 ⇒ score≥3,873× para que el camino "atacante único" decida,
no solo el mínimo literal de 1,5× del prompt) + 2 dominios bajo (0,3×).

| Dominio | Rol | Fuente | k | pps |
|---|---|---|---|---|
| enterprise | sobre umbral | ent-site-1 | 4,5 | 345,69 |
| fixed | bajo umbral | fixed1 | 0,3 | 23,046 |
| peering | bajo umbral | peer-flow* | 0,3 | 23,046 |

Σ = 391,782 pps, 3 fuentes, 3 dominios.

| Modo | Camino | score | confianza | peso | final | decide |
|---|---|---|---|---|---|---|
| **I** (enterprise aislado) | atacante único | 4,5 | 0,45 | 1,0 | 2,025 | **sí** |
| I (fixed/peering aislados) | — | 0,3 | — | — | — | no (bajo umbral, ningún camino dispara) |
| **M** (los 3 fusionados) | atacante único (3 fuentes < `DIST_MIN_SOURCES`=5) | 5,099 | 0,510 | 1,0 | 2,600 | **sí** |

Con solo 3 fuentes totales, M **no** cruza a `MULTIDOMAIN_DISTRIBUTED_ATTACK`
(necesita ≥5 fuentes distintas) — se clasifica como `SYN_FLOOD` atribuido
al agregado total. Tanto I como M deciden: este escenario no depende de
coordinación entre dominios (un dominio ya rompe su propio umbral), a
propósito, para contrastar con la composición 3.

### Composición 3 — multidominio bajo el umbral local (confirmatoria)

6 fuentes (no 5, para no quedar justo en el mínimo de
`DIST_MIN_SOURCES`), 3 dominios, 2 fuentes/dominio, f ∈ {0,9; 0,7; 0,5},
repartido parejo entre las 2 fuentes de cada dominio (entropía alta).

| Dominio | f | Agregado | Fuentes | pps/fuente |
|---|---|---|---|---|
| enterprise | 0,9 | 69,138 | ent-site-1, ent-site-2 | 34,569 |
| fixed | 0,7 | 53,774 | fixed1, fixed2 | 26,887 |
| mobile | 0,5 | 38,41 | ue1, ue2 | 19,205 |

Σ = 161,322 pps (2,10× `SYN_THRESHOLD`, ≥1,3× pedido), 6 fuentes,
entropía normalizada = **0,9846** (≥0,7).

| Modo | Camino | score | confianza | peso | final | decide |
|---|---|---|---|---|---|---|
| **I** (cada dominio aislado, 2 fuentes, agregado<umbral) | ninguno | — | — | — | — | **no**, en los 3 dominios |
| **M** (los 6 fusionados) | distribuido, multidominio | 2,101 | 1,0 (saturada: 0,9846×1,3=1,28→1,0) | 1,4 | **2,94** | **sí** |

**Este es el resultado central esperado**: en I, cada dominio por
separado queda por debajo de su propio umbral (f<1 en los tres) y con
solo 2 fuentes nunca alcanza `DIST_MIN_SOURCES`, así que **no se detecta
nada** en ningún dominio. En M, al fusionar los 6 orígenes hacia el mismo
destino, la suma supera el umbral global y cruza
`DIST_MIN_SOURCES`/`DIST_ENTROPY_THRESHOLD`, clasificando correctamente
como `MULTIDOMAIN_DISTRIBUTED_ATTACK` y decidiendo mitigar. Es el
contraste I-vs-M que esta composición está diseñada para confirmar — no
un fallo a corregir.

## Ninguna composición falla en M

Las tres composiciones alcanzan `DECISION_THRESHOLD` (1,5) en modo M
(`scripts/generate_regenerated_attack_plans.py` imprime una advertencia
explícita si alguna no lo hiciera; no se imprimió ninguna). No hay nada
que avisarte en este punto.

## Planes guardados

`data/attack_plans/composition{1_enterprise,1_fixed,1_mobile,1_peering,
2_multidomain_over_threshold,3_multidomain_under_threshold}.json`, cada
uno con su `plan_hash`, listados en `data/attack_plans_manifest.json`.
Cada plan embebe su propio cálculo (tasa por fuente, agregado por
dominio, f, Σ, #fuentes, puntuación esperada en I y M) en su campo
`description` (JSON serializado).

## Pendiente — validación (requiere tu confirmación antes de tocar el laboratorio real)

Punto de control del prompt: correr cada plan una vez, **pipeline
suspendido** (`BaselineGuard`, nunca `pipeline=enabled`), sobre la semilla
de prueba (201), y verificar:

1. `attack_pps_actual` de cada fuente dentro de ±10 % del objetivo.
2. La tasa agregada por dominio que registra el controlador
   (`observed_rates`, instrumentación del Prompt 2) dentro de ±15 % de lo
   planificado.
3. En la composición 3, cada dominio por debajo de su umbral local y la
   suma por encima.

Esto **no se ha ejecutado todavía** — lo hago en cuanto confirmes que
puedo tocar el laboratorio real (los 6 planes lanzan tráfico real desde
nodos reales, aunque sea con la detección suspendida).
