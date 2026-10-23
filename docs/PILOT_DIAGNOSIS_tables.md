
### 0. Inventario de las 60 ejecuciones

| condición | válidas | no válidas (conservadas, excluidas) |
|---|---|---|
| C1-I | 3 | 0 |
| C1-M | 3 | 0 |
| C2 | 18 | 0 |
| C3 | 15 | 3 |
| C4 | 13 | 5 |

| run | pos | seed | cond | escenario | estado | motivo |
|---|---|---|---|---|---|---|
| 20261020T173026-ccbc81b6 | 38 | 202 | C4 | c1_fixed | failed | incomplete_or_aborted |
| 20261020T174050-9bd5ac18 | 40 | 203 | C4 | c1_peering | failed | incomplete_or_aborted,no_traffic_start,observation_incomplete |
| 20261020T174251-d0d65aab | 41 | 203 | C3 | c1_mobile | failed | incomplete_or_aborted,no_traffic_start,observation_incomplete |
| 20261020T174948-a47998c2 | 43 | 203 | C3 | c1_peering | failed | incomplete_or_aborted,no_traffic_start,observation_incomplete |
| 20261020T182228-7813b2f3 | 50 | 203 | C4 | c3_under | failed | incomplete_or_aborted,no_traffic_start,observation_incomplete |
| 20261020T183451-d63e941c | 53 | 203 | C3 | c1_enterprise | failed | incomplete_or_aborted |
| 20261020T184019-38614dd4 | 54 | 203 | C4 | c1_fixed | failed | incomplete_or_aborted,observation_incomplete |
| 20261020T184846-d38d5ecc | 56 | 203 | C4 | c2_over | failed | incomplete_or_aborted |

Reparto de bytes planificados por dominio (determina el peso de cada dominio en `delivery_pct` global): enterprise 47.45%, fixed 34.01%, mobile 0.30%, peering 18.24%.


### 1. response_metrics.compute() sobre C2/C3/C4 válidas (LAB_AUDIT crudo)

| cond | composición | n | A% media (valores) | cobertura detección | cobertura mitigación | TD mediana s | TD0 med s | TO med s | TM (tE) | TR med s |
|---|---|---|---|---|---|---|---|---|---|---|
| C2 | c1_enterprise | 3 | 87.2 (92/92/77) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c1_fixed | 3 | 59.0 (85/8/85) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c1_mobile | 3 | 74.4 (62/85/77) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c1_peering | 3 | 94.9 (85/100/100) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c2_over | 3 | 69.2 (54/77/77) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c3_under | 3 | 87.2 (69/92/100) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C3 | c1_enterprise | 2 | 0.0 (0/0) | 0/2 | 0/2 | — (2 cens) | — | — (2 cens) | 2 cens | — (2 cens) |
| C3 | c1_fixed | 3 | 0.0 (0/0/0) | 3/3 | 3/3 | 1.6 (0 cens) | 1.1 | 1.2 (0 cens) | 3 cens | — (3 cens) |
| C3 | c1_mobile | 2 | 0.0 (0/0) | 2/2 | 2/2 | 7.1 (0 cens) | 6.0 | 0.0 (0 cens) | 2 cens | — (2 cens) |
| C3 | c1_peering | 2 | 0.0 (0/0) | 2/2 | 2/2 | 6.3 (0 cens) | 4.2 | 0.0 (0 cens) | 2 cens | — (2 cens) |
| C3 | c2_over | 3 | 0.0 (0/0/0) | 3/3 | 2/3 | 11.0 (0 cens) | 10.5 | 108.2 (1 cens) | 3 cens | — (3 cens) |
| C3 | c3_under | 3 | 0.0 (0/0/0) | 3/3 | 3/3 | 26.6 (0 cens) | -2.5 | 0.1 (0 cens) | 3 cens | — (3 cens) |
| C4 | c1_enterprise | 3 | 0.0 (0/0/0) | 1/3 | 1/3 | 9.6 (2 cens) | 5.0 | 0.0 (2 cens) | 3 cens | — (3 cens) |
| C4 | c1_fixed | 1 | 11.1 (11) | 1/1 | 1/1 | 6.1 (0 cens) | 5.5 | 0.7 (0 cens) | 1 cens | 40.9 (0 cens) |
| C4 | c1_mobile | 3 | 5.1 (15/0/0) | 3/3 | 3/3 | 3.9 (0 cens) | 3.9 | 0.1 (0 cens) | 3 cens | 10.0 (1 cens) |
| C4 | c1_peering | 2 | 7.7 (15/0) | 2/2 | 2/2 | 9.0 (0 cens) | 6.8 | 0.0 (0 cens) | 2 cens | 20.0 (1 cens) |
| C4 | c2_over | 2 | 0.0 (0/0) | 2/2 | 2/2 | 4.2 (0 cens) | 4.2 | 0.0 (0 cens) | 2 cens | — (2 cens) |
| C4 | c3_under | 2 | 0.0 (0/0) | 2/2 | 2/2 | 5.6 (0 cens) | 5.6 | 0.0 (0 cens) | 2 cens | — (2 cens) |

TM/tE: **no calculable** — no existe serie de tasas independiente del atacante en los datos capturados (`rate_series` ausente, motivo `no_independent_rate_series` en las 33/33 ejecuciones con ataque válidas). TI: `not_observable` (sin evidencia de instalación por dominio). Censura: TD censurado = ninguna detección que incluya IP atacante tras tA; TO censurado = ninguna `mitigation_issued` que afecte IP atacante; TR censurado = nunca K=3 ventanas PASS consecutivas tras tF (TR=5 s es el mínimo posible: tF=120 s, ventana de 5 s).

| cond | n | A% media (ventana ataque 60–120) | sd | detección | mitigación |
|---|---|---|---|---|---|
| C2 | 18 | 78.6 | 21.8 | 0/18 | 0/18 |
| C3 | 15 | 0.0 | 0.0 | 13/15 | 12/15 |
| C4 | 13 | 3.2 | 6.2 | 11/13 | 11/13 |


### 2. Impacto del ataque: C1 vs C2 en 60–120 s, y control interno de C2

| dominio | entrega% C1-I | entrega% C1-M | entrega% C2 | C2 − media(C1) | A% C1-I | A% C1-M | A% C2 |
|---|---|---|---|---|---|---|---|
| all | 55.0 | 66.8 | 94.9 | 34.0 | 5.1 | 15.4 | 78.6 |
| enterprise | 34.9 | 68.2 | 96.3 | 44.8 | 0.0 | 53.8 | 83.3 |
| fixed | 64.4 | 53.6 | 92.7 | 33.7 | 41.0 | 25.6 | 78.6 |
| mobile | 94.4 | 25.2 | 98.0 | 38.2 | 66.7 | 10.3 | 93.6 |
| peering | 98.7 | 94.8 | 95.4 | -1.3 | 100.0 | 94.9 | 92.7 |

Control interno de C2 (pipeline suspendido, mismo plan benigno; n=18): entrega por tramo, dentro de cada ejecución.

| dominio | 0–60 | 60–120 (ataque) | 120–180 | (60–120)−(0–60) media ± ee | (60–120)−(120–180) media ± ee |
|---|---|---|---|---|---|
| all | 95.1 | 94.9 | 96.1 | -0.14 ± 0.62 | -1.20 ± 0.60 |
| enterprise | 95.4 | 96.3 | 97.3 | 0.90 ± 1.16 | -1.00 ± 0.91 |
| fixed | 92.0 | 92.7 | 93.6 | 0.75 ± 1.06 | -0.94 ± 0.74 |
| mobile | 96.6 | 98.0 | 96.8 | 1.34 ± 1.18 | 1.16 ± 0.57 |
| peering | 98.8 | 95.4 | 97.7 | -3.38 ± 1.07 | -2.27 ± 1.43 |

| composición (C2) | n | entrega% 0–60 | entrega% 60–120 | Δ | A% 60–120 | A% 120–180 (sin ataque) |
|---|---|---|---|---|---|---|
| c1_enterprise | 3 | 96.2 | 97.0 | 0.79 | 87.2 | 91.7 |
| c1_fixed | 3 | 95.0 | 92.7 | -2.34 | 59.0 | 88.9 |
| c1_mobile | 3 | 94.9 | 94.2 | -0.72 | 74.4 | 75.0 |
| c1_peering | 3 | 96.6 | 97.2 | 0.62 | 94.9 | 100.0 |
| c2_over | 3 | 92.8 | 91.8 | -0.95 | 69.2 | 72.2 |
| c3_under | 3 | 94.9 | 96.7 | 1.78 | 87.2 | 91.7 |

A en C2 (n=18), pareada por ejecución: pre-ataque [0,60) (ventanas de 5 s, warmup omitido) 80.1%, ataque [60,120] 78.6%, post-ataque [120,180) 86.6%. Δ(ataque−pre) = -1.46 ± 3.44 pp (ee); Δ(ataque−post) = -7.94 ± 4.46 pp.


### 3. Diferencia M−I por tramo y dominio (entrega%)

Pares C4−C3 completos (semilla×escenario con ambas válidas): 11; pares C1-M−C1-I: 3. Cada celda: media (n positivos/n).

**C4−C3 (todas las composiciones)**

| dominio | 0–60 | 60–120 (ataque) | 120–180 |
|---|---|---|---|
| all | 20.5 (11/11) | 15.0 (10/11) | 20.2 (10/11) |
| enterprise | 29.3 (11/11) | 33.0 (11/11) | 36.0 (11/11) |
| fixed | 28.2 (10/11) | 1.6 (6/11) | 11.8 (8/11) |
| mobile | -93.8 (0/11) | -59.3 (0/11) | -45.1 (0/11) |
| peering | -9.2 (2/11) | -7.4 (2/11) | -6.4 (5/11) |

**C4−C3 solo composición 1 (control)**

| dominio | 0–60 | 60–120 (ataque) | 120–180 |
|---|---|---|---|
| all | 23.8 (7/7) | 15.8 (6/7) | 25.6 (7/7) |
| enterprise | 30.3 (7/7) | 34.6 (7/7) | 45.8 (7/7) |
| fixed | 37.7 (7/7) | 1.0 (4/7) | 11.5 (6/7) |
| mobile | -92.4 (0/7) | -55.9 (0/7) | -39.8 (0/7) |
| peering | -11.7 (2/7) | -5.4 (2/7) | -2.3 (3/7) |

**C1-M − C1-I (sin ataque)**

| dominio | 0–60 | 60–120 (ataque) | 120–180 |
|---|---|---|---|
| all | 1.9 (2/3) | 11.9 (2/3) | 18.5 (3/3) |
| enterprise | 3.9 (2/3) | 33.3 (3/3) | 30.7 (3/3) |
| fixed | 10.5 (2/3) | -10.8 (1/3) | 7.6 (2/3) |
| mobile | -95.1 (0/3) | -69.1 (0/3) | -34.0 (1/3) |
| peering | -12.7 (0/3) | -3.9 (2/3) | 3.1 (2/3) |

**C4−C3 por composición, entrega% global**

| composición | n pares | 0–60 | 60–120 | 120–180 | whole-run (delivery_pct del piloto) |
|---|---|---|---|---|---|
| c1_enterprise | 2 | 23.6 | 21.1 | 8.2 | 17.2 |
| c1_fixed | 1 | 28.6 | 22.0 | 21.9 | 23.8 |
| c1_mobile | 2 | 23.4 | 10.5 | 39.2 | 24.3 |
| c1_peering | 2 | 21.8 | 12.7 | 31.3 | 21.7 |
| c2_over | 2 | 16.7 | 8.9 | 1.8 | 8.6 |
| c3_under | 2 | 12.9 | 18.0 | 19.6 | 17.2 |


### 4. Reinicio de ryu-manager, orden y hora

| modo | reinicio inmediatamente antes (60 ejec.) | sin reinicio | reinicio (34 válidas) | sin reinicio (válidas) |
|---|---|---|---|---|
| I | 21 | 0 | 18 | 0 |
| M | 21 | 0 | 16 | 0 |

| pos | semilla | cond | esc. | modo | reinicio antes | s desde reinicio al inicio del tráfico | hora (h desde 1ª) | válida | entrega% run | entrega% 0–60 | entrega% 60–120 | A% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 201 | C3 | c1_mobile | I | sí | 34 | 0.00 | sí | 59.1 | 63.9 | 53.9 | 0.0 |
| 1 | 201 | C2 | c3_under | none | no | 323 | 0.09 | sí | 96.7 | 97.6 | 95.2 | 69.2 |
| 2 | 201 | C3 | c1_enterprise | I | sí | 37 | 0.17 | sí | 35.3 | 42.0 | 18.8 | 0.0 |
| 3 | 201 | C2 | c1_peering | none | no | 330 | 0.25 | sí | 97.6 | 98.6 | 96.7 | 84.6 |
| 4 | 201 | C2 | c1_mobile | none | no | 620 | 0.33 | sí | 89.6 | 90.8 | 89.1 | 61.5 |
| 5 | 201 | C4 | c3_under | M | sí | 37 | 0.41 | sí | 80.5 | 89.0 | 71.8 | 0.0 |
| 6 | 201 | C4 | c1_enterprise | M | sí | 37 | 0.50 | sí | 60.7 | 71.7 | 51.7 | 0.0 |
| 7 | 201 | C2 | c1_fixed | none | no | 327 | 0.58 | sí | 97.8 | 98.8 | 97.4 | 84.6 |
| 8 | 201 | C1-I | — | I | sí | 38 | 0.66 | sí | 77.6 | 84.9 | 68.9 | 15.4 |
| 9 | 201 | C2 | c1_enterprise | none | no | 333 | 0.74 | sí | 97.2 | 96.7 | 97.3 | 92.3 |
| 10 | 201 | C4 | c2_over | M | sí | 41 | 0.82 | sí | 51.8 | 68.7 | 33.6 | 0.0 |
| 11 | 201 | C4 | c1_fixed | M | sí | 44 | 0.91 | sí | 78.6 | 85.7 | 67.1 | 7.7 |
| 12 | 201 | C3 | c1_peering | I | sí | 43 | 1.00 | sí | 53.0 | 57.2 | 39.6 | 0.0 |
| 13 | 201 | C4 | c1_peering | M | sí | 41 | 1.09 | sí | 80.0 | 91.3 | 65.3 | 15.4 |
| 14 | 201 | C3 | c3_under | I | sí | 41 | 1.17 | sí | 54.8 | 69.0 | 47.8 | 0.0 |
| 15 | 201 | C1-M | — | M | sí | 45 | 1.26 | sí | 81.1 | 91.4 | 62.0 | 7.7 |
| 16 | 201 | C3 | c2_over | I | sí | 43 | 1.35 | sí | 37.3 | 48.6 | 18.8 | 0.0 |
| 17 | 201 | C3 | c1_fixed | I | sí | 36 | 1.43 | sí | 54.8 | 57.1 | 45.1 | 0.0 |
| 18 | 201 | C4 | c1_mobile | M | sí | 41 | 1.52 | sí | 85.0 | 93.6 | 66.1 | 15.4 |
| 19 | 201 | C2 | c2_over | none | no | 331 | 1.60 | sí | 88.5 | 90.0 | 86.6 | 53.8 |
| 20 | 202 | C3 | c1_peering | I | sí | 37 | 1.68 | sí | 49.7 | 59.2 | 45.9 | 0.0 |
| 21 | 202 | C3 | c1_mobile | I | sí | 37 | 1.77 | sí | 49.7 | 53.0 | 53.6 | 0.0 |
| 22 | 202 | C2 | c1_fixed | none | no | 335 | 1.86 | sí | 89.6 | 90.3 | 84.1 | 7.7 |
| 23 | 202 | C4 | c1_peering | M | sí | 57 | 1.94 | sí | 66.1 | 68.6 | 45.6 | 0.0 |
| 24 | 202 | C3 | c1_enterprise | I | sí | 44 | 2.03 | sí | 53.3 | 55.6 | 56.4 | 0.0 |
| 25 | 202 | C2 | c1_peering | none | no | 344 | 2.12 | sí | 97.7 | 96.6 | 97.8 | 100.0 |
| 26 | 202 | C2 | c1_mobile | none | no | 646 | 2.20 | sí | 97.4 | 97.3 | 97.3 | 84.6 |
| 27 | 202 | C4 | c1_mobile | M | sí | 41 | 2.28 | sí | 72.5 | 70.2 | 62.5 | 0.0 |
| 28 | 202 | C4 | c3_under | M | sí | 39 | 2.37 | sí | 61.9 | 63.8 | 67.9 | 0.0 |
| 29 | 202 | C3 | c3_under | I | sí | 38 | 2.46 | sí | 53.2 | 58.1 | 55.9 | 0.0 |
| 30 | 202 | C3 | c2_over | I | sí | 43 | 2.54 | sí | 54.2 | 58.6 | 56.6 | 0.0 |
| 31 | 202 | C1-M | — | M | sí | 45 | 2.63 | sí | 72.5 | 71.3 | 57.2 | 0.0 |
| 32 | 202 | C2 | c1_enterprise | none | no | 336 | 2.72 | sí | 97.8 | 97.2 | 97.3 | 92.3 |
| 33 | 202 | C2 | c2_over | none | no | 631 | 2.80 | sí | 95.4 | 95.7 | 94.8 | 76.9 |
| 34 | 202 | C1-I | — | I | sí | 44 | 2.88 | sí | 53.0 | 57.3 | 52.6 | 0.0 |
| 35 | 202 | C4 | c1_enterprise | M | sí | 45 | 2.97 | sí | 62.4 | 73.2 | 65.7 | 0.0 |
| 36 | 202 | C3 | c1_fixed | I | sí | 40 | 3.06 | sí | 45.6 | 56.8 | 43.9 | 0.0 |
| 37 | 202 | C4 | c2_over | M | sí | 39 | 3.14 | sí | 56.9 | 71.9 | 59.5 | 0.0 |
| 38 | 202 | C4 | c1_fixed | M | sí | 45 | 3.23 | no | 64.2 | 72.1 | 60.4 | — |
| 39 | 202 | C2 | c3_under | none | no | 354 | 3.32 | sí | 97.4 | 95.8 | 97.4 | 92.3 |
| 40 | 203 | C4 | c1_peering | M | sí | — | 3.40 | no | 0.0 | 0.0 | 0.0 | — |
| 41 | 203 | C3 | c1_mobile | I | sí | — | 3.44 | no | 0.0 | 0.0 | 0.0 | — |
| 42 | 203 | C2 | c1_peering | none | no | 145 | 3.47 | sí | 96.8 | 94.7 | 97.2 | 100.0 |
| 43 | 203 | C3 | c1_peering | I | sí | — | 3.55 | no | 0.0 | 0.0 | 0.0 | — |
| 44 | 203 | C3 | c2_over | I | sí | 41 | 3.59 | sí | 54.3 | 65.0 | 48.6 | 0.0 |
| 45 | 203 | C2 | c1_mobile | none | no | 339 | 3.67 | sí | 96.3 | 96.6 | 96.1 | 76.9 |
| 46 | 203 | C1-I | — | I | sí | 42 | 3.76 | sí | 50.6 | 60.1 | 43.3 | 0.0 |
| 47 | 203 | C2 | c3_under | none | no | 340 | 3.84 | sí | 95.5 | 91.3 | 97.5 | 100.0 |
| 48 | 203 | C4 | c1_mobile | M | sí | 42 | 3.92 | sí | 49.0 | 54.1 | 44.1 | 0.0 |
| 49 | 203 | C4 | c1_enterprise | M | sí | 41 | 4.01 | sí | 50.0 | 51.8 | 47.6 | 0.0 |
| 50 | 203 | C4 | c3_under | M | sí | — | 4.10 | no | 0.0 | 0.0 | 0.0 | — |
| 51 | 203 | C2 | c1_fixed | none | no | 160 | 4.13 | sí | 96.4 | 96.0 | 96.6 | 84.6 |
| 52 | 203 | C2 | c2_over | none | no | 464 | 4.22 | sí | 94.2 | 92.6 | 94.0 | 76.9 |
| 53 | 203 | C3 | c1_enterprise | I | sí | 50 | 4.30 | no | 52.3 | 61.5 | 47.2 | — |
| 54 | 203 | C4 | c1_fixed | M | sí | 44 | 4.40 | no | 3.1 | 11.6 | 0.0 | — |
| 55 | 203 | C3 | c1_fixed | I | sí | 51 | 4.44 | sí | 48.1 | 60.8 | 36.8 | 0.0 |
| 56 | 203 | C4 | c2_over | M | sí | 46 | 4.54 | no | 53.6 | 54.2 | 69.0 | — |
| 57 | 203 | C1-M | — | M | sí | 43 | 4.63 | sí | 62.2 | 45.3 | 81.3 | 38.5 |
| 58 | 203 | C3 | c3_under | I | sí | 47 | 4.72 | sí | 51.8 | 60.5 | 44.5 | 0.0 |
| 59 | 203 | C2 | c1_enterprise | none | no | 354 | 4.81 | sí | 95.7 | 94.8 | 96.4 | 76.9 |


Regresión OLS (solo ejecuciones válidas con pipeline activo: C1-I, C1-M, C3, C4; n=34; error estándar clásico; sin corrección por semilla). Coeficientes en pp de entrega (o pp de A) con su t.

| modelo | n | R² | coeficientes |
|---|---|---|---|
| entrega 0–60 (pre-ataque) ~ modo M | 34 | 0.248 | intercepto=59.32 (t=21.2) · M=13.28 (t=3.3) |
| entrega 0–60 (pre-ataque) ~ modo M + ataque | 34 | 0.256 | intercepto=61.80 (t=11.6) · M=13.22 (t=3.2) · ataque=-2.97 (t=-0.5) |
| entrega 0–60 (pre-ataque) ~ M + ataque + s_desde_reinicio(min) + reinicio_antes | 34 | — | matriz singular (regresor sin variación o colineal) |
| entrega 0–60 (pre-ataque) ~ M + ataque + posición(/10) + hora(h) | 34 | 0.415 | intercepto=72.65 (t=11.4) · M=13.17 (t=3.5) · ataque=-5.39 (t=-1.1) · pos/10=0.33 (t=0.0) · hora=-4.51 (t=-0.1) |
| entrega run completo ~ modo M | 34 | 0.356 | intercepto=51.99 (t=21.3) · M=14.96 (t=4.2) |
| entrega run completo ~ modo M + ataque | 34 | 0.418 | intercepto=58.80 (t=13.3) · M=14.79 (t=4.3) · ataque=-8.17 (t=-1.8) |
| entrega run completo ~ M + ataque + s_desde_reinicio(min) + reinicio_antes | 34 | — | matriz singular (regresor sin variación o colineal) |
| entrega run completo ~ M + ataque + posición(/10) + hora(h) | 34 | 0.526 | intercepto=67.11 (t=12.4) · M=14.74 (t=4.6) · ataque=-10.04 (t=-2.4) · pos/10=-0.99 (t=-0.0) · hora=-1.95 (t=-0.1) |
| entrega 60–120 ~ modo M | 34 | 0.233 | intercepto=46.16 (t=15.9) · M=13.15 (t=3.1) |
| entrega 60–120 ~ modo M + ataque | 34 | 0.310 | intercepto=54.43 (t=10.4) · M=12.94 (t=3.2) · ataque=-9.92 (t=-1.9) |
| entrega 60–120 ~ M + ataque + s_desde_reinicio(min) + reinicio_antes | 34 | — | matriz singular (regresor sin variación o colineal) |
| entrega 60–120 ~ M + ataque + posición(/10) + hora(h) | 34 | 0.335 | intercepto=52.83 (t=7.6) · M=12.62 (t=3.0) · ataque=-10.09 (t=-1.8) · pos/10=-40.07 (t=-1.0) · hora=49.05 (t=1.0) |
| A 60–120 ~ modo M | 34 | 0.083 | intercepto=0.85 (t=0.5) · M=4.43 (t=1.7) |
| A 60–120 ~ modo M + ataque | 34 | 0.270 | intercepto=8.13 (t=2.7) · M=4.25 (t=1.8) · ataque=-8.73 (t=-2.8) |
| A 60–120 ~ M + ataque + s_desde_reinicio(min) + reinicio_antes | 34 | — | matriz singular (regresor sin variación o colineal) |
| A 60–120 ~ M + ataque + posición(/10) + hora(h) | 34 | 0.357 | intercepto=9.60 (t=2.5) · M=4.59 (t=2.0) · ataque=-8.51 (t=-2.8) · pos/10=42.19 (t=2.0) · hora=-51.57 (t=-2.0) |

Entrega 0–60 s y reinicio, solo ejecuciones C3/C4 (pre-ataque, comparables), media por grupo:

| modo | grupo | n | entrega% 0–60 | entrega% run | s desde reinicio (media) |
|---|---|---|---|---|---|
| I | reinicio antes | 18 | 59.3 | 52.0 | 41 |
| I | sin reinicio | 0 | — | — | — |
| M | reinicio antes | 16 | 72.6 | 66.9 | 42 |
| M | sin reinicio | 0 | — | — | — |

| tramo del piloto | modo | n | entrega% 0–60 | entrega% run |
|---|---|---|---|---|
| 1/3 inicial (pos 0–19) | I | 7 | 60.4 | 53.1 |
| 1/3 inicial (pos 0–19) | M | 7 | 84.5 | 74.0 |
| 1/3 medio (20–39) | I | 7 | 57.0 | 51.3 |
| 1/3 medio (20–39) | M | 6 | 69.8 | 65.4 |
| 1/3 final (40–59) | I | 4 | 61.6 | 51.2 |
| 1/3 final (40–59) | M | 3 | 50.4 | 53.7 |

Control sin pipeline (C2) a lo largo del piloto:

| tramo | n | entrega% run | A% |
|---|---|---|---|
| pos 0–19 | 6 | 94.6 | 74.4 |
| pos 20–39 | 6 | 95.9 | 75.6 |
| pos 40–59 | 6 | 95.8 | 85.9 |


Secuencia de las 42 ejecuciones con modo (C2 excluidas): 15 pares consecutivos con el mismo modo; el diseño del piloto preveía **omitir** el reinicio en esos pares. Reinicios observados en esos 15 pares: 15. Ejecuciones con modo que reiniciaron: 42/42 (PILOT_DESIGN preveía 27 reinicios). Mensajes "Applying detection mode" en logs: 1 por cada una de las 42.


**Prueba de arranque limpio**: entrega de los eventos que TERMINAN antes de T1 (los eventos cortados por un bloqueo posterior no se cuentan, para no arrastrar su pérdida al intervalo previo), con T1 = primer bloqueo/mitigación de la propia ejecución (o 60 s), solo ejecuciones con pipeline activo y T1≥5 s, contra la media de C2 de la misma semilla (mismo plan benigno) en el mismo intervalo. Si el reinicio (~40 s antes) degradara el reenvío, esta diferencia sería negativa aun sin bloqueos.

| pos | semilla | cond | modo | T1 s | entrega% [0,T1) | C2 misma semilla | Δ pp | eventos contenidos | s desde reinicio |
|---|---|---|---|---|---|---|---|---|---|
| 0 | 201 | C3 | I | 20.6 | 97.9 | 99.4 | -1.5 | 162 | 34 |
| 2 | 201 | C3 | I | 27.8 | 98.2 | 98.5 | -0.3 | 194 | 37 |
| 5 | 201 | C4 | M | 11.0 | 95.2 | 98.9 | -3.7 | 78 | 37 |
| 6 | 201 | C4 | M | 11.1 | 93.7 | 98.9 | -5.2 | 79 | 37 |
| 8 | 201 | C1-I | I | 23.5 | 98.1 | 98.6 | -0.5 | 188 | 38 |
| 10 | 201 | C4 | M | 11.0 | 94.6 | 98.9 | -4.4 | 77 | 41 |
| 11 | 201 | C4 | M | 9.6 | 73.2 | 98.6 | -25.4 | 30 | 44 |
| 12 | 201 | C3 | I | 27.6 | 97.8 | 98.5 | -0.7 | 194 | 43 |
| 13 | 201 | C4 | M | 9.8 | 68.9 | 98.6 | -29.7 | 30 | 41 |
| 14 | 201 | C3 | I | 23.9 | 98.7 | 98.6 | 0.1 | 190 | 41 |
| 15 | 201 | C1-M | M | 9.0 | 79.1 | 98.6 | -19.5 | 30 | 45 |
| 16 | 201 | C3 | I | 23.8 | 98.4 | 98.6 | -0.2 | 190 | 43 |
| 17 | 201 | C3 | I | 27.8 | 98.7 | 98.5 | 0.2 | 194 | 36 |
| 18 | 201 | C4 | M | 8.2 | 70.5 | 98.6 | -28.1 | 30 | 41 |
| 20 | 202 | C3 | I | 19.0 | 98.9 | 99.6 | -0.7 | 148 | 37 |
| 21 | 202 | C3 | I | 19.4 | 99.0 | 99.6 | -0.6 | 150 | 37 |
| 24 | 202 | C3 | I | 19.1 | 98.6 | 99.6 | -1.0 | 148 | 44 |
| 29 | 202 | C3 | I | 19.0 | 98.8 | 99.6 | -0.8 | 148 | 38 |
| 30 | 202 | C3 | I | 19.6 | 98.8 | 99.6 | -0.8 | 151 | 43 |
| 34 | 202 | C1-I | I | 19.2 | 98.9 | 99.6 | -0.6 | 148 | 44 |
| 36 | 202 | C3 | I | 19.4 | 98.8 | 99.6 | -0.7 | 150 | 40 |
| 44 | 203 | C3 | I | 22.3 | 98.0 | 99.2 | -1.2 | 117 | 41 |
| 46 | 203 | C1-I | I | 21.5 | 97.8 | 99.2 | -1.4 | 117 | 42 |
| 48 | 203 | C4 | M | 8.8 | 22.0 | 94.7 | -72.7 | 15 | 42 |
| 49 | 203 | C4 | M | 8.8 | 31.9 | 94.7 | -62.8 | 15 | 41 |
| 55 | 203 | C3 | I | 21.8 | 99.1 | 99.2 | -0.1 | 117 | 51 |
| 57 | 203 | C1-M | M | 9.4 | 52.5 | 94.7 | -42.2 | 15 | 43 |
| 58 | 203 | C3 | I | 22.1 | 96.2 | 99.2 | -3.0 | 117 | 47 |

Modo I: n=18, Δ media -0.77 pp, mediana -0.72 pp; T1 mediana 21.7 s; eventos contenidos (mediana) 150.

Modo M: n=10, Δ media -29.36 pp, mediana -26.70 pp; T1 mediana 9.5 s; eventos contenidos (mediana) 30.

Tiempo hasta el primer bloqueo/mitigación (s desde el inicio del tráfico), ejecuciones válidas con pipeline activo, todas sin ataque hasta t=60:

| modo | n | mín | mediana | máx |
|---|---|---|---|---|
| I | 18 | 19.0 | 21.7 | 27.8 |
| M | 16 | 2.3 | 8.8 | 11.1 |

Eventos enterprise (pipeline activo): entrega por evento según si había bloqueo enterprise activo al inicio del evento, por modo.

| modo | estado al inicio del evento | eventos | entrega% (bytes) |
|---|---|---|---|
| I | sin bloqueo | 747 | 27.0 |
| I | bloqueo activo | 856 | 0.6 |
| M | sin bloqueo | 628 | 66.6 |
| M | bloqueo activo | 740 | 17.2 |

Efecto del modo tras controlar por fracción bloqueada (OLS por dominio, pares ejecución×tramo, pipeline activo): entrega ~ bloqueo(0–1) + M.

| dominio | n | coef bloqueo (pp por 100%) | coef M (pp) | R² |
|---|---|---|---|---|
| enterprise | 102 | -46.9 (t=-6.3) | 25.9 (t=5.4) | 0.42 |
| fixed | 102 | -26.8 (t=-2.8) | 9.1 (t=2.0) | 0.12 |
| mobile | 102 | -36.3 (t=-3.3) | -33.6 (t=-3.3) | 0.68 |
| peering | 102 | -20.0 (t=-4.8) | 2.0 (t=0.6) | 0.23 |


### 5. Actividad del detector

**C1 (benigno puro, sin ataque): toda detección, decisión y mitigación es sobre tráfico benigno.**

| semilla | cond | detecciones | tipos | origen del criterio | decisiones aceptadas/total | mitigaciones emitidas | por dominio/acción | fuentes únicas bloqueadas | detecciones KPM |
|---|---|---|---|---|---|---|---|---|---|
| 201 | C1-I | 12 | {'DDOS_DISTRIBUTED': 12} | {'respaldo_distribuido(DIST_PPS=300)': 12} | 11/11 | 60 | {('broadband', 'block'): 56, ('enterprise', 'block'): 4} | 11 | 0 |
| 201 | C1-M | 5 | {'MULTIDOMAIN_DISTRIBUTED_ATTACK': 5} | {'respaldo_distribuido(DIST_PPS=300)': 5} | 5/5 | 60 | {('mobile', 'block'): 23, ('broadband', 'block'): 33, ('bgp', 'bgp_flowspec_discard'): 2, ('enterprise', 'block'): 2} | 16 | 0 |
| 202 | C1-M | 4 | {'MULTIDOMAIN_DISTRIBUTED_ATTACK': 4} | {'respaldo_distribuido(DIST_PPS=300)': 4} | 4/4 | 40 | {('mobile', 'block'): 20, ('broadband', 'block'): 17, ('enterprise', 'block'): 2, ('bgp', 'bgp_flowspec_discard'): 1} | 12 | 0 |
| 202 | C1-I | 9 | {'DDOS_DISTRIBUTED': 9} | {'respaldo_distribuido(DIST_PPS=300)': 9} | 9/9 | 39 | {('broadband', 'block'): 36, ('enterprise', 'block'): 3} | 11 | 0 |
| 203 | C1-I | 8 | {'DDOS_DISTRIBUTED': 8} | {'respaldo_distribuido(DIST_PPS=300)': 8} | 8/8 | 50 | {('broadband', 'block'): 48, ('enterprise', 'block'): 2} | 11 | 0 |
| 203 | C1-M | 4 | {'MULTIDOMAIN_DISTRIBUTED_ATTACK': 4} | {'respaldo_distribuido(DIST_PPS=300)': 4} | 4/4 | 44 | {('enterprise', 'block'): 3, ('mobile', 'block'): 17, ('broadband', 'block'): 21, ('bgp', 'bgp_flowspec_discard'): 3} | 16 | 0 |


Fracción del tiempo con bloqueos activos (`active_blocks>0` en los ciclos LAB_AUDIT) por dominio y tramo; media sobre ejecuciones válidas.

| cond | n | enterprise 0-60/60-120/120-180 (%) | fixed | mobile | peering |
|---|---|---|---|---|---|
| C1-I | 3 | ent 47/58/73 | fix 27/40/38 | mob 0/0/0 | pee 0/0/0 |
| C1-M | 3 | ent 53/68/37 | fix 23/43/21 | mob 88/100/98 | pee 59/67/79 |
| C2 | 18 | ent 0/0/0 | fix 0/0/0 | mob 0/0/0 | pee 0/0/0 |
| C3 | 15 | ent 47/76/77 | fix 26/34/24 | mob 0/12/3 | pee 0/12/3 |
| C4 | 13 | ent 44/94/58 | fix 25/34/15 | mob 88/93/79 | pee 25/49/46 |

Relación entrega% ↔ fracción bloqueada (pares ejecución×tramo, ejecuciones con pipeline activo; OLS entrega ~ bloqueo%):

| dominio | n | entrega% con 0% bloqueo (intercepto) | pendiente por 100% bloqueado (pp) | R² | media entrega% sin bloqueo | media entrega% con ≥50% bloqueo | n sin bloqueo | n con ≥50% |
|---|---|---|---|---|---|---|---|---|
| enterprise | 102 | 67.1 | -48.4 (t=-5.7) | 0.25 | 67.3 | 28.1 | 7 | 71 |
| fixed | 102 | 82.7 | -28.4 (t=-3.0) | 0.08 | 80.6 | 58.8 | 14 | 13 |
| mobile | 102 | 83.5 | -68.4 (t=-13.6) | 0.65 | 85.3 | 18.0 | 51 | 46 |
| peering | 102 | 96.0 | -18.6 (t=-5.3) | 0.22 | 97.4 | 79.9 | 68 | 24 |

Mitigaciones antes de tA (t<60 s) en C3/C4 — por definición no responden al ataque de la ejecución:

| cond | n | detecciones pre-ataque (media/ejec.) | mitigaciones pre-ataque (media) | ejec. con ≥1 | entrega% 0–60 |
|---|---|---|---|---|---|
| C3 | 15 | 2.9 | 10.8 | 15 | 57.7 |
| C4 | 13 | 1.7 | 14.1 | 13 | 73.4 |

Tasa máxima observada (`trigger_pps` por ciclo, cualquier destino) antes de t=60 s y umbral del protocolo (máximo sobre todos los ciclos y destinos; un cruce aislado de un ciclo no basta para detectar por la histéresis de activación, y la columna «origen» de las tablas de detección sólo marca «umbral_protocolo» si el destino detectado cruzó el umbral en la ventana previa a la detección):

| cond | TCP_SYN máx / umbral | UDP máx / umbral | ICMP máx / umbral |
|---|---|---|---|
| C1-I | 27.2 / 76.82 | 6142.4 / 14515.64 | 256.3 / 240.37 |
| C1-M | 62.2 / 76.82 | 19061.5 / 14515.64 | 179.8 / 240.37 |
| C3 | 48.0 / 76.82 | 11632.9 / 14515.64 | 298.5 / 240.37 |
| C4 | 96.9 / 76.82 | 15375.3 / 14515.64 | 285.0 / 240.37 |

| cond | n | mitigaciones/ejec. | sobre IP no atacante (incl. "*") | detecciones/ejec. | de ellas, por respaldo distribuido | flowspec bgp/ejec. |
|---|---|---|---|---|---|---|
| C1-I | 3 | 49.7 | 49.7 | 9.7 | 9.7 | 0.0 |
| C1-M | 3 | 48.0 | 48.0 | 4.3 | 4.3 | 2.0 |
| C3 | 15 | 32.6 | 30.2 | 13.3 | 4.4 | 0.1 |
| C4 | 13 | 44.8 | 41.2 | 9.2 | 3.5 | 1.5 |

Detecciones por tipo y origen, todas las ejecuciones válidas con pipeline activo:

| cond | tipo | origen | n |
|---|---|---|---|
| C1-I | DDOS_DISTRIBUTED | respaldo_distribuido(DIST_PPS=300) | 29 |
| C1-M | MULTIDOMAIN_DISTRIBUTED_ATTACK | respaldo_distribuido(DIST_PPS=300) | 13 |
| C3 | DDOS_DISTRIBUTED | respaldo_distribuido(DIST_PPS=300) | 65 |
| C3 | DDOS_DISTRIBUTED | umbral_protocolo:TCP_SYN | 32 |
| C3 | SYN_FLOOD | respaldo_distribuido(DIST_PPS=300) | 1 |
| C3 | SYN_FLOOD | umbral_protocolo:TCP_SYN | 101 |
| C4 | MULTIDOMAIN_DISTRIBUTED_ATTACK | respaldo_distribuido(DIST_PPS=300) | 46 |
| C4 | MULTIDOMAIN_DISTRIBUTED_ATTACK | umbral_protocolo:TCP_SYN | 5 |
| C4 | SYN_FLOOD | umbral_protocolo:TCP_SYN | 68 |


### 6. Estado de reenvío

| cond | n | bloqueos activos en 1ros 5 s (media) | ejec. con bloqueos al inicio | openflow_residual_drops previo (media) | eventos fallidos % | shortfall % | deadline % | reset % | bind % | unreachable % |
|---|---|---|---|---|---|---|---|---|---|---|
| C1-I | 3 | 0.0 | 0 | 0.0 | 76.8 | 60.30 | 13.87 | 0.72 | 1.61 | 0.29 |
| C1-M | 3 | 2.7 | 1 | 0.0 | 78.0 | 59.82 | 16.88 | 0.91 | 0.21 | 0.14 |
| C2 | 18 | 0.0 | 0 | 0.0 | 77.3 | 68.76 | 7.74 | 0.76 | 0.00 | 0.00 |
| C3 | 15 | 0.0 | 0 | 0.0 | 78.6 | 58.33 | 18.66 | 0.75 | 0.72 | 0.17 |
| C4 | 13 | 3.2 | 5 | 0.0 | 79.7 | 57.06 | 21.41 | 0.90 | 0.24 | 0.14 |

| modo | grupo | n | bloqueos iniciales media | fallidos % | reset % | deadline % |
|---|---|---|---|---|---|---|
| I | reinicio antes | 18 | 0.0 | 78.3 | 0.75 | 17.86 |
| I | sin reinicio | 0 | — | — | — | — |
| M | reinicio antes | 16 | 3.1 | 79.4 | 0.90 | 20.56 |
| M | sin reinicio | 0 | — | — | — | — |

Hashes de implementación del controlador registrados por LAB_AUDIT: `controller/ryu_controller_2.py` → 1 valor(es) distinto(s) en las 60 ejecuciones, `orchestration/controller.py` → 1 valor(es) distinto(s) en las 60 ejecuciones, `detection/engine.py` → 1 valor(es) distinto(s) en las 60 ejecuciones, `decision/engine.py` → 1 valor(es) distinto(s) en las 60 ejecuciones, `telemetry/openflow_adapter.py` → 1 valor(es) distinto(s) en las 60 ejecuciones, `telemetry/mobile_adapter.py` → 1 valor(es) distinto(s) en las 60 ejecuciones, `telemetry/broadband_adapter.py` → 1 valor(es) distinto(s) en las 60 ejecuciones, `collectors/ddos_collector.py` → 1 valor(es) distinto(s) en las 60 ejecuciones.
