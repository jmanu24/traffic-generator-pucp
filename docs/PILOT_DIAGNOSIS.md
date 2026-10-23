# Diagnóstico del piloto I vs. M (semillas 201–203)

Fecha: 2026-10-21. Rama `pilot-diagnosis` (generador y controlador; sin push).
**Solo análisis offline** de datos ya capturados (`.runtime/benign-lab/data/runs/`,
60 carpetas de ejecución y `calibration/pilot_manifest.json`). No se lanzó
ninguna ejecución, no se tocó el laboratorio ni se modificó el controlador, el
diseño o los umbrales.

Reproducible con:

```bash
python3 scripts/pilot_diagnosis.py   # ~100 s; escribe docs/PILOT_DIAGNOSIS_tables.md y
                                     # .runtime/benign-lab/calibration/pilot_diagnosis.json
```

Todas las tablas completas (incluida la lista de las 60 ejecuciones con modo,
reinicio, hora, entrega y A) están en
[PILOT_DIAGNOSIS_tables.md](PILOT_DIAGNOSIS_tables.md); aquí se copian las
necesarias para cada conclusión.

## 0. Resumen ejecutivo

| Pregunta | Conclusión | Evidencia clave |
|---|---|---|
| (a) ¿El ataque degrada el servicio en C2 respecto de C1? | **No de forma apreciable.** En C2 (pipeline suspendido) la entrega global es 95,1 / 94,9 / 96,1 % en 0–60 / 60–120 / 120–180 s: Δ(ataque − pre) = −0,14 ± 0,62 pp. A en ataque = 78,6 %, frente a 80,1 % pre-ataque (Δ = −1,5 ± 3,4 pp; n=18). **C1 no es una referencia válida** (es *peor* que C2 por 28–40 pp, por el propio detector). | §2 |
| (b) Causa de M−I ≠ 0 en el control | (1) **El detector bloquea tráfico benigno** (criterio distribuido de respaldo, `DIST_PPS_THRESHOLD=300` sin calibrar): 6/6 ejecuciones C1 y 28/28 ejecuciones C3/C4 válidas bloquean antes de t=60 s. (2) **El modo cambia el alcance de ese falso positivo** (otro tipo de detección, otra velocidad, otros dominios y fuentes bloqueados) y, ponderado por bytes, da M−I > 0 aunque M perjudique a móvil y peering. (3) Residual en enterprise no explicado por el tiempo bloqueado. **Reinicio, orden y hora: no explican** (ver §4; el reinicio está completamente confundido con el pipeline y no se puede estimar, pero la prueba de arranque limpio en modo I no muestra efecto). | §3, §4, §5 |
| (c) Cambio que lo elimina | Medir el control **sin falsos positivos del detector**: recalibrar (o desactivar para la campaña) el criterio distribuido de respaldo con tráfico benigno de semillas disjuntas, verificado primero con *replay* offline; y, en el diseño, separar el efecto del pipeline del efecto del modo. Detalle y criterios numéricos en §7. | §7 |

Hallazgos adicionales que afectan al diseño:

* **A (disponibilidad) es 0,0 % en C3 y 3,2 % en C4** (C2: 78,6 %): con el detector activo el servicio casi nunca cumple el umbral D=90 % en ninguna ventana de 5 s. A no puede discriminar I de M mientras el detector bloquee tráfico benigno (diferencia C4−C3 en A ≈ +3 pp).
* **El reinicio condicional de `ryu-manager` no operó**: 42/42 ejecuciones con modo reiniciaron el controlador (incluidos 15/15 pares consecutivos con el mismo modo, donde el diseño preveía omitirlo); `PILOT_DESIGN.md` preveía 27 reinicios.

## 1. `response_metrics.compute()` sobre C2/C3/C4

Ejecuciones: 60 en total; 52 válidas (`eligible`), 8 fallidas (conservadas y
excluidas: 4 `no_traffic_start`; ver lista en las tablas). Válidas con ataque:
C2 18, C3 15, C4 13 (46) más 6 de C1 (3 C1-I + 3 C1-M). `compute()`
se ejecutó con los registros `detection_events.jsonl` crudos de cada una.

| cond | composición | n | A% media (valores) | cob. detección | cob. mitigación | TD med s | TD0 med s | TO med s | TM (tE) | TR med s |
|---|---|---|---|---|---|---|---|---|---|---|
| C2 | c1_enterprise | 3 | 87.2 (92/92/77) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c1_fixed | 3 | 59.0 (85/8/85) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c1_mobile | 3 | 74.4 (62/85/77) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c1_peering | 3 | 94.9 (85/100/100) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c2_over | 3 | 69.2 (54/77/77) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C2 | c3_under | 3 | 87.2 (69/92/100) | 0/3 | 0/3 | — (3 cens) | — | — (3 cens) | 3 cens | 5.0 (0 cens) |
| C3 | c1_enterprise | 2 | 0.0 (0/0) | 0/2 | 0/2 | — (2 cens) | — | — (2 cens) | 2 cens | — (2 cens) |
| C3 | c1_fixed | 3 | 0.0 (0/0/0) | 3/3 | 3/3 | 1.6 | 1.1 | 1.2 | 3 cens | — (3 cens) |
| C3 | c1_mobile | 2 | 0.0 (0/0) | 2/2 | 2/2 | 7.1 | 6.0 | 0.0 | 2 cens | — (2 cens) |
| C3 | c1_peering | 2 | 0.0 (0/0) | 2/2 | 2/2 | 6.3 | 4.2 | 0.0 | 2 cens | — (2 cens) |
| C3 | c2_over | 3 | 0.0 (0/0/0) | 3/3 | 2/3 | 11.0 | 10.5 | 108.2 (1 cens) | 3 cens | — (3 cens) |
| C3 | c3_under | 3 | 0.0 (0/0/0) | 3/3 | 3/3 | 26.6 | −2.5 | 0.1 | 3 cens | — (3 cens) |
| C4 | c1_enterprise | 3 | 0.0 (0/0/0) | 1/3 | 1/3 | 9.6 (2 cens) | 5.0 | 0.0 (2 cens) | 3 cens | — (3 cens) |
| C4 | c1_fixed | 1 | 11.1 (11) | 1/1 | 1/1 | 6.1 | 5.5 | 0.7 | 1 cens | 40.9 |
| C4 | c1_mobile | 3 | 5.1 (15/0/0) | 3/3 | 3/3 | 3.9 | 3.9 | 0.1 | 3 cens | 10.0 (1 cens) |
| C4 | c1_peering | 2 | 7.7 (15/0) | 2/2 | 2/2 | 9.0 | 6.8 | 0.0 | 2 cens | 20.0 (1 cens) |
| C4 | c2_over | 2 | 0.0 (0/0) | 2/2 | 2/2 | 4.2 | 4.2 | 0.0 | 2 cens | — (2 cens) |
| C4 | c3_under | 2 | 0.0 (0/0) | 2/2 | 2/2 | 5.6 | 5.6 | 0.0 | 2 cens | — (2 cens) |

| cond | n | A% media (60–120) | sd | detección | mitigación |
|---|---|---|---|---|---|
| C2 | 18 | 78.6 | 21.8 | 0/18 (pipeline suspendido) | 0/18 |
| C3 | 15 | 0.0 | 0.0 | 13/15 | 12/15 |
| C4 | 13 | 3.2 | 6.2 | 11/13 | 11/13 |

Notas y límites:

* **tE / TM: no calculables.** No existe serie de tasas independiente del
  atacante en los datos capturados (`rate_series` ausente → `tE` censurado con
  motivo `no_independent_rate_series` en 46/46). **TI**: `not_observable`
  (sin evidencia de instalación por dominio).
* **TO ≈ 0 s no es "mitigación rápida"**: TO se mide desde TD, y la primera
  `mitigation_issued` que afecta a una IP atacante suele ser *la misma*
  detección (o un bloqueo preexistente del falso positivo, ver §5). Además, las
  IPs de atacante coinciden con hosts que también generan tráfico benigno, así
  que "detectado" puede ser consecuencia del falso positivo.
* **TD0 = −2,5 s** (C3 c3_under): el retardo de activación fue mayor que TD, es decir,
  el detector ya había clasificado tráfico antes de tA (detección previa al
  ataque, coherente con §5); no se interpreta como adelantamiento real.
* **TR = 5,0 s en C2** es el mínimo posible (tF = 120 s, ventana de 5 s, K=3
  ventanas consecutivas PASS ya cumplidas al terminar el ataque): C2 se
  recupera "al instante" porque nunca se degradó.
* Censura: TD/TO censurados = sin detección/mitigación que afecte a IP
  atacante tras tA; TR censurado = nunca K=3 ventanas PASS tras tF.
* Ventana de ataque de `compute()` = [60,001; 120,002] s → 13 ventanas de 5 s
  (por eso los A de C2 son múltiplos de 1/13). Todos los A de este informe usan esa misma ventana.

## 2. Impacto del ataque: C1 vs. C2 (60–120 s) y control interno

Entrega% (bytes entregados / planificados, ventana 60–120 s) y A% por dominio,
medias sobre ejecuciones válidas (C1-I 3, C1-M 3, C2 18):

| dominio | entrega C1-I | entrega C1-M | entrega C2 | C2 − media(C1) | A C1-I | A C1-M | A C2 |
|---|---|---|---|---|---|---|---|
| all | 55.0 | 66.8 | 94.9 | +34.0 | 5.1 | 15.4 | 78.6 |
| enterprise | 34.9 | 68.2 | 96.3 | +44.8 | 0.0 | 53.8 | 83.3 |
| fixed | 64.4 | 53.6 | 92.7 | +33.7 | 41.0 | 25.6 | 78.6 |
| mobile | 94.4 | 25.2 | 98.0 | +38.2 | 66.7 | 10.3 | 93.6 |
| peering | 98.7 | 94.8 | 95.4 | −1.3 | 100.0 | 94.9 | 92.7 |

La comparación C1 vs. C2 **no mide el efecto del ataque**: difiere en dos cosas
a la vez (C1 = detector activo sin ataque; C2 = ataque con pipeline suspendido).
C2 entrega 28–40 pp *más* que C1, es decir, lo que degrada el servicio es el
detector (§5), no el ataque. No existe en el piloto una condición "benigno con
pipeline suspendido", que sería la referencia limpia.

El control válido es **dentro de C2** (mismo plan benigno, pipeline suspendido,
n=18, pareado por ejecución):

| dominio | 0–60 | 60–120 (ataque) | 120–180 | (60–120)−(0–60) ± ee | (60–120)−(120–180) ± ee |
|---|---|---|---|---|---|
| all | 95.1 | 94.9 | 96.1 | −0.14 ± 0.62 | −1.20 ± 0.60 |
| enterprise | 95.4 | 96.3 | 97.3 | +0.90 ± 1.16 | −1.00 ± 0.91 |
| fixed | 92.0 | 92.7 | 93.6 | +0.75 ± 1.06 | −0.94 ± 0.74 |
| mobile | 96.6 | 98.0 | 96.8 | +1.34 ± 1.18 | +1.16 ± 0.57 |
| peering | 98.8 | 95.4 | 97.7 | **−3.38 ± 1.07** | −2.27 ± 1.43 |

A en C2 (n=18, pareada): pre-ataque [0,60) = 80,1 %; ataque = 78,6 %;
post-ataque [120,180) = 86,6 %. Δ(ataque − pre) = **−1,46 ± 3,44 pp**;
Δ(ataque − post) = −7,94 ± 4,46 pp (11/18 negativos).

Por composición (C2): la única con una señal de A llamativa es `c1_fixed`
(A 59,0 % en ataque vs. 88,9 % post; entrega 95,0 → 92,7 %), arrastrada por una
ejecución (semilla 202, A = 7,7 %) con n=3; no concluyente.

**Conclusión (a)**: el ataque, tal como se genera en el piloto y sin
mitigación, **no degrada de forma medible la entrega** (−0,14 ± 0,62 pp
global; el único dominio con efecto detectable es peering, −3,4 ± 1,1 pp, t≈3,2)
y degrada A, como máximo, entre 1,5 ± 3,4 pp (frente a pre-ataque) y 7,9 ± 4,5 pp
(frente a post-ataque; la diferencia entre ambas referencias, 6,5 pp, da idea
del ruido de A entre ventanas). Con A ≈ 79 % y entrega ≈ 95 % sin mitigación, el
margen de mejora que una mitigación puede ganar sobre C2 es ≤ ~8 pp de A y
≈ 0–3 pp de entrega: **el piloto no tiene ataque que mitigar** en términos de
disponibilidad (la capacidad de ataque alcanzable en el laboratorio ya estaba
acotada, `ATTACK_CAPACITY_MEASUREMENT.md`). Esto no invalida TD/TO, pero deja a A
sin sensibilidad a la mitigación.

## 3. Diferencia M−I por tramo y dominio

Entrega% por tramo; celdas: media de la diferencia (n positivos / n pares).
Pares C4−C3 con ambas ejecuciones válidas: 11; pares C1-M−C1-I: 3.

**C4 − C3, todas las composiciones**

| dominio | 0–60 | 60–120 (ataque) | 120–180 |
|---|---|---|---|
| all | +20.5 (11/11) | +15.0 (10/11) | +20.2 (10/11) |
| enterprise | +29.3 (11/11) | +33.0 (11/11) | +36.0 (11/11) |
| fixed | +28.2 (10/11) | +1.6 (6/11) | +11.8 (8/11) |
| mobile | −93.8 (0/11) | −59.3 (0/11) | −45.1 (0/11) |
| peering | −9.2 (2/11) | −7.4 (2/11) | −6.4 (5/11) |

**C4 − C3, solo composición 1 (control; n=7)**

| dominio | 0–60 | 60–120 | 120–180 |
|---|---|---|---|
| all | +23.8 (7/7) | +15.8 (6/7) | +25.6 (7/7) |
| enterprise | +30.3 | +34.6 | +45.8 |
| fixed | +37.7 | +1.0 | +11.5 |
| mobile | −92.4 | −55.9 | −39.8 |
| peering | −11.7 | −5.4 | −2.3 |

**C1-M − C1-I (sin ataque; n=3)**

| dominio | 0–60 | 60–120 | 120–180 |
|---|---|---|---|
| all | +1.9 (2/3) | +11.9 (2/3) | +18.5 (3/3) |
| enterprise | +3.9 | +33.3 | +30.7 |
| fixed | +10.5 | −10.8 | +7.6 |
| mobile | −95.1 | −69.1 | −34.0 |
| peering | −12.7 | −3.9 | +3.1 |

Lectura:

* **La diferencia existe y es del mismo tamaño fuera de la ventana de ataque**
  (0–60 s: +20,5 pp; 120–180 s: +20,2 pp; ventana: +15,0 pp). En el control
  (composición 1) también: +23,8 / +15,8 / +25,6 pp. En C1 (sin ataque en
  absoluto) la diferencia aparece y crece con el tiempo (+1,9 → +11,9 → +18,5).
  **No es un efecto de la mitigación del ataque.**
* **Es una mezcla de signos por dominio**: M entrega más en enterprise
  (+29…+36 pp, 11/11) y fixed, pero **mucho menos en móvil** (−94/−59/−45 pp,
  0/11) y algo menos en peering (−9…−6 pp).
* El agregado `all` sale positivo por el **peso en bytes** de cada dominio en
  `delivery_pct`: enterprise 47,45 %, fixed 34,01 %, peering 18,24 %, **mobile
  0,30 %**. M pierde casi todo el móvil, pero el móvil casi no pesa.
* Por composición (entrega global, 0–60 / 60–120 / 120–180 / run completo):
  c1_enterprise +23,6/+21,1/+8,2/+17,2; c1_fixed +28,6/+22,0/+21,9/+23,8;
  c1_mobile +23,4/+10,5/+39,2/+24,3; c1_peering +21,8/+12,7/+31,3/+21,7;
  c2_over +16,7/+8,9/+1,8/+8,6; c3_under +12,9/+18,0/+19,6/+17,2 (n=1–2 pares
  cada una; los valores "run completo" reproducen los +9…+27 pp de
  `PILOT_RESULT.md`).

## 4. Reinicio de `ryu-manager`, orden y hora

**Hallazgo estructural: el reinicio no varía dentro del diseño.**

| modo | con reinicio inmediatamente antes (60 ejec.) | sin reinicio | con reinicio (34 válidas) | sin reinicio (válidas) |
|---|---|---|---|---|
| I | 21 | 0 | 18 | 0 |
| M | 21 | 0 | 16 | 0 |

* 42/42 ejecuciones con modo (C1-I, C1-M, C3, C4) reiniciaron el controlador
  (cada una tiene su "Applying detection mode", y `controller_restarted=true`),
  **incluidos los 15 pares consecutivos con el mismo modo** donde
  `apply_detection_mode()` debía omitir el reinicio; `PILOT_DESIGN.md` preveía 27.
  (No se investiga aquí por qué no se omitió: el código del panel desplegado en
  el piloto no está en los datos capturados; queda como hallazgo.)
* Las 18 C2 (pipeline suspendido) nunca reiniciaron.
* Consecuencia: **"reinicio ~40 s antes" y "pipeline activo" son la misma
  variable**. Entre ejecuciones con pipeline activo, los segundos desde el
  último reinicio hasta el inicio del tráfico están en 34–57 s (media I 41 s,
  M 42 s) y no hay ninguna sin reinicio; en C2, 145–646 s. La regresión con
  `reinicio_antes` y `s_desde_reinicio` es **singular** (regresor sin
  variación) y no se puede estimar: ni con los datos del piloto es posible
  separar un efecto del reinicio de un efecto del detector activo.
* Orden: las ejecuciones I y M quedaron igual de "justo después de un
  reinicio" (21/21). No hay sesgo de reinicio entre modos.

Regresión OLS (34 ejecuciones válidas con pipeline activo; sin corrección por
semilla; t entre paréntesis). Entrega en pp, A en pp:

| modelo | R² | coeficientes |
|---|---|---|
| entrega 0–60 ~ M | 0.248 | const 59.32 (21.2) · **M +13.28 (3.3)** |
| entrega 0–60 ~ M + ataque | 0.256 | M +13.22 (3.2) · ataque −2.97 (−0.5) |
| entrega 0–60 ~ M + ataque + posición/10 + hora | 0.415 | M +13.17 (3.5) · pos/10 +0.33 (0.0) · hora −4.51 (−0.1) |
| entrega run ~ M + ataque + posición/10 + hora | 0.526 | M +14.74 (4.6) · ataque −10.04 (−2.4) · pos −0.99 (−0.0) · hora −1.95 (−0.1) |
| entrega 60–120 ~ M + ataque | 0.310 | M +12.94 (3.2) · ataque −9.92 (−1.9) |
| A 60–120 ~ M + ataque | 0.270 | M +4.25 (1.8) · ataque −8.73 (−2.8) |
| A 60–120 ~ M + ataque + posición/10 + hora | 0.357 | M +4.59 (2.0) · pos +42.19 (2.0) · hora −51.57 (−2.0) |

* El coeficiente de M (+13 pp en entrega, estable al añadir ataque, posición y
  hora) **ya aparece en 0–60 s (pre-ataque)**: no depende del ataque.
* Posición y hora no tienen efecto en entrega (t ≈ 0); en A sí aparecen con
  t≈±2 pero con signos opuestos y colineales (pos y hora son casi la misma
  variable), no interpretable. Con n=34 y 3 semillas, sin cluster por semilla,
  los t son optimistas.
* Control sin pipeline (C2) a lo largo del piloto, por tercios: entrega
  94,6 / 95,9 / 95,8 %, A 74,4 / 75,6 / 85,9 % → **sin deriva temporal del
  laboratorio** (la entrega de C2 es estable de la primera a la última hora).
* Por tercios del piloto, la ventaja de M en 0–60 s (84,5 / 69,8 / 50,4 % frente
  a I 60,4 / 57,0 / 61,6 %) decae con el tiempo, pero n=3–7 por celda y coincide
  con el cambio de semilla (201 → 202 → 203); no concluyente.

**Prueba de arranque limpio** (separa el reinicio del bloqueo): entrega de los
eventos que *terminan antes* del primer bloqueo/mitigación de la propia
ejecución (T1), frente a la media de C2 de la misma semilla (mismo plan, mismos
`event_id`):

| modo | n | T1 mediana (s) | eventos comparados (mediana) | Δ vs C2 (media / mediana) |
|---|---|---|---|---|
| I | 18 | 21,7 (19,0–27,8) | 150 | **−0,77 / −0,72 pp** |
| M | 10 | 9,5 (de 16 ejecuciones M: 2,3–11,1) | 30 | −29,4 / −26,7 pp |

* En **modo I**, 34–51 s después del reinicio y *antes de cualquier bloqueo*,
  el servicio entrega lo mismo que C2 (−0,77 pp, sobre ~150 eventos): **el
  reinicio por sí solo no degrada el reenvío benigno**.
* En **modo M** la prueba **no es concluyente**: el primer bloqueo llega a los
  2–11 s, quedan ~30 eventos (la mayoría de pocos segundos), y esos eventos
  entregan 22–79 % (vs. 95–99 % en C2). No se pudo atribuir con los datos (no se
  registra el estado del plano de datos antes del primer `mitigation_issued`);
  es un residual abierto. Se señala para §7.
* M detecta (y bloquea) **mucho antes** que I sobre el mismo tráfico benigno
  (mediana 8,8 s vs. 21,7 s).

**Conclusión §4**: el reinicio no se puede estimar (confundido con el
pipeline), pero la evidencia disponible (modo I) no lo señala como causa; orden
y hora no tienen efecto en entrega; no hay desbalance de reinicios entre modos
(21/21).

## 5. Actividad del detector en C1-I y C1-M (sin ataque)

C1 es tráfico benigno puro: **toda** detección, decisión y mitigación es sobre
tráfico benigno.

| semilla | cond | detecciones (tipo) | decisiones aceptadas/total | mitigaciones | por dominio/acción | fuentes únicas bloqueadas |
|---|---|---|---|---|---|---|
| 201 | C1-I | 12 DDOS_DISTRIBUTED | 11/11 | 60 | broadband 56, enterprise 4 (block) | 11 |
| 202 | C1-I | 9 DDOS_DISTRIBUTED | 9/9 | 39 | broadband 36, enterprise 3 | 11 |
| 203 | C1-I | 8 DDOS_DISTRIBUTED | 8/8 | 50 | broadband 48, enterprise 2 | 11 |
| 201 | C1-M | 5 MULTIDOMAIN_DISTRIBUTED_ATTACK | 5/5 | 60 | mobile 23, broadband 33, enterprise 2, **bgp flowspec discard 2** | 16 |
| 202 | C1-M | 4 MULTIDOMAIN_DISTRIBUTED_ATTACK | 4/4 | 40 | mobile 20, broadband 17, enterprise 2, bgp 1 | 12 |
| 203 | C1-M | 4 MULTIDOMAIN_DISTRIBUTED_ATTACK | 4/4 | 44 | mobile 17, broadband 21, enterprise 3, bgp 3 | 16 |

* **Origen del criterio: 42/42 detecciones de C1 provienen del criterio
  distribuido de respaldo** (`_classify_distributed`: suma de pps de *todos* los
  eventos hacia el destino ≥ `DIST_PPS_THRESHOLD` = 300, ≥ 5 fuentes distintas,
  entropía ≥ 0,7). Ningún protocolo cruzó su umbral en la ventana previa a esas
  detecciones. Las pps de esas detecciones son 670–26 000 (2–87× el umbral).
  Detecciones por KPM móvil: 0. Las decisiones se aceptaron 100 % (puntaje
  efectivo ≥ `DECISION_THRESHOLD`=1,5).
* `DIST_PPS_THRESHOLD` quedó "sin tocar" en la recalibración
  (`THRESHOLD_CALIBRATION_RESULT.md`: solo se calibraron SYN/UDP/ICMP), y el
  criterio no usa tasas por protocolo, así que la calibración SYN/UDP/ICMP no lo
  protege.
* Tasas máximas por ciclo antes de t=60 s (detalle en las tablas): ICMP llega a
  256 pps (umbral 240,37) en C1-I y UDP a 19 061 (umbral 14 516) en C1-M, es
  decir, el margen ×1,5 sobre q=0,999 de la calibración es fino: hay cruces
  aislados de umbral por protocolo en tráfico benigno que la histéresis de
  activación no convirtió en detección en C1.
* **Sí hubo mitigaciones sobre tráfico benigno que explican la diferencia**:
  C1-I emite 49,7 mitigaciones/ejecución (todas sobre IP no atacante, 0 flowspec) y
  C1-M 48,0 (incluye 2,0 FlowSpec/ejecución que descarta **todo** el tráfico
  hacia el destino víctima y bloquea los 5 UEs móviles).

Fracción del tiempo con bloqueos activos (`active_blocks>0` en los ciclos
LAB_AUDIT), media por dominio, tramos 0–60 / 60–120 / 120–180 (%):

| cond | n | enterprise | fixed | mobile | peering |
|---|---|---|---|---|---|
| C1-I | 3 | 47/58/73 | 27/40/38 | 0/0/0 | 0/0/0 |
| C1-M | 3 | 53/68/37 | 23/43/21 | 88/100/98 | 59/67/79 |
| C2 | 18 | 0/0/0 | 0/0/0 | 0/0/0 | 0/0/0 |
| C3 | 15 | 47/76/77 | 26/34/24 | 0/12/3 | 0/12/3 |
| C4 | 13 | 44/94/58 | 25/34/15 | 88/93/79 | 25/49/46 |

**Entrega ↔ bloqueo** (pares ejecución×tramo con pipeline activo, n=102 por
dominio; OLS entrega ~ fracción bloqueada):

| dominio | pendiente por 100 % bloqueado (pp) | R² | entrega sin bloqueo | entrega con ≥50 % bloqueo |
|---|---|---|---|---|
| enterprise | −48,4 (t=−5,7) | 0,25 | 67,3 (n=7) | 28,1 (n=71) |
| fixed | −28,4 (t=−3,0) | 0,08 | 80,6 (n=14) | 58,8 (n=13) |
| mobile | −68,4 (t=−13,6) | **0,65** | 85,3 (n=51) | 18,0 (n=46) |
| peering | −18,6 (t=−5,3) | 0,22 | 97,4 (n=68) | 79,9 (n=24) |

Mitigaciones **antes de t=60 s** en C3/C4 (el ataque no ha empezado: son
falsos positivos por definición): C3 10,8 mitigaciones/ejecución (15/15
ejecuciones con ≥1), C4 14,1 (13/13).

Detecciones por tipo y origen (ejecuciones válidas con pipeline activo):

| cond | tipo | origen | n |
|---|---|---|---|
| C1-I | DDOS_DISTRIBUTED | respaldo distribuido | 29 |
| C1-M | MULTIDOMAIN_DISTRIBUTED_ATTACK | respaldo distribuido | 13 |
| C3 | DDOS_DISTRIBUTED | respaldo / umbral TCP_SYN | 65 / 32 |
| C3 | SYN_FLOOD | respaldo / umbral TCP_SYN | 1 / 101 |
| C4 | MULTIDOMAIN_DISTRIBUTED_ATTACK | respaldo / umbral TCP_SYN | 46 / 5 |
| C4 | SYN_FLOOD | umbral TCP_SYN | 68 |

**Por qué el modo cambia el resultado en el control** (mecanismo, verificado en
los registros): ambos modos reciben la misma telemetría, pero la correlación
agrupa distinto (I: por `(dominio, dst_ip)`; M: por `dst_ip`;
`LAB_AUDIT_OBSERVED_RATES.md`), y el criterio de respaldo se evalúa **por
grupo**. Resultado sobre el mismo tráfico benigno:

| aspecto | I | M |
|---|---|---|
| tipo de detección | DDOS_DISTRIBUTED (un dominio) | MULTIDOMAIN_DISTRIBUTED_ATTACK |
| primer bloqueo (mediana, rango) | 21,7 s (19,0–27,8) | 8,8 s (2,3–11,1) |
| dominios bloqueados | enterprise y broadband | **mobile (5 UEs), broadband, enterprise y FlowSpec sobre la víctima** |
| fuentes enterprise cubiertas por cada bloqueo | 4–5 en 35/35 | 5 en 16/34, ≤2 en 15/34 |
| entrega enterprise con bloqueo activo al inicio del evento | 0,6 % | 17,2 % |
| entrega enterprise sin bloqueo al inicio del evento | 27,0 % | 66,6 % |

(Entrega por evento enterprise: I 747 eventos sin bloqueo / 856 con; M 628 / 740.)
El bloqueo enterprise de M es más estrecho (menos fuentes) y por eso deja pasar más:
tras controlar por fracción bloqueada, M sigue sumando **+25,9 pp (t=5,4)** en
enterprise y +9,1 pp (t=2,0) en fixed, y **−33,6 pp (t=−3,3)** en mobile (peering:
+2,0, t=0,6).

## 6. Estado de reenvío (flujos provisionales de 2 s)

**No observable con los datos capturados.** Ningún archivo de las 60 ejecuciones
contiene conteos de flujos provisionales/validados (`grep -il provisional` en las
carpetas de ejecución: vacío); LAB_AUDIT registra `active_blocks` por ciclo, no
el estado de la tabla de flujos. Lo que sí hay:

| cond | n | bloqueos activos en los 1ros 5 s (media) | ejec. con bloqueos al inicio | `openflow_residual_drops` previo | eventos fallidos % | reset % | deadline % |
|---|---|---|---|---|---|---|---|
| C1-I | 3 | 0,0 | 0 | 0 | 76,8 | 0,72 | 13,9 |
| C1-M | 3 | 2,7 | 1 | 0 | 78,0 | 0,91 | 16,9 |
| C2 | 18 | 0,0 | 0 | 0 | 77,3 | 0,76 | 7,7 |
| C3 | 15 | 0,0 | 0 | 0 | 78,6 | 0,75 | 18,7 |
| C4 | 13 | 3,2 | 5 | 0 | 79,7 | 0,90 | 21,4 |

* **Bloqueos al inicio, por modo**: I 0/18 ejecuciones; M 6/16 (5 en C4 y 1 en
  C1-M): arrancan con bloqueos heredados de la ejecución anterior (la preparación aplica
  `release_previous_blocks_before_every_run_v1`; el controlador sigue reportándolos
  en los primeros ciclos). Es una diferencia entre modos (hipótesis, no verificada: los bloqueos de M abarcan más
  dominios y se liberan más tarde) y no del reinicio, que ocurre en ambos.
* `openflow_residual_drops` = 0 en todas las ejecuciones previas.
* Los errores por conexión (reset, deadline, bind, unreachable) no distinguen
  modo ni reinicio (reset 0,75 % I vs. 0,90 % M; deadline 17,9 % vs. 20,6 %;
  "% fallidos" ≈ 77–80 % en todas las condiciones, incluida C2, porque casi
  todos los eventos incumplen la cuota planificada exacta —`shortfall`— aun
  entregando ≈95 %).
* El código desplegado en el controlador durante el piloto es el mismo en las 60
  ejecuciones (un único hash por archivo). `orchestration/controller.py`
  (`9e9e34841160…`) coincide con el repositorio (`16e1ecf`, que incluye ambas
  correcciones de validación de flujo por NAT), así que la causa "flujos
  provisionales de 2 s por NAT" ya estaba corregida durante el piloto.
* **Divergencia repositorio ↔ despliegue (a registrar, no a corregir aquí)**:
  `detection/engine.py` desplegado = `6451eb1a5854…` (commit `eb1a8b5`); el
  `HEAD` del repositorio es `ac7773101c64…` (commit `f96df1f`, "D4-B: prepare
  (not apply)…", una opción **preparada y no aplicada**). Los otros 7 archivos
  registrados coinciden con el `HEAD`. La diferencia es deliberada y anterior al
  piloto; no afecta a este diagnóstico.

**Conclusión §6**: con estos datos no se puede afirmar ni descartar que el modo o
el reinicio cambien cuántos flujos benignos quedan en reglas provisionales. Lo que
sí está medido: el reinicio no está asociado a pérdida de entrega pre-bloqueo en
modo I (−0,77 pp) y sí hay un efecto de modo en el **estado inicial de bloqueos**.

## 7. Conclusiones

### (a) ¿El ataque degrada el servicio en C2 respecto de C1? ¿Cuántos pp en A?

**No.** En C2 (pipeline suspendido): entrega −0,14 ± 0,62 pp (60–120 vs. 0–60),
A: −1,5 ± 3,4 pp vs. pre-ataque (−7,9 ± 4,5 pp vs. post). C1 *no* es la
referencia (tiene detector activo): C2 entrega 28–40 pp **más** que C1
(94,9 % vs. 55,0 % C1-I y 66,8 % C1-M) y A=78,6 % vs. 5,1 % / 15,4 %. Criterio
numérico: efecto del ataque en A = **≈ −1,5 pp (IC ≈ ±7 pp)**, no distinguible
de cero; el ataque tiene capacidad insuficiente para degradar el servicio.

### (b) Causa de M−I ≠ 0 en el control — ordenadas por evidencia

1. **Falsos positivos del detector sobre tráfico benigno** (criterio distribuido
   de respaldo con `DIST_PPS_THRESHOLD`=300, no calibrado, suma de pps de todos
   los protocolos). Evidencia: 6/6 C1 y 28/28 C3/C4 con ≥1 bloqueo antes de t=60 s
   (49,7 y 48,0 mitigaciones por C1; 10,8 y 14,1 antes del ataque en C3/C4);
   42/42 detecciones de C1 por este criterio; pendiente entrega–bloqueo
   significativa en los 4 dominios (mobile R²=0,65). Es la causa del colapso de A
   (C3 0,0 %, C4 3,2 %) y de que C2 supere a C1 por 28–40 pp. **Evidencia fuerte.**
2. **El modo cambia el alcance del falso positivo** (agrupación por dominio vs.
   global): otro tipo de detección, primer bloqueo 2,5× más temprano en M (8,8 s vs.
   21,7 s), M bloquea móvil y FlowSpec sobre la víctima mientras I no, y los
   bloqueos enterprise de M son más estrechos. Evidencia: diferencia M−I presente en
   0–60 s (+20,5 pp), 120–180 s (+20,2 pp) y en C1 sin ataque (+1,9 → +18,5 pp);
   mezcla de signos por dominio (enterprise +29…+36, mobile −94…−45); el signo
   positivo de `all` se explica por el peso en bytes (mobile 0,30 %). **Evidencia
   fuerte para el signo por dominio; el tamaño de la diferencia ±n=3 pares en C1 es
   incierto.** Importante: *en el control I y M no tienen por qué dar lo mismo*
   mientras exista este criterio, porque la correlación de M cambia qué
   fuentes se agrupan y por tanto cuándo y a quién se bloquea.
3. **Residual de enterprise tras controlar por tiempo bloqueado** (+25,9 pp, t=5,4)
   y **residual de arranque en M** (entrega pre-bloqueo −29 pp, n=10, no atribuible).
   **Evidencia parcial / abierta.**
4. **Reinicio, orden y hora: sin evidencia.** El reinicio está confundido al 100 %
   con el pipeline (42/42), pero el arranque limpio en modo I no muestra efecto
   (−0,77 pp); 21/21 reinicios por modo (sin desbalance); posición y hora t≈0 en
   entrega; C2 estable en el tiempo (94,6/95,9/95,8 %). El estado de reenvío
   provisional no es observable (§6).

### (c) Cambio de diseño o de procedimiento que elimina M−I ≠ 0 en el control

Ninguna de estas acciones se ha ejecutado (el prompt pide detenerse aquí); cada una
requiere tu confirmación, y las que tocan el controlador, además, autorización
explícita (cambio de detección/decisión).

1. **Eliminar el falso positivo de base** (condición necesaria): antes de repetir
   el piloto, que C1-I y C1-M tengan 0 detecciones/0 mitigaciones. Opciones:
   (i) recalibrar `DIST_PPS_THRESHOLD` (y revisar `DIST_MIN_SOURCES`) con tráfico
   benigno de semillas disjuntas, usando el cuantil q=0,999 × 1,5 como en
   SYN/UDP/ICMP (la suma de pps por grupo hoy no está en `observed_rates`, que es
   por protocolo: **instrumentar** `fallback_pps` por grupo en `LAB_AUDIT kind=cycle`
   —permitido, con prueba de no cambio de decisión—); (ii) o desactivar el respaldo
   para la campaña si ninguna composición lo necesita. Evidencia a favor de (ii): las
   detecciones de ataque de C3/C4 llegan por umbral TCP_SYN (SYN_FLOOD 101+68,
   DDOS/MULTIDOMAIN 32+5) y las composiciones se diseñaron por umbral de protocolo
   (`ATTACK_PLAN_REGENERATION.md`: Σ=161 pps = 2,10×SYN_THRESHOLD).
   **Criterio de paso**: *replay* offline (`threshold_replay.py`) sobre los LAB_AUDIT
   de C1/C3/C4 ya capturados con el candidato: 0 detecciones en C1 (hoy 42), 0
   mitigaciones antes de t=60 s en C3/C4 (hoy 10,8 y 14,1 por ejecución) y cobertura de las 28 ejecuciones C3/C4 con ataque sin pérdida (hoy detección 13/15 y 11/13, mitigación 12/15 y 11/13).
2. **Hacer visible la causa en el diseño**: añadir la condición **C0 = benigno con
   pipeline suspendido** (referencia limpia para el impacto del ataque en A y de
   C1 como control de falsos positivos); hoy "impacto del ataque" solo se puede
   medir dentro de C2.
3. **Procedimiento (reinicio)**: (i) verificar por qué `apply_detection_mode()` no
   omitió el reinicio en 15/15 pares con el mismo modo (el piloto no registra el
   código del panel); (ii) dar a la comparación una variable de reinicio con
   variación (p. ej. 1 de cada N corridas sin reinicio, o reiniciar también antes de
   C2) para poder estimarlo, o registrar el reinicio como bloque. Sin variación no se
   puede decir nada del reinicio.
4. **Indicador**: mientras exista bloqueo de tráfico benigno, A es ≈0 en C3/C4 y
   no discrimina; sólo tras (1) A tiene margen (C2 = 78,6 %, de modo que el techo de
   mejora por mitigación es ≈ 20 pp). Y el ataque debe tener capacidad real para
   degradar C2 (hoy −1,5 ± 3,4 pp en A): subir la intensidad (dentro de la capacidad
   medida) o cambiar la métrica a una que el ataque sí mueva.
5. **Instrumentación pendiente** (no cambia decisiones): estado del plano de datos
   antes del primer bloqueo (conteos de flujos provisionales/validados), `fallback_pps`
   por grupo, y serie de tasas independiente del atacante para tE/TM.

## 8. Supuestos y límites

* n pequeño: 3 semillas, 6–18 ejecuciones por condición, 1–3 pares por
  composición. Los errores estándar son clásicos, sin cluster por semilla (optimistas).
* `delivery_pct` por tramo reparte proporcionalmente los bytes de cada evento sobre su
  duración planificada; un evento cortado por un bloqueo posterior arrastra su pérdida
  a tramos previos (mismo método que `response_metrics.compute_availability`). La
  prueba de arranque limpio usa solo eventos que terminan antes de T1 para evitarlo.
* A usa D=90 %, L=150 ms (valores por defecto *provisionales* de
  `response_metrics.DEFAULTS`), ventana de 5 s, "cobertura" simplificada (ventana
  completa y posterior al warmup).
* El "origen" de cada detección (respaldo vs. umbral de protocolo) se infiere de
  `observed_rates` en la ventana previa a la detección (incluye el retardo de
  activación); no hay un campo explícito en LAB_AUDIT.
* "Bloqueo activo" se toma de `active_blocks` por ciclo (~0,5 s); no equivale a
  confirmación de instalación en el plano de datos.
* La explicación de que el bloqueo enterprise de M es más estrecho se basa en el
  número de fuentes del bloqueo emitido; no se verificó en el plano de datos.
* Los 8 runs fallidos (todos en semilla 202–203, relojes/timeout) están
  conservados y excluidos; no se descartó ningún dato.

## 9. Qué se cambió y trazabilidad

Solo se añadieron archivos nuevos en `traffic-generator-pucp` (rama
`pilot-diagnosis`, sin commit ni push todavía); no hay despliegues ni cambios en ninguna VM:

| archivo | sha256 |
|---|---|
| `scripts/pilot_diagnosis_lib.py` | `c05b15238e4ac9f5f340d20f14e3e62933c434ca6d7612c075d5f30d4c1306cc` |
| `scripts/pilot_diagnosis.py` | `945eb4be2e422cc18e88262d453f63fcb6b28c1f20f70988dfff14104b43061a` |
| `docs/PILOT_DIAGNOSIS_tables.md` (generado) | `1f298f2ac7cb92632340eec2e3339faef5c7b906f41ae239f1f463ef75a34619` |

En `orchestrator-ddos-pucp` se creó la rama `pilot-diagnosis` sin cambios (el
informe no modifica el controlador). Datos de salida:
`.runtime/benign-lab/calibration/pilot_diagnosis.json`.

## Punto de control

Aquí me detengo, como se pidió: no se modificó el laboratorio ni el diseño. Quedan
a tu decisión (§7c): (1) abrir el paso de calibración/replay del criterio
distribuido de respaldo; (2) añadir C0; (3) revisar el no-salto del reinicio.
