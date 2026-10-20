# Validación de los planes regenerados (semilla 201, pipeline suspendido)

Ejecutado el 2026-10-20 con `scripts/validate_regenerated_attack_plans.py`:
`detection_mode` cambiado a `isolated` (solo para que `observed_rates`
venga por dominio, no logica nueva), pipeline suspendido
(`BaselineGuard`), los 6 planes lanzados una vez cada uno, `detection_mode`
devuelto a `multidomain` (su valor previo) al terminar. Pipeline y modo
confirmados restaurados (`{'restored': True, ...}`). Evidencia completa en
`/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/calibration/attack_plan_regeneration_validation.json`
y en `detection_audit.sqlite` (registros LAB_AUDIT crudos, conservados).

## Resultado 1 — `attack_pps_actual` (criterio ±10 %): **pasa, con margen amplio**

| Plan | Fuente | Objetivo (pps) | Real (pps) | Error |
|---|---|---|---|---|
| composition1_enterprise | ent-site-1 | 364,895 | 364,888 | 0,002 % |
| composition1_fixed | fixed1 | 364,895 | 364,888 | 0,002 % |
| composition1_mobile | ue1 | 364,895 | 364,889 | 0,002 % |
| composition1_peering | peer-flow* | 364,895 | 364,891 | 0,001 % |
| composition2 enterprise | ent-site-1 | 345,69 | 345,687 | 0,001 % |
| composition2 fixed | fixed1 | 23,046 | 23,052 | 0,025 % |
| composition2 peering | peer-flow* | 23,046 | 23,052 | 0,027 % |
| composition3 enterprise | ent-site-1/2 | 34,569 c/u | 34,583 / 34,568 | <0,05 % |
| composition3 fixed | fixed1/2 | 26,887 c/u | 26,901 / 26,901 | <0,06 % |
| composition3 mobile | ue1/2 | 19,205 c/u | 19,218 / 19,217 | <0,07 % |

Todas las fuentes, en las 3 composiciones, muy por debajo del 10 % de
error permitido.

## Resultado 2 — tasa agregada observada por el controlador (criterio
±15 %): **no se pudo validar — se encontró una divergencia de
configuración en vivo, ajena a este prompt**

| Plan / dominio | Planificado (pps) | `observed_controller_trigger_pps` | Razón (ver más abajo) |
|---|---|---|---|
| composition1 enterprise | 364,895 | 688,54 (1,89×) | **A** |
| composition1 fixed | 364,895 | 366,0 (1,003×) | dentro de ±15 % |
| composition1 mobile | 364,895 | **null** (ningún grupo) | **B** |
| composition1 peering | 364,895 | 2 900,6 (7,95×) | **C** |
| composition2 enterprise | 345,69 | 672,82 (1,95×) | **A** |
| composition2 fixed | 23,046 | 23,5 (1,02×) | dentro de ±15 % |
| composition2 peering | 23,046 | 2 108,2 (91,5×) | **C** |
| composition3 enterprise (Σ) | 69,138 | 134,77 (1,95×) | **A** |
| composition3 fixed (Σ) | 53,774 | 54,0 (1,004×) | dentro de ±15 % |
| composition3 mobile (Σ) | 38,41 | **null** (ningún grupo) | **B** |

**fixed es el único dominio que coincide (±2 %) en las tres
composiciones** — confirma que el método de medición (lanzar el plan,
capturar `LAB_AUDIT kind=cycle` en la ventana real del ataque) es
correcto; los otros tres dominios muestran problemas reales distintos:

### A — CONFIRMADO: `ThresholdControl.apply()` edita un árbol de código
abandonado, nunca el que corre de verdad — la calibración de Task B
**nunca llegó al controlador real**

Diagnóstico de solo lectura (con tu permiso explícito), resultado
inequívoco:

```
systemctl show ryu-manager -p Environment -p WorkingDirectory -p ExecStart
  ExecStart = /opt/Tesis_Controller/venv/bin/ryu-manager ... controller/ryu_controller_2.py
  WorkingDirectory = /home/labadmin/orchestrator-ddos-pucp
  Environment = PYTHONPATH=/home/labadmin/orchestrator-ddos-pucp ...

grep SYN_THRESHOLD /opt/Tesis_Controller/config/settings.py
  SYN_THRESHOLD = 76.82      # <- lo que ThresholdControl.apply() escribió

grep SYN_THRESHOLD /home/labadmin/orchestrator-ddos-pucp/config/settings.py
  SYN_THRESHOLD = 10         # <- lo que el proceso real IMPORTA (PYTHONPATH)

readlink -f /opt/Tesis_Controller
  /opt/Tesis_Controller       # no es un symlink; es un árbol real y aparte,
                              # con su propio .git, viejo (log.log de sep-14),
                              # que nada importa en producción
```

`ryu-manager` corre el binario del venv que vive bajo `/opt/Tesis_Controller`,
pero su `PYTHONPATH`/`WorkingDirectory` apuntan a
`/home/labadmin/orchestrator-ddos-pucp` — ahí es de donde Python
realmente importa `config.settings`. `benign_lab/threshold_control.py`
tiene **hardcodeada** la ruta `/opt/Tesis_Controller/config/settings.py`
(línea 12 y 26) — un árbol que el proceso real nunca lee. El `git log`
de `/home/labadmin/orchestrator-ddos-pucp` en el controlador confirma
que su HEAD sigue en `3e2610c` (el fix de duración de peering, el commit
anterior a la calibración) — **Paso 4 de `THRESHOLD_CALIBRATION` nunca
tocó el árbol real**, a pesar de que `ThresholdControl.apply()` reportó
`controller_restarted: true` y un `config_sha256` nuevo: ese reinicio
fue real, pero reinició el controlador con los umbrales **viejos**
(10/200/150) porque el archivo que de verdad importa nunca cambió.

Esto también explica el **≈1,9× en enterprise** de la tabla de arriba
si corresponde al mismo mecanismo de doble conteo que el bug de duración
de `peering` que ya se corrigió en Paso 1-3 (ese fix también fue a
`/home/labadmin/orchestrator-ddos-pucp`, así que si existe un bug
análogo en el colector de enterprise, sigue sin corregir en el árbol
real) — no confirmado, pero coherente.

**Esto es ajeno al prompt de esta tarea (regeneración de planes) y no lo
corregí yo mismo** — ni el path hardcodeado en `threshold_control.py` ni
una reaplicación de los umbrales al árbol real, porque ambos son
cambios de infraestructura/calibración fuera del alcance de "regenera
los planes de ataque", y la regla "no cambies detección/decisión/
mitigación salvo que el prompt lo pida explícitamente" aplica también a
re-aplicar una calibración anterior sin que tú lo pidas aquí. Avísame
cómo quieres proceder (¿otra tarea dedicada a corregir
`threshold_control.py` y volver a aplicar Paso 4 contra el árbol real?).

### B — la señal SYN de mobile no aparece en `observed_rates`

En los 133 ciclos de `LAB_AUDIT` capturados durante la ventana completa
del ataque de mobile (composition1_mobile, 60 s) y los capturados
durante composition3, `observed_rates` viene **vacío** (`[]`) — ningún
grupo con `domains=["mobile"]` se reportó en absoluto, ni con
`TCP_SYN` ni con ningún otro protocolo. No es un problema de umbral
(trigger_pps se reporta sin importar el umbral) — es que la correlación
no está viendo tráfico de mobile en modo `isolated` durante estas
ventanas. Esto es independiente del hallazgo A y no estaba documentado
en `THRESHOLD_CALIBRATION_RESULT.md` (cuyas calibraciones de
entrenamiento/validación sí usaron mobile exitosamente, pero en modo M,
no I, y posiblemente antes de que algo cambiara). **Sin confirmar la
causa.**

### C — peering tiene un fondo benigno dominante, ya documentado como
un comportamiento esperado

`THRESHOLD_CALIBRATION_RESULT.md` ya documenta que "las tasas UDP/ICMP de
peering siguen siendo notablemente más altas... se trató como una
característica real de peer-flow* (~100 flujos simulados)". Lo mismo
aplica aquí para SYN: el agregado observado de peering (2 900,6 y
2 108,2 pps, en corridas con ataques de 364,9 y 23,0 pps respectivamente)
es casi independiente de la tasa de ataque — dominado por tráfico
legítimo de fondo, no por un error de medición. **Esto no es nuevo, pero
sí significa que el criterio ±15 % tal como está escrito en el prompt
(comparar agregado observado contra SOLO la tasa de ataque planificada)
nunca podría cumplirse para peering**, con o sin el hallazgo A resuelto
— habría que comparar contra (ataque + fondo benigno medido
independientemente), que este prompt no pidió medir.

## Resultado 3 — criterio de composición 3 (cada dominio bajo su umbral
local, suma sobre el umbral): **no evaluable con los datos de hoy**

Con `SYN_THRESHOLD` en vivo mostrando 10 (no 76,82), literalmente
**todos** los agregados observados (enterprise 134,77; fixed 54,0) están
muy por ENCIMA del umbral en vivo (10) — lo opuesto a por diseño. Con el
umbral calibrado (76,82) que debería estar activo: fixed (54,0) sí
quedaría debajo; enterprise (134,77) quedaría **por encima**, violando el
diseño de la composición — pero ese 134,77 en sí depende del hallazgo A
sin resolver (¿es 134,77 real, o es ~69 con el "×1,9" siendo un artefacto
de configuración?). mobile no se puede evaluar (hallazgo B). **No puedo
darte un resultado confiable de este criterio hoy.**

## Lo que sí quedó confirmado y no requiere más acción

- La generación/emisión del lado del generador (`attack_pps_actual`) es
  correcta y precisa en las 10 fuentes de las 3 composiciones.
- El pipeline fue suspendido correctamente durante toda la validación
  (ninguna mitigación real se aplicó) y restaurado al finalizar.
- `detection_mode` fue devuelto a `multidomain` (su valor antes de este
  script) al finalizar.
- Ninguna de las 6 corridas quedó a medio terminar ni se perdió
  evidencia; todo está en
  `calibration/attack_plan_regeneration_validation.json` y en
  `detection_audit.sqlite`.

## Punto de control: me detengo aquí

El prompt pide "Detente tras la validación. No ejecutes condiciones con
detección activa." — no ejecuté ninguna condición con detección activa
(el pipeline estuvo suspendido todo el tiempo). Pero la validación en sí
reveló una divergencia real de configuración en el controlador (hallazgo
A) y una ausencia de señal de mobile (hallazgo B) que no puedo resolver
sin un diagnóstico adicional de solo lectura sobre el laboratorio real,
bloqueado por el modo automático de esta sesión y que requiere tu
permiso explícito. No seguí investigando por mi cuenta.
