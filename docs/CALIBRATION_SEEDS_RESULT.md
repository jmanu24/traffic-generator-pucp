# Paso 3 (THRESHOLD_CALIBRATION): resultado — completo

Las 20 corridas de calibración (semillas 101–110, B0, `pipeline=enabled`,
180 s, modo `lab`) se completaron contra el laboratorio real el
2026-10-19, cada semilla en ambos tratamientos, **I** (`isolated`) y
**M** (`multidomain`), con verificación doble de `detection_mode` exitosa
en todas. Manifiesto completo en
`.runtime/benign-lab/calibration/calibration_seeds_manifest.json`
(`final`: las 20 corridas con evidencia; `full_history`: también los
intentos fallidos, nunca borrados).

| Semilla | Conjunto | `run_id` (I) | `run_id` (M) |
|---|---|---|---|
| 101 | entrenamiento | `20261019T210650-ecbf3622` | `20261019T211702-40ee7cdb` |
| 102 | entrenamiento | `20261019T212052-6d331410` | `20261019T215517-6089ceed` |
| 103 | entrenamiento | `20261019T220006-22c705eb` | `20261019T220459-9d3bab5f` |
| 104 | entrenamiento | `20261019T220949-45e70c8b` | `20261019T221442-ef09557d` |
| 105 | entrenamiento | `20261019T221938-6586404d` | `20261019T222433-ada37284` |
| 106 | validación | `20261019T222926-5341497e` | `20261019T223416-8b4b55dd` |
| 107 | validación | `20261019T223915-1a3deb0f` | `20261019T224412-e6a321ce` |
| 108 | validación | `20261019T224905-bc47d4a1` | `20261019T231548-6eec296a` (reintento) |
| 109 | validación | `20261019T225547-bf5e3d1e` | `20261019T230046-98d089fd` |
| 110 | validación | `20261019T230540-dfd6162c` | `20261019T231027-f36e973c` |

Todas `completed_with_errors` (estado terminal normal en esta base de
código — los errores de evento son parte del resultado, no motivo para
excluir la corrida). Ninguna falló por disconformidad de `detection_mode`
en el resultado final.

## Cómo se llegó aquí (bloqueo inicial + 4 problemas reales encontrados y corregidos)

1. **Bloqueo inicial — `ue5` desconectado del core 5G.** El Paso 3
   corre B0 con los 4 dominios a la vez; a diferencia del Paso 2 no hay
   forma de excluir `mobile` por API. Pausado a tu pedido hasta que
   reconectaste `ue5` tú mismo (confirmado vía
   `GET http://10.10.0.5:8766/telemetry`).
2. **`manager.audit` nunca estaba conectado** (documentado en
   `IM_COMPARISON_DESIGN.md` §7, pero nunca escrito) — la primera corrida
   real falló en preparación porque la segunda evidencia de
   `detection_mode` no tenía de dónde leer. Corregido en `api.py`
   (commit `a0ee244`), con prueba de regresión.
3. **Carrera de tiempos en la verificación de `detection_mode`** — el
   reloj `since` se capturaba ANTES del restart lento del controlador, así
   que la primera corrida de cada tratamiento recogía un ciclo LAB_AUDIT
   todavía del modo anterior y fallaba la verificación. Reproducido en 4
   corridas reales consecutivas, siempre con el mismo patrón (nunca un
   valor realmente discordante, siempre el modo previo). Corregido
   capturando `since` después de que el restart se confirma (commit
   `145c034`), con prueba de regresión que falla sin el fix y pasa con él.
4. **Regla de bloqueo OpenFlow residual** — un falso positivo real y
   legítimo (`MULTIDOMAIN_DISTRIBUTED_ATTACK`, enterprise+mobile) de
   `seed102/M` instaló un bloqueo (`duration=60s`) que nunca tuvo ventana
   para auto-liberarse porque la pipeline se suspendía de nuevo para la
   siguiente corrida antes de que transcurriera. Identificado
   comparando la regla OVS exacta
   (`tcp,in_port=3,nw_dst=10.55.0.100,tp_dst=9001,actions=drop`) contra
   el `mitigation_issued` real de esa corrida (coincidencia exacta:
   mismo dominio, puerto, `in_port`, `sources`); liberado con tu
   confirmación explícita (`ovs-ofctl del-flows`, solo esa coincidencia).
   Después de esto, el orquestador (`scripts/run_calibration_seeds.py`)
   se ajustó con 65 s de enfriamiento entre corridas para que cualquier
   bloqueo con `duration=60s` tenga ventana de auto-liberarse antes de
   la siguiente suspensión.
5. **Un timeout de conexión transitorio** en `seed108/M` (primer
   intento): `Receiver preflight: Cannot connect to 10.55.0.100:9001
   from 10.45.1.2: TimeoutError` — no relacionado con `detection_mode`
   ni con ninguno de los puntos anteriores. El primer intento fallido
   se conserva en `full_history`; el reintento exitoso es el que cuenta
   en `final`.

## Qué sigue

Paso 4 (propuesta de umbrales con cuantil×margen sobre las tasas
`observed_rates` del Paso 1, registradas en estas 20 corridas bajo M;
replay de FPR en I y M; validación en 106-110) — pendiente, siguiente
paso natural ahora que las 20 corridas están completas.
