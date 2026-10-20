# Paso 3 (THRESHOLD_CALIBRATION) — bloqueado, pausado a tu pedido

## Estado

- Dashboard en vivo (`benign-lab-web.service`) reiniciado con el código
  de esta rama (`threshold-calibration`) — ya soporta `detection_mode`
  con verificación doble (D1) y quedó verificado en vivo: una corrida
  real con `detection_mode=I` mostró
  `detection_mode_verification: {requested: isolated, log_evidence:
  {applied: isolated, controller_restarted: true}, audit_cycle_evidence:
  {value: false}}` — ambas evidencias coincidieron.
- Los 10 planes benignos de calibración (semillas 101-110, 180 s) ya
  están cargados en el almacén de planes del dashboard en vivo
  (`.runtime/benign-lab/data/plans/{hash}.json`), listos para usar.
- `scripts/run_calibration_seeds.py` (el orquestador del Paso 3) está
  escrito y probado en su primer paso (arranca la corrida, espera,
  recopila el manifiesto) — nunca llegó a ejecutar las 20 corridas
  completas.

## Por qué está bloqueado

La corrida de prueba (semilla 101, modo I) pasó la verificación de
`detection_mode` y llegó a `BaselineGuard.enter()`, que falla igual que
en el Paso 2: `ue5` (10.45.1.7) no tiene una sesión única en el core 5G
(`Mobile identity missing or ambiguous for ue5 / 10.45.1.7`). A
diferencia del Paso 2 (donde pude acotar `guard.domains` a solo los
dominios que estaba midiendo), el Paso 3 corre B0 con los 4 dominios a
la vez a través de la API del dashboard — no hay forma de excluir
`mobile` de esa ejecución sin regenerar los planes sin tráfico móvil.

La corrida falló limpiamente: `baseline_control.restoration.restored ==
true`, controlador `active: false` — no quedó nada suspendido en el
laboratorio real.

## Confirmado contigo (2026-10-19)

Decidiste pausar el Paso 3 hasta que arregles `ue5` tú mismo, en vez de
que yo lo diagnostique o regenere los planes sin `mobile`. No se tocó
nada más del laboratorio real desde esa decisión.

## Para reanudar

Cuando `ue5` esté reconectado (confirmable con
`GET http://10.10.0.5:8766/telemetry` → `sessions` debe incluir
`{"ip": "10.45.1.7", ...}`), avísame y corro
`python3 scripts/run_calibration_seeds.py` — las 20 corridas (10
semillas × {I, M}), ~70 minutos de laboratorio real, con tu confirmación
antes de arrancar si ha pasado tiempo desde esta decisión.
