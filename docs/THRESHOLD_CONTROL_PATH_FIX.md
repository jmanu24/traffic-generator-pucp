# Fix: `ThresholdControl` apuntaba a un árbol de código muerto

Continuación directa del hallazgo A de
`ATTACK_PLAN_REGENERATION_VALIDATION.md` (sección "CONFIRMADO:
`ThresholdControl.apply()` edita un árbol de código abandonado").

## El bug

`benign_lab/threshold_control.py` (`read()` y `apply()`) tenía
hardcodeada la ruta `/opt/Tesis_Controller/config/settings.py`. Esa
ruta:

- existe en el host del controlador,
- tiene su propio `.git`, viejo y sin relación con el proyecto actual,
- **no es la que `ryu-manager` importa**.

La unidad systemd real (`systemctl show ryu-manager -p WorkingDirectory
-p Environment`) corre con `WorkingDirectory=/home/labadmin/orchestrator-ddos-pucp`
y `PYTHONPATH=/home/labadmin/orchestrator-ddos-pucp`, así que
`config.settings` se importa desde ahí, no desde `/opt/Tesis_Controller`.

Consecuencia: `ThresholdControl.apply()` escribía los umbrales
calibrados en el archivo equivocado, reiniciaba `ryu-manager` de verdad
(el reinicio sí ocurría, `controller_restarted: true` era honesto sobre
eso) y el controlador volvía a arrancar con el **mismo** `config/settings.py`
real de siempre — sin leer nunca el archivo que `apply()` acababa de
escribir. El `config_sha256` que devolvía tampoco correspondía al
archivo que el controlador usa.

## El fix

En vez de hardcodear ninguna ruta (ni la vieja ni la nueva — un segundo
hardcodeo volvería a poder desincronizarse si alguna vez el
`WorkingDirectory` de la unidad cambia), tanto `read()` como `apply()`
resuelven la ruta **en el momento de la llamada**, en el controlador
mismo, con:

```python
out=subprocess.run(['systemctl','show','ryu-manager','-p','WorkingDirectory'],
                    capture_output=True,text=True,check=True).stdout
p=Path(out.strip().split('=',1)[1])/'config'/'settings.py'
```

Este es exactamente el mismo patrón que ya usa
`benign_lab/detection_mode_control.py` para leer
`DETECTION_CROSS_DOMAIN_CORRELATION` en vivo vía `systemctl show
ryu-manager -p Environment` — no se introduce ningún mecanismo nuevo,
solo se aplica el que ya existía en el propio proyecto al problema de
`threshold_control.py`. Con esto, si algún día se reconfigura
`WorkingDirectory` del servicio, `ThresholdControl` lo sigue
automáticamente en vez de volver a apuntar a un árbol viejo en
silencio.

El código compartido vive en `_SETTINGS_PATH_CODE` dentro de
`threshold_control.py` y se inyecta en los dos bloques de código remoto
(`read()` y `apply()`) vía `.replace('SETTINGS_PATH_CODE', ...)`, igual
que ya se hacía con `FIELDS`/`EXPECTED`/`VALUES`.

## Qué NO cambió

- Ninguna lógica de detección, decisión o mitigación.
- El contrato de `read()`/`apply()` (firma, forma del JSON devuelto,
  validaciones de campos/rango, el lease check, el backup antes de
  escribir, el rollback si el controlador no vuelve a responder en
  `6653`) — todo igual.
- `FIELDS` (el conjunto de umbrales permitidos).

## Cómo se validó (sin tocar el lab real)

`tests/test_threshold_control.py` (nuevo): genera el código remoto para
`read()` y `apply()` sin ejecutar nada por SSH, y verifica que:

1. el código compila (`compile(..., 'exec')`),
2. **no** contiene la ruta vieja `/opt/Tesis_Controller`,
3. contiene la llamada a `systemctl show ryu-manager -p WorkingDirectory`,
4. construye la ruta final como `Path(WorkingDirectory)/config/settings.py`.

Esto es exactamente el tipo de regresión que habría detectado este bug
sin necesitar SSH al lab: si alguien reintroduce una ruta hardcodeada,
la aserción 2 falla.

`tests/test_detection_evaluation.py::test_threshold_writer_changes_only_allowed_assignment`
(ya existía, cubre la escritura real del archivo vía `exec()` del
código generado) se actualizó para simular la llamada a `systemctl show
... WorkingDirectory` en lugar de la sustitución directa de la ruta
hardcodeada — sigue ejerciendo el mismo camino de escritura/backup/
restart/rollback que antes.

Toda la suite de `pytest` (menos los módulos que ya fallaban antes de
este cambio por falta de `fastapi` en este entorno, y
`test_fixed_preparation.py::test_enabled_runner_refreshes_before_agents_without_entering_baseline`,
que falla igual en la rama base `attack-plan-regeneration` sin este
fix — confirmado comparando ambas ramas) pasa igual que antes.

## Lo que este fix NO hizo (y por qué)

Este fix en sí mismo solo corrige la ruta; no reaplica umbrales por sí
solo. La reaplicación real se hizo como un paso separado, con
confirmación explícita antes de la acción remota (ver más abajo).

## Reaplicación real (2026-10-20, con confirmación explícita)

Con el fix ya en el árbol, se reaplicaron los umbrales ya calibrados
por `THRESHOLD_CALIBRATION` (nunca antes aplicados de verdad — ver la
advertencia al inicio de `THRESHOLD_CALIBRATION_RESULT.md`) contra el
path correcto:

- Lectura previa (vía el `read()` ya corregido): `SYN_THRESHOLD=10`,
  `UDP_THRESHOLD=200`, `ICMP_THRESHOLD=150` — confirma que el
  controlador seguía sin calibrar antes de este paso.
- `apply()` con `{SYN_THRESHOLD: 76.82, UDP_THRESHOLD: 14515.64,
  ICMP_THRESHOLD: 240.37}`: `config_sha256` final
  `1ad54993ad3b41e2f2a94755c19a6da8368d47eb225a9008f54d2e6927648708`.
- Confirmado en vivo por tres vías independientes: (1)
  `/home/labadmin/orchestrator-ddos-pucp/config/settings.py` en disco
  tiene los tres valores nuevos; (2) `systemctl show ryu-manager`
  reporta `active` con un `ExecMainStartTimestamp` que coincide con el
  momento de la reaplicación (reinicio real, no solo reportado); (3) un
  ciclo `LAB_AUDIT kind=cycle` fresco, leído directamente de
  `/var/log/ryu-manager.log`, reporta
  `thresholds.values.SYN_THRESHOLD=76.82`, `UDP_THRESHOLD=14515.64`,
  `ICMP_THRESHOLD=240.37` — el motor de detección en ejecución ya usa
  los valores calibrados. `DECISION_THRESHOLD` (1,5) y
  `DETECTION_CROSS_DOMAIN_CORRELATION` (multidomain) quedaron intactos,
  como se pidió.

Nota de concurrencia: la primera invocación de `apply()` desde esta
tarea chocó con el guard de hash (`'Threshold configuration changed;
reload before applying'`) porque otra sesión aplicó los mismos valores
casi al mismo tiempo contra el mismo controlador; el estado final
verificado arriba es el correcto y único resultado — no hubo dos
escrituras conflictivas, solo una carrera benigna entre dos lecturas.

## Hallazgo de seguimiento: el ≈2× de enterprise es real y no depende de esto

Ver el addendum de 2026-10-20 en
[`ATTACK_PLAN_REGENERATION_VALIDATION.md`](ATTACK_PLAN_REGENERATION_VALIDATION.md#addendum-2026-10-20--hallazgo-a-corregido-el-19-2-de-enterprise-no-depende-de-él-confirmado-en-vivo):
con los umbrales ya calibrados en vivo, una reejecución de
`composition1_enterprise` sigue mostrando ~1,96× de sobre-conteo
(715,60 pps observados vs 364,89 emitidos) -- confirma que el
hallazgo A nunca fue la causa de esa discrepancia; el sospechoso real
es un posible doble conteo en `telemetry/openflow_adapter.py`
(`orchestrator-ddos-pucp`), no corregido aquí (fuera de alcance de
esta tarea).
