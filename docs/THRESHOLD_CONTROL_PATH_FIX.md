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

Este fix solo corrige la ruta; **no** reaplica los umbrales calibrados
al árbol real. Eso requiere tocar el lab real (SSH + reinicio de
`ryu-manager`) y se hizo como un paso separado, con confirmación
explícita antes de cada acción remota — ver el reporte final de esta
tarea para los resultados numéricos de esa reaplicación.
