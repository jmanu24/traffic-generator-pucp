# Verificación: la validación de FPR/FNR de THRESHOLD_CALIBRATION no
dependía del umbral en vivo

## Contexto

`docs/THRESHOLD_CONTROL_PATH_FIX.md` descubrió que `ThresholdControl.apply()`
escribía los umbrales calibrados en una ruta muerta
(`/opt/Tesis_Controller/config/settings.py`), nunca en la que
`ryu-manager` realmente importa — el controlador corrió con los
umbrales viejos (SYN=10/UDP=200/ICMP=150) durante todo el periodo en
que se midió el FPR/FNR de `THRESHOLD_CALIBRATION_RESULT.md`. Esto hizo
sospechar (advertencia añadida inicialmente a ese documento) que la
validación de FPR/FNR quedaba "no verificada" y habría que repetirla.

## Verificación

**Esa sospecha era incorrecta.** `benign_lab/threshold_replay.py` (Paso
4) es una réplica **pura y offline**: `propose_thresholds()` y
`replay_activation()` solo leen las tasas crudas ya capturadas por la
instrumentación de Paso 1 (`observed_rates` en `LAB_AUDIT`, que mide
`trigger_pps` SIN comparar contra ningún umbral — por diseño, para que
Paso 1 nunca cambie ninguna decisión) y reciben el **umbral propuesto**
como parámetro explícito de Python. El módulo nunca abre una conexión
SSH, nunca lee el estado del controlador en vivo (su propio docstring
ya lo decía: "Pure computation: no SSH, no live state").

`scripts/verify_fpr_replay_independence.py` reproduce, a partir de los
MISMOS datos ya guardados en `.runtime/benign-lab/data/runs/` (sin
tocar el laboratorio real), exactamente los números publicados:

```
Umbrales propuestos: SYN=76.82 (n=6605) UDP=14515.644 (n=1354) ICMP=240.367 (n=641)
FPR entrenamiento: I=0.0% M=1.67% (8/480)
FPR validación: 0.0% (0/960)
```

Coinciden byte a byte con `THRESHOLD_CALIBRATION_RESULT.md`. Esto
demuestra que el valor de `SYN_THRESHOLD` que el controlador real
tuviera configurado durante la captura (10, o 76,82 — da igual) **no
afecta en nada** a estos números, porque el cómputo nunca lo consulta.

## Conclusión

No se requiere repetir ninguna corrida ni recalcular nada de
`THRESHOLD_CALIBRATION_RESULT.md`. La advertencia original en ese
documento fue corregida (ver su propia nota al inicio) para reflejar
esto.
