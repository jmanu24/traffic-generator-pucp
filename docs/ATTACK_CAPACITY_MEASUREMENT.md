# Paso 2 (THRESHOLD_CALIBRATION): capacidad de ataque alcanzable

Medido en vivo contra el laboratorio real, 2026-10-19, pipeline suspendido
(`BaselineGuard`, por dominio), `attack_runner`, 64 B/paquete, 30 s
sostenidos por combinación. Metodología: `attack_flood`
(`benign_lab/agent.py`) *pacea* su envío al `rate_pps` pedido — no corre a
toda velocidad por defecto — así que para medir el techo real se pidió
una tasa objetivo deliberadamente inalcanzable (50 000 pps; 500 000 pps
en el reintento de enterprise/UDP, ver abajo) y se reportó
`attack_pps_actual` como la tasa real sostenida sin que el *pacing* la
limitara. Una sola pasada por combinación (no un protocolo de sondeo +
confirmación en dos fases) para acotar el tiempo real de laboratorio —
ver "Supuestos" más abajo.

## Tabla dominio × vector

| Dominio | Fuentes disponibles | UDP (pps) | SYN (pps) | ICMP (pps) |
|---|---|---|---|---|
| enterprise | 5 (`ent-site-1..5`) | **330 224** (`ent-site-1`; reintento a 500 000 pps objetivo — el primer intento a 50 000 pps rozó el objetivo al 99,99 %, señal de que no era el techo real) | 24 686 (`ent-site-1`) | **no medido** — ver limitación |
| fixed | 10 (`fixed1..10`) | 29 253 (`fixed1`) | 13 462 (`fixed1`) | 23 677 (`fixed1`) |
| peering | 1 (`peer-flow*`, representa hasta ~100 flujos simulados) | 35 733 (`peer-flow*`) | 15 325 (`peer-flow*`) | **no medido** — ver limitación |
| mobile | 5 configuradas (`ue1..5`); **4 confirmadas conectadas ahora** | **no medido** — ver limitación | **no medido** | **no medido** |

Datos crudos: `.runtime/benign-lab/calibration/attack_capacity_measurement.json`
(fixed/enterprise/peering UDP+SYN, más el ICMP exitoso de `fixed`).

## Limitaciones encontradas (no resueltas sin tu confirmación)

1. **ICMP en `enterprise` y `peering` falla**: `icmp_flood requires
   CAP_NET_RAW/root on the client` — esos nodos se conectan como
   `labadmin` sin ese capability (a diferencia de `fixed`/`mobile`, que
   corren dentro de un *namespace* con `sudo`). Una posible solución de
   mínimo privilegio es `setcap cap_net_raw+ep $(which python3)` en esos
   hosts — un cambio de configuración del host, no de este repositorio;
   **pendiente de tu confirmación**, no se aplicó.
2. **`mobile` no se midió**: `BaselineGuard.enter()` falla al restaurar
   presupuestos móviles porque `ue5` (10.45.1.7) no tiene una sesión
   única y clara en el core 5G (`Mobile identity missing or ambiguous`)
   — un estado del laboratorio no relacionado con esta tarea. Se excluyó
   `mobile` del alcance de la suspensión de pipeline (`guard.domains`)
   para no bloquear los otros tres dominios. **Pendiente de tu decisión**:
   reconectar/diagnosticar `ue5` (coherente con el orden estricto de
   arranque documentado en memoria) antes de medir `mobile`, o medir con
   una fuente distinta si `ue1-4` sí están sanas.

## Incidentes durante la medición (ya resueltos, sin impacto duradero)

- La contraseña root de `pe` (10.10.0.7) no es la compartida del
  laboratorio — es `root`/`root`. El primer intento con la contraseña
  equivocada hizo fallar `BaselineGuard.enter()` en el paso que lee
  `ovs-ofctl dump-flows` en `pe`, **después de que el lease ya había
  suspendido la mitigación** pero antes de que mi script llegara a su
  bloque `try/finally`. Se restauró manualmente de inmediato
  (`guard.leave()` con el mismo `run_id`) y se verificó de forma
  independiente: `systemctl show ryu-manager` activo, cero reglas de
  bloqueo OVS residuales en `pe`. El script se corrigió para que
  `guard.enter()` quede dentro del mismo `try/finally` que el resto, así
  un fallo de `enter()` ya nunca deja la suspensión sin restaurar.
- El primer intento completo (con `mobile` incluido) falló en
  `BaselineGuard.enter()` por el problema de `ue5` descrito arriba, con
  el mismo patrón: lease activo brevemente, restaurado de inmediato y
  verificado.

## Supuestos

- Una sola fuente por dominio (`ent-site-1`, `fixed1`, `peer-flow*`,
  `ue1` pendiente) — el prompt pide "tasa máxima alcanzable por fuente",
  no agregada entre fuentes; el número de fuentes disponibles se reporta
  aparte (tabla) para la composición multidominio del Paso 4.
- Objetivo deliberadamente inalcanzable (50 000 pps, 500 000 para el
  reintento) en vez de un protocolo sondeo→confirmación en dos fases —
  una sola pasada de 30 s por combinación, para acotar el tiempo total
  contra el laboratorio real (~6 minutos de tráfico de ataque real en
  total, sin contar el *overhead* de suspender/restaurar la pipeline).
- No se investigó por qué `fixed`/`peering` SYN (13-15 kpps) son
  notablemente más bajos que su UDP/ICMP — consistente con el costo de
  `socket()+connect()+close()` por paquete que ya documenta
  `benign_lab/agent.py::attack_flood`, no una anomalía de esta medición.
