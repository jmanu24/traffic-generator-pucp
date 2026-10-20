# Paso 2 (THRESHOLD_CALIBRATION): capacidad de ataque alcanzable

Medido en vivo contra el laboratorio real, 2026-10-19, pipeline suspendido
(`BaselineGuard`, por dominio), `attack_runner`, 64 B/paquete, 30 s
sostenidos por combinación. Metodología: `attack_flood`
(`benign_lab/agent.py`) *pacea* su envío al `rate_pps` pedido — no corre a
toda velocidad por defecto — así que para medir el techo real se pidió
una tasa objetivo deliberadamente inalcanzable (50 000 pps; 500 000 pps
en los reintentos de `enterprise`/UDP e `enterprise`/ICMP, ver "Supuestos")
y se reportó `attack_pps_actual` como la tasa real sostenida sin que el
*pacing* la limitara. Una sola pasada por combinación (no un protocolo de
sondeo + confirmación en dos fases) para acotar el tiempo real de
laboratorio.

## Tabla dominio × vector — completa

| Dominio | Fuentes disponibles | UDP (pps) | SYN (pps) | ICMP (pps) |
|---|---|---|---|---|
| enterprise | 5 (`ent-site-1..5`) | **330 224** (`ent-site-1`) | 24 686 (`ent-site-1`) | **102 830** (`ent-site-1`) |
| fixed | 10 (`fixed1..10`) | 29 253 (`fixed1`) | 13 462 (`fixed1`) | 23 677 (`fixed1`) |
| peering | 1 (`peer-flow*`, representa hasta ~100 flujos simulados) | 35 733 (`peer-flow*`) | 15 325 (`peer-flow*`) | 25 755 (`peer-flow*`) |
| mobile | 5 configuradas (`ue1..5`); **4 confirmadas conectadas al core 5G** (`ue5` no) | 34 825 (`ue1`) | 5 116 (`ue1`) | 13 096 (`ue1`) |

`enterprise`/UDP y `enterprise`/ICMP necesitaron un segundo intento: el
primero, a 50 000 pps objetivo, llegó a 99,99 % del objetivo (señal de
que el objetivo —no el cliente— era el límite); repetidos a 500 000 pps
objetivo dieron el techo real mostrado arriba.

**Nota de diseño del detector, relevante para el Paso 4**: para UDP/ICMP,
`detection/engine.py::_classify()` excluye explícitamente el tráfico
`mobile` del `trigger_pps` evaluado (es KPM-driven, no pps-driven — ver
`docs/LAB_AUDIT_OBSERVED_RATES.md`). Los números de UDP/ICMP de `mobile`
en esta tabla son reales y quedan documentados, pero **no participan** en
la factibilidad de umbrales UDP/ICMP del Paso 4; solo su SYN (5 116 pps)
es relevante ahí, porque TCP_SYN sí incluye a mobile en `trigger_pps`.

Datos crudos: `.runtime/benign-lab/calibration/attack_capacity_measurement.json`
(fixed/enterprise/peering UDP+SYN+fixed-ICMP) y
`attack_capacity_measurement_gaps.json` (enterprise/peering-ICMP, mobile
completo).

## Cómo se resolvieron las dos limitaciones iniciales

1. **ICMP en `enterprise`/`peering`** (`icmp_flood requires CAP_NET_RAW/
   root`): se aplicó `setcap cap_net_raw+ep` al binario real de python3.10
   (resuelto el symlink `/usr/bin/python3` primero — `setcap` falla sobre
   un symlink) en `ent-site-1` (10.10.0.21) y `peer-flow*`/`br`
   (10.10.0.17), confirmado con `getcap`. Cambio de host, mínimo
   privilegio (solo esa capability, no root completo), reversible
   (`setcap -r`), aplicado con tu confirmación explícita.
2. **`mobile`**: `ue5` (10.45.1.7) no tiene sesión en el core 5G
   (`GET http://10.10.0.5:8766/telemetry` confirma `ue1-4` conectadas,
   `ue5` ausente de `sessions`) — un estado del laboratorio no relacionado
   con esta tarea, no se intentó diagnosticar/reconectar `ue5` (pediste
   medir con otra UE sana en vez de eso). Se midió con `ue1`. Para que
   `BaselineGuard.enter()` pudiera restaurar los presupuestos móviles sin
   `ue5`, se le pasó una copia de `cfg` con `nodes.ue5.configured=False`
   **solo al guard** — `run_attack()` siguió usando el `cfg` real sin tocar
   (marcar `ue5` como no configurado ahí dispara
   `config.mapping_issues()`, que exige TODOS los nodos configurados sin
   importar qué use un plan de ataque concreto, y habría bloqueado medir
   cualquier dominio).

## Incidentes durante la medición (ya resueltos, sin impacto duradero)

- La contraseña root de `pe` (10.10.0.7) no es la compartida del
  laboratorio — es `root`/`root`. El primer intento con la contraseña
  equivocada hizo fallar `BaselineGuard.enter()` en el paso que lee
  `ovs-ofctl dump-flows` en `pe`, **después de que el lease ya había
  suspendido la mitigación** pero antes de que el script llegara a su
  bloque `try/finally`. Se restauró manualmente de inmediato
  (`guard.leave()` con el mismo `run_id`) y se verificó de forma
  independiente: `systemctl show ryu-manager` activo, cero reglas de
  bloqueo OVS residuales en `pe`. El script se corrigió para que
  `guard.enter()` quede dentro del mismo `try/finally` que el resto, así
  un fallo ahí ya nunca deja la suspensión sin restaurar.
- El primer intento completo (con `mobile` incluido, antes de saber del
  problema de `ue5`) falló en `BaselineGuard.enter()` con el mismo patrón
  de restauración inmediata y verificada.
- El primer intento de medir los huecos marcó `ue5` como no configurado
  en el `cfg` compartido por error, lo que bloqueó los 5 intentos de esa
  corrida con `Incomplete laboratory mapping: nodes.ue5.configured` —sin
  tocar el laboratorio real (el error ocurre en `config.resolve()`,
  antes de cualquier SSH de ataque). Corregido separando el `cfg` del
  guard del `cfg` de `run_attack()`.

## Supuestos

- Una sola fuente por dominio (`ent-site-1`, `fixed1`, `peer-flow*`,
  `ue1`) — el prompt pide "tasa máxima alcanzable por fuente", no
  agregada entre fuentes; el número de fuentes disponibles se reporta
  aparte (tabla) para la composición multidominio del Paso 4.
- Objetivo deliberadamente inalcanzable (50 000 pps, 500 000 en los dos
  reintentos) en vez de un protocolo sondeo→confirmación en dos fases —
  una sola pasada de 30 s por combinación, para acotar el tiempo total
  contra el laboratorio real (~8 minutos de tráfico de ataque real en
  total entre las tres corridas, sin contar el *overhead* de suspender/
  restaurar la pipeline).
- No se investigó por qué `fixed`/`peering`/mobile SYN son notablemente
  más bajos que su UDP/ICMP — consistente con el costo de
  `socket()+connect()+close()` por paquete que ya documenta
  `benign_lab/agent.py::attack_flood`, no una anomalía de esta medición.
- `setcap` en `ent-site-1`/`peer-flow*` es una capability a nivel de
  binario (python3.10), no por proceso — queda aplicada permanentemente
  en esos hosts hasta que alguien la revierta explícitamente
  (`setcap -r /usr/bin/python3.10`). No se revirtió porque habilita
  mediciones ICMP futuras legítimas desde esos clientes; avísame si
  prefieres que la retire.
