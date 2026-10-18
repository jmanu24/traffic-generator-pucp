"""Homogeneous telemetry records across domains (#9).

Today each domain's telemetry has its own shape: interface_monitor.py stores
{ts, element, domain, body} with body from interface_probe.py (rx_mbps,
tx_mbps, rx_bytes, ...); Peering additionally has nfcapd-derived flow
records (docs/WATCHDOG_PEERING.md); Mobile's own KPM telemetry comes from
the RIC's E2 subscription (isp-ddos-ryu, FlexRIC/O-RAN SC RIC, outside this
repository — see memory on E2 fragility). Analytics (#6) and audit (#10)
currently have to know each shape separately.

This module does not add new collectors: it defines one canonical record
shape and a normalize() entry point so each domain's existing collector
output can be mapped into it with a small per-source adapter, instead of
every consumer learning every domain's native format.
"""
from __future__ import annotations
import time

CANONICAL_FIELDS = ('domain', 'source', 'element', 'metric', 'value', 'unit', 'timestamp')


def record(domain, source, element, metric, value, unit, timestamp=None):
    if not domain or not source or not element or not metric:
        raise ValueError('domain, source, element and metric are required')
    if unit not in ('mbps', 'bytes', 'packets', 'pct', 'count', 'ms'):
        raise ValueError(f'Unsupported unit: {unit}')
    return dict(domain=domain, source=source, element=element, metric=metric,
                value=value, unit=unit, timestamp=timestamp if timestamp is not None else time.time())


def from_interface_sample(domain, element, body, timestamp):
    """benign_lab.interface_monitor's stored {ts, element, domain, body}."""
    out = []
    for metric, unit in (('rx_mbps', 'mbps'), ('tx_mbps', 'mbps'),
                          ('rx_bytes', 'bytes'), ('tx_bytes', 'bytes'),
                          ('rx_dropped', 'count'), ('tx_dropped', 'count'),
                          ('rx_errors', 'count'), ('tx_errors', 'count')):
        if body.get(metric) is not None:
            out.append(record(domain, 'interface', element, metric, body[metric], unit, timestamp))
    return out


def from_mapping(domain, source, element, raw, mapping, timestamp=None):
    """Generic adapter for a source whose native field names/units are known
    but not yet worth a dedicated from_*() function: mapping is
    {native_field: (metric_name, unit)}. Used to wire Peering's nfcapd
    records and Mobile's KPM samples once their exact field names are
    confirmed against the live RIC/collector (pending, see
    docs/INSTRUMENTATION_PLAN.md Fase 6) without inventing a new mechanism
    for each one.
    """
    out = []
    for native_field, (metric, unit) in mapping.items():
        if raw.get(native_field) is not None:
            out.append(record(domain, source, element, metric, raw[native_field], unit, timestamp))
    return out
