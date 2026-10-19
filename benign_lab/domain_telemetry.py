"""Homogeneous telemetry records across domains (#9).

Today each domain's telemetry has its own shape: interface_monitor.py stores
{ts, element, domain, body} with body from interface_probe.py (rx_mbps,
tx_mbps, rx_bytes, ...); Peering's real shape is
orchestrator-ddos-pucp/collectors/peering_flow_collector.py's nfdump-decoded
{src_ip, dst_ip, dst_port, protocol, pps, bps}; Mobile's real shape is
orchestrator-ddos-pucp/telemetry/mobile_adapter.py's row, whose `kpm` dict is
oran_bridge/kpm_telemetry_api.py's parsed E2SM-KPM counters (DRB.UEThpUl,
DRB.AirIfDelayUl, RRU.PrbUsedDl, ...). orchestrator-ddos-pucp (not
isp-ddos-ryu) is what's actually deployed on the orchestrator node; both
source files were confirmed byte-identical between the two repos before
building this on them. Analytics (#6) and audit (#10) currently have to
know each shape separately.

This module does not add new collectors: it defines one canonical record
shape and adapters so each domain's existing collector output maps into it,
instead of every consumer learning every domain's native format.
"""
from __future__ import annotations
import time

CANONICAL_FIELDS = ('domain', 'source', 'element', 'metric', 'value', 'unit', 'timestamp')
UNITS = ('mbps', 'kbps', 'bps', 'pps', 'bytes', 'packets', 'pct', 'count', 'ms')


def record(domain, source, element, metric, value, unit, timestamp=None):
    if not domain or not source or not element or not metric:
        raise ValueError('domain, source, element and metric are required')
    if unit not in UNITS:
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
    {native_field: (metric_name, unit)}. from_peering_flow() and
    from_kpm_sample() below are built on this once the real field names
    were confirmed; a future domain can start the same way.
    """
    out = []
    for native_field, (metric, unit) in mapping.items():
        if raw.get(native_field) is not None:
            out.append(record(domain, source, element, metric, raw[native_field], unit, timestamp))
    return out


_PEERING_FLOW_MAPPING = dict(pps=('pps', 'pps'), bps=('throughput_bps', 'bps'))


def from_peering_flow(flow, timestamp=None):
    """orchestrator-ddos-pucp's (the repo actually deployed on the
    orchestrator node) collectors.peering_flow_collector
    .PeeringFlowCollector._parse_csv(): one nfdump-decoded flow,
    {src_ip, dst_ip, dst_port, protocol, pps, bps} (confirmed by reading
    that module directly). `element` identifies the flow (source ->
    destination:port/protocol), mirroring from_interface_sample()'s
    per-element rows."""
    element = f"{flow['src_ip']}->{flow['dst_ip']}:{flow.get('dst_port', 0)}/{flow.get('protocol', 'IP')}"
    return from_mapping('peering', 'nfcapd', element, flow, _PEERING_FLOW_MAPPING, timestamp)


# orchestrator-ddos-pucp's oran_bridge/kpm_telemetry_api.py _KEEP_METRICS,
# the exact E2SM-KPM counter names that module keeps (confirmed by reading
# it directly; byte-identical to isp-ddos-ryu's copy of the same file, but
# orchestrator-ddos-pucp is the repo actually deployed on the orchestrator
# node and the one to keep checking against); units from the standard
# counters' own definitions. The parser there discards the bracketed/
# parenthesised unit the RIC itself reports per sample (only the numeric
# value is kept upstream), so these are the nominal units for each counter,
# not read back from a live sample -- worth a spot check against
# oran_bridge's own output if this ever looks off.
_KPM_MAPPING = {
    'RRC.ConnMean': ('connected_ues_mean', 'count'),
    'DRB.UEThpDl': ('throughput_dl', 'kbps'),
    'DRB.UEThpUl': ('throughput_ul', 'kbps'),
    'DRB.AirIfDelayUl': ('air_interface_delay_ul', 'ms'),
    'DRB.RlcDelayUl': ('rlc_delay_ul', 'ms'),
    'DRB.RlcPacketDropRateDl': ('rlc_packet_drop_rate_dl', 'pct'),
    'DRB.RlcSduDelayDl': ('rlc_sdu_delay_dl', 'ms'),
    'DRB.RlcSduTransmittedVolumeDL': ('rlc_sdu_volume_dl', 'bytes'),
    'DRB.RlcSduTransmittedVolumeUL': ('rlc_sdu_volume_ul', 'bytes'),
    'RRU.PrbAvailDl': ('prb_avail_dl', 'count'),
    'RRU.PrbAvailUl': ('prb_avail_ul', 'count'),
    'RRU.PrbTotDl': ('prb_tot_dl', 'count'),
    'RRU.PrbTotUl': ('prb_tot_ul', 'count'),
    'RRU.PrbUsedDl': ('prb_used_dl', 'count'),
    'RRU.PrbUsedUl': ('prb_used_ul', 'count'),
}


def from_kpm_sample(element, kpm, timestamp=None):
    """orchestrator-ddos-pucp's telemetry.mobile_adapter.TelemetryEvent.kpm:
    a flat {E2SM-KPM counter name: numeric value} dict (confirmed by
    reading mobile_adapter.py and oran_bridge/kpm_telemetry_api.py
    directly on the orchestrator-ddos-pucp checkout). `element` is the
    UE/DU identity (e.g. the row's device_id/src_ip)."""
    return from_mapping('mobile', 'kpm', element, kpm, _KPM_MAPPING, timestamp)
