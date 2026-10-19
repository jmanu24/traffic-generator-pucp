"""Homogeneous telemetry records across domains (Fase 6, #9)."""
import pytest
from benign_lab.domain_telemetry import (
    record, from_interface_sample, from_mapping, from_peering_flow,
    from_kpm_sample, CANONICAL_FIELDS,
)


def test_record_has_the_canonical_shape():
    r = record('mobile', 'interface', 'ue1', 'rx_mbps', 12.5, 'mbps', timestamp=100.0)
    assert set(r) == set(CANONICAL_FIELDS)


def test_record_rejects_unknown_units():
    with pytest.raises(ValueError):
        record('mobile', 'interface', 'ue1', 'rx_mbps', 1, 'furlongs')


def test_from_interface_sample_maps_the_real_interface_probe_body():
    body = dict(rx_mbps=10.0, tx_mbps=2.0, rx_bytes=1000, tx_bytes=200,
                rx_dropped=0, tx_dropped=0, rx_errors=None, tx_errors=None,
                operstate='up', interface='eth0')
    rows = from_interface_sample('enterprise', 'ent-site-1', body, timestamp=5.0)
    metrics = {r['metric'] for r in rows}
    assert metrics == {'rx_mbps', 'tx_mbps', 'rx_bytes', 'tx_bytes', 'rx_dropped', 'tx_dropped'}
    assert all(r['domain'] == 'enterprise' and r['timestamp'] == 5.0 for r in rows)


def test_from_mapping_is_the_generalized_adapter_for_future_domains():
    raw = dict(bps=5_000_000, pkts=1200, unused_field=None)
    rows = from_mapping('peering', 'nfcapd', 'peer-flow-3', raw,
                         mapping={'bps': ('throughput_bps', 'count'), 'pkts': ('packets', 'packets')})
    assert {r['metric']: r['value'] for r in rows} == {'throughput_bps': 5_000_000, 'packets': 1200}


def test_from_peering_flow_maps_the_real_nfdump_decoded_record():
    # Exact shape of collectors.peering_flow_collector.PeeringFlowCollector
    # ._parse_csv()'s output in orchestrator-ddos-pucp (the repo actually
    # deployed on the orchestrator node).
    flow = dict(src_ip='203.0.113.5', dst_ip='10.55.0.100', dst_port=80,
                protocol='TCP_SYN', pps=50.0, bps=32000.0)
    rows = from_peering_flow(flow, timestamp=42.0)
    by_metric = {r['metric']: r for r in rows}
    assert by_metric['pps']['value'] == 50.0 and by_metric['pps']['unit'] == 'pps'
    assert by_metric['throughput_bps']['value'] == 32000.0 and by_metric['throughput_bps']['unit'] == 'bps'
    assert all(r['domain'] == 'peering' and r['source'] == 'nfcapd' and r['timestamp'] == 42.0 for r in rows)
    assert by_metric['pps']['element'] == '203.0.113.5->10.55.0.100:80/TCP_SYN'


def test_from_kpm_sample_maps_the_real_e2sm_kpm_counters():
    # Exact counter names oran_bridge.kpm_telemetry_api._KEEP_METRICS keeps,
    # as surfaced in telemetry.mobile_adapter.TelemetryEvent.kpm.
    kpm = {'DRB.UEThpUl': 1200, 'DRB.AirIfDelayUl': 12.5,
           'RRU.PrbUsedUl': 40, 'RRC.ConnMean': 3}
    rows = from_kpm_sample('ue1', kpm, timestamp=7.0)
    by_metric = {r['metric']: r for r in rows}
    assert by_metric['throughput_ul']['value'] == 1200 and by_metric['throughput_ul']['unit'] == 'kbps'
    assert by_metric['air_interface_delay_ul']['unit'] == 'ms'
    assert by_metric['prb_used_ul']['unit'] == 'count'
    assert all(r['domain'] == 'mobile' and r['source'] == 'kpm' and r['element'] == 'ue1' for r in rows)


def test_from_kpm_sample_skips_counters_not_present_in_the_sample():
    rows = from_kpm_sample('ue1', {'DRB.UEThpUl': 1200})
    assert {r['metric'] for r in rows} == {'throughput_ul'}
