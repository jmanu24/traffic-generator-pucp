"""Homogeneous telemetry records across domains (Fase 6, #9)."""
import pytest
from benign_lab.domain_telemetry import record, from_interface_sample, from_mapping, CANONICAL_FIELDS


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
