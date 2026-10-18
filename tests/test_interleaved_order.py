"""Balanced run ordering generalized beyond the fixed 3-seed design (Fase 3)."""
import pytest
from benign_lab.scenario_series import interleaved_order


def test_interleaved_order_matches_known_three_seed_rotation_count():
    order = interleaved_order([1, 2, 3])
    assert len(order) == 9  # 3 seeds x 3 repeats (default repeats_per_seed=len(seeds))
    assert sorted(order[:3]) == [1, 2, 3]


def test_interleaved_order_every_seed_appears_in_every_position():
    seeds = [10, 20, 30, 40]
    order = interleaved_order(seeds, repeats_per_seed=4)
    rows = [order[i:i+4] for i in range(0, len(order), 4)]
    for position in range(4):
        assert sorted(row[position] for row in rows) == sorted(seeds)


def test_interleaved_order_scales_beyond_three_seeds():
    order = interleaved_order(list(range(1, 8)), repeats_per_seed=7)
    assert len(order) == 49
    assert all(seed in order for seed in range(1, 8))


def test_interleaved_order_rejects_empty_or_bad_repeats():
    with pytest.raises(ValueError):
        interleaved_order([])
    with pytest.raises(ValueError):
        interleaved_order([1, 2], repeats_per_seed=0)
