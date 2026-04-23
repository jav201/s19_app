from __future__ import annotations

from s19_app.range_index import (
    address_in_sorted_ranges,
    build_sorted_range_index,
    range_in_sorted_ranges,
)


def test_address_in_sorted_ranges_binary_search_membership():
    index = build_sorted_range_index([(0x2000, 0x2100), (0x1000, 0x1010)])
    assert address_in_sorted_ranges(0x1000, index)
    assert address_in_sorted_ranges(0x100F, index)
    assert address_in_sorted_ranges(0x2001, index)
    assert not address_in_sorted_ranges(0x1010, index)
    assert not address_in_sorted_ranges(0x0FFF, index)


def test_range_in_sorted_ranges_requires_single_range_coverage():
    index = build_sorted_range_index([(0x1000, 0x1010), (0x1020, 0x1030)])
    assert range_in_sorted_ranges(0x1004, 4, index)
    assert not range_in_sorted_ranges(0x100F, 2, index)
    assert not range_in_sorted_ranges(0x1010, 1, index)
    assert not range_in_sorted_ranges(0x1004, 0, index)
