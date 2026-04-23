from __future__ import annotations

import bisect
from typing import List, Tuple

RangeIndex = Tuple[List[int], List[int]]


def build_sorted_range_index(ranges: List[Tuple[int, int]]) -> RangeIndex:
    """
    Summary:
        Build a sorted parallel ``(starts, ends)`` index for binary-search membership checks.

    Args:
        ranges (List[Tuple[int, int]]): Half-open ``(start, end)`` ranges.

    Returns:
        RangeIndex: Two aligned lists sorted by ``start``.

    Data Flow:
        - Sort incoming ranges by start address.
        - Split into parallel start/end vectors.

    Dependencies:
        Used by:
            - ``address_in_sorted_ranges``
            - ``range_in_sorted_ranges``
            - ``s19_app.validation.engine``
            - ``s19_app.tui.hexview``
    """
    if not ranges:
        return ([], [])
    sorted_ranges = sorted(ranges, key=lambda item: item[0])
    starts = [start for start, _ in sorted_ranges]
    ends = [end for _, end in sorted_ranges]
    return starts, ends


def address_in_sorted_ranges(addr: int, index: RangeIndex) -> bool:
    """
    Summary:
        Test whether ``addr`` belongs to any indexed half-open range.

    Args:
        addr (int): Address to test.
        index (RangeIndex): Output of ``build_sorted_range_index``.

    Returns:
        bool: True when ``starts[i] <= addr < ends[i]`` for some ``i``.

    Data Flow:
        - Locate candidate range with ``bisect_right`` on starts.
        - Confirm candidate exists and contains ``addr``.

    Dependencies:
        Uses:
            - ``bisect.bisect_right``
        Used by:
            - ``s19_app.validation.engine.validate_artifact_consistency``
            - ``s19_app.tui.hexview`` helpers
    """
    starts, ends = index
    if not starts:
        return False
    candidate = bisect.bisect_right(starts, addr) - 1
    if candidate < 0:
        return False
    return addr < ends[candidate]


def range_in_sorted_ranges(addr: int, length: int, index: RangeIndex) -> bool:
    """
    Summary:
        Test whether ``[addr, addr + length)`` is fully contained by one indexed range.

    Args:
        addr (int): Range start.
        length (int): Positive range length in bytes.
        index (RangeIndex): Output of ``build_sorted_range_index``.

    Returns:
        bool: True when one indexed range contains the whole span.

    Data Flow:
        - Reject non-positive lengths.
        - Locate candidate range via binary search.
        - Confirm span fits the candidate boundaries.

    Dependencies:
        Uses:
            - ``bisect.bisect_right``
        Used by:
            - ``s19_app.validation.engine.validate_artifact_consistency``
            - ``s19_app.tui.hexview`` helpers
    """
    if length <= 0:
        return False
    starts, ends = index
    if not starts:
        return False
    candidate = bisect.bisect_right(starts, addr) - 1
    if candidate < 0:
        return False
    return addr >= starts[candidate] and (addr + length) <= ends[candidate]
