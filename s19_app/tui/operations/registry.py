"""
Deterministic code-driven operation registry (batch-08, HLR-002 /
LLR-002.2). A static literal mapping — no entry points, no reflection, no
model involvement in dispatch (engineering rule 5).
"""

from __future__ import annotations

from .crc import CrcOperation
from .model import Operation
from .placeholders import ExtractOperation, SplitBySegmentOperation

#: The static registry — insertion order IS the deterministic enumeration
#: order of :func:`list_operation_ids` (LLR-002.2).
_REGISTRY: dict[str, Operation] = {
    "crc": CrcOperation(),
    "extract": ExtractOperation(),
    "split_by_segment": SplitBySegmentOperation(),
}


def list_operation_ids() -> list[str]:
    """
    Summary:
        Enumerate the registered operation ids in their fixed deterministic
        order — exactly ``["crc", "extract", "split_by_segment"]`` on every
        call (LLR-002.2).

    Returns:
        list[str]: A fresh list of the registered ids in registry order.

    Data Flow:
        - Reads the static :data:`_REGISTRY` mapping; never mutates it.

    Dependencies:
        Uses:
            - _REGISTRY
        Used by:
            - The HLR-004 operations view (increment I3)
            - tests/test_operations.py (TC-005)
    """
    return list(_REGISTRY)


def get_operation(operation_id: str) -> Operation:
    """
    Summary:
        Resolve an ``operation_id`` to its registered operation instance
        (LLR-002.2); an unknown id is a loud failure (LLR-002.3) — no
        fallback, no fuzzy match, no default operation.

    Args:
        operation_id (str): The id to resolve, one of
            :func:`list_operation_ids`.

    Returns:
        Operation: The registered instance for ``operation_id``.

    Raises:
        KeyError: If ``operation_id`` is not registered; the message
            contains the requested id verbatim.

    Data Flow:
        - Membership check + lookup against the static :data:`_REGISTRY`;
          never mutates it.

    Dependencies:
        Uses:
            - _REGISTRY
        Used by:
            - tui.services.operation_service.run_operation (increment I2)
            - tests/test_operations.py (TC-004 / TC-005 / TC-006)
    """
    if operation_id not in _REGISTRY:
        raise KeyError(f"unknown operation id: {operation_id}")
    return _REGISTRY[operation_id]
