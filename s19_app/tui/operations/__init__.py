"""
Special operations over a loaded image — re-export facade (batch-08,
HLR-001/HLR-002).

Public surface of the ``operations`` package: the ``Operation`` abstraction
and ``OperationResult`` envelope (``model.py``), the three placeholder
operations (``placeholders.py``), and the deterministic registry
(``registry.py``). Import from here; the modules stay the implementation
detail. Headless by contract — no Textual imports anywhere (LLR-003.2).
"""

from .crc import CrcOperation
from .model import Operation, OperationResult, STATUS_DOMAIN
from .placeholders import (
    ExtractOperation,
    SplitBySegmentOperation,
)
from .registry import get_operation, list_operation_ids

__all__ = [
    "Operation",
    "OperationResult",
    "STATUS_DOMAIN",
    "CrcOperation",
    "ExtractOperation",
    "SplitBySegmentOperation",
    "get_operation",
    "list_operation_ids",
]
