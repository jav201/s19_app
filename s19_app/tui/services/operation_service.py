"""
Operation service — the headless entry point for special operations
(batch-08, HLR-003 / LLR-003.1).

:func:`run_operation` resolves an operation id through the deterministic
registry (LLR-002.2) and invokes its ``execute``, forwarding the caller's
``now_fn`` clock unchanged (the single delivery route: caller →
``run_operation`` → ``execute``). The registry lookup is held in the
module-level :data:`operation_resolver` seam — the ``check_runner``
precedent (``change_service.ChangeService.check_runner``) — defaulting to
the real ``registry.get_operation``, substitutable in tests. An unknown id
propagates the registry's ``KeyError`` unchanged (LLR-002.3).

This module performs no I/O, writes nothing to disk, and performs no
parsing (LLR-003.1 acceptance criterion — the guarantee A-4 cites to
justify synchronous UI-thread execution). It imports stdlib + the
``operations`` package + ``models`` only — **no Textual import**, no
import of ``app`` / ``screens`` (LLR-003.2).
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

from ..models import LoadedFile
from ..operations import Operation, OperationResult
from ..operations.registry import get_operation

#: The registry-lookup seam (LLR-003.1): a callable
#: ``(operation_id) -> Operation`` defaulting to the real registry resolver
#: (``operations.registry.get_operation``); kept injectable so tests can
#: substitute a stub operation (the ``check_runner`` seam precedent,
#: ``change_service.py``).
operation_resolver: Callable[[str], Operation] = get_operation


def run_operation(
    operation_id: str,
    loaded: LoadedFile,
    *,
    now_fn: Optional[Callable[[], datetime]] = None,
) -> OperationResult:
    """
    Summary:
        Execute one registered operation against a loaded-image snapshot
        and return its :class:`OperationResult`, with no TUI interaction
        (LLR-003.1). Resolution goes through the :data:`operation_resolver`
        seam; ``now_fn`` is forwarded unchanged to the operation's
        ``execute`` keyword-only clock parameter.

    Args:
        operation_id (str): The registry id of the operation to run, one of
            ``list_operation_ids()`` (LLR-002.2).
        loaded (LoadedFile): The loaded-image snapshot to operate on.
        now_fn (Optional[Callable[[], datetime]]): Injectable UTC clock,
            forwarded unchanged to ``Operation.execute``; ``None`` lets the
            operation default to the system UTC clock (LLR-001.1).

    Returns:
        OperationResult: The 7-field result envelope produced by the
        operation's ``execute`` (LLR-001.2).

    Raises:
        KeyError: If ``operation_id`` is not registered — the LLR-002.3
            registry error, propagated unchanged (no fallback, no fuzzy
            match).

    Data Flow:
        - ``operation_id`` → :data:`operation_resolver` → operation
          instance → ``execute(loaded, now_fn=now_fn)`` → result returned
          unmodified. No I/O, no disk writes, no parsing anywhere on the
          path (probe P11).

    Dependencies:
        Uses:
            - operation_resolver (default: operations.registry.get_operation)
            - Operation.execute
        Used by:
            - The HLR-004 operations view (increment I3)
            - tests/test_operations.py (TC-007)

    Example:
        >>> result = run_operation("crc", loaded)
        >>> result.operation_id
        'crc'
        >>> result.status
        'placeholder'
    """
    operation = operation_resolver(operation_id)
    return operation.execute(loaded, now_fn=now_fn)
