"""
The three placeholder operations (batch-08, HLR-002 / LLR-002.1).

``CrcOperation``, ``ExtractOperation``, and ``SplitBySegmentOperation`` are
identity passthroughs: ``execute`` echoes the neutral :class:`OperationInput`
it received back out as ``output`` (a ``LoadedFile`` over the same
``mem_map`` / ``ranges``), with ``status="placeholder"`` and exactly one
``"placeholder: <operation_id> not yet implemented"`` note (LLR-001.3).
Zero operation logic lives here — the fill-in batch replaces exactly one
class body (§6.1 "fill-in batch"). No I/O, no parsing, no Textual imports.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from ..models import LoadedFile
from .model import Operation, OperationInput, OperationResult


def _placeholder_result(
    operation: Operation,
    op_input: OperationInput,
    now_fn: Optional[Callable[[], datetime]],
) -> OperationResult:
    """
    Summary:
        Build the identity-passthrough :class:`OperationResult` shared by
        the three placeholder ``execute`` implementations (LLR-001.3 /
        LLR-002.1) — ``output`` is a ``LoadedFile`` echoing the neutral
        input's ``mem_map`` / ``ranges`` / metadata, nothing is read from or
        written to them.

    Args:
        operation (Operation): The placeholder producing the result; only
            its ``operation_id`` is read.
        op_input (OperationInput): The neutral input, echoed back as
            ``output``.
        now_fn (Optional[Callable[[], datetime]]): Injectable UTC clock;
            ``None`` defaults to ``datetime.now(timezone.utc)`` (the
            ``changes.apply`` clock-seam idiom).

    Returns:
        OperationResult: ``status="placeholder"``, ``output`` a
        ``LoadedFile`` over the input's ``mem_map`` / ``ranges``, exactly
        one ``"placeholder: <operation_id> not yet implemented"`` note,
        ``input_path`` / ``variant_id`` copied from the input.

    Data Flow:
        - Called by each placeholder's ``execute`` with its own instance;
          performs no I/O and no parsing (LLR-003.1 acceptance criterion,
          probe P11).

    Dependencies:
        Uses:
            - OperationResult
            - LoadedFile
        Used by:
            - CrcOperation.execute
            - ExtractOperation.execute
            - SplitBySegmentOperation.execute
    """
    clock: Callable[[], datetime] = (
        now_fn if now_fn is not None else (lambda: datetime.now(timezone.utc))
    )
    output = LoadedFile(
        path=op_input.input_path if op_input.input_path is not None else Path(""),
        file_type=op_input.file_type,
        mem_map=op_input.mem_map,
        row_bases=[],
        ranges=op_input.ranges,
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        variant_id=op_input.variant_id,
    )
    return OperationResult(
        operation_id=operation.operation_id,
        status="placeholder",
        input_path=op_input.input_path,
        variant_id=op_input.variant_id,
        output=output,
        notes=[f"placeholder: {operation.operation_id} not yet implemented"],
        timestamp_utc=clock().isoformat(),
    )


class CrcOperation(Operation):
    """
    Summary:
        Placeholder for the future CRC computation over a loaded image
        (LLR-002.1). Identity passthrough — no CRC is computed yet.

    Data Flow:
        - Registered under id ``"crc"`` in ``operations.registry``;
          executed through the ``run_operation`` service seam.

    Dependencies:
        Uses:
            - Operation
            - _placeholder_result
        Used by:
            - operations.registry
    """

    operation_id: str = "crc"
    title: str = "CRC"

    def describe(self) -> str:
        """
        Summary:
            Describe the future CRC operation (LLR-001.1).

        Returns:
            str: Non-empty description text.

        Data Flow:
            - Read by presentation surfaces and TC-009.

        Dependencies:
            Used by:
                - tests/test_operations.py (TC-009)
        """
        return (
            "Compute a CRC over the loaded image (placeholder — not yet "
            "implemented)."
        )

    def execute(
        self,
        op_input: OperationInput,
        *,
        now_fn: Optional[Callable[[], datetime]] = None,
    ) -> OperationResult:
        """
        Summary:
            Identity passthrough (LLR-001.3): echo the neutral input back
            as ``output`` with ``status="placeholder"``.

        Args:
            op_input (OperationInput): The neutral input; not mutated.
            now_fn (Optional[Callable[[], datetime]]): Injectable UTC
                clock; ``None`` defaults to the system UTC clock.

        Returns:
            OperationResult: ``output`` echoes ``op_input``, one placeholder
            note.

        Data Flow:
            - Delegates to :func:`_placeholder_result`; no I/O, no parsing.

        Dependencies:
            Uses:
                - _placeholder_result
            Used by:
                - tui.services.operation_service.run_operation
        """
        return _placeholder_result(self, op_input, now_fn)


class ExtractOperation(Operation):
    """
    Summary:
        Placeholder for the future memory-region extraction over a loaded
        image (LLR-002.1). Identity passthrough — nothing is extracted yet.

    Data Flow:
        - Registered under id ``"extract"`` in ``operations.registry``;
          executed through the ``run_operation`` service seam.

    Dependencies:
        Uses:
            - Operation
            - _placeholder_result
        Used by:
            - operations.registry
    """

    operation_id: str = "extract"
    title: str = "Extract"

    def describe(self) -> str:
        """
        Summary:
            Describe the future extract operation (LLR-001.1).

        Returns:
            str: Non-empty description text.

        Data Flow:
            - Read by presentation surfaces and TC-009.

        Dependencies:
            Used by:
                - tests/test_operations.py (TC-009)
        """
        return (
            "Extract a memory region from the loaded image (placeholder — "
            "not yet implemented)."
        )

    def execute(
        self,
        op_input: OperationInput,
        *,
        now_fn: Optional[Callable[[], datetime]] = None,
    ) -> OperationResult:
        """
        Summary:
            Identity passthrough (LLR-001.3): echo the neutral input back
            as ``output`` with ``status="placeholder"``.

        Args:
            op_input (OperationInput): The neutral input; not mutated.
            now_fn (Optional[Callable[[], datetime]]): Injectable UTC
                clock; ``None`` defaults to the system UTC clock.

        Returns:
            OperationResult: ``output`` echoes ``op_input``, one placeholder
            note.

        Data Flow:
            - Delegates to :func:`_placeholder_result`; no I/O, no parsing.

        Dependencies:
            Uses:
                - _placeholder_result
            Used by:
                - tui.services.operation_service.run_operation
        """
        return _placeholder_result(self, op_input, now_fn)


class SplitBySegmentOperation(Operation):
    """
    Summary:
        Placeholder for the future per-memory-segment split of a loaded
        image (LLR-002.1). Identity passthrough — nothing is split yet.

    Data Flow:
        - Registered under id ``"split_by_segment"`` in
          ``operations.registry``; executed through the ``run_operation``
          service seam.

    Dependencies:
        Uses:
            - Operation
            - _placeholder_result
        Used by:
            - operations.registry
    """

    operation_id: str = "split_by_segment"
    title: str = "Split by segment"

    def describe(self) -> str:
        """
        Summary:
            Describe the future split-by-segment operation (LLR-001.1).

        Returns:
            str: Non-empty description text.

        Data Flow:
            - Read by presentation surfaces and TC-009.

        Dependencies:
            Used by:
                - tests/test_operations.py (TC-009)
        """
        return (
            "Split the loaded image into one artifact per contiguous "
            "memory segment (placeholder — not yet implemented)."
        )

    def execute(
        self,
        op_input: OperationInput,
        *,
        now_fn: Optional[Callable[[], datetime]] = None,
    ) -> OperationResult:
        """
        Summary:
            Identity passthrough (LLR-001.3): echo the neutral input back
            as ``output`` with ``status="placeholder"``.

        Args:
            op_input (OperationInput): The neutral input; not mutated.
            now_fn (Optional[Callable[[], datetime]]): Injectable UTC
                clock; ``None`` defaults to the system UTC clock.

        Returns:
            OperationResult: ``output`` echoes ``op_input``, one placeholder
            note.

        Data Flow:
            - Delegates to :func:`_placeholder_result`; no I/O, no parsing.

        Dependencies:
            Uses:
                - _placeholder_result
            Used by:
                - tui.services.operation_service.run_operation
        """
        return _placeholder_result(self, op_input, now_fn)
