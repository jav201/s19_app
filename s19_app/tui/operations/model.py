"""
Operation abstraction and result envelope (batch-08, HLR-001).

Defines the ``Operation`` abstract base class every special operation
implements (LLR-001.1), the §6.2 C-2 canonical ``OperationResult`` envelope
(LLR-001.2), and the closed :data:`STATUS_DOMAIN`. Headless by contract —
no Textual imports anywhere in this package (LLR-003.2).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from ..models import LoadedFile

#: The closed ``OperationResult.status`` domain (§6.2 C-2). Fixed NOW at
#: three tokens so the fill-in batch can report success/failure without a
#: schema change; any value outside it is rejected at construction.
STATUS_DOMAIN: frozenset[str] = frozenset({"placeholder", "ok", "error"})


@dataclass
class OperationResult:
    """
    Summary:
        The structured result envelope every operation's ``execute`` returns
        — the §6.2 C-2 canonical 7-field contract (LLR-001.2). The envelope
        (rather than bare passthrough returns) is what lets the fill-in
        batch replace one placeholder's body without re-plumbing callers.

    Args:
        operation_id (str): Id of the operation that produced this result
            (the registry lookup key, LLR-002.1).
        status (str): One token of :data:`STATUS_DOMAIN` —
            ``"placeholder"`` / ``"ok"`` / ``"error"``. Validated by
            ``__post_init__``; an out-of-domain value raises ``ValueError``.
        input_path (Optional[Path]): The source file of the input snapshot
            (``LoadedFile.path``).
        variant_id (Optional[str]): The project variant the input snapshot
            belongs to (``LoadedFile.variant_id``); ``None`` outside
            multi-variant loads.
        output (LoadedFile): The resulting image snapshot. For a placeholder
            operation this is the SAME object as the input (identity
            passthrough, LLR-001.3).
        notes (list[str]): Human-readable result notes; a placeholder
            carries exactly one ``"placeholder: <operation_id> not yet
            implemented"`` note (LLR-002.1).
        timestamp_utc (str): ISO-8601 UTC timestamp of the execution, taken
            from the producer's injectable ``now_fn`` clock (the
            ``changes.apply`` clock-seam precedent).

    Returns:
        None: Dataclass container.

    Raises:
        ValueError: If ``status`` is not a member of :data:`STATUS_DOMAIN`
            (construction-time domain check).

    Data Flow:
        - Built by the placeholder ``execute`` implementations
          (``operations.placeholders``); returned unmodified by the
          ``run_operation`` service seam (LLR-003.1, increment I2).
        - ``to_dict`` is the size-bounded serialization consumed by tests
          and, later, by logging/reporting — never the full ``mem_map``.

    Dependencies:
        Uses:
            - LoadedFile
        Used by:
            - Operation.execute implementations (operations.placeholders)
            - tui.services.operation_service.run_operation (increment I2)

    Example:
        >>> from pathlib import Path
        >>> snapshot = LoadedFile(
        ...     path=Path("fw.s19"), file_type="s19", mem_map={0: 0xAA},
        ...     row_bases=[0], ranges=[(0, 1)], range_validity=[True],
        ...     errors=[], a2l_path=None, a2l_data=None,
        ... )
        >>> result = OperationResult(
        ...     operation_id="crc", status="placeholder",
        ...     input_path=snapshot.path, variant_id=None, output=snapshot,
        ...     notes=["placeholder: crc not yet implemented"],
        ...     timestamp_utc="2026-06-11T12:00:00+00:00",
        ... )
        >>> result.to_dict()["output"]["byte_count"]
        1
    """

    operation_id: str
    status: str
    input_path: Optional[Path]
    variant_id: Optional[str]
    output: LoadedFile
    notes: list[str]
    timestamp_utc: str

    def __post_init__(self) -> None:
        """
        Summary:
            Reject a ``status`` outside the closed :data:`STATUS_DOMAIN` at
            construction time (LLR-001.2).

        Raises:
            ValueError: If ``status`` is not one of ``"placeholder"`` /
                ``"ok"`` / ``"error"``.

        Data Flow:
            - Pure membership check against :data:`STATUS_DOMAIN`; no field
              is coerced or mutated.
        """
        if self.status not in STATUS_DOMAIN:
            raise ValueError(
                f"OperationResult status {self.status!r} is outside the "
                f"closed domain {sorted(STATUS_DOMAIN)}"
            )

    def to_dict(self) -> dict[str, object]:
        """
        Summary:
            Serialize this result to a deterministic plain-data dict — same
            object, same dict, every call. ``output`` is a size-bounded
            reference summary (``path`` / ``file_type`` / ``byte_count``),
            never the full ``mem_map`` (LLR-001.2 disclosure guard).

        Returns:
            dict[str, object]: JSON-compatible mapping of the 7 canonical
            fields; paths as strings (or ``None``), ``notes`` as a fresh
            list, ``output`` as exactly
            ``{"path", "file_type", "byte_count"}``.

        Data Flow:
            - Rebuilt from the dataclass fields on every call — no caching,
              no mutation — so two calls under a fixed clock over the same
              snapshot compare equal (TC-001 determinism equality).

        Dependencies:
            Uses:
                - LoadedFile
            Used by:
                - tests/test_operations.py (TC-001)

        Example:
            >>> sorted(OperationResult(
            ...     operation_id="crc", status="placeholder",
            ...     input_path=None, variant_id=None,
            ...     output=LoadedFile(
            ...         path=Path("fw.s19"), file_type="s19", mem_map={},
            ...         row_bases=[], ranges=[], range_validity=[],
            ...         errors=[], a2l_path=None, a2l_data=None,
            ...     ),
            ...     notes=[], timestamp_utc="2026-06-11T12:00:00+00:00",
            ... ).to_dict()["output"])
            ['byte_count', 'file_type', 'path']
        """
        return {
            "operation_id": self.operation_id,
            "status": self.status,
            "input_path": (
                str(self.input_path) if self.input_path is not None else None
            ),
            "variant_id": self.variant_id,
            "output": {
                "path": str(self.output.path),
                "file_type": self.output.file_type,
                "byte_count": len(self.output.mem_map),
            },
            "notes": list(self.notes),
            "timestamp_utc": self.timestamp_utc,
        }


class Operation(ABC):
    """
    Summary:
        Abstract base class of every special operation over a loaded image
        (LLR-001.1). Concrete subclasses provide a class-level
        ``operation_id`` and ``title``, a ``describe()`` text, and the
        ``execute`` transformation; instantiating a subclass that omits an
        abstract method raises ``TypeError`` (ABC machinery, TC-009).

    Args:
        None: Subclasses declare ``operation_id`` / ``title`` as class
            attributes and implement the abstract methods.

    Data Flow:
        - Subclassed by the three placeholders in
          ``operations.placeholders``; instances are registered in
          ``operations.registry`` and resolved by id (LLR-002.2).

    Dependencies:
        Uses:
            - OperationResult
            - LoadedFile
        Used by:
            - operations.placeholders (CrcOperation / ExtractOperation /
              SplitBySegmentOperation)
            - operations.registry
    """

    operation_id: str
    title: str

    @abstractmethod
    def describe(self) -> str:
        """
        Summary:
            Return a non-empty human-readable description of what this
            operation does (LLR-001.1).

        Returns:
            str: Non-empty description text.

        Data Flow:
            - Read by presentation surfaces (the HLR-004 view lists
              ``title``; ``describe()`` is the longer text).

        Dependencies:
            Used by:
                - tests/test_operations.py (TC-009)
        """

    @abstractmethod
    def execute(
        self,
        loaded: LoadedFile,
        *,
        now_fn: Optional[Callable[[], datetime]] = None,
    ) -> OperationResult:
        """
        Summary:
            Execute this operation against one loaded-image snapshot and
            return the structured :class:`OperationResult` (LLR-001.1).

        Args:
            loaded (LoadedFile): The loaded-image snapshot to operate on.
            now_fn (Optional[Callable[[], datetime]]): Injectable UTC clock
                (the ``changes.apply.apply_change_document`` ``now_fn``
                seam); ``None`` defaults to ``datetime.now(timezone.utc)``.
                The result records ``now_fn().isoformat()``.

        Returns:
            OperationResult: The 7-field result envelope; a placeholder
            returns ``output is loaded`` with ``status="placeholder"``
            (LLR-001.3).

        Data Flow:
            - Invoked by the ``run_operation`` service seam (LLR-003.1,
              increment I2), which forwards ``now_fn`` unchanged.

        Dependencies:
            Uses:
                - OperationResult
            Used by:
                - tui.services.operation_service.run_operation
                  (increment I2)
        """
