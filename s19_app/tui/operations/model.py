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
class OperationInput:
    """
    Summary:
        The neutral operation input (§6.2 D-1 / LLR-005.1) every
        ``Operation.execute`` receives, replacing the direct
        ``LoadedFile`` binding. It carries only the minimal surface a
        headless operation needs — the memory map and ranges for compute,
        plus identifying metadata for reporting — so an operation never
        depends on the Textual-side ``LoadedFile`` (``row_bases`` /
        ``range_validity`` / ``a2l_*`` are intentionally dropped).

    Args:
        mem_map (dict[int, int]): Address-to-byte map the operation reads.
        ranges (list[tuple[int, int]]): Contiguous memory ranges
            ``(start, end)``.
        input_path (Optional[Path]): Source file of the input snapshot
            (``LoadedFile.path``); ``None`` when unknown.
        variant_id (Optional[str]): Project variant the snapshot belongs to
            (``LoadedFile.variant_id``); ``None`` outside multi-variant
            loads.
        file_type (str): Loader classification (``"s19"`` / ``"hex"`` /
            ``"mac"``), from ``LoadedFile.file_type``.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :meth:`from_loaded` at the two migrated call-sites
          (``operation_service.run_operation`` and the
          ``OperationsScreen`` execute handler), then handed to
          ``Operation.execute``.

    Dependencies:
        Uses:
            - LoadedFile (only inside :meth:`from_loaded`)
        Used by:
            - Operation.execute implementations (operations.placeholders)
            - tui.services.operation_service.run_operation

    Example:
        >>> op_input = OperationInput(
        ...     mem_map={0: 0xAA}, ranges=[(0, 1)], input_path=None,
        ...     variant_id=None, file_type="s19",
        ... )
        >>> op_input.ranges
        [(0, 1)]
    """

    mem_map: dict[int, int]
    ranges: list[tuple[int, int]]
    input_path: Optional[Path]
    variant_id: Optional[str]
    file_type: str

    @classmethod
    def from_loaded(cls, loaded: LoadedFile) -> "OperationInput":
        """
        Summary:
            Build a neutral :class:`OperationInput` from a ``LoadedFile``,
            mapping the five fields a headless operation needs and dropping
            the rest (``row_bases`` / ``range_validity`` / ``errors`` /
            ``a2l_*``) — the single ``LoadedFile``-coupling site (D-1).

        Args:
            loaded (LoadedFile): The loaded-image snapshot to adapt.

        Returns:
            OperationInput: A neutral input over ``loaded.mem_map`` /
            ``loaded.ranges`` with ``input_path`` = ``loaded.path``,
            ``variant_id`` = ``loaded.variant_id``, ``file_type`` =
            ``loaded.file_type``.

        Data Flow:
            - Called at ``operation_service.run_operation`` and the
              ``OperationsScreen`` execute handler before ``execute``.

        Dependencies:
            Uses:
                - LoadedFile
            Used by:
                - tui.services.operation_service.run_operation
                - tui.screens.OperationsScreen (execute handler)
                - tests/test_operations.py (TC-108 and adapted TCs)

        Example:
            >>> from pathlib import Path
            >>> loaded = LoadedFile(
            ...     path=Path("fw.s19"), file_type="s19", mem_map={0: 0xAA},
            ...     row_bases=[0], ranges=[(0, 1)], range_validity=[True],
            ...     errors=[], a2l_path=None, a2l_data=None,
            ... )
            >>> OperationInput.from_loaded(loaded).file_type
            's19'
        """
        return cls(
            mem_map=loaded.mem_map,
            ranges=loaded.ranges,
            input_path=loaded.path,
            variant_id=loaded.variant_id,
            file_type=loaded.file_type,
        )


@dataclass
class CrcRegionResult:
    """
    Summary:
        Per-region CRC payload entry (§6.2 D-2 / LLR-005.2) carried by
        :attr:`OperationResult.crc_regions`. Defined now as part of the
        widened result contract; populated by the CRC operation in a later
        increment (the check path sets ``computed_crc`` / ``stored_value`` /
        ``matched``; the inject path sets ``written``).

    Args:
        output_address (int): The memory address at which this region's CRC
            is stored (check) or written (inject).
        computed_crc (int): The CRC computed over the region's bytes.
        stored_value (Optional[int]): The 4-byte little-endian value read at
            ``output_address``; ``None`` when no stored value is present.
        matched (Optional[bool]): Whether ``stored_value`` equals
            ``computed_crc``; ``None`` when there is no stored value to
            compare.
        written (bool): Whether the inject path wrote this CRC to
            ``output_address`` (``False`` on the non-mutating check path).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Produced by the CRC operation; carried on
          ``OperationResult.crc_regions``; serialized by
          ``OperationResult.to_dict`` and rendered by the result/report
          surfaces.

    Dependencies:
        Used by:
            - OperationResult (crc_regions field)
            - tests/test_operations.py (TC-109)

    Example:
        >>> CrcRegionResult(
        ...     output_address=0x100, computed_crc=0xDEADBEEF,
        ...     stored_value=0xDEADBEEF, matched=True, written=False,
        ... ).matched
        True
    """

    output_address: int
    computed_crc: int
    stored_value: Optional[int]
    matched: Optional[bool]
    written: bool


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
        crc_regions (Optional[list[CrcRegionResult]]): Per-region CRC
            payload (§6.2 D-2 / LLR-005.2); ``None`` for every current
            producer (the three placeholders) so they construct unchanged,
            populated only by the CRC operation in a later increment.

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
    crc_regions: Optional[list[CrcRegionResult]] = None

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
            fields plus ``crc_regions``; paths as strings (or ``None``),
            ``notes`` as a fresh list, ``output`` as exactly
            ``{"path", "file_type", "byte_count"}``, ``crc_regions`` as a
            list of per-region dicts when present or ``None`` when absent.

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
            "crc_regions": (
                [
                    {
                        "output_address": region.output_address,
                        "computed_crc": region.computed_crc,
                        "stored_value": region.stored_value,
                        "matched": region.matched,
                        "written": region.written,
                    }
                    for region in self.crc_regions
                ]
                if self.crc_regions is not None
                else None
            ),
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
        op_input: OperationInput,
        *,
        now_fn: Optional[Callable[[], datetime]] = None,
    ) -> OperationResult:
        """
        Summary:
            Execute this operation against one neutral operation input
            (LLR-005.1) and return the structured :class:`OperationResult`
            (LLR-001.1). The input is the ``LoadedFile``-decoupled
            :class:`OperationInput`, not a ``LoadedFile``.

        Args:
            op_input (OperationInput): The neutral input carrying
                ``mem_map`` / ``ranges`` / metadata to operate on.
            now_fn (Optional[Callable[[], datetime]]): Injectable UTC clock
                (the ``changes.apply.apply_change_document`` ``now_fn``
                seam); ``None`` defaults to ``datetime.now(timezone.utc)``.
                The result records ``now_fn().isoformat()``.

        Returns:
            OperationResult: The result envelope; a placeholder returns the
            echoed input with ``status="placeholder"`` (LLR-001.3).

        Data Flow:
            - Invoked by the ``run_operation`` service seam and the
              ``OperationsScreen`` execute handler, both of which build the
              :class:`OperationInput` via :meth:`OperationInput.from_loaded`
              and forward ``now_fn`` unchanged.

        Dependencies:
            Uses:
                - OperationResult
                - OperationInput
            Used by:
                - tui.services.operation_service.run_operation
                - tui.screens.OperationsScreen (execute handler)
        """
