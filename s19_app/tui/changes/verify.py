"""Verify-on-save engine (HLR-003) — re-read a written image and diff it.

The save-back path writes a firmware image to disk; this module re-reads that
written file with the parser matching its format and diffs the re-read memory
map against the *intended* memory map using the batch-09 compare engine
(``s19_app.compare.diff_mem_maps``). The outcome is a :class:`VerifyResult` —
``verified`` when the diff is empty, ``mismatch`` otherwise (carrying the diff
runs/stats so the caller can name what drifted).

Headless by contract (LLR-003.1): stdlib + sibling-engine imports only, no
``textual`` symbol — this module is reachable from ``services/change_service``
and is walked by ``test_no_textual_in_static_import_graph``.

No-logging precedent (F-S-05 / apply.py C-9 style): the result carries
addresses and counts, never raw image bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from s19_app.compare import DiffRun, DiffStats, diff_mem_maps
from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile

#: Verify outcome — the re-read map matched the intended map exactly.
STATUS_VERIFIED = "verified"

#: Verify outcome — the re-read map differs from the intended map.
STATUS_MISMATCH = "mismatch"


@dataclass(slots=True)
class VerifyResult:
    """
    Summary:
        The outcome of a verify-on-save check — the §6.2 C-10 carrier
        produced by :func:`verify_written_image` (HLR-003). ``status`` is
        :data:`STATUS_VERIFIED` when the re-read image equals the intended
        image and :data:`STATUS_MISMATCH` otherwise; ``runs`` / ``stats``
        carry the :func:`s19_app.compare.diff_mem_maps` diff so a consumer
        can summarize what drifted.

    Args:
        status (str): :data:`STATUS_VERIFIED` or :data:`STATUS_MISMATCH`.
        runs (list[DiffRun]): The maximal contiguous difference runs between
            the intended map (A) and the re-read map (B); empty iff verified.
        stats (DiffStats): Per-kind run/byte counts over the same diff.
        written_path (Optional[Path]): The file that was re-read — stamped so
            a mismatch notice can name it (LLR-004.2). ``None`` only if the
            caller chose not to stamp it.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Produced by :func:`verify_written_image` (status/runs/stats), which
          stamps ``written_path`` from its argument.
        - Consumed by the save-back handler (LLR-003.3) and the TUI quiet/loud
          surfacing (LLR-004.1/004.2).

    Dependencies:
        Uses:
            - DiffRun / DiffStats
        Used by:
            - verify_written_image

    Example:
        >>> result = verify_written_image(p, {0x10: 0xAB}, "hex")
        >>> result.status
        'verified'
    """

    status: str
    runs: List[DiffRun]
    stats: DiffStats
    written_path: Optional[Path] = None


def _reread_mem_map(written_path: Path, file_type: str) -> Dict[int, int]:
    """
    Summary:
        Re-read ``written_path`` into a memory map using the parser matching
        ``file_type`` — ``IntelHexFile`` for ``"hex"``, ``S19File`` for
        ``"s19"`` (LLR-003.1).

    Args:
        written_path (Path): The just-written image file.
        file_type (str): ``"hex"`` or ``"s19"`` (``LoadedFile.file_type``).

    Returns:
        dict[int, int]: The re-read address-to-byte map.

    Raises:
        ValueError: If ``file_type`` is neither ``"hex"`` nor ``"s19"`` —
            a programming error in the caller (the save-back only verifies
            the formats it can write).

    Data Flow:
        - Dispatch on ``file_type``; both parsers take a path string and
          collect (not raise) per-record load failures, so a corrupt write
          surfaces as a divergent map, not an exception.

    Dependencies:
        Uses:
            - IntelHexFile / S19File
        Used by:
            - verify_written_image
    """
    path_str = str(written_path)
    if file_type == "hex":
        return IntelHexFile(path_str).memory
    if file_type == "s19":
        return S19File(path_str).get_memory_map()
    raise ValueError(f"verify-on-save cannot re-read file_type {file_type!r}")


def verify_written_image(
    written_path: Path,
    intended_mem_map: Dict[int, int],
    file_type: str,
) -> VerifyResult:
    """
    Summary:
        Re-read a just-written image and diff it against the intended memory
        map, returning a :class:`VerifyResult` (HLR-003 / LLR-003.1/.2). The
        result is :data:`STATUS_VERIFIED` when the diff is empty and
        :data:`STATUS_MISMATCH` (carrying the runs/stats) otherwise.

    Args:
        written_path (Path): The file the save-back just wrote.
        intended_mem_map (dict[int, int]): The post-apply image the caller
            meant to persist — diff map A.
        file_type (str): ``"hex"`` or ``"s19"``; selects the re-read parser.

    Returns:
        VerifyResult: ``status`` + ``runs`` + ``stats`` + ``written_path``.
        A byte the file failed to persist (dropped) appears as a ``only_a``
        run; a byte written with the wrong value appears as a ``changed`` run.

    Raises:
        ValueError: Propagated from :func:`_reread_mem_map` on an
            unsupported ``file_type``.

    Data Flow:
        - Re-read ``written_path`` via the format parser into map B.
        - ``runs, stats = diff_mem_maps(intended, reread)`` (A=intended,
          B=reread) so a dropped byte classifies ``only_a``.
        - ``status`` is verified iff ``runs`` is empty.

    Dependencies:
        Uses:
            - _reread_mem_map
            - diff_mem_maps
        Used by:
            - save-back handler (LLR-003.3, I3)

    Example:
        >>> verify_written_image(p, {0x10: 0xAB}, "hex").status
        'verified'
    """
    reread = _reread_mem_map(written_path, file_type)
    runs, stats = diff_mem_maps(intended_mem_map, reread)
    status = STATUS_VERIFIED if not runs else STATUS_MISMATCH
    return VerifyResult(
        status=status,
        runs=runs,
        stats=stats,
        written_path=written_path,
    )
