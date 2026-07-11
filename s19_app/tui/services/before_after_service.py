"""
Before/after save-back report composer — s19_app batch-24, increment I4
(US-034 / HLR-038, LLR-038.2 / LLR-038.4 / LLR-038.5).

Headless service composing the ONE-ACTION report that proves what changed
between the ORIGINAL loaded image and the SAVED patched image after an
apply + save-back:

- validates the five LLR-038.2 preconditions in order — (1) a
  ``ChangeSummary`` exists, (2) ``saved_path`` was stamped (the save-back
  succeeded), (3) both image paths still exist on disk (cheap guard;
  ``compare_images`` re-checks per source), (4) the loaded image IS the image
  the summary was saved from (``summary.source_image_path``, the B-2
  provenance stamp), and (5) ``saved_path`` resolves inside the CURRENT
  project directory (or the workarea root when no project is active — the
  save-back ``dest_dir`` fallback);
- refuses without an active project, naming the manual A<->B Diff report
  path instead (§6.2 D-3 — the generators' no-project branch needs an
  operator-typed destination, which this one-key action has no UI for);
- refuses when the resolved ``reports/`` destination is a symbolic link
  (S-F4 containment hardening);
- compares the pair FRESH from disk via ``compare_service.compare_images``
  with two ``SOURCE_EXTERNAL`` sources — never the in-place-mutated
  ``LoadedFile.mem_map`` — re-loads both memory maps through the headless
  loaders (the ``app._diff_load_maps`` pattern, replicated service-side), and
  invokes BOTH LLR-038.1 generators with the provenance/linkage kwargs and
  this module's OWN filename stem.

Every failure is a diagnostic-bearing refusal on the returned
:class:`BeforeAfterReportResult` — the composer never raises for a missing or
refused input (LLR-038.4) and never writes a file on any refusal path.

Filename ownership (the diff-report owns-its-own-regex precedent): this
module owns :data:`BEFORE_AFTER_REPORT_FILENAME_REGEX` and
:data:`BEFORE_AFTER_REPORT_HTML_FILENAME_REGEX` for the
``<UTC %Y%m%dT%H%M%SZ>(-NN)?-before-after-report.md|.html`` scheme; the
shared ``report_service.REPORT_FILENAME_REGEX`` and both diff-report regexes
are untouched.

Confidentiality (LLR-038.5, F-S-07): the written pair carries raw memory
bytes, so this module performs NO logging at all and imports no Textual
symbol (the ``compare_service`` service-layer purity precedent); reports land
only under ``<project_dir>/reports/`` (``REPORTS_DIR_NAME``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

from ...core import S19File
from ...hexfile import IntelHexFile
from .compare_service import SOURCE_EXTERNAL, ImageSource, compare_images
from .diff_report_service import (
    BeforeAfterProvenance,
    NowFn,
    generate_diff_report,
    generate_diff_report_html,
)
from .load_service import build_loaded_hex, build_loaded_s19
from .report_service import REPORTS_DIR_NAME

if TYPE_CHECKING:  # pragma: no cover - typing-only, keeps runtime imports flat
    from ..changes.model import ChangeSummary
    from .report_filter import ReportFilterMatcher

#: Markdown before/after report filename regex (LLR-038.2) — owned HERE so
#: the shared ``report_service.REPORT_FILENAME_REGEX`` and the diff-report
#: regexes are never edited; matches exactly the
#: ``<UTC %Y%m%dT%H%M%SZ>(-NN)?-before-after-report.md`` scheme.
BEFORE_AFTER_REPORT_FILENAME_REGEX = re.compile(
    r"^\d{8}T\d{6}Z(-\d{2})?-before-after-report\.md$"
)

#: HTML twin of :data:`BEFORE_AFTER_REPORT_FILENAME_REGEX` for the
#: ``<UTC %Y%m%dT%H%M%SZ>(-NN)?-before-after-report.html`` scheme.
BEFORE_AFTER_REPORT_HTML_FILENAME_REGEX = re.compile(
    r"^\d{8}T\d{6}Z(-\d{2})?-before-after-report\.html$"
)

#: The filename kind-stem threaded into the LLR-038.1 ``filename_stem`` kwarg
#: of both generators — the scheme the two regexes above pin.
_BEFORE_AFTER_REPORT_STEM = "before-after-report"


@dataclass(slots=True)
class BeforeAfterReportResult:
    """
    Summary:
        Outcome of one before/after report composition — the two written
        paths on success, or refusal diagnostics (LLR-038.4). Composition
        never raises for a missing/refused input; it returns this object.

    Args:
        md_path (Optional[Path]): The written Markdown report when ``written``
            is ``True``; ``None`` on refusal.
        html_path (Optional[Path]): The written HTML report when ``written``
            is ``True``; ``None`` on refusal.
        written (bool): ``True`` when BOTH files were written.
        diagnostics (List[str]): Human-readable refusal reasons; non-empty
            only when ``written`` is ``False``. Paths and reasons only —
            never entry byte content (LLR-038.5).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :func:`compose_before_after_report`; consumed by
          ``S19TuiApp.action_before_after_report`` (the LLR-038.3 trigger)
          which surfaces the paths or the diagnostic on the status line.

    Dependencies:
        Used by:
            - compose_before_after_report
            - s19_app.tui.app.S19TuiApp.action_before_after_report
    """

    md_path: Optional[Path] = None
    html_path: Optional[Path] = None
    written: bool = False
    diagnostics: List[str] = field(default_factory=list)


def _refused(*diagnostics: str) -> BeforeAfterReportResult:
    """
    Summary:
        Build a refusal result carrying the given diagnostics — the single
        construction point for every LLR-038.4 refusal class (no file
        written, nothing raised).

    Args:
        *diagnostics (str): One or more human-readable refusal reasons.

    Returns:
        BeforeAfterReportResult: ``written=False`` with the diagnostics.

    Dependencies:
        Used by:
            - compose_before_after_report
    """
    return BeforeAfterReportResult(
        md_path=None, html_path=None, written=False, diagnostics=list(diagnostics)
    )


def _load_map(path: Path) -> Dict[int, int]:
    """
    Summary:
        Re-load one image's memory map from disk through the headless
        loaders — the ``app.py`` ``_diff_load_maps`` per-side pattern
        replicated service-side (the composer must not import from the app).
        A raised parse becomes an empty map (display-side, non-fatal): the
        generators then state ``Memory maps unavailable`` instead of failing.

    Args:
        path (Path): The image file to re-parse (suffix selects the loader:
            ``.hex``/``.ihex`` -> Intel HEX, anything else -> S19).

    Returns:
        Dict[int, int]: The address-to-byte map; empty when the re-parse
        raised.

    Data Flow:
        - Fresh disk parse per call — never the in-place-mutated
          ``LoadedFile.mem_map`` (``change_service.py`` apply mutates it).

    Dependencies:
        Uses:
            - build_loaded_s19 / build_loaded_hex
        Used by:
            - compose_before_after_report
    """
    try:
        if path.suffix.lower() in (".hex", ".ihex"):
            return build_loaded_hex(path, IntelHexFile(str(path)), None, None).mem_map
        return build_loaded_s19(path, S19File(str(path)), None, None).mem_map
    except Exception:  # noqa: BLE001 — display-side, non-fatal (app pattern)
        return {}


def compose_before_after_report(
    summary: Optional["ChangeSummary"],
    loaded_path: Optional[Path],
    *,
    project_dir: Optional[Path],
    workarea: Path,
    now_fn: Optional[NowFn] = None,
    report_filter: Optional["ReportFilterMatcher"] = None,
) -> BeforeAfterReportResult:
    """
    Summary:
        Compose the before/after save-back report pair (LLR-038.2): validate
        the five preconditions in order, refuse without an active project
        (D-3) or across a symlinked destination (S-F4), compare the ORIGINAL
        loaded image against the SAVED patched image fresh from disk, and
        write BOTH report formats with the provenance header and the
        per-entry change-linkage table under ``<project_dir>/reports/``.
        Never raises for a missing/refused input — every failure is a
        diagnostic-bearing refusal that writes no file (LLR-038.4).

    Args:
        summary (Optional[ChangeSummary]): ``ChangeService.last_summary`` —
            carries ``saved_path`` (the actual post-dedup written path),
            ``source_image_path`` (the B-2 provenance stamp), the apply
            instant, the change-doc origin, and the linkage entries.
        loaded_path (Optional[Path]): ``LoadedFile.path`` — the currently
            loaded image, the report's "before" side; ``None`` when nothing
            is loaded.
        project_dir (Optional[Path]): The active project directory
            (``_active_project_dir()``); ``None`` -> D-3 refusal naming the
            manual A<->B path.
        workarea (Path): The workarea root — the precondition-5 containment
            target when no project was active at save time (the save-back
            ``dest_dir`` fallback).
        now_fn (Optional[NowFn]): Injectable UTC clock forwarded to both
            generators; ``None`` resolves to ``datetime.now(timezone.utc)``.
        report_filter (Optional[ReportFilterMatcher]): The resolved report
            filter (LLR-053.7 / LLR-054.1, batch-35) — the ONLY new
            generator input; resolved by the caller on the UI thread at
            trigger time (D-9). Forwarded into BOTH generators via the
            shared kwargs dict when set; ``None`` (the default) adds no
            kwarg, keeping the unfiltered generator call shape — and output
            — byte-for-byte today's (F-01 / LLR-054.4, TC-311 pin). The
            LLR-038.2 precondition order is untouched — the filter is
            additive, never a reordering (LLR-053.5).

    Returns:
        BeforeAfterReportResult: ``written=True`` with both paths, or a
        refusal whose diagnostics name the failing precondition — the
        stale-summary refusal names BOTH image identities so a
        project-switch survivor is diagnosable, not silent (LLR-038.4
        class 4).

    Data Flow:
        - Preconditions 1-5 (order fixed by LLR-038.2), each an early
          refusal.
        - No-project -> D-3 refusal; ``reports/`` symlink -> S-F4 refusal.
        - ``compare_images`` with two ``SOURCE_EXTERNAL`` sources
          (original=``loaded_path``, patched=``saved_path``); a refused
          comparison forwards the engine's per-source diagnostics.
        - Re-load both maps (:func:`_load_map`), build the
          :class:`BeforeAfterProvenance`, then ``generate_diff_report`` +
          ``generate_diff_report_html`` with ``linkage_entries``, the owned
          filename stem, and — only when set — the resolved
          ``report_filter`` (LLR-054.1).

    Dependencies:
        Uses:
            - compare_images / ImageSource
            - _load_map / _refused
            - generate_diff_report / generate_diff_report_html
            - BeforeAfterProvenance / REPORTS_DIR_NAME
        Used by:
            - s19_app.tui.app.S19TuiApp.action_before_after_report
            - tests/test_before_after_report.py

    Example:
        >>> # see tests/test_before_after_report.py for executable usage
    """
    # Precondition 1 — a summary exists (an apply ran this session).
    if summary is None:
        return _refused(
            "No applied change summary - apply a change document and save "
            "the patched image first."
        )
    # Precondition 2 — the save-back succeeded (saved_path stamped).
    if summary.saved_path is None:
        return _refused(
            "No saved patched image - the save-back was declined or refused."
        )
    saved_path = Path(summary.saved_path)
    # Precondition 3 — both paths still exist (cheap guard; compare_images
    # re-checks per source and would refuse with its own diagnostics).
    if loaded_path is None:
        return _refused(
            "No image loaded - the original (before) side is unavailable."
        )
    original_path = Path(loaded_path)
    if not original_path.is_file():
        return _refused(
            f"Original image no longer on disk: {original_path}"
        )
    if not saved_path.is_file():
        return _refused(
            f"Saved patched image no longer on disk: {saved_path}"
        )
    # Precondition 4 (B-2) — the loaded image IS the image the summary was
    # saved from; a project-switch/file-load survivor refuses loudly.
    stamped = summary.source_image_path
    if stamped is None or Path(stamped).resolve() != original_path.resolve():
        return _refused(
            f"Stale change summary: the loaded image ({original_path}) is "
            f"not the image the patched file was saved from "
            f"({stamped if stamped is not None else 'unknown'}) - re-apply "
            "and save in the current session."
        )
    # Precondition 5 (B-2) — saved_path containment in the current project
    # dir, or the workarea root when no project is active (the save-back
    # dest_dir fallback).
    containment_root = (
        Path(project_dir) if project_dir is not None else Path(workarea)
    )
    if not saved_path.resolve().is_relative_to(containment_root.resolve()):
        return _refused(
            f"Stale change summary: saved patched image {saved_path} lies "
            f"outside the current "
            f"{'project directory' if project_dir is not None else 'work area'} "
            f"{containment_root}."
        )
    # Destination — D-3: no active project means no reports/ destination for
    # a one-key action; point at the manual path instead of adding input UI.
    if project_dir is None:
        return _refused(
            "No active project - the before/after report needs a project "
            "reports/ destination; use the manual A<->B Diff report "
            "(screen 7) with an explicit destination instead."
        )
    reports_dir = Path(project_dir) / REPORTS_DIR_NAME
    # S-F4 — refuse a symlinked destination before the generators mkdir/write.
    if reports_dir.is_symlink():
        return _refused(
            f"Reports destination is a symbolic link - refusing to write: "
            f"{reports_dir}"
        )

    comparison = compare_images(
        ImageSource(
            kind=SOURCE_EXTERNAL,
            raw_path=str(original_path),
            label=original_path.name,
        ),
        ImageSource(
            kind=SOURCE_EXTERNAL,
            raw_path=str(saved_path),
            label=saved_path.name,
        ),
    )
    if comparison.refused:
        return _refused(*comparison.diagnostics)

    provenance = BeforeAfterProvenance(
        original_path=original_path,
        saved_path=saved_path,
        applied_at_utc=summary.timestamp_utc,
        change_doc_path=summary.source_path,
    )
    kwargs = dict(
        mem_map_a=_load_map(original_path),
        mem_map_b=_load_map(saved_path),
        project_dir=Path(project_dir),
        provenance=provenance,
        linkage_entries=summary.entries,
        filename_stem=_BEFORE_AFTER_REPORT_STEM,
        now_fn=now_fn,
    )
    if report_filter is not None:
        # LLR-054.1: the matcher is the ONLY new generator input; added
        # conditionally so the no-filter kwargs shape stays byte-for-byte
        # today's (F-01, TC-311 pin).
        kwargs["report_filter"] = report_filter
    md = generate_diff_report(comparison, **kwargs)
    if not md.written:
        return _refused(*md.diagnostics)
    html = generate_diff_report_html(comparison, **kwargs)
    if not html.written:
        return _refused(*html.diagnostics)
    return BeforeAfterReportResult(
        md_path=md.path, html_path=html.path, written=True, diagnostics=[]
    )
