"""
Diff-report generator tests — s19_app batch-09, increment I3 (HLR-004).

Test -> TC -> LLR map:
    test_filename_scheme_and_same_second_collision   TC-016  LLR-004.1
    test_collision_never_overwrites_existing_file     TC-016  LLR-004.1 (M-5)
    test_self_contained_listing_newest_first          TC-017  LLR-004.2 (G-4)
    test_report_service_regex_unedited                TC-017  LLR-004.2 (G-4 NON-edit)
    test_report_sections_present_in_order             TC-018  LLR-004.3
    test_run_dump_cap_emits_truncated_marker          TC-018  LLR-004.3 (caps)
    test_byte_budget_emits_truncated_marker           TC-018  LLR-004.3 (caps)
    test_symbol_annotation_only_intersecting_run      TC-019  LLR-004.4 (G-2)
    test_annotation_absent_without_context            TC-019  LLR-004.4 (non-gating)
    test_module_performs_no_logging                   TC-020  LLR-004.5 (F-S-07)
    test_no_project_valid_directory_writes_one_file   TC-025  LLR-004.6 (G-8 valid)
    test_no_project_empty_path_refused                TC-025  LLR-004.6 (G-8 refuse)
    test_no_project_nonexistent_dir_refused           TC-025  LLR-004.6 (G-8 refuse)
    test_no_project_collision_no_overwrite            TC-025  LLR-004.6 (M-5)
    test_no_sanitize_project_name_in_validator        TC-025  LLR-004.6 (M-4 source probe)
    test_generation_is_deterministic_fixed_clock      TC-018  LLR-004.3 (determinism)

Element-style thresholds are inline on each test.

Confidentiality (F-S-07): every fixture is a synthetic in-memory byte run —
never operator firmware.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from s19_app.compare import (
    KIND_CHANGED,
    KIND_ONLY_A,
    ComparisonResult,
    DiffRun,
    DiffStats,
    ImageRef,
)
from s19_app.tui.services import diff_report_service
from s19_app.tui.services.compare_service import ArtifactNote, ArtifactUsage
from s19_app.tui.services.diff_report_service import (
    DIFF_REPORT_FILENAME_REGEX,
    DiffReportResult,
    generate_diff_report,
    list_diff_reports,
)

FIXED_NOW = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)


def _fixed_clock() -> datetime:
    return FIXED_NOW


def _stats(
    changed_runs: int = 0,
    changed_bytes: int = 0,
    only_a_runs: int = 0,
    only_a_bytes: int = 0,
) -> DiffStats:
    return DiffStats(
        run_counts={"changed": changed_runs, "only_a": only_a_runs, "only_b": 0},
        byte_counts={"changed": changed_bytes, "only_a": only_a_bytes, "only_b": 0},
    )


def _usage(summary: str = "both") -> ArtifactUsage:
    return ArtifactUsage(
        a2l=ArtifactNote(status="used", covered=1, total=2),
        mac=ArtifactNote(status="used", covered=1, total=1),
        summary=summary,
    )


def _comparison(
    runs: Optional[List[DiffRun]] = None,
    stats: Optional[DiffStats] = None,
    with_notes: bool = True,
) -> ComparisonResult:
    """A self-contained, non-refused comparison fixture (no parse needed)."""
    runs = runs if runs is not None else [DiffRun(0x100, 0x104, KIND_CHANGED)]
    stats = stats if stats is not None else _stats(changed_runs=1, changed_bytes=4)
    image_a = ImageRef(label="A.s19", path="/tmp/a.s19", source_kind="external")
    image_b = ImageRef(label="B.s19", path="/tmp/b.s19", source_kind="external")
    notes = {"image_a": _usage(), "image_b": _usage()} if with_notes else {}
    return ComparisonResult(
        image_a=image_a,
        image_b=image_b,
        runs=runs,
        stats=stats,
        notes=notes,
        diagnostics=[],
        refused=False,
    )


def _mem(start: int, byte: int, length: int) -> Dict[int, int]:
    return {start + i: byte for i in range(length)}


# ---------------------------------------------------------------------------
# TC-016 — LLR-004.1 — filename scheme + same-second collision + no overwrite
# ---------------------------------------------------------------------------


def test_filename_scheme_and_same_second_collision(tmp_path: Path) -> None:
    """Injected fixed clock → base name, then zero-padded -01 counter.

    Intent: LLR-004.1 — the diff filename carries the ``-diff-report.md`` kind
    suffix and a same-second collision inserts ``-NN`` before it instead of
    overwriting. Threshold: two distinct files (base + ``-01``), both matching
    DIFF_REPORT_FILENAME_REGEX; 0 overwrites.
    """
    mem_a = _mem(0x100, 0x01, 4)
    mem_b = _mem(0x100, 0x02, 4)

    first = generate_diff_report(
        _comparison(), mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, now_fn=_fixed_clock,
    )
    second = generate_diff_report(
        _comparison(), mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, now_fn=_fixed_clock,
    )

    assert first.written is True
    assert second.written is True
    assert first.path.name == "20260611T120000Z-diff-report.md"
    assert second.path.name == "20260611T120000Z-01-diff-report.md"
    assert DIFF_REPORT_FILENAME_REGEX.match(first.path.name)
    assert DIFF_REPORT_FILENAME_REGEX.match(second.path.name)
    assert first.path.parent == tmp_path / "reports"
    assert first.path != second.path


def test_collision_never_overwrites_existing_file(tmp_path: Path) -> None:
    """A pre-created target filename forces a -01 sibling; the original is untouched.

    Intent: LLR-004.1 / M-5 — never a silent overwrite. Threshold: pre-existing
    file byte-identical after generation; the new file is the ``-01`` sibling.
    """
    reports = tmp_path / "reports"
    reports.mkdir()
    planted = reports / "20260611T120000Z-diff-report.md"
    planted.write_text("PLANTED CONTENT", encoding="utf-8")

    result = generate_diff_report(
        _comparison(), mem_map_a=_mem(0x100, 1, 4), mem_map_b=_mem(0x100, 2, 4),
        project_dir=tmp_path, now_fn=_fixed_clock,
    )

    assert result.path.name == "20260611T120000Z-01-diff-report.md"
    assert planted.read_text(encoding="utf-8") == "PLANTED CONTENT"  # 0 overwrites


# ---------------------------------------------------------------------------
# TC-017 — LLR-004.2 — self-contained listing (G-4); report_service NON-edit
# ---------------------------------------------------------------------------


def test_self_contained_listing_newest_first(tmp_path: Path) -> None:
    """list_diff_reports returns diff reports newest-first within a second group.

    Intent: LLR-004.2 / G-4 — the module owns its listing. Threshold: base then
    ``-01`` are returned with the ``-01`` (newer) FIRST; a foreign ``.md`` is
    listed LAST.
    """
    reports = tmp_path / "reports"
    reports.mkdir()
    base = reports / "20260611T120000Z-diff-report.md"
    sibling = reports / "20260611T120000Z-01-diff-report.md"
    foreign = reports / "notes.md"
    for p in (base, sibling, foreign):
        p.write_text("x", encoding="utf-8")

    listed = list_diff_reports(reports)

    assert listed[0] == sibling  # -01 is the newer of the same-second group
    assert listed[1] == base
    assert listed[-1] == foreign
    assert list_diff_reports(tmp_path / "missing") == []


def test_report_service_regex_unedited() -> None:
    """The shared REPORT_FILENAME_REGEX still rejects the diff scheme (G-4).

    Intent: LLR-004.2 / G-4 — proof the diff module did NOT generalize the
    shared regex. Threshold: the shared regex matches the project-report scheme
    and does NOT match the diff scheme.
    """
    from s19_app.tui.services.report_service import REPORT_FILENAME_REGEX

    assert REPORT_FILENAME_REGEX.match("20260611T120000Z-report.md")
    assert not REPORT_FILENAME_REGEX.match("20260611T120000Z-diff-report.md")
    assert not DIFF_REPORT_FILENAME_REGEX.match("20260611T120000Z-report.md")


# ---------------------------------------------------------------------------
# TC-018 — LLR-004.3 — sections in order + caps + TRUNCATED + determinism
# ---------------------------------------------------------------------------


def test_report_sections_present_in_order(tmp_path: Path) -> None:
    """Header → Statistics → Runs → Hex windows appear, in that order.

    Intent: LLR-004.3 — all four sections present in order; exact stats/run
    table rows. Threshold: section indices strictly increasing; exact rows
    present.
    """
    runs = [DiffRun(0x100, 0x104, KIND_CHANGED), DiffRun(0x200, 0x202, KIND_ONLY_A)]
    comparison = _comparison(
        runs=runs,
        stats=_stats(1, 4, 1, 2),
    )
    result = generate_diff_report(
        comparison,
        mem_map_a=_mem(0x100, 0x01, 4) | _mem(0x200, 0x05, 2),
        mem_map_b=_mem(0x100, 0x02, 4),
        project_dir=tmp_path,
        now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    i_header = text.index("# Diff report")
    i_stats = text.index("## Statistics")
    i_runs = text.index("## Runs")
    i_hex = text.index("## Hex windows")
    assert i_header < i_stats < i_runs < i_hex

    # header identities + usage + version
    assert "- Image A: A.s19 [external]" in text
    assert "- Image B: B.s19 [external]" in text
    assert "- Image A artifacts: summary=both;" in text
    assert "- Tool version: " in text
    assert f"- Generated (UTC): {FIXED_NOW.isoformat()}" in text
    # stats table exact rows
    assert "| changed | 1 | 4 |" in text
    assert "| only in A | 1 | 2 |" in text
    assert "| only in B | 0 | 0 |" in text
    # run table exact rows
    assert "| 0x00000100 | 0x00000104 | 4 | changed | - |" in text
    assert "| 0x00000200 | 0x00000202 | 2 | only in A | - |" in text
    # no caps fired → no TRUNCATED
    assert "TRUNCATED" not in text


def test_run_dump_cap_emits_truncated_marker(tmp_path: Path) -> None:
    """More runs than the dump cap → a TRUNCATED marker with the exact omitted count.

    Intent: LLR-004.3 — the run-dump cap fires an explicit marker, never a
    silent cut. Threshold: marker present; stated omitted count == actual
    omission (3 runs, cap 1 → 2 omitted).
    """
    runs = [
        DiffRun(0x100, 0x104, KIND_CHANGED),
        DiffRun(0x200, 0x204, KIND_CHANGED),
        DiffRun(0x300, 0x304, KIND_CHANGED),
    ]
    comparison = _comparison(runs=runs, stats=_stats(3, 12))
    result = generate_diff_report(
        comparison,
        mem_map_a=_mem(0x100, 1, 4) | _mem(0x200, 1, 4) | _mem(0x300, 1, 4),
        mem_map_b=_mem(0x100, 2, 4) | _mem(0x200, 2, 4) | _mem(0x300, 2, 4),
        project_dir=tmp_path,
        run_dump_cap=1,
        now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    assert "> TRUNCATED: 2 of 3 run hex windows omitted (cap: 1 runs per report)." in text
    # the run TABLE still lists all 3 runs (only the windows are capped)
    assert text.count(" | changed | - |") == 3


def test_byte_budget_emits_truncated_marker(tmp_path: Path) -> None:
    """A tiny byte budget → a hex-window TRUNCATED marker with the omitted count.

    Intent: LLR-004.3 — the whole-document byte budget fires an explicit
    block-omission marker. Threshold: marker present stating ≥ 1 omitted block.
    """
    runs = [DiffRun(0x100, 0x104, KIND_CHANGED)]
    comparison = _comparison(runs=runs, stats=_stats(1, 4))
    result = generate_diff_report(
        comparison,
        mem_map_a=_mem(0x100, 1, 4),
        mem_map_b=_mem(0x100, 2, 4),
        project_dir=tmp_path,
        budget_limit=1,  # forces every hex block to be omitted
        now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    assert "> TRUNCATED:" in text
    assert "hex window block(s) omitted (report size cap: 1 bytes)." in text


def test_generation_is_deterministic_fixed_clock(tmp_path: Path) -> None:
    """Two generations with the same fixed clock produce byte-identical BODIES.

    Intent: LLR-004.3 — deterministic output. Threshold: the two files' text
    is equal after stripping the filename difference (collision counter).
    """
    a = tmp_path / "one"
    b = tmp_path / "two"
    a.mkdir()
    b.mkdir()
    comparison = _comparison()
    mem_a = _mem(0x100, 1, 4)
    mem_b = _mem(0x100, 2, 4)
    r1 = generate_diff_report(
        comparison, mem_map_a=mem_a, mem_map_b=mem_b, project_dir=a, now_fn=_fixed_clock
    )
    r2 = generate_diff_report(
        comparison, mem_map_a=mem_a, mem_map_b=mem_b, project_dir=b, now_fn=_fixed_clock
    )
    assert r1.path.read_text(encoding="utf-8") == r2.path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# TC-019 — LLR-004.4 — best-effort symbol annotation (G-2, non-gating)
# ---------------------------------------------------------------------------


def test_symbol_annotation_only_intersecting_run(tmp_path: Path) -> None:
    """A symbol inside one run annotates that run only; an outside symbol does not.

    Intent: LLR-004.4 / G-2 — annotate exactly the intersecting symbol, 0 false
    positives. Threshold: the inside symbol name appears on its run row; the
    outside symbol never appears; the non-annotated run renders ``-``.
    """
    runs = [DiffRun(0x100, 0x104, KIND_CHANGED), DiffRun(0x300, 0x304, KIND_CHANGED)]
    comparison = _comparison(runs=runs, stats=_stats(2, 8))
    mac = [
        {"name": "INSIDE_SYM", "address": 0x102},   # inside run 1 [0x100,0x104)
        {"name": "OUTSIDE_SYM", "address": 0x500},  # inside no run
    ]
    result = generate_diff_report(
        comparison,
        mem_map_a=_mem(0x100, 1, 4) | _mem(0x300, 1, 4),
        mem_map_b=_mem(0x100, 2, 4) | _mem(0x300, 2, 4),
        project_dir=tmp_path,
        mac_records=mac,
        now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    assert "| 0x00000100 | 0x00000104 | 4 | changed | INSIDE_SYM |" in text
    assert "| 0x00000300 | 0x00000304 | 4 | changed | - |" in text
    assert "OUTSIDE_SYM" not in text


def test_annotation_absent_without_context(tmp_path: Path) -> None:
    """No artifact context → every run is a raw binary run annotated ``-``.

    Intent: LLR-004.4 — annotation is non-gating; the diff is unaffected.
    Threshold: the run row renders ``-`` and the run is still reported.
    """
    comparison = _comparison()
    result = generate_diff_report(
        comparison,
        mem_map_a=_mem(0x100, 1, 4),
        mem_map_b=_mem(0x100, 2, 4),
        project_dir=tmp_path,
        now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")
    assert "| 0x00000100 | 0x00000104 | 4 | changed | - |" in text


# ---------------------------------------------------------------------------
# TC-020 — LLR-004.5 — confidentiality (no logging of report bytes)
# ---------------------------------------------------------------------------


def test_module_performs_no_logging() -> None:
    """The module source imports no logging and grabs no logger (F-S-07).

    Intent: LLR-004.5 — report body content can never reach the rotating log.
    Threshold: 0 occurrences of ``import logging`` / ``getLogger`` in the
    module source.
    """
    source = inspect.getsource(diff_report_service)
    assert "import logging" not in source
    assert "getLogger" not in source


# ---------------------------------------------------------------------------
# TC-025 — LLR-004.6 — no-project destination resolution + validation (G-8/M-4/M-5)
# ---------------------------------------------------------------------------


def test_no_project_valid_directory_writes_one_file(tmp_path: Path) -> None:
    """An operator directory that exists → exactly one tool-generated file there.

    Intent: LLR-004.6 / G-8 (a) — valid dir ⇒ 1 file, tool-generated filename.
    Threshold: exactly 1 ``.md`` file in the dir; its name matches the regex
    and is wholly tool-generated (no operator string).
    """
    result = generate_diff_report(
        _comparison(),
        mem_map_a=_mem(0x100, 1, 4),
        mem_map_b=_mem(0x100, 2, 4),
        project_dir=None,
        dest_input=str(tmp_path),
        now_fn=_fixed_clock,
    )

    assert result.written is True
    files = list(tmp_path.glob("*.md"))
    assert len(files) == 1
    assert DIFF_REPORT_FILENAME_REGEX.match(files[0].name)
    assert result.path == files[0]


@pytest.mark.parametrize("bad", ["", "   "])
def test_no_project_empty_path_refused(tmp_path: Path, bad: str) -> None:
    """An empty/blank operator path → 0 files, a diagnostic, no exception.

    Intent: LLR-004.6 / G-8 (b) — no implicit default; empty path is REFUSED.
    Threshold: written False; ≥ 1 diagnostic; 0 files anywhere; 0 exceptions.
    """
    result = generate_diff_report(
        _comparison(),
        mem_map_a=_mem(0x100, 1, 4),
        mem_map_b=_mem(0x100, 2, 4),
        project_dir=None,
        dest_input=bad,
        now_fn=_fixed_clock,
    )

    assert result.written is False
    assert result.path is None
    assert len(result.diagnostics) >= 1
    assert list(tmp_path.glob("*.md")) == []


def test_no_project_nonexistent_dir_refused(tmp_path: Path) -> None:
    """A non-existent directory path → 0 files, a diagnostic naming the input.

    Intent: LLR-004.6 / G-8 (b) — a path that is not an existing directory is
    REFUSED. Threshold: written False; the rejected input appears in a
    diagnostic; 0 files written.
    """
    missing = tmp_path / "does_not_exist"
    result = generate_diff_report(
        _comparison(),
        mem_map_a=_mem(0x100, 1, 4),
        mem_map_b=_mem(0x100, 2, 4),
        project_dir=None,
        dest_input=str(missing),
        now_fn=_fixed_clock,
    )

    assert result.written is False
    assert any("does_not_exist" in d for d in result.diagnostics)
    assert not missing.exists()


def test_no_project_collision_no_overwrite(tmp_path: Path) -> None:
    """A pre-created target in the operator dir → a -01 sibling; original untouched.

    Intent: LLR-004.6 / M-5 — the no-project branch applies the same
    no-silent-overwrite counter. Threshold: pre-existing file byte-identical;
    the new file is the ``-01`` sibling.
    """
    planted = tmp_path / "20260611T120000Z-diff-report.md"
    planted.write_text("PLANTED", encoding="utf-8")

    result = generate_diff_report(
        _comparison(),
        mem_map_a=_mem(0x100, 1, 4),
        mem_map_b=_mem(0x100, 2, 4),
        project_dir=None,
        dest_input=str(tmp_path),
        now_fn=_fixed_clock,
    )

    assert result.path.name == "20260611T120000Z-01-diff-report.md"
    assert planted.read_text(encoding="utf-8") == "PLANTED"  # 0 overwrites


def test_no_sanitize_project_name_in_validator() -> None:
    """The destination validator never calls sanitize_project_name (M-4).

    Intent: LLR-004.6 / M-4 — path validation must NOT use the single-token
    name cleaner. Probe targets the validator function body (the module
    docstring legitimately explains the M-4 decision). Threshold: 0 occurrences
    of ``sanitize_project_name`` in the validator source.
    """
    source = inspect.getsource(diff_report_service._resolve_destination)
    assert "sanitize_project_name" not in source
