"""
Diff-report generator tests — s19_app batch-09, increment I3 (HLR-004),
amended at the I3 gate (G-9: complete files, ```diff cue, HTML export).

Test -> TC -> LLR map:
    test_filename_scheme_and_same_second_collision   TC-016  LLR-004.1
    test_collision_never_overwrites_existing_file     TC-016  LLR-004.1 (M-5)
    test_self_contained_listing_newest_first          TC-017  LLR-004.2 (G-4)
    test_report_service_regex_unedited                TC-017  LLR-004.2 (G-4 NON-edit)
    test_report_sections_present_in_order             TC-018  LLR-004.3
    test_generation_is_deterministic_fixed_clock      TC-018  LLR-004.3 (determinism)
    test_symbol_annotation_only_intersecting_run      TC-019  LLR-004.4 (G-2)
    test_annotation_absent_without_context            TC-019  LLR-004.4 (non-gating)
    test_module_performs_no_logging                   TC-020  LLR-004.5 (F-S-07)
    test_no_project_valid_directory_writes_one_file   TC-025  LLR-004.6 (G-8 valid)
    test_no_project_empty_path_refused                TC-025  LLR-004.6 (G-8 refuse)
    test_no_project_nonexistent_dir_refused           TC-025  LLR-004.6 (G-8 refuse)
    test_no_project_collision_no_overwrite            TC-025  LLR-004.6 (M-5)
    test_no_sanitize_project_name_in_validator        TC-025  LLR-004.6 (M-4 source probe)
    test_markdown_file_is_complete_no_truncation      TC-026  LLR-004.3 (G-9 complete)
    test_changed_run_emits_diff_fenced_block          TC-027  LLR-004.3 (```diff cue)
    test_html_export_complete_and_safe                TC-028  LLR-004.7 (G-9 HTML)
    test_html_escapes_embedded_payload                TC-028  LLR-004.7 (html.escape)
    test_html_filename_scheme_and_collision           TC-028  LLR-004.7 (M-5 / regex)

Batch-24 (HLR-038 / LLR-038.1 — provenance + linkage kwargs):
    test_default_kwargs_output_byte_identical_pre_change_golden
                                                      TC-038.1 (byte-identical)
    test_provenance_and_linkage_render_in_both_formats
                                                      TC-038.1 (kwargs render)
    test_zero_entries_linkage_states_no_entries       TC-038.2 (empty linkage)
    test_pipe_bearing_symbol_md_escaped_html_intact   TC-038.6 (S-F2 _md_cell)

Batch-35 Inc-2 (B-07 / HLR-054 — report_filter on the diff generators):
    test_tc312_filter_restricts_linkage_and_run_sections_both_formats
                                                      TC-312  LLR-054.2 (D-2/D-5)
    test_tc312_a9_merged_window_spans_excluded_run    TC-312  LLR-054.2 (F-03/Q-2 A9)
    test_tc312_zero_match_notice_and_refusal_disjoint TC-312  LLR-054.3 (D-3/Q-12)
    test_tc312_audit_header_first_block_fixed_format  TC-312  LLR-054.3 (S-F6/F-07)
    test_tc318_hostile_filter_name_sanitized_md_html  TC-318  LLR-055.4 (diff half)
    test_tc313_no_filter_output_byte_identical_todays TC-313  LLR-054.5

Element-style thresholds are inline on each test.

Confidentiality (F-S-07): every fixture is a synthetic in-memory byte run —
never operator firmware.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from s19_app.compare import (
    KIND_CHANGED,
    KIND_ONLY_A,
    KIND_ONLY_B,
    ComparisonResult,
    DiffRun,
    DiffStats,
    ImageRef,
)
from s19_app.tui.changes import ChangeSummaryEntry
from s19_app.tui.services import diff_report_service
from s19_app.tui.services.compare_service import ArtifactNote, ArtifactUsage
from s19_app.tui.services.diff_report_service import (
    DIFF_REPORT_FILENAME_REGEX,
    DIFF_REPORT_HTML_FILENAME_REGEX,
    BeforeAfterProvenance,
    generate_diff_report,
    generate_diff_report_html,
    list_diff_reports,
)
from s19_app.tui.services.report_filter import (
    parse_report_filter,
    read_report_filter_text,
    resolve_report_filter,
)
from s19_app.version import __version__

FIXED_NOW = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)

#: External-resource patterns that a self-contained HTML report must NOT carry
#: (LLR-004.7 / probe P-19 regime).
_EXTERNAL_RESOURCE_RE = re.compile(r"<script|https?://|@import|src=|url\(")


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
    image_a: Optional[ImageRef] = None,
    image_b: Optional[ImageRef] = None,
) -> ComparisonResult:
    """A self-contained, non-refused comparison fixture (no parse needed)."""
    runs = runs if runs is not None else [DiffRun(0x100, 0x104, KIND_CHANGED)]
    stats = stats if stats is not None else _stats(changed_runs=1, changed_bytes=4)
    image_a = image_a or ImageRef(label="A.s19", path="/tmp/a.s19", source_kind="external")
    image_b = image_b or ImageRef(label="B.s19", path="/tmp/b.s19", source_kind="external")
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


def _planted_diff(run_count: int) -> tuple:
    """Build a comparison + two memory maps with ``run_count`` changed runs.

    Each run is a distinct 4-byte changed block 0x100 apart; A and B differ at
    every byte. Returns ``(comparison, mem_a, mem_b, run_starts)``.
    """
    runs: List[DiffRun] = []
    mem_a: Dict[int, int] = {}
    mem_b: Dict[int, int] = {}
    starts: List[int] = []
    for i in range(run_count):
        start = 0x1000 + i * 0x100
        starts.append(start)
        runs.append(DiffRun(start, start + 4, KIND_CHANGED))
        mem_a.update(_mem(start, 0xAA, 4))
        mem_b.update(_mem(start, 0xBB, 4))
    comparison = _comparison(runs=runs, stats=_stats(run_count, run_count * 4))
    return comparison, mem_a, mem_b, starts


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
# TC-018 — LLR-004.3 — sections in order + determinism
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
    assert "- Image A: A\\.s19 [external]" in text
    assert "- Image B: B\\.s19 [external]" in text
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
    # the written file is complete (G-9) → never a TRUNCATED marker
    assert "TRUNCATED" not in text


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
# TC-026 — LLR-004.3 — complete export (G-9): every run, 0 TRUNCATED
# ---------------------------------------------------------------------------


def test_markdown_file_is_complete_no_truncation(tmp_path: Path) -> None:
    """A large planted diff → every run present, 0 TRUNCATED markers (G-9).

    Intent: LLR-004.3 / G-9 — the WRITTEN file is complete: no run cap, no byte
    truncation, no marker. Threshold: 0 ``TRUNCATED`` occurrences; every
    planted run's hex-window heading is present (200 runs).
    """
    comparison, mem_a, mem_b, starts = _planted_diff(200)
    result = generate_diff_report(
        comparison,
        mem_map_a=mem_a,
        mem_map_b=mem_b,
        project_dir=tmp_path,
        now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    assert text.count("TRUNCATED") == 0
    # every run's window section heading is present (complete, uncapped)
    for start in starts:
        assert f"### Run 0x{start:08X}" in text
    # the run table lists all 200 runs
    assert text.count(" | changed | - |") == 200


# ---------------------------------------------------------------------------
# TC-027 — LLR-004.3 — changed run renders as a fenced ```diff block
# ---------------------------------------------------------------------------


def test_changed_run_emits_diff_fenced_block(tmp_path: Path) -> None:
    """A changed run emits a ```diff block: A bytes as `-`, B bytes as `+`.

    Intent: LLR-004.3 — the format-appropriate Markdown cue. Threshold: a
    ```diff fence exists; inside it ≥ 1 ``-`` line (image A byte 0xAA) and ≥ 1
    ``+`` line (image B byte 0xBB).
    """
    comparison = _comparison(
        runs=[DiffRun(0x100, 0x104, KIND_CHANGED)],
        stats=_stats(1, 4),
    )
    result = generate_diff_report(
        comparison,
        mem_map_a=_mem(0x100, 0xAA, 4),
        mem_map_b=_mem(0x100, 0xBB, 4),
        project_dir=tmp_path,
        now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    assert "```diff" in text
    # carve out the diff fence body and assert -/+ lines with the image bytes
    fence_start = text.index("```diff")
    fence_body = text[fence_start + len("```diff"):]
    fence_body = fence_body[: fence_body.index("```")]
    minus_lines = [ln for ln in fence_body.splitlines() if ln.startswith("-")]
    plus_lines = [ln for ln in fence_body.splitlines() if ln.startswith("+")]
    assert len(minus_lines) >= 1
    assert len(plus_lines) >= 1
    assert any("AA" in ln for ln in minus_lines)  # image A byte
    assert any("BB" in ln for ln in plus_lines)   # image B byte


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

    assert "| 0x00000100 | 0x00000104 | 4 | changed | INSIDE\\_SYM |" in text
    assert "| 0x00000300 | 0x00000304 | 4 | changed | - |" in text
    # Both spellings (F-E3-2): the escaped one alone passes when a sink leaks
    # the raw name, the raw one alone passes when the name is merely escaped.
    assert "OUTSIDE_SYM" not in text and "OUTSIDE\\_SYM" not in text


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


# ---------------------------------------------------------------------------
# TC-028 — LLR-004.7 — self-contained HTML export (G-9): complete + safe
# ---------------------------------------------------------------------------


def test_html_export_complete_and_safe(tmp_path: Path) -> None:
    """A large planted diff → complete, self-contained, safe HTML (LLR-004.7).

    Intent: LLR-004.7 / G-9 — the HTML is complete (0 TRUNCATED, every run
    present), self-contained (0 ``<script>``, 0 external-resource matches), and
    colour-cued (≥ 1 inline-CSS colour per run kind). Threshold encoded inline.
    """
    comparison, mem_a, mem_b, starts = _planted_diff(120)
    # mix in an only-A and only-B run so all three colour cues appear
    comparison.runs.append(DiffRun(0x9000, 0x9004, KIND_ONLY_A))
    comparison.runs.append(DiffRun(0xA000, 0xA004, KIND_ONLY_B))
    mem_a.update(_mem(0x9000, 0xAA, 4))
    mem_b.update(_mem(0xA000, 0xBB, 4))

    result = generate_diff_report_html(
        comparison,
        mem_map_a=mem_a,
        mem_map_b=mem_b,
        project_dir=tmp_path,
        now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    # completeness (G-9)
    assert text.count("TRUNCATED") == 0
    for start in starts:
        assert f"0x{start:08X}" in text
    # self-contained / no injection surface
    assert text.count("<script") == 0
    assert _EXTERNAL_RESOURCE_RE.search(text) is None
    # colour cues for the three run kinds (inline CSS)
    assert "#b58900" in text   # changed
    assert "#dc322f" in text   # only-A
    assert "#268bd2" in text   # only-B
    assert "style=" in text
    # the file actually ends in </html> (self-contained document)
    assert text.rstrip().endswith("</html>")
    assert DIFF_REPORT_HTML_FILENAME_REGEX.match(result.path.name)


def test_html_escapes_embedded_payload(tmp_path: Path) -> None:
    """An escapable payload in a path round-trips as its html.escape form.

    Intent: LLR-004.7 — every embedded value is ``html.escape``-d. Threshold:
    a path containing ``<script>`` & ``"`` appears escaped (``&lt;``/``&amp;``/
    ``&quot;``), NOT raw; 0 ``<script`` tags; 0 external-resource matches.
    """
    payload = '<script>alert("x")</script>&'
    image_a = ImageRef(label=payload, path=payload, source_kind="external")
    comparison = _comparison(image_a=image_a)

    result = generate_diff_report_html(
        comparison,
        mem_map_a=_mem(0x100, 1, 4),
        mem_map_b=_mem(0x100, 2, 4),
        project_dir=tmp_path,
        now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    assert payload not in text          # the raw payload never appears
    assert "&lt;script&gt;" in text     # escaped form present
    assert "&amp;" in text
    assert "&quot;" in text
    assert text.count("<script") == 0   # no live script tag
    assert _EXTERNAL_RESOURCE_RE.search(text) is None


def test_html_filename_scheme_and_collision(tmp_path: Path) -> None:
    """HTML filename matches its own regex; a same-second collision → -01 (M-5).

    Intent: LLR-004.7 — own ``.html`` filename scheme + collision discipline,
    shared regex untouched. Threshold: base + ``-01`` siblings, both matching
    DIFF_REPORT_HTML_FILENAME_REGEX; the Markdown regex does NOT match.
    """
    mem_a = _mem(0x100, 1, 4)
    mem_b = _mem(0x100, 2, 4)
    first = generate_diff_report_html(
        _comparison(), mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, now_fn=_fixed_clock,
    )
    second = generate_diff_report_html(
        _comparison(), mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, now_fn=_fixed_clock,
    )

    assert first.path.name == "20260611T120000Z-diff-report.html"
    assert second.path.name == "20260611T120000Z-01-diff-report.html"
    assert DIFF_REPORT_HTML_FILENAME_REGEX.match(first.path.name)
    assert DIFF_REPORT_HTML_FILENAME_REGEX.match(second.path.name)
    assert not DIFF_REPORT_FILENAME_REGEX.match(first.path.name)


# ---------------------------------------------------------------------------
# TC-038.1 / TC-038.2 / TC-038.6 — LLR-038.1 (batch-24) — provenance/linkage
# kwargs; omitted-kwargs output BYTE-IDENTICAL to pre-change behavior.
# ---------------------------------------------------------------------------

# PRE-CHANGE golden capture (TC-038.1 byte-identical regression): these two
# templates are the EXACT bytes generate_diff_report / generate_diff_report_html
# wrote for the fixture below BEFORE the LLR-038.1 kwargs landed (captured
# 2026-07-02 against the unedited module, fixed clock FIXED_NOW, mem A=AA x4 /
# B=BB x4 at 0x100). The live tool version is templated as @@VERSION@@ so the
# golden survives version bumps while staying byte-exact otherwise.
# batch-34 NOTE: goldens re-captured at batch-34 (the side-by-side HTML
# pane + grouped headings deliberately changed the changed-run output);
# the test's INTENT (omitted kwargs add nothing) is unchanged.
_PRE_CHANGE_MD_TEMPLATE = '# Diff report\n\n- Generated (UTC): 2026-06-11T12:00:00+00:00\n- Tool version: @@VERSION@@\n- Image A: A\\.s19 [external] path=`/tmp/a.s19` parse-errors=0\n- Image B: B\\.s19 [external] path=`/tmp/b.s19` parse-errors=0\n- Image A artifacts: summary=both; a2l=used (1/2); mac=used (1/1)\n- Image B artifacts: summary=both; a2l=used (1/2); mac=used (1/1)\n\n## Statistics\n\n| Classification | Runs | Bytes |\n|---|---|---|\n| changed | 1 | 4 |\n| only in A | 0 | 0 |\n| only in B | 0 | 0 |\n\n## Runs\n\n| Start | End | Length | Classification | Symbols |\n|---|---|---|---|---|\n| 0x00000100 | 0x00000104 | 4 | changed | - |\n\n## Hex windows\n\n### Run 0x00000100-0x00000104 (changed)\n\n```diff\n-0x000000C0                                                   |................|\n-0x000000D0                                                   |................|\n-0x000000E0                                                   |................|\n-0x000000F0                                                   |................|\n-0x00000100  AA AA AA AA                                      |................|\n+0x000000C0                                                   |................|\n+0x000000D0                                                   |................|\n+0x000000E0                                                   |................|\n+0x000000F0                                                   |................|\n+0x00000100  BB BB BB BB                                      |................|\n```\n\nImage A window 0x000000C0-0x00000110:\n\n```text\n0x000000C0                                                   |................|\n0x000000D0                                                   |................|\n0x000000E0                                                   |................|\n0x000000F0                                                   |................|\n0x00000100  AA AA AA AA                                      |................|\n```\n\nImage B window 0x000000C0-0x00000110:\n\n```text\n0x000000C0                                                   |................|\n0x000000D0                                                   |................|\n0x000000E0                                                   |................|\n0x000000F0                                                   |................|\n0x00000100  BB BB BB BB                                      |................|\n```\n'

_PRE_CHANGE_HTML_TEMPLATE = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Diff report</title>\n<style>body{font-family:monospace;background:#fdf6e3;color:#073642;}table{border-collapse:collapse;}th,td{border:1px solid #93a1a1;padding:2px 6px;text-align:left;}pre{border:1px solid #93a1a1;padding:6px;overflow:auto;}</style>\n</head>\n<body>\n<h1>Diff report</h1>\n<ul>\n<li>Generated (UTC): 2026-06-11T12:00:00+00:00</li>\n<li>Tool version: @@VERSION@@</li>\n<li>Image A: A.s19 [external] path=<code>/tmp/a.s19</code> parse-errors=0</li>\n<li>Image B: B.s19 [external] path=<code>/tmp/b.s19</code> parse-errors=0</li>\n<li>Image A artifacts: summary=both; a2l=used (1/2); mac=used (1/1)</li>\n<li>Image B artifacts: summary=both; a2l=used (1/2); mac=used (1/1)</li>\n</ul>\n<h2>Statistics</h2>\n<table>\n<tr><th>Classification</th><th>Runs</th><th>Bytes</th></tr>\n<tr><td style="color:#b58900">changed</td><td>1</td><td>4</td></tr>\n<tr><td style="color:#dc322f">only in A</td><td>0</td><td>0</td></tr>\n<tr><td style="color:#268bd2">only in B</td><td>0</td><td>0</td></tr>\n</table>\n<h2>Runs</h2>\n<table>\n<tr><th>Start</th><th>End</th><th>Length</th><th>Classification</th><th>Symbols</th></tr>\n<tr><td>0x00000100</td><td>0x00000104</td><td>4</td><td style="color:#b58900">changed</td><td>-</td></tr>\n</table>\n<h2>Hex windows</h2>\n<h3 style="color:#b58900">Run 0x00000100-0x00000104 (changed)</h3>\n<p>Window 0x000000C0-0x00000110 (changed bytes highlighted):</p>\n<table style="width:100%;border-collapse:collapse"><tr>\n<td style="vertical-align:top;width:50%;padding-right:8px"><strong>Before (A)</strong><pre>0x000000C0                                                   |                |\n0x000000D0                                                   |                |\n0x000000E0                                                   |                |\n0x000000F0                                                   |                |\n0x00000100  <span style="background:#ffd54d;color:#000;font-weight:bold">AA</span> <span style="background:#ffd54d;color:#000;font-weight:bold">AA</span> <span style="background:#ffd54d;color:#000;font-weight:bold">AA</span> <span style="background:#ffd54d;color:#000;font-weight:bold">AA</span>                                      |<span style="background:#ffd54d;color:#000;font-weight:bold">.</span><span style="background:#ffd54d;color:#000;font-weight:bold">.</span><span style="background:#ffd54d;color:#000;font-weight:bold">.</span><span style="background:#ffd54d;color:#000;font-weight:bold">.</span>            |</pre></td>\n<td style="vertical-align:top;width:50%"><strong>After (B)</strong><pre>0x000000C0                                                   |                |\n0x000000D0                                                   |                |\n0x000000E0                                                   |                |\n0x000000F0                                                   |                |\n0x00000100  <span style="background:#ffd54d;color:#000;font-weight:bold">BB</span> <span style="background:#ffd54d;color:#000;font-weight:bold">BB</span> <span style="background:#ffd54d;color:#000;font-weight:bold">BB</span> <span style="background:#ffd54d;color:#000;font-weight:bold">BB</span>                                      |<span style="background:#ffd54d;color:#000;font-weight:bold">.</span><span style="background:#ffd54d;color:#000;font-weight:bold">.</span><span style="background:#ffd54d;color:#000;font-weight:bold">.</span><span style="background:#ffd54d;color:#000;font-weight:bold">.</span>            |</pre></td>\n</tr></table>\n</body>\n</html>'


def _entry(
    *,
    address_start: int = 0x100,
    address_end: int = 0x102,
    before_bytes: tuple = (0xAA, 0xAA),
    after_bytes: tuple = (0x01, 0x02),
    disposition: str = "applied",
    linkage: str = "mac-linked",
    linkage_symbol: str = "CAL_SYM",
    entry_type: str = "bytes",
) -> ChangeSummaryEntry:
    """Build one linkage entry with overridable fields (TC-038.* fixture)."""
    return ChangeSummaryEntry(
        entry_type=entry_type,
        address_start=address_start,
        address_end=address_end,
        before_bytes=before_bytes,
        after_bytes=after_bytes,
        disposition=disposition,
        linkage=linkage,
        linkage_symbol=linkage_symbol,
    )


def _provenance() -> BeforeAfterProvenance:
    return BeforeAfterProvenance(
        original_path=Path("/tmp/original.s19"),
        saved_path=Path("/tmp/original-patched_1.s19"),
        applied_at_utc="2026-07-02T09:00:00+00:00",
        change_doc_path=Path("/tmp/change-doc.json"),
    )


def test_default_kwargs_output_byte_identical_pre_change_golden(
    tmp_path: Path,
) -> None:
    """Omitted new kwargs → output byte-identical to the PRE-CHANGE capture.

    Intent: LLR-038.1 — the default-off kwargs leave the diff-report path
    untouched. Threshold: the written .md and .html BYTES equal the golden
    captured against the unedited module (fixed clock; version templated);
    neither new section heading appears anywhere in the default output.
    """
    md = generate_diff_report(
        _comparison(),
        mem_map_a=_mem(0x100, 0xAA, 4),
        mem_map_b=_mem(0x100, 0xBB, 4),
        project_dir=tmp_path,
        now_fn=_fixed_clock,
    )
    html_r = generate_diff_report_html(
        _comparison(),
        mem_map_a=_mem(0x100, 0xAA, 4),
        mem_map_b=_mem(0x100, 0xBB, 4),
        project_dir=tmp_path,
        now_fn=_fixed_clock,
    )

    # write_text translates "\n" to os.linesep — the pre-change writer did the
    # same, so expanding the LF-normalized golden per platform preserves exact
    # byte identity on Windows (CRLF) and CI Linux (LF) alike.
    expected_md = _PRE_CHANGE_MD_TEMPLATE.replace("@@VERSION@@", __version__)
    expected_html = _PRE_CHANGE_HTML_TEMPLATE.replace(
        "@@VERSION@@", __version__
    )
    assert md.path.read_bytes() == expected_md.replace(
        "\n", os.linesep
    ).encode("utf-8")
    assert html_r.path.read_bytes() == expected_html.replace(
        "\n", os.linesep
    ).encode("utf-8")
    # explicit absence of the new sections in default output
    for text in (expected_md, expected_html):
        assert "Before/after provenance" not in text
        assert "Change-entry linkage" not in text
    # default filename scheme untouched
    assert md.path.name == "20260611T120000Z-diff-report.md"
    assert html_r.path.name == "20260611T120000Z-diff-report.html"


def test_provenance_and_linkage_render_in_both_formats(tmp_path: Path) -> None:
    """Provenance + linkage kwargs render the header section and the table.

    Intent: LLR-038.1 — both formats carry the before/after header (original
    path, saved post-dedup path, apply instant, change-doc origin), one
    linkage row per entry (all dispositions), the before_bytes=None
    create-into-hole marker (never fabricated bytes), and the filename-stem
    override. Threshold: every named element present in BOTH written files;
    the None-before cell carries the marker and no hex bytes.
    """
    entries = [
        _entry(),
        _entry(
            address_start=0x9000,
            address_end=0x9002,
            before_bytes=None,
            after_bytes=(0xCC, 0xDD),
            disposition="applied",
            linkage="standalone",
            linkage_symbol=None,
        ),
        _entry(
            address_start=0x200,
            address_end=0x201,
            before_bytes=None,
            after_bytes=(0xEE,),
            disposition="skipped",
            linkage="a2l-linked",
            linkage_symbol="A2L_SYM",
        ),
    ]
    prov = _provenance()
    kwargs = dict(
        mem_map_a=_mem(0x100, 0xAA, 4),
        mem_map_b=_mem(0x100, 0xBB, 4),
        project_dir=tmp_path,
        now_fn=_fixed_clock,
        provenance=prov,
        linkage_entries=entries,
        filename_stem="before-after-report",
    )
    md = generate_diff_report(_comparison(), **kwargs)
    html_r = generate_diff_report_html(_comparison(), **kwargs)

    # filename-stem override in both formats
    assert md.path.name == "20260611T120000Z-before-after-report.md"
    assert html_r.path.name == "20260611T120000Z-before-after-report.html"

    md_text = md.path.read_text(encoding="utf-8")
    html_text = html_r.path.read_text(encoding="utf-8")

    for text in (md_text, html_text):
        # provenance header content (str() — platform-native separators)
        assert "Before/after provenance" in text
        assert str(prov.original_path) in text
        assert str(prov.saved_path) in text
        assert "2026-07-02T09:00:00+00:00" in text
        assert str(prov.change_doc_path) in text
        # linkage table content — all three entries, all dispositions
        assert "Change-entry linkage" in text
        # Markdown writes symbol names as report-safe text (R-CMP-004.9.1);
        # the HTML file keeps the raw name (R-CMP-004.8).
        cal_sym = "CAL\\_SYM" if text is md_text else "CAL_SYM"
        a2l_sym = "A2L\\_SYM" if text is md_text else "A2L_SYM"
        assert cal_sym in text
        assert a2l_sym in text
        assert "skipped" in text
        assert "0x00009000" in text
        # create-into-hole marker, never fabricated bytes
        assert "(none - created into hole)" in text
        assert "CC DD" in text  # after side still real
    # md linkage row shape: entry 1 fully tabular — batch-34 (AC-5,
    # supersedes the hex-only pin): cells carry the ASCII companion with
    # its gutter pipes escaped via _md_table_cell.
    assert (
        "| 1 | bytes | 0x00000100 | 0x00000102 | applied | mac-linked "
        "| CAL\\_SYM | AA AA \\|..\\| | 01 02 \\|..\\| |" in md_text
    )
    # the None-before md row carries the marker cell, not hex (marker
    # unchanged — no fabricated ASCII).
    assert (
        "| 2 | bytes | 0x00009000 | 0x00009002 | applied | standalone "
        "| - | (none - created into hole) | CC DD \\|..\\| |" in md_text
    )
    # html stays self-contained and safe with the new sections
    assert html_text.count("<script") == 0
    assert _EXTERNAL_RESOURCE_RE.search(html_text) is None


def test_zero_entries_linkage_states_no_entries(tmp_path: Path) -> None:
    """An EMPTY linkage sequence renders a 'No entries.' linkage section.

    Intent: LLR-038.1 / TC-038.2 — an apply with 0 applied entries still
    reports, and the linkage section states there are no entries (the no-diff
    report precedent). Threshold: section heading + 'No entries.' in both
    formats; no linkage table header row.
    """
    kwargs = dict(
        mem_map_a=_mem(0x100, 0xAA, 4),
        mem_map_b=_mem(0x100, 0xBB, 4),
        project_dir=tmp_path,
        now_fn=_fixed_clock,
        linkage_entries=[],
    )
    md = generate_diff_report(_comparison(), **kwargs)
    html_r = generate_diff_report_html(_comparison(), **kwargs)

    md_text = md.path.read_text(encoding="utf-8")
    html_text = html_r.path.read_text(encoding="utf-8")
    for text in (md_text, html_text):
        assert "Change-entry linkage" in text
        assert "No entries." in text
        assert "Disposition" not in text  # no table header for 0 entries


def test_pipe_bearing_symbol_md_escaped_html_intact(tmp_path: Path) -> None:
    """A pipe/control-char symbol is _md_cell-escaped in md, _esc-d in html.

    Intent: LLR-038.1 / S-F2 (TC-038.6) — a parsed-artifact symbol carrying
    ``|`` and a control char cannot break the Markdown table: the pipe renders
    escaped (``\\|``), the control char is stripped, and the row still has the
    9-column shape. The HTML side renders the symbol intact-escaped through
    ``html.escape``. Threshold: escaped pipe present in md; raw control char
    absent from both files; md row cell count == 9; html carries the
    escaped-form symbol.
    """
    evil = "EVIL|SYM<b>\x01END"
    entries = [_entry(linkage_symbol=evil)]
    kwargs = dict(
        mem_map_a=_mem(0x100, 0xAA, 4),
        mem_map_b=_mem(0x100, 0xBB, 4),
        project_dir=tmp_path,
        now_fn=_fixed_clock,
        linkage_entries=entries,
    )
    md = generate_diff_report(_comparison(), **kwargs)
    html_r = generate_diff_report_html(_comparison(), **kwargs)

    md_text = md.path.read_text(encoding="utf-8")
    html_text = html_r.path.read_text(encoding="utf-8")

    # md: pipe escaped, control char stripped, table row intact (9 cells)
    # batch-101 Inc 7 (R-CMP-004.9.1 / R-BEFORE-AFTER-REPORT-001.21): report-safe
    # text: the pipe and the angle brackets are escaped and U+0001 becomes a
    # visible U+FFFD instead of vanishing.
    assert "EVIL\\|SYM\\<b\\>\ufffdEND" in md_text
    assert "\x01" not in md_text
    row = next(
        ln for ln in md_text.splitlines() if ln.startswith("| 1 | bytes |")
    )
    unescaped_pipes = re.findall(r"(?<!\\)\|", row)
    assert len(unescaped_pipes) == 10  # 9 cells -> 10 structural pipes
    # html: symbol intact-escaped (pipe preserved, markup escaped via _esc;
    # ctl-char stripping is the md-cell rule only — S-F2)
    assert "EVIL|SYM&lt;b&gt;\ufffdEND" in html_text
    assert "<b>" not in html_text


# ---------------------------------------------------------------------------
# batch-34 Inc-1 (B-08) — merged context windows for contiguous runs.
# ---------------------------------------------------------------------------


def test_ac1_contiguous_runs_share_one_merged_window(tmp_path: Path) -> None:
    """AC-1: two changed runs two rows apart yield ONE grouped heading and
    ONE Image-A/Image-B window pair (RED-first: pre-batch-34 each run
    emitted its own overlapping pair, duplicating the shared context)."""
    # Runs at 0x1000 and 0x1020 (two rows apart); context 0 keeps the
    # window math exact: rows 0x1000 and 0x1020 bridge (gap 1 row <= 5).
    runs = [
        DiffRun(0x1000, 0x1004, KIND_CHANGED),
        DiffRun(0x1020, 0x1024, KIND_CHANGED),
    ]
    mem_a = {addr: 0xAA for addr in range(0x1000, 0x1030)}
    mem_b = {addr: 0xBB for addr in range(0x1000, 0x1030)}
    comparison = _comparison(runs=runs, stats=_stats(2, 8))

    result = generate_diff_report(
        comparison, mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, context_bytes=0, now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    assert text.count("### Run") == 1, "one grouped heading, not one per run"
    assert "### Runs 0x00001000-0x00001004 (changed), 0x00001020-0x00001024 (changed)" in text
    assert text.count("Image A window") == 1
    assert text.count("Image B window") == 1
    assert "Image A window 0x00001000-0x00001030:" in text
    assert text.count("```diff") == 1, "one merged diff block"


def test_ac1_boundary_five_rows_merges_six_does_not(tmp_path: Path) -> None:
    """AC-1 boundary: a 5-row gap between run windows merges; a 6-row gap
    keeps two separate windows (the operator's +5-lines limit)."""

    def _report(second_start: int) -> str:
        runs = [
            DiffRun(0x1000, 0x1004, KIND_CHANGED),
            DiffRun(second_start, second_start + 4, KIND_CHANGED),
        ]
        top = second_start + 0x10
        mem_a = {addr: 0xAA for addr in range(0x1000, top)}
        mem_b = {addr: 0xBB for addr in range(0x1000, top)}
        result = generate_diff_report(
            _comparison(runs=runs, stats=_stats(2, 8)),
            mem_map_a=mem_a, mem_map_b=mem_b,
            project_dir=tmp_path, context_bytes=0, now_fn=_fixed_clock,
        )
        return result.path.read_text(encoding="utf-8")

    # Window 1 covers [0x1000, 0x1010); a run starting at 0x1060 opens its
    # window exactly 5 rows (0x50 bytes) past that end -> merges.
    merged = _report(0x1060)
    assert merged.count("Image A window") == 1
    assert "### Runs" in merged

    # 6 rows past (0x1070) -> stays separate.
    separate = _report(0x1070)
    assert separate.count("Image A window") == 2
    assert separate.count("### Run 0x") == 2  # two singular headings


def test_ac2_compute_hexdump_windows_gap_parameter() -> None:
    """AC-2: the default (gap 0) is byte-identical to the old fold; a
    positive merge_gap_bytes bridges windows separated by <= gap."""
    from s19_app.tui.services.report_service import compute_hexdump_windows
    regions = [(0x100, 0x104), (0x160, 0x164)]  # windows 0x100-0x110, 0x160-0x170
    # Default: overlap-or-touch only -> two windows (gap is 0x50).
    assert compute_hexdump_windows(regions, 0, 0x200) == [
        (0x100, 0x110),
        (0x160, 0x170),
    ]
    # Gap 5 rows (0x50): exactly bridges -> one window.
    assert compute_hexdump_windows(regions, 0, 0x200, merge_gap_bytes=0x50) == [
        (0x100, 0x170),
    ]
    # Gap one row short (0x40): still two windows.
    assert compute_hexdump_windows(regions, 0, 0x200, merge_gap_bytes=0x40) == [
        (0x100, 0x110),
        (0x160, 0x170),
    ]


# ---------------------------------------------------------------------------
# batch-34 Inc-2 (B-09) — HTML side-by-side panes with per-changed-byte
# highlights (escape-then-wrap construction, security F2/F3).
# ---------------------------------------------------------------------------


def test_ac3_html_side_by_side_highlights_changed_bytes(tmp_path: Path) -> None:
    """AC-3: the changed window renders Before(A)/After(B) side by side and
    wraps EXACTLY the differing bytes' hex tokens in the highlight span —
    an unchanged byte's token stays span-free."""
    # One changed run 0x100-0x102 (two bytes differ); byte at 0x102 equal.
    runs = [DiffRun(0x100, 0x102, KIND_CHANGED)]
    mem_a = {0x100: 0xAA, 0x101: 0xAB, 0x102: 0x55}
    mem_b = {0x100: 0xBB, 0x101: 0xBC, 0x102: 0x55}
    result = generate_diff_report_html(
        _comparison(runs=runs, stats=_stats(1, 2)),
        mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, context_bytes=0, now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    assert "Before (A)" in text and "After (B)" in text
    assert "(changed bytes highlighted)" in text
    span = '<span style="background:#ffd54d;color:#000;font-weight:bold">'
    assert f"{span}AA</span>" in text
    assert f"{span}BB</span>" in text
    assert f"{span}AB</span>" in text
    assert f"{span}BC</span>" in text
    # The unchanged 0x55 byte is NOT highlighted on either pane.
    assert f"{span}55</span>" not in text
    assert "55" in text  # ...but it renders


def test_ac3_hostile_gutter_bytes_escaped_in_html(tmp_path: Path) -> None:
    """AC-3 hostile case (security fixture 5): a run whose bytes decode to
    '<b>&' renders the gutter ESCAPED (no raw '<b>' anywhere; the ampersand
    beside a highlighted byte yields exactly one '&amp;', never a split or
    doubled entity)."""
    payload = [0x3C, 0x62, 0x3E, 0x26]  # "<b>&"
    runs = [DiffRun(0x100, 0x104, KIND_CHANGED)]
    mem_a = {0x100 + i: b for i, b in enumerate(payload)}
    mem_b = {0x100 + i: (b ^ 0xFF) for i, b in enumerate(payload)}
    result = generate_diff_report_html(
        _comparison(runs=runs, stats=_stats(1, 4)),
        mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, context_bytes=0, now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")

    assert "<b>" not in text, "raw file-derived tag must never reach the HTML"
    # Gutter chars are escaped per-fragment (escape-then-wrap), so '<' and
    # '>' appear as individual escaped entities, never as a raw tag.
    assert "&lt;" in text and "&gt;" in text
    assert "&amp;amp;" not in text, "no double-escaped entity"
    assert "&amp;" in text
    # The escaped gutter chars themselves carry the highlight (escape-then-wrap).
    span = '<span style="background:#ffd54d;color:#000;font-weight:bold">'
    assert f"{span}&lt;</span>" in text


def test_ac4_markdown_diff_block_format_unchanged(tmp_path: Path) -> None:
    """AC-4 (regression pin): the Markdown report's ```diff block keeps its
    -A/+B row format for a changed run."""
    result = generate_diff_report(
        _comparison(), mem_map_a=_mem(0x100, 0xAA, 4), mem_map_b=_mem(0x100, 0xBB, 4),
        project_dir=tmp_path, context_bytes=0, now_fn=_fixed_clock,
    )
    text = result.path.read_text(encoding="utf-8")
    assert "```diff" in text
    assert "-0x00000100  AA AA AA AA" in text
    assert "+0x00000100  BB BB BB BB" in text


# ---------------------------------------------------------------------------
# batch-34 Inc-3 (B-10) — linkage-table ASCII companions + hostile bytes.
# ---------------------------------------------------------------------------


def _linkage_report_pair(tmp_path: Path, entry) -> "tuple[str, str]":
    """Generate MD + HTML with one linkage entry; return both texts."""
    md = generate_diff_report(
        _comparison(), mem_map_a=_mem(0x100, 0xAA, 4), mem_map_b=_mem(0x100, 0xBB, 4),
        project_dir=tmp_path, now_fn=_fixed_clock, linkage_entries=[entry],
    )
    html_r = generate_diff_report_html(
        _comparison(), mem_map_a=_mem(0x100, 0xAA, 4), mem_map_b=_mem(0x100, 0xBB, 4),
        project_dir=tmp_path, now_fn=_fixed_clock, linkage_entries=[entry],
    )
    return (
        md.path.read_text(encoding="utf-8"),
        html_r.path.read_text(encoding="utf-8"),
    )


def test_ac5_linkage_cells_carry_ascii_companion(tmp_path: Path) -> None:
    """AC-5: a text-valued patch renders readable — the Before/After cells
    carry the ASCII rendering beside the hex in BOTH formats (RED-first:
    cells were hex-only)."""
    entry = _entry(
        address_start=0x100,
        address_end=0x105,
        before_bytes=(0x52, 0x45, 0x56, 0x5F, 0x42),  # "REV_B"
        after_bytes=(0x52, 0x45, 0x56, 0x5F, 0x43),  # "REV_C"
    )
    md_text, html_text = _linkage_report_pair(tmp_path, entry)

    # MD: gutter pipes escaped by _md_table_cell; ASCII visible.
    assert "52 45 56 5F 42 \\|REV_B\\|" in md_text
    assert "52 45 56 5F 43 \\|REV_C\\|" in md_text
    # HTML: plain pipes (inert), html-escaped path.
    assert "52 45 56 5F 42 |REV_B|" in html_text
    assert "52 45 56 5F 43 |REV_C|" in html_text


def test_ac5_hostile_bytes_keep_md_table_and_html_safe(tmp_path: Path) -> None:
    """AC-5 hostile set (security F1 counterfactual + fixtures 1/2/4/6):
    pipe and backslash-pipe bytes keep the MD row at exactly its 9 cells
    (plain _md_cell would leak a live delimiter on the adjacent \\| pair);
    '<b>'-shaped bytes are escaped in HTML; non-printables render '.'."""
    hostile = (0x5C, 0x7C, 0x3C, 0x62, 0x3E, 0x0A, 0x60)  # \ | < b > LF `
    entry = _entry(
        address_start=0x200,
        address_end=0x207,
        before_bytes=hostile,
        after_bytes=(0x41,) * 7,
    )
    md_text, html_text = _linkage_report_pair(tmp_path, entry)

    # The MD row still splits into exactly 9 cells: split on pipes that are
    # NOT backslash-escaped.
    row = next(
        line for line in md_text.splitlines() if line.startswith("| 1 | ")
    )
    cells = re.split(r"(?<!\\)\|", row)
    assert len([c for c in cells if c != ""]) == 9, (
        f"hostile bytes must not add/remove MD columns; row: {row!r}"
    )
    # ASCII shows the literal printables (escaped) and '.' for LF.
    assert "\\\\" in row  # the 0x5C byte, backslash-doubled
    assert "." in row  # the LF placeholder
    # HTML: tag-shaped bytes escaped, never raw.
    assert "<b>" not in html_text
    assert "&lt;b&gt;" in html_text


def test_ac5_markers_unchanged(tmp_path: Path) -> None:
    """AC-5 boundary: the None-before marker and empty-run dash render
    exactly as before (no fabricated ASCII)."""
    entry = _entry(
        address_start=0x300,
        address_end=0x302,
        before_bytes=None,
        after_bytes=(0x01, 0x02),
    )
    md_text, html_text = _linkage_report_pair(tmp_path, entry)
    assert "(none - created into hole)" in md_text
    assert "(none - created into hole)" in html_text


# ---------------------------------------------------------------------------
# batch-35 Inc-2 (B-07) — report_filter kwarg on both generators: filtered
# linkage rows + run sections (LLR-054.2, D-5 filter-then-merge, F-03/Q-2),
# audit header + zero-match notice (LLR-054.3, S-F6, Q-12), filter-name
# sanitation (LLR-055.4 diff-module half), and the TC-313 no-filter guard
# (LLR-054.5 white-box half).
# ---------------------------------------------------------------------------


def _report_matcher(symbols=(), addresses=(), name="cal-filter.json"):
    """Resolved matcher via the public parse+resolve API (LLR-053.7).

    ``name`` is passed to ``resolve_report_filter(..., source_name=name)``,
    which stamps the declared ``ReportFilterMatcher.source_name`` field the
    audit header reads (batch-41 retired the earlier frozen-dataclass
    attribute bypass now that the field and the resolver param exist).
    """
    doc = json.dumps(
        {
            "format": "s19app-report-filter",
            "version": "1.0",
            "include": {
                "symbols": list(symbols),
                "addresses": [
                    {"start": start, "end": end} for start, end in addresses
                ],
            },
        }
    )
    flt, errors = parse_report_filter(doc)
    assert errors == []
    return resolve_report_filter(flt, [], [], source_name=name)


def _two_disjoint_run_fixture() -> tuple:
    """Two far-apart changed runs + one linkage entry per run.

    Run/entry 1 at 0x100 (symbol CAL_KEEP) is inside the filter window
    [0x100, 0x110); run/entry 2 at 0x900 (symbol OTHER_DROP) is not.
    Returns ``(comparison, mem_a, mem_b, entries)``.
    """
    runs = [
        DiffRun(0x100, 0x104, KIND_CHANGED),
        DiffRun(0x900, 0x904, KIND_CHANGED),
    ]
    comparison = _comparison(runs=runs, stats=_stats(2, 8))
    mem_a = _mem(0x100, 0xAA, 4) | _mem(0x900, 0xAA, 4)
    mem_b = _mem(0x100, 0xBB, 4) | _mem(0x900, 0xBB, 4)
    entries = [
        _entry(linkage_symbol="CAL_KEEP"),
        _entry(
            address_start=0x900, address_end=0x902, linkage_symbol="OTHER_DROP"
        ),
    ]
    return comparison, mem_a, mem_b, entries


def _filtered_pair(tmp_path: Path, matcher, comparison, mem_a, mem_b, entries):
    """Generate the MD + HTML pair with ``report_filter``; return both texts."""
    kwargs = dict(
        mem_map_a=mem_a,
        mem_map_b=mem_b,
        project_dir=tmp_path,
        now_fn=_fixed_clock,
        linkage_entries=entries,
        report_filter=matcher,
    )
    md = generate_diff_report(comparison, **kwargs)
    html_r = generate_diff_report_html(comparison, **kwargs)
    assert md.written and html_r.written
    return (
        md.path.read_text(encoding="utf-8"),
        html_r.path.read_text(encoding="utf-8"),
    )


def test_tc312_filter_restricts_linkage_and_run_sections_both_formats(
    tmp_path: Path,
) -> None:
    """TC-312 / LLR-054.2 (a)/(b): the matched run keeps its linkage row,
    run-table row, and window heading; the unmatched run seeds none of the
    three — in BOTH formats — while the statistics section stays complete.

    Threshold (Q-2 scope): unmatched run → 0 linkage rows, 0 window
    headings; matched run → all present; stats row still counts BOTH runs.
    """
    comparison, mem_a, mem_b, entries = _two_disjoint_run_fixture()
    matcher = _report_matcher(addresses=[(0x100, 0x110)])

    md_text, html_text = _filtered_pair(
        tmp_path, matcher, comparison, mem_a, mem_b, entries
    )

    # MD: matched linkage row + run row + window heading present.
    assert "CAL\\_KEEP" in md_text
    assert "| 0x00000100 | 0x00000104 | 4 | changed | - |" in md_text
    assert "### Run 0x00000100-0x00000104 (changed)" in md_text
    # MD: unmatched run seeds no linkage row, no run row, no window heading.
    # Both spellings (F-E3-2).
    assert "OTHER_DROP" not in md_text and "OTHER\\_DROP" not in md_text
    assert "| 0x00000900 | 0x00000904 | 4 | changed | - |" not in md_text
    assert "0x00000900-0x00000904 (changed)" not in md_text
    # Statistics stay COMPLETE (D-2): both runs still counted.
    assert "| changed | 2 | 8 |" in md_text
    # HTML twin.
    assert "CAL_KEEP" in html_text
    assert "Run 0x00000100-0x00000104 (changed)" in html_text
    assert "OTHER_DROP" not in html_text and "OTHER\\_DROP" not in html_text
    assert "0x00000900-0x00000904 (changed)" not in html_text


def test_tc312_a9_merged_window_spans_excluded_run(tmp_path: Path) -> None:
    """TC-312 / LLR-054.2 (F-03/Q-2, A9): two matched runs whose <=5-row gap
    spans an excluded run merge into ONE window; the excluded run seeds no
    heading and no linkage row, but its bytes MAY appear inside the merged
    window (assert heading/linkage absence, NOT byte absence).
    """
    runs = [
        DiffRun(0x1000, 0x1004, KIND_CHANGED),
        DiffRun(0x1020, 0x1024, KIND_CHANGED),  # excluded
        DiffRun(0x1040, 0x1044, KIND_CHANGED),
    ]
    comparison = _comparison(runs=runs, stats=_stats(3, 12))
    mem_a = {addr: 0xAA for addr in range(0x1000, 0x1050)}
    mem_b = {addr: 0xBB for addr in range(0x1000, 0x1050)}
    entries = [
        _entry(address_start=0x1000, address_end=0x1002, linkage_symbol="EDGE_A"),
        _entry(address_start=0x1020, address_end=0x1022, linkage_symbol="MID_DROP"),
        _entry(address_start=0x1040, address_end=0x1042, linkage_symbol="EDGE_B"),
    ]
    matcher = _report_matcher(addresses=[(0x1000, 0x1004), (0x1040, 0x1044)])

    kwargs = dict(
        mem_map_a=mem_a,
        mem_map_b=mem_b,
        project_dir=tmp_path,
        context_bytes=0,
        now_fn=_fixed_clock,
        linkage_entries=entries,
        report_filter=matcher,
    )
    md_text = generate_diff_report(comparison, **kwargs).path.read_text(
        encoding="utf-8"
    )

    # ONE merged window over the two matched runs (D-5 filter-then-merge:
    # window rows [0x1000,0x1010) and [0x1040,0x1050) bridge across 3 rows).
    assert md_text.count("Image A window") == 1
    assert (
        "### Runs 0x00001000-0x00001004 (changed), "
        "0x00001040-0x00001044 (changed)" in md_text
    )
    # The excluded run seeds NO heading member and NO linkage row...
    assert "0x00001020-0x00001024 (changed)" not in md_text
    assert "MID_DROP" not in md_text and "MID\\_DROP" not in md_text
    assert "EDGE\\_A" in md_text and "EDGE\\_B" in md_text
    # ...but its bytes legitimately appear inside the merged window (F-03).
    assert "0x00001020  AA AA AA AA" in md_text


def test_tc312_zero_match_notice_and_refusal_disjoint(tmp_path: Path) -> None:
    """TC-312 / LLR-054.3 (D-3, Q-12): a valid filter matching zero items
    still writes both non-empty files; each filtered section's body is the
    ``filter matched 0 of N items`` notice; the notice wording shares no
    prefix token with the refusal wording (LLR-053.5 = the read/parse
    diagnostics, report-kind-prefixed).
    """
    comparison, mem_a, mem_b, entries = _two_disjoint_run_fixture()
    matcher = _report_matcher(addresses=[(0xF000, 0xF010)], name=None)

    md_text, html_text = _filtered_pair(
        tmp_path, matcher, comparison, mem_a, mem_b, entries
    )

    notice = "filter matched 0 of 2 items"
    # Written, non-empty, notice replaces all three filtered section bodies.
    assert md_text.count(notice) == 3  # linkage + runs + hex windows
    assert notice in html_text
    for name in ("CAL_KEEP", "OTHER_DROP"):
        # Both spellings (F-E3-2): raw and Markdown-escaped.
        assert name not in md_text and name.replace("_", "\\_") not in md_text
    assert "Disposition" not in md_text  # no linkage table header row
    assert "Image A window" not in md_text  # no hex window emitted
    # Counts: shown 0, hidden == pre-filter count, per section (F-07).
    assert "- Linkage entries: shown 0 of 2 (hidden 2)" in md_text
    assert "- Runs: shown 0 of 2 (hidden 2)" in md_text
    # A matcher without a display name renders the explicit fallback.
    assert "- Filter file: (unnamed filter)" in md_text
    # Q-12: no shared prefix token with the refusal wordings.
    _, parse_refusals = parse_report_filter("{not json")
    _, read_refusals = read_report_filter_text(
        str(tmp_path / "missing-filter.json")
    )
    refusals = parse_refusals + read_refusals
    assert refusals, "refusal wordings must exist for the disjointness pin"
    for refusal in refusals:
        assert refusal.split()[0] != notice.split()[0], (
            f"zero-match notice shares its prefix token with refusal {refusal!r}"
        )


def test_tc312_audit_header_first_block_fixed_format(tmp_path: Path) -> None:
    """TC-312 / LLR-054.3 (S-F6, F-07): the audit header is the FIRST block
    after the report title, with the fixed line format — filter file name,
    per-section shown/hidden counts (shown+hidden == pre-filter count), and
    the F-03 informative note — in BOTH formats.
    """
    comparison, mem_a, mem_b, entries = _two_disjoint_run_fixture()
    matcher = _report_matcher(addresses=[(0x100, 0x110)])

    md_text, html_text = _filtered_pair(
        tmp_path, matcher, comparison, mem_a, mem_b, entries
    )

    md_lines = md_text.splitlines()
    assert md_lines[0] == "# Diff report"
    assert md_lines[1] == ""
    assert md_lines[2] == "## Report filter applied"
    assert md_lines[3] == ""
    assert md_lines[4] == "- Filter file: cal-filter\\.json"
    assert md_lines[5] == "- Linkage entries: shown 1 of 2 (hidden 1)"
    assert md_lines[6] == "- Runs: shown 1 of 2 (hidden 1)"
    assert md_lines[7] == (
        "- Note: windows seeded by matched runs may include excluded "
        "addresses as merged context."
    )
    assert md_lines[8] == ""
    assert md_lines[9].startswith("- Generated (UTC): ")

    html_lines = html_text.splitlines()
    title_index = html_lines.index("<h1>Diff report</h1>")
    assert html_lines[title_index + 1] == "<h2>Report filter applied</h2>"
    assert "<li>Filter file: cal-filter.json</li>" in html_text
    assert "<li>Linkage entries: shown 1 of 2 (hidden 1)</li>" in html_text
    assert "<li>Runs: shown 1 of 2 (hidden 1)</li>" in html_text


def test_tc318_hostile_filter_name_sanitized_md_html(tmp_path: Path) -> None:
    """TC-318 (diff-module half) / LLR-055.4: a hostile filter display name
    (pipe, backtick, ``<b>``, control bytes) renders ctl-stripped on the
    non-cell MD audit line and html-escaped in the HTML — never raw.
    """
    comparison, mem_a, mem_b, entries = _two_disjoint_run_fixture()
    hostile = "a|b`c<b>\x01\x0dd.json"
    matcher = _report_matcher(addresses=[(0x100, 0x110)], name=hostile)

    md_text, html_text = _filtered_pair(
        tmp_path, matcher, comparison, mem_a, mem_b, entries
    )

    # MD non-cell line: report-safe text (R-CMP-004.9.1) - every Markdown
    # structural character is escaped, U+0001 becomes a visible U+FFFD and CR
    # one space (visible text, R-CMP-004.15).
    assert "- Filter file: a\\|b\\`c\\<b\\>\ufffd d\\.json" in md_text
    assert "\x01" not in md_text
    # HTML: escaped, never a raw file-derived tag; the same visible text.
    assert "<li>Filter file: a|b`c&lt;b&gt;\ufffd d.json</li>" in html_text
    assert "<b>" not in html_text
    assert "\x01" not in html_text
    assert _EXTERNAL_RESOURCE_RE.search(html_text) is None


def test_tc313_no_filter_output_byte_identical_todays(tmp_path: Path) -> None:
    """TC-313 / LLR-054.5 (white-box half): ``report_filter`` omitted AND
    ``report_filter=None`` explicit both produce output byte-identical to
    today's capture (the batch-34 golden templates) — no audit header, no
    code-path drift on the unfiltered branch.
    """
    mem_a = _mem(0x100, 0xAA, 4)
    mem_b = _mem(0x100, 0xBB, 4)
    omitted = generate_diff_report(
        _comparison(), mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, now_fn=_fixed_clock,
    )
    explicit_none = generate_diff_report(
        _comparison(), mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, now_fn=_fixed_clock, report_filter=None,
    )
    html_none = generate_diff_report_html(
        _comparison(), mem_map_a=mem_a, mem_map_b=mem_b,
        project_dir=tmp_path, now_fn=_fixed_clock, report_filter=None,
    )

    expected_md = (
        _PRE_CHANGE_MD_TEMPLATE.replace("@@VERSION@@", __version__)
        .replace("\n", os.linesep)
        .encode("utf-8")
    )
    expected_html = (
        _PRE_CHANGE_HTML_TEMPLATE.replace("@@VERSION@@", __version__)
        .replace("\n", os.linesep)
        .encode("utf-8")
    )
    assert omitted.path.read_bytes() == expected_md
    assert explicit_none.path.read_bytes() == expected_md
    assert html_none.path.read_bytes() == expected_html
    assert "Report filter applied" not in omitted.path.read_text(
        encoding="utf-8"
    )


# ===========================================================================
# batch-101 Inc 7 - whole hex windows (F6-1), report-safe Markdown text
# (D14-10), visible text in the HTML file, atomic report writes, the
# before/after title (F-42). Written from the approved requirements and test
# cases only (independent tester); every expected value below is a literal
# spelled out from the requirement text, never computed by the code under
# test. Cases are named in each docstring by their requirement row.
# ===========================================================================

import builtins  # noqa: E402
import html as _html  # noqa: E402
import io  # noqa: E402

from s19_app.render.hexview import render_hex_view  # noqa: E402
from s19_app.tui.services.diff_report_service import (  # noqa: E402
    FlowChangeAttribution,
    flow_change_census_complete,
)
from s19_app.tui.services.flow_model import (  # noqa: E402
    FlowChangeRecord,
    FlowRefusal,
)
from s19_app.tui.services.markdown_safety import _normalise  # noqa: E402
from tests.test_report_markup_safety import DEFAULT, _walk  # noqa: E402

_FFFD = "�"


# ----- helpers -------------------------------------------------------------


def _oracle_row(mem: Dict[int, int], base: int) -> str:
    """One hex row spelled from the format definition (independent oracle):
    ``0x<8 hex>  <16 cells>  |<16 ascii>|``; unmapped cell = two spaces and
    a ``.`` in the ASCII column."""
    cells = []
    ascii_cells = []
    for address in range(base, base + 16):
        value = mem.get(address)
        cells.append("  " if value is None else f"{value:02X}")
        ascii_cells.append(
            chr(value) if value is not None and 0x20 <= value <= 0x7E else "."
        )
    return f"0x{base:08X}  {' '.join(cells)}  |{''.join(ascii_cells)}|"


def _oracle_rows(mem: Dict[int, int], low: int, high: int) -> List[str]:
    return [_oracle_row(mem, base) for base in range(low, high, 16)]


def _md_fences(text: str) -> List[tuple]:
    """``(opening fence line, inner lines)`` per fenced block, in order."""
    blocks: List[tuple] = []
    current = None
    for line in text.splitlines():
        if current is None:
            if line.startswith("```") and line != "```":
                current = (line, [])
        elif line == "```":
            blocks.append(current)
            current = None
        else:
            current[1].append(line)
    return blocks


def _rows_with_prefix(lines: List[str], prefix: str = "") -> List[str]:
    return [ln[len(prefix):] for ln in lines if ln.startswith(prefix + "0x")]


def _cap_lines(text: str) -> List[str]:
    return [
        ln
        for ln in text.splitlines()
        if "window limited to" in ln or "output truncated at" in ln
    ]


def _html_pre_blocks(text: str) -> List[List[str]]:
    """Each ``<pre>`` body as its list of rows, tags dropped and entities
    decoded (the visible text of the pane)."""
    out = []
    for body in re.findall(r"<pre[^>]*>(.*?)</pre>", text, re.S):
        out.append(
            [
                _html.unescape(re.sub(r"<[^>]+>", "", line))
                for line in body.split("\n")
            ]
        )
    return out


def _whole_pair(tmp_path: Path, comparison, mem_a, mem_b, **extra) -> tuple:
    kwargs = dict(
        mem_map_a=mem_a,
        mem_map_b=mem_b,
        project_dir=tmp_path,
        now_fn=_fixed_clock,
        **extra,
    )
    md = generate_diff_report(comparison, **kwargs)
    html_r = generate_diff_report_html(comparison, **kwargs)
    assert md.written and html_r.written
    return (
        md.path.read_text(encoding="utf-8"),
        html_r.path.read_text(encoding="utf-8"),
    )


def _long_changed_fixture() -> tuple:
    """One changed run of 10,240 bytes, both images map exactly the run."""
    mem_a = _mem(0x1000, 0xAA, 0x2800)
    mem_b = _mem(0x1000, 0xBB, 0x2800)
    comparison = _comparison(
        runs=[DiffRun(0x1000, 0x3800, KIND_CHANGED)],
        stats=_stats(1, 0x2800),
    )
    return comparison, mem_a, mem_b


def _only_b_fixture() -> tuple:
    """A maps 0x0..0xF; B maps the same 16 bytes plus one only-B run of
    69,632 bytes (0x10000..0x20FFF, byte 0x3C = ``<``)."""
    head = _mem(0x0, 0x11, 16)
    mem_a = dict(head)
    mem_b = dict(head) | _mem(0x10000, 0x3C, 0x11000)
    comparison = _comparison(
        runs=[DiffRun(0x10000, 0x21000, KIND_ONLY_B)],
        stats=DiffStats(
            run_counts={"changed": 0, "only_a": 0, "only_b": 1},
            byte_counts={"changed": 0, "only_a": 0, "only_b": 0x11000},
        ),
    )
    return comparison, mem_a, mem_b


# ----- R-CMP-004.14: every row of every hex window --------------------------


def test_r_cmp_004_14_1_markdown_changed_run_whole(tmp_path: Path) -> None:
    """A 10,240-byte changed run: 644 rows in each of the 4 Markdown blocks
    (diff ``-``, diff ``+``, A, B), first row 0x00000FC0, last 0x000037F0,
    0 cap lines. Fails when the 512-row cap is in force."""
    comparison, mem_a, mem_b = _long_changed_fixture()
    md_text, _ = _whole_pair(tmp_path, comparison, mem_a, mem_b)

    blocks = _md_fences(md_text)
    assert [opener for opener, _ in blocks] == ["```diff", "```text", "```text"]
    diff_lines, a_lines, b_lines = (inner for _, inner in blocks)
    expected_a = _oracle_rows(mem_a, 0xFC0, 0x3800)
    expected_b = _oracle_rows(mem_b, 0xFC0, 0x3800)
    assert len(expected_a) == 644
    assert _rows_with_prefix(diff_lines, "-") == expected_a
    assert _rows_with_prefix(diff_lines, "+") == expected_b
    assert a_lines == expected_a
    assert b_lines == expected_b
    assert expected_a[0].startswith("0x00000FC0  ")
    assert expected_a[-1].startswith("0x000037F0  ")
    assert _cap_lines(md_text) == []


def test_r_cmp_004_14_2_html_and_markdown_agree(tmp_path: Path) -> None:
    """The HTML side-by-side panes of the same run hold 644 rows each, the
    same addresses as the Markdown A and B blocks, and no cap line."""
    comparison, mem_a, mem_b = _long_changed_fixture()
    md_text, html_text = _whole_pair(tmp_path, comparison, mem_a, mem_b)

    panes = _html_pre_blocks(html_text)
    assert len(panes) == 2
    blocks = _md_fences(md_text)
    md_a, md_b = blocks[1][1], blocks[2][1]
    for pane, md_rows in zip(panes, (md_a, md_b)):
        assert len(pane) == 644
        # E5 C-6: the address and all 16 byte cells are equal, row for row
        # (the ASCII column differs by design: an unmapped byte is a space in
        # the HTML pane, F-E3-5).
        assert [row[:58] for row in pane] == [row[:58] for row in md_rows]
        assert [row.split("  |")[0] for row in pane] == [
            row.split("  |")[0] for row in md_rows
        ]
    assert _cap_lines(html_text) == []


def test_r_cmp_004_14_3_markdown_window_over_64_kib(tmp_path: Path) -> None:
    """A window holding 69,632 mapped bytes: the Markdown B block has all
    4,356 rows (0x0000FFC0 .. 0x00020FF0), there is no A block, and neither
    cap line appears (the screen's 65,536-byte cap must not reach the file)."""
    comparison, mem_a, mem_b = _only_b_fixture()
    md_text, _ = _whole_pair(tmp_path, comparison, mem_a, mem_b)

    blocks = _md_fences(md_text)
    assert [opener for opener, _ in blocks] == ["```text"]
    rows = blocks[0][1]
    assert len(rows) == 4356
    assert rows[0].startswith("0x0000FFC0  ")
    assert rows[-1].startswith("0x00020FF0  ")
    assert rows == _oracle_rows(mem_b, 0xFFC0, 0x21000)
    assert "output truncated at 65536 bytes" not in md_text
    assert _cap_lines(md_text) == []


def test_r_cmp_004_14_4_html_window_over_64_kib(tmp_path: Path) -> None:
    """The HTML only-B window of the same run: the B ``<pre>`` holds 4,356
    rows and no cap line is written."""
    comparison, mem_a, mem_b = _only_b_fixture()
    _, html_text = _whole_pair(tmp_path, comparison, mem_a, mem_b)

    panes = _html_pre_blocks(html_text)
    assert len(panes) == 1
    assert len(panes[0]) == 4356
    assert panes[0] == _oracle_rows(mem_b, 0xFFC0, 0x21000)
    assert _cap_lines(html_text) == []


def test_r_cmp_004_14_7_rows_match_render_hex_view_for_all_byte_values(
    tmp_path: Path,
) -> None:
    """The row format, byte value by byte value: image A holds 0x00..0xFF in
    order at 0x100. The A block equals the screen's own renderer row for row
    (the independent differential oracle) and three spelled-out rows pin the
    ASCII column at the printable boundaries (0x20, 0x7E, 0x7F)."""
    mem_a = {0x100 + value: value for value in range(256)}
    mem_b = {0x100 + value: value ^ 0xFF for value in range(256)}
    comparison = _comparison(
        runs=[DiffRun(0x100, 0x200, KIND_CHANGED)], stats=_stats(1, 256)
    )
    md_text, _ = _whole_pair(tmp_path, comparison, mem_a, mem_b)

    blocks = _md_fences(md_text)
    a_rows = blocks[1][1]
    window = list(range(0xC0, 0x200, 16))
    assert len(window) == 20
    assert a_rows == render_hex_view(
        mem_a, row_bases=window, max_rows=512
    ).splitlines()
    assert a_rows == _oracle_rows(mem_a, 0xC0, 0x200)
    by_address = {row[:10]: row for row in a_rows}
    assert by_address["0x00000120"] == (
        "0x00000120  20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F  "
        "| !\"#$%&'()*+,-./|"
    )
    assert by_address["0x00000170"] == (
        "0x00000170  70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F  "
        "|pqrstuvwxyz{|}~.|"
    )
    assert by_address["0x00000180"].endswith("|................|")
    assert by_address["0x00000100"].endswith("|................|")


# ----- R-CMP-005.16 / .17: atomic report writes -----------------------------


def _inject_half_write(monkeypatch, needle: str) -> list:
    """Every write-mode open of a file whose NAME contains ``needle`` writes
    half of its first payload, flushes, then raises ``OSError`` (a disk that
    fills up mid-write). Patches both ``builtins.open`` and ``io.open`` (the
    entry ``pathlib`` uses). Returns the list of intercepted names, so a test
    can prove the injection was reached."""
    real_open = io.open
    hit: list = []

    class _Half:
        def __init__(self, handle):
            self._handle = handle

        def write(self, data):
            self._handle.write(data[: len(data) // 2])
            self._handle.flush()
            raise OSError("disk full")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._handle.close()
            return False

        def close(self):
            self._handle.close()

        def __getattr__(self, name):
            return getattr(self._handle, name)

    def _open(file, mode="r", *args, **kwargs):
        handle = real_open(file, mode, *args, **kwargs)
        name = os.path.basename(os.fspath(file)) if not isinstance(file, int) else ""
        if needle in name and any(flag in mode for flag in "wxa"):
            hit.append(name)
            return _Half(handle)
        return handle

    monkeypatch.setattr(builtins, "open", _open)
    monkeypatch.setattr(io, "open", _open)
    return hit


def _folder_names(folder: Path) -> List[str]:
    return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


def test_r_cmp_005_16_1_failed_markdown_write_leaves_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disk that fails after half the text: the Markdown generator raises
    and ``reports/`` holds no ``-diff-report.md`` and no ``.part`` file."""
    comparison, mem_a, mem_b = _long_changed_fixture()
    hit = _inject_half_write(monkeypatch, "-diff-report.md")

    with pytest.raises(OSError, match="disk full"):
        generate_diff_report(
            comparison, mem_map_a=mem_a, mem_map_b=mem_b,
            project_dir=tmp_path, now_fn=_fixed_clock,
        )

    assert hit, "the injected failure was never reached (write path changed)"
    assert _folder_names(tmp_path / "reports") == []


def test_r_cmp_005_16_2_failed_html_write_leaves_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same for the HTML generator: 0 ``-diff-report.html``, 0 ``.part``."""
    comparison, mem_a, mem_b = _long_changed_fixture()
    hit = _inject_half_write(monkeypatch, "-diff-report.html")

    with pytest.raises(OSError, match="disk full"):
        generate_diff_report_html(
            comparison, mem_map_a=mem_a, mem_map_b=mem_b,
            project_dir=tmp_path, now_fn=_fixed_clock,
        )

    assert hit, "the injected failure was never reached (write path changed)"
    assert _folder_names(tmp_path / "reports") == []


def test_r_cmp_005_16_3_stale_part_file_is_not_touched(tmp_path: Path) -> None:
    """A ``.part`` file left by another writer is never overwritten or
    removed: it keeps its bytes (E3 round 2, N-1). Since E5 C-1 the staging
    name is ``<name>.<random>.part``, so a stale file at the old guessable
    ``<name>.part`` no longer collides: the report is written whole under its
    own name beside it, and no other file is left."""
    reports = tmp_path / "reports"
    reports.mkdir()
    planted = reports / "20260611T120000Z-diff-report.md.part"
    planted.write_bytes(b"ANOTHER WRITER")

    result = generate_diff_report(
        _comparison(), mem_map_a=_mem(0x100, 1, 4), mem_map_b=_mem(0x100, 2, 4),
        project_dir=tmp_path, now_fn=_fixed_clock,
    )

    assert result.written and result.path == reports / "20260611T120000Z-diff-report.md"
    assert result.path.read_text(encoding="utf-8").startswith("# Diff report\n")
    assert planted.read_bytes() == b"ANOTHER WRITER"
    assert _folder_names(reports) == [result.path.name, planted.name]


def test_r_cmp_005_16_5_planted_link_at_part_name_is_not_followed(
    tmp_path: Path,
) -> None:
    """A dangling link planted at the guessable staging name ``<name>.part``
    is never followed (E5 C-1, security finding S5-1): the file it points to
    is not created, the link is left as it was, and the report is written
    whole under its own name as a regular file. Base (fixed name, exclusive
    create): on Windows ``CreateFile(CREATE_NEW)`` follows the link, writes
    the report into its target and moves the link onto the report's name."""
    reports = tmp_path / "reports"
    reports.mkdir()
    name = "20260611T120000Z-diff-report.md"
    elsewhere = tmp_path / "elsewhere.txt"
    link = reports / (name + ".part")
    try:
        os.symlink(elsewhere, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symbolic links cannot be created on this host: {exc}")

    result = generate_diff_report(
        _comparison(), mem_map_a=_mem(0x100, 1, 4), mem_map_b=_mem(0x100, 2, 4),
        project_dir=tmp_path, now_fn=_fixed_clock,
    )

    assert not os.path.lexists(elsewhere), "the planted link was followed"
    # Windows reports the link target with its ``\\?\`` long-path prefix.
    target = os.readlink(link).removeprefix("\\\\?\\")
    assert link.is_symlink() and Path(target) == elsewhere
    assert result.written and result.path == reports / name
    assert result.path.is_file() and not result.path.is_symlink()
    assert result.path.read_text(encoding="utf-8").startswith("# Diff report\n")
    assert _folder_names(reports) == [name, link.name]


def test_r_cmp_005_16_4_stale_part_file_survives_failed_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failure arm of "a stale ``.part`` file is never touched" (E5
    re-audit RA-2): a file at the pre-C-1 name ``<name>.part`` keeps its
    bytes when the write of the report fails half way, and the only file the
    failed run leaves behind is that stale one."""
    reports = tmp_path / "reports"
    reports.mkdir()
    planted = reports / "20260611T120000Z-diff-report.md.part"
    planted.write_bytes(b"ANOTHER WRITER")
    hit = _inject_half_write(monkeypatch, "-diff-report.md")

    with pytest.raises(OSError, match="disk full"):
        generate_diff_report(
            _comparison(), mem_map_a=_mem(0x100, 1, 4), mem_map_b=_mem(0x100, 2, 4),
            project_dir=tmp_path, now_fn=_fixed_clock,
        )

    assert hit, "the injected failure was never reached (write path changed)"
    assert planted.read_bytes() == b"ANOTHER WRITER"
    assert _folder_names(reports) == [planted.name]


def test_r_cmp_005_16_6_staging_name_is_random_per_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The staging file is created exclusively under
    ``<final name>.<16 lowercase hex>.part`` and the 16 digits differ between
    two writes of the same report (E5 re-audit RA-1): a fixed or guessable
    staging name would let a planted link be followed (S5-1)."""
    created: list = []
    real_open = builtins.open

    def _spy(file, mode="r", *args, **kwargs):
        if "x" in mode:
            created.append(os.path.basename(os.fspath(file)))
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _spy)
    name = "20260611T120000Z-diff-report.md"
    for run in range(2):
        generate_diff_report(
            _comparison(), mem_map_a=_mem(0x100, 1, 4), mem_map_b=_mem(0x100, 2, 4),
            project_dir=tmp_path / str(run), now_fn=_fixed_clock,
        )

    pattern = re.compile(re.escape(name) + r"\.[0-9a-f]{16}\.part")
    assert len(created) == 2, created
    assert all(pattern.fullmatch(n) for n in created), created
    assert created[0] != created[1], "the staging name repeats between writes"


def test_r_cmp_005_17_1_ab_html_failure_removes_markdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Manual A<->B report, project open, the HTML generator raising after the
    real Markdown generator wrote its file: the status keeps its text
    ``Diff report failed: RuntimeError: x`` and ``reports/`` holds no ``.md``
    and no ``.html`` (the orphan Markdown file is removed)."""
    import asyncio

    import s19_app.tui.app as app_mod
    from s19_app.tui.app import S19TuiApp
    from tests.support.timing import wait_until
    from tests.test_tui_diff_screen import _b78_press_compare, _diff_result

    fake = _diff_result([(0x10, 0x14, "changed")])

    def _raising(*_a, **_k):
        raise RuntimeError("x")

    monkeypatch.setattr(app_mod, "compare_images", lambda *a, **k: fake)
    monkeypatch.setattr(app_mod, "generate_diff_report_html", _raising)
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            project_dir.mkdir(parents=True, exist_ok=True)
            app.current_project = "proj"
            app.action_show_screen("diff")
            await pilot.pause()
            await _b78_press_compare(app, pilot)
            app.query_one("#diff_report_button").press()
            await wait_until(
                pilot,
                lambda: "Diff report failed"
                in str(app.query_one("#diff_status").render()),
                "the failure status never reached the diff panel",
            )
            await app.workers.wait_for_complete()
            return str(app.query_one("#diff_status").render())

    status = asyncio.run(_drive())

    assert "Diff report failed: RuntimeError: x" in status
    # E5 C-7: the Markdown file was written into this folder and then
    # removed, so the folder exists; were it absent, the emptiness check
    # below would pass without testing anything.
    assert (project_dir / "reports").is_dir()
    assert _folder_names(project_dir / "reports") == []


@pytest.mark.parametrize("failing", ["-diff-report.md", "-diff-report.html"])
def test_r_cmp_005_16_3_report_control_failed_write_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    """Black-box through keys (E5 C-3 / C-4 R-2): key ``7`` opens the A2B
    Diff screen, Compare and Report are pressed with ``enter``, and the
    Markdown (then, second arm, the HTML) file's write fails half way. The
    diff panel paints exactly ``Diff report failed: OSError: disk full``,
    the status log holds the same line, and ``reports/`` holds no report
    and no ``.part`` file (R-CMP-005.16 status clause, R-CMP-005.10)."""
    import asyncio

    from textual.widgets import Input

    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.changes import emit_s19_from_mem_map
    from tests.support.timing import wait_until

    image_a = tmp_path / "a.s19"
    image_b = tmp_path / "b.s19"
    image_a.write_text(
        emit_s19_from_mem_map(_mem(0x100, 0x00, 16), [(0x100, 0x110)]),
        encoding="ascii",
    )
    image_b.write_text(
        emit_s19_from_mem_map(
            _mem(0x100, 0x00, 16) | {0x100: 0xAA, 0x101: 0xBB}, [(0x100, 0x110)]
        ),
        encoding="ascii",
    )
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    hit = _inject_half_write(monkeypatch, failing)

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            project_dir.mkdir(parents=True, exist_ok=True)
            app.current_project = "proj"
            app.set_focus(None)
            await pilot.press("7")
            await pilot.pause()
            app.query_one("#diff_path_a", Input).value = str(image_a)
            app.query_one("#diff_path_b", Input).value = str(image_b)
            generation = app._diff_compare_generation
            app.query_one("#diff_compare_button").focus()
            await pilot.press("enter")
            await wait_until(
                pilot,
                lambda: app._diff_compare_generation > generation,
                "the compare handler never completed",
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app._diff_last_result is not None, "the compare refused"
            app.query_one("#diff_report_button").focus()
            await pilot.press("enter")
            await wait_until(
                pilot,
                lambda: "Diff report failed"
                in str(app.query_one("#diff_status").render()),
                "the failure status never reached the diff panel",
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            painted = [
                str(app.query_one(f"#log_line_{index}").render())
                for index in range(1, 5)
            ]
            return str(app.query_one("#diff_status").render()), painted

    status, painted = asyncio.run(_drive())

    expected = "Diff report failed: OSError: disk full"
    assert hit, "the injected failure was never reached (write path changed)"
    assert status == expected
    assert expected in painted, painted
    assert (project_dir / "reports").is_dir()
    assert _folder_names(project_dir / "reports") == []


# ----- title of a diff report (guards for the before/after title) -----------


def test_r_cmp_004_1_1_diff_report_keeps_its_title(tmp_path: Path) -> None:
    """A diff report without provenance: Markdown line 1 ``# Diff report``,
    ``<title>Diff report</title>`` and ``<h1>Diff report</h1>``."""
    md_text, html_text = _whole_pair(
        tmp_path, _comparison(), _mem(0x100, 0xAA, 4), _mem(0x100, 0xBB, 4)
    )
    assert md_text.splitlines()[0] == "# Diff report"
    assert html_text.count("<title>Diff report</title>") == 1
    assert html_text.count("<h1>Diff report</h1>") == 1
    assert "Before/after report" not in md_text
    assert "Before/after report" not in html_text


def test_r_cmp_004_1_2_title_follows_provenance_only(tmp_path: Path) -> None:
    """Linkage entries without provenance do not switch the title."""
    md_text, html_text = _whole_pair(
        tmp_path, _comparison(), _mem(0x100, 0xAA, 4), _mem(0x100, 0xBB, 4),
        linkage_entries=[_entry()], provenance=None,
    )
    assert md_text.splitlines()[0] == "# Diff report"
    assert "<title>Diff report</title>" in html_text
    assert "<h1>Diff report</h1>" in html_text


# ----- R-CMP-004.5: a symbol is named by the address it holds ----------------


def test_r_cmp_004_5_1_symbol_by_address_not_extent(tmp_path: Path) -> None:
    """A tag whose extent covers the run but whose address lies outside it
    leaves the Symbols cell ``-``; the tag whose address is in the run names
    it."""
    comparison = _comparison(
        runs=[DiffRun(0x100, 0x102, KIND_CHANGED)], stats=_stats(1, 2)
    )
    wide = [{"name": "WIDE", "address": 0xF0, "length": 0x40, "byte_size": 0x40}]
    here = [{"name": "HERE", "address": 0x100, "length": 1, "byte_size": 1}]
    first, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 2), _mem(0x100, 2, 2),
        a2l_records=wide,
    )
    second, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 2), _mem(0x100, 2, 2),
        a2l_records=here,
    )
    assert "| 0x00000100 | 0x00000102 | 2 | changed | - |" in first
    assert "WIDE" not in first
    assert "| 0x00000100 | 0x00000102 | 2 | changed | HERE |" in second


# ----- R-CMP-004.9.1: label fields are report-safe text ----------------------


def _label_report(tmp_path: Path, **overrides) -> str:
    comparison = _comparison(**overrides.pop("comparison", {}))
    md_text, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4), **overrides
    )
    return md_text


def test_r_cmp_004_9_1_1_image_label_and_variant_report_safe(
    tmp_path: Path,
) -> None:
    """A hostile image label and a hostile variant id are escaped character
    by character in the header's image lines."""
    image_a = ImageRef(
        label="A*b_[x].s19", path="/tmp/a.s19", source_kind="external"
    )
    image_b = ImageRef(
        label="B.s19", path="/tmp/b.s19", source_kind="project-variant",
        variant_id="v_1<b>",
    )
    text = _label_report(
        tmp_path, comparison={"image_a": image_a, "image_b": image_b}
    )
    assert (
        "- Image A: A\\*b\\_\\[x\\]\\.s19 [external] path=`/tmp/a.s19` "
        "parse-errors=0"
    ) in text
    assert (
        "- Image B: B\\.s19 [project-variant variant=v\\_1\\<b\\>] "
        "path=`/tmp/b.s19` parse-errors=0"
    ) in text
    assert "A*b_[x]" not in text and "v_1<b>" not in text


def test_r_cmp_004_9_1_3_runs_symbols_name_by_name(tmp_path: Path) -> None:
    """The Runs Symbols cell escapes each name on its own: ``A_B`` and
    ``x|y`` give ``A\\_B, x\\|y`` and the row keeps its 5 cells."""
    comparison = _comparison(
        runs=[DiffRun(0x100, 0x104, KIND_CHANGED)], stats=_stats(1, 4)
    )
    text, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4),
        mac_records=[
            {"name": "A_B", "address": 0x100},
            {"name": "x|y", "address": 0x101},
        ],
    )
    row = next(ln for ln in text.splitlines() if ln.startswith("| 0x00000100 |"))
    assert row == "| 0x00000100 | 0x00000104 | 4 | changed | A\\_B, x\\|y |"
    assert len(re.split(r"(?<!\\)\|", row.strip("|"))) == 5
    assert "A_B" not in text


def _flow_fixture() -> tuple:
    record = FlowChangeRecord(
        block_index=1,
        change_doc_ref="patches/c_1.json",
        a2l_ref=None,
        entry_type="bytes",
        symbol="S*1",
        address_start=0x1000,
        address_end=0x1002,
        disposition="applied",
        before_bytes=(0x00, 0x00),
        after_bytes=(0xAA, 0xBB),
    )
    refusal = FlowRefusal(
        block_index=1,
        change_doc_ref="patches/c_1.json",
        a2l_ref=None,
        code="CHG-X",
        symbol="S*1",
        address=0x1000,
        message="m",
    )
    comparison = _comparison(
        runs=[DiffRun(0x1000, 0x1002, KIND_CHANGED)], stats=_stats(1, 2)
    )
    mem_a = _mem(0x1000, 0x00, 2)
    mem_b = _mem(0x1000, 0xAA, 2)
    return record, refusal, comparison, mem_a, mem_b


def test_r_cmp_004_9_1_5_flow_attribution_report_safe(tmp_path: Path) -> None:
    """Flow change attribution: the change-document reference and the symbol
    are report-safe text in the table row and in the refusal bullet, and the
    census predicate holds on the complete section and fails with a row
    dropped."""
    record, refusal, comparison, mem_a, mem_b = _flow_fixture()
    full = FlowChangeAttribution(records=(record,), refusals=(refusal,))
    text, _ = _whole_pair(
        tmp_path, comparison, mem_a, mem_b, flow_changes=full
    )

    section = text.split("## Flow change attribution")[1].split("\n## ")[0]
    lines = section.splitlines()
    row = next(ln for ln in lines if ln.startswith("| patches"))
    assert "| patches\\/c\\_1\\.json | S\\*1 | 0x00001000 |" in row
    assert (
        "- refused: patches\\/c\\_1\\.json symbol 'S\\*1' @ 0x00001000 "
        "[CHG-X] m"
    ) in lines
    assert "patches/c_1.json" not in section and "S*1" not in section
    assert flow_change_census_complete(full, lines) is True

    dropped = FlowChangeAttribution(records=(), refusals=(refusal,))
    text_dropped, _ = _whole_pair(
        tmp_path, comparison, mem_a, mem_b, flow_changes=dropped
    )
    lines_dropped = (
        text_dropped.split("## Flow change attribution")[1]
        .split("\n## ")[0]
        .splitlines()
    )
    assert flow_change_census_complete(full, lines_dropped) is False


def test_r_cmp_004_9_1_6_filter_file_name_report_safe(tmp_path: Path) -> None:
    """A filter file name with a pipe, a backtick and markup is escaped on
    the audit line."""
    comparison, mem_a, mem_b, entries = _two_disjoint_run_fixture()
    matcher = _report_matcher(
        addresses=[(0x100, 0x110)], name="a|b`c<b>d.json"
    )
    md_text, _ = _filtered_pair(
        tmp_path, matcher, comparison, mem_a, mem_b, entries
    )
    assert "- Filter file: a\\|b\\`c\\<b\\>d\\.json" in md_text.splitlines()


def test_r_cmp_004_9_1_7_symbol_cut_to_512_characters(tmp_path: Path) -> None:
    """A 600-character symbol name is cut at the 512-character field limit
    and marked."""
    comparison = _comparison(
        runs=[DiffRun(0x100, 0x104, KIND_CHANGED)], stats=_stats(1, 4)
    )
    text, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4),
        mac_records=[{"name": "A" * 600, "address": 0x100}],
    )
    row = next(ln for ln in text.splitlines() if ln.startswith("| 0x00000100 |"))
    assert row == (
        "| 0x00000100 | 0x00000104 | 4 | changed | "
        + "A" * 512 + "… (truncated) |"
    )


def test_r_cmp_004_9_1_10_refusal_message_report_safe(tmp_path: Path) -> None:
    """A refusal message that repeats a hostile symbol is report-safe text:
    the bullet is the exact escaped line, a CommonMark reader finds no
    ``html_inline``, ``link_open`` or ``image`` token in it, and a
    600-character message is cut to 500 characters plus the marker."""
    hostile = "<img src=https://h/p>[x](http://b)"
    refusal = FlowRefusal(
        block_index=1, change_doc_ref="c.json", a2l_ref=None,
        code="CHG-SYMBOL-UNRESOLVED", symbol=hostile, address=None,
        message=f"the symbol '{hostile}' is not declared",
    )
    comparison, mem_a, mem_b = _long_changed_fixture()
    text, _ = _whole_pair(
        tmp_path, comparison, mem_a, mem_b,
        flow_changes=FlowChangeAttribution(records=(), refusals=(refusal,)),
    )
    bullet = next(ln for ln in text.splitlines() if ln.startswith("- refused:"))
    escaped = "\\<img src=https:\\/\\/h\\/p\\>\\[x\\](http:\\/\\/b)"
    assert bullet == (
        f"- refused: c\\.json symbol '{escaped}' [CHG-SYMBOL-UNRESOLVED] "
        f"the symbol '{escaped}' is not declared"
    )
    live = {t.type for t in _walk(DEFAULT.parse(bullet))}
    assert not live & {"html_inline", "html_block", "link_open", "image"}

    long_refusal = FlowRefusal(
        block_index=1, change_doc_ref="c.json", a2l_ref=None, code="CHG-X",
        symbol=None, address=None, message="q" * 600,
    )
    text_long, _ = _whole_pair(
        tmp_path, comparison, mem_a, mem_b,
        flow_changes=FlowChangeAttribution(
            records=(), refusals=(long_refusal,)
        ),
    )
    long_bullet = next(
        ln for ln in text_long.splitlines() if ln.startswith("- refused:")
    )
    assert long_bullet.endswith("[CHG-X] " + "q" * 500 + "… (truncated)")
    assert long_bullet.count("q") == 500


_HOSTILE = (
    "<img src=https://h/p>[x](http://b) www.h.com ops@h.com &vert;   "
    "1) - end"
)
_HOSTILE_PATH = "P<img src=h>[x](h)www.h.com&vert;"
_BAD_TOKENS = {"html_inline", "html_block", "link_open", "image"}


def _unescaped_pipe_counts_per_table(md_text: str) -> List[set]:
    tables: List[set] = []
    block: List[str] = []
    for line in md_text.splitlines() + [""]:
        if line.startswith("|"):
            block.append(line)
        elif block:
            tables.append({len(re.findall(r"(?<!\\)\|", row)) for row in block})
            block = []
    return tables


def test_r_cmp_004_9_1_11_diff_report_sinks_inert_under_a_reader(
    tmp_path: Path,
) -> None:
    """One hostile payload planted in every label, path, symbol and message
    field of a diff report that carries linkage, provenance, flow
    attribution and a filter: a CommonMark reader (links and HTML on) finds
    0 ``html_inline``, ``html_block``, ``link_open`` and ``image`` tokens and
    every table keeps one column count. The control: the same payload
    written raw IS flagged by that reader, so the check can fail."""
    assert {t.type for t in _walk(DEFAULT.parse("- Image A: " + _HOSTILE))} & _BAD_TOKENS

    record = FlowChangeRecord(
        block_index=1, change_doc_ref=_HOSTILE, a2l_ref=None,
        entry_type="bytes", symbol=_HOSTILE, address_start=0x100,
        address_end=0x102, disposition="applied", before_bytes=(1, 1),
        after_bytes=(2, 2),
    )
    refusal = FlowRefusal(
        block_index=1, change_doc_ref=_HOSTILE, a2l_ref=None, code="CHG-X",
        symbol=_HOSTILE, address=0x100, message=_HOSTILE,
    )
    comparison = _comparison(
        runs=[DiffRun(0x100, 0x104, KIND_CHANGED)], stats=_stats(1, 4),
        image_a=ImageRef(
            label=_HOSTILE, path=_HOSTILE_PATH, source_kind="project-variant",
            variant_id=_HOSTILE,
        ),
        image_b=ImageRef(label=_HOSTILE, path=_HOSTILE_PATH, source_kind="external"),
    )
    provenance = BeforeAfterProvenance(
        original_path=Path(_HOSTILE_PATH),
        saved_path=Path(_HOSTILE_PATH),
        applied_at_utc="2026-07-02T09:00:00+00:00",
        change_doc_path=Path(_HOSTILE_PATH),
    )
    matcher = _report_matcher(addresses=[(0x100, 0x110)], name=_HOSTILE)
    md_text, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4),
        provenance=provenance,
        linkage_entries=[_entry(linkage_symbol=_HOSTILE)],
        mac_records=[{"name": _HOSTILE, "address": 0x100}],
        flow_changes=FlowChangeAttribution(records=(record,), refusals=(refusal,)),
        report_filter=matcher,
    )

    live = {t.type for t in _walk(DEFAULT.parse(md_text))}
    assert not live & _BAD_TOKENS, sorted(live & _BAD_TOKENS)
    tables = _unescaped_pipe_counts_per_table(md_text)
    assert tables, "the document holds no table: the check would be vacuous"
    assert all(len(counts) == 1 for counts in tables), tables
    # the payload reached the file at all (the sinks are not simply dropped):
    assert "img src" in md_text


def test_r_cmp_004_9_1_12_c1_and_bidi_visible_in_markdown(
    tmp_path: Path,
) -> None:
    """U+0085 in an image label and U+202E in a Runs symbol become U+FFFD in
    place; neither raw character reaches the file."""
    comparison = _comparison(
        runs=[DiffRun(0x100, 0x104, KIND_CHANGED)], stats=_stats(1, 4),
        image_a=ImageRef(
            label="a\x85b", path="/tmp/a.s19", source_kind="external"
        ),
    )
    text, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4),
        mac_records=[{"name": "S‮T", "address": 0x100}],
    )
    assert f"- Image A: a{_FFFD}b [external] path=`/tmp/a.s19`" in text
    assert f"| changed | S{_FFFD}T |" in text
    assert "\x85" not in text and "‮" not in text


# ----- R-CMP-004.9.2: path fields are path text ------------------------------


def test_r_cmp_004_9_2_1_image_path_text(tmp_path: Path) -> None:
    """A backtick in an image path becomes U+FFFD and the code span closes
    once: the line holds exactly 2 backticks."""
    comparison = _comparison(
        image_a=ImageRef(label="A.s19", path="a`b.s19", source_kind="external")
    )
    text, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4)
    )
    line = next(ln for ln in text.splitlines() if ln.startswith("- Image A:"))
    assert f"path=`a{_FFFD}b.s19`" in line
    assert line.count("`") == 2


def test_r_cmp_004_9_2_2_provenance_path_text(tmp_path: Path) -> None:
    """Backticks in the original, saved and change-document paths: U+FFFD in
    place, 2 backticks on each of the 3 lines."""
    provenance = BeforeAfterProvenance(
        original_path=Path("o`1.s19"),
        saved_path=Path("s`1.s19"),
        applied_at_utc="2026-07-02T09:00:00+00:00",
        change_doc_path=Path("c`1.json"),
    )
    text, _ = _whole_pair(
        tmp_path, _comparison(), _mem(0x100, 1, 4), _mem(0x100, 2, 4),
        provenance=provenance,
    )
    lines = text.splitlines()
    expected = [
        f"- Original image (before): `o{_FFFD}1.s19`",
        f"- Saved patched image (after): `s{_FFFD}1.s19`",
        f"- Change document: `c{_FFFD}1.json`",
    ]
    for line in expected:
        assert line in lines
        assert line.count("`") == 2


def test_r_cmp_004_9_2_4_path_keeps_its_characters(tmp_path: Path) -> None:
    """A path is path text, not report-safe text: the header line holds the
    path exactly as ``str(path)``, underscores and dots unescaped."""
    name = "my_img.s19" if os.name == "nt" else "my_img*.s19"
    path = tmp_path / name
    comparison = _comparison(
        image_a=ImageRef(label="x", path=str(path), source_kind="external")
    )
    text, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4)
    )
    assert f"path=`{path}`" in text
    assert "my\\_img" not in text


def test_r_cmp_004_9_2_5_image_b_path_text(tmp_path: Path) -> None:
    """Image B's path is path text too (the threshold's 4/4 fields name both
    image paths; E5 C-3): a backtick becomes U+FFFD and the line holds
    exactly 2 backticks, while image A's ordinary path is unchanged."""
    comparison = _comparison(
        image_b=ImageRef(label="B.s19", path="c`d.s19", source_kind="external")
    )
    text, _ = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4)
    )
    lines = text.splitlines()
    line_b = next(ln for ln in lines if ln.startswith("- Image B:"))
    assert line_b == (
        f"- Image B: B\\.s19 [external] path=`c{_FFFD}d.s19` parse-errors=0"
    )
    assert line_b.count("`") == 2
    assert "- Image A: A\\.s19 [external] path=`/tmp/a.s19` parse-errors=0" in lines


# ----- R-BEFORE-AFTER-REPORT-001.22: a pipe in a system-vocabulary cell -------


def test_r_before_after_report_001_22_2_pipe_in_vocabulary_cells_stays_escaped(
    tmp_path: Path,
) -> None:
    """Every field written by ``_md_cell`` keeps a planted ``|`` inside its
    cell (E5 C-2; the M22 survivor): linkage Type, Disposition and Linkage,
    the flow record's disposition, the refusal code and the Applied (UTC)
    value. Each pipe is preceded by a backslash and every table row keeps its
    column count. These fields are system vocabulary today, so this pins
    the escaper's guarantee, not an exposure."""
    record, refusal, comparison, mem_a, mem_b = _flow_fixture()
    record = dataclasses.replace(record, disposition="app|lied")
    refusal = dataclasses.replace(refusal, code="CHG|X")
    provenance = BeforeAfterProvenance(
        original_path=Path("/tmp/original.s19"),
        saved_path=Path("/tmp/original-patched_1.s19"),
        applied_at_utc="2026-07-02|09:00",
        change_doc_path=Path("/tmp/change-doc.json"),
    )
    entry = _entry(
        address_start=0x1000,
        address_end=0x1002,
        entry_type="by|tes",
        disposition="app|lied",
        linkage="mac|linked",
    )
    md_text, _ = _whole_pair(
        tmp_path, comparison, mem_a, mem_b,
        linkage_entries=[entry],
        provenance=provenance,
        flow_changes=FlowChangeAttribution(records=(record,), refusals=(refusal,)),
    )
    lines = md_text.splitlines()

    def _structural(row: str) -> int:
        return len(re.findall(r"(?<!\\)\|", row))

    linkage_row = next(ln for ln in lines if ln.startswith("| 1 | "))
    assert linkage_row.startswith(
        "| 1 | by\\|tes | 0x00001000 | 0x00001002 | app\\|lied | mac\\|linked "
        "| CAL\\_SYM |"
    ), linkage_row
    assert _structural(linkage_row) == 10
    flow_row = next(ln for ln in lines if ln.startswith("| patches"))
    assert flow_row == (
        "| patches\\/c\\_1\\.json | S\\*1 | 0x00001000 | 2 | app\\|lied "
        "| 0x00001000–0x00001002 |"
    ), flow_row
    assert _structural(flow_row) == 7
    assert (
        "- refused: patches\\/c\\_1\\.json symbol 'S\\*1' @ 0x00001000 "
        "[CHG\\|X] m"
    ) in lines
    assert "- Applied (UTC): 2026-07-02\\|09:00" in lines
    for raw in ("by|tes", "app|lied", "mac|linked", "CHG|X", "02|09"):
        assert raw not in md_text, raw


# ----- R-CMP-004.8: the HTML file takes no Markdown escape -------------------


def test_r_cmp_004_8_1_html_has_no_markdown_escape(tmp_path: Path) -> None:
    """The HTML file of a report with an underscore label and an A2L symbol
    holds the characters as they are: no backslash is added."""
    comparison = _comparison(
        runs=[DiffRun(0x100, 0x104, KIND_CHANGED)], stats=_stats(1, 4),
        image_a=ImageRef(label="A_b.s19", path="/tmp/a.s19", source_kind="external"),
    )
    _, html_text = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4),
        a2l_records=[{"name": "CAL_A", "address": 0x100}],
    )
    assert "Image A: A_b.s19" in html_text
    assert "<td>CAL_A</td>" in html_text
    assert "\\_" not in html_text and "\\." not in html_text


# ----- R-CMP-004.15 / R-BEFORE-AFTER-REPORT-001.21: visible text -------------


def test_r_cmp_004_15_1_html_visible_text_matches_markdown(
    tmp_path: Path,
) -> None:
    """U+0085 and U+202E planted in an image label, a Runs symbol, a linkage
    symbol, a provenance path and a refusal message: both files show U+FFFD
    at the same place in all 5 fields and neither holds a raw U+0085 or
    U+202E."""
    refusal = FlowRefusal(
        block_index=1, change_doc_ref="c.json", a2l_ref=None, code="CHG-X",
        symbol=None, address=None, message="MS\x85MT",
    )
    comparison = _comparison(
        runs=[DiffRun(0x100, 0x104, KIND_CHANGED)], stats=_stats(1, 4),
        image_a=ImageRef(label="LA\x85LB", path="/tmp/a.s19", source_kind="external"),
    )
    provenance = BeforeAfterProvenance(
        original_path=Path("/tmp/o.s19"),
        saved_path=Path("/tmp/s.s19"),
        applied_at_utc="2026-07-02T09:00:00+00:00",
        change_doc_path=Path("cd‮ef.json"),
    )
    md_text, html_text = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4),
        provenance=provenance,
        linkage_entries=[_entry(linkage_symbol="KS\x85KT")],
        mac_records=[{"name": "RS‮RT", "address": 0x100}],
        flow_changes=FlowChangeAttribution(records=(), refusals=(refusal,)),
    )
    for planted in (
        f"LA{_FFFD}LB", f"RS{_FFFD}RT", f"KS{_FFFD}KT",
        f"cd{_FFFD}ef.json", f"MS{_FFFD}MT",
    ):
        assert planted in md_text, ("markdown", planted)
        assert planted in html_text, ("html", planted)
    for text in (md_text, html_text):
        assert "\x85" not in text and "‮" not in text


def test_r_cmp_004_15_2_tab_becomes_one_space_in_both_files(
    tmp_path: Path,
) -> None:
    """A tab in an image label is one space in both files."""
    comparison = _comparison(
        image_a=ImageRef(label="a\tb.s19", path="/tmp/a.s19", source_kind="external")
    )
    md_text, html_text = _whole_pair(
        tmp_path, comparison, _mem(0x100, 1, 4), _mem(0x100, 2, 4)
    )
    assert "- Image A: a b\\.s19 [external]" in md_text
    assert "Image A: a b.s19 [external]" in html_text
    assert "\t" not in md_text and "\t" not in html_text


def test_r_cmp_004_15_3_strip_ctl_is_the_shared_visible_text() -> None:
    """The HTML side's helper and the Markdown side's visible-text step are
    one definition: equal over the planted classes, and spelled out for the
    ones that matter (E3 round 2, N-1 coupling pin)."""
    from s19_app.tui.services import diff_report_service as drs

    samples = [
        "a\x85b", "c‮d", "e\x01f", "g h", "i\tj", "k\rl", "m\nn",
        "o\ud800p", "plain", "",
    ]
    for value in samples:
        assert drs._strip_ctl(value) == _normalise(value), repr(value)
    assert drs._strip_ctl("a\x85b") == f"a{_FFFD}b"
    assert drs._strip_ctl("c‮d") == f"c{_FFFD}d"
    assert drs._strip_ctl("i\tj") == "i j"
    assert drs._strip_ctl("e\x01f") == f"e{_FFFD}f"


def test_r_before_after_report_001_21_2_provenance_path_visible(
    tmp_path: Path,
) -> None:
    """A control character in the change-document path is replaced by U+FFFD
    in both files, never removed and never raw."""
    provenance = BeforeAfterProvenance(
        original_path=Path("/tmp/o.s19"),
        saved_path=Path("/tmp/s.s19"),
        applied_at_utc="2026-07-02T09:00:00+00:00",
        change_doc_path=Path("pa\x01th.json"),
    )
    md_text, html_text = _whole_pair(
        tmp_path, _comparison(), _mem(0x100, 1, 4), _mem(0x100, 2, 4),
        provenance=provenance,
    )
    assert f"pa{_FFFD}th.json" in md_text
    assert f"pa{_FFFD}th.json" in html_text
    assert "\x01" not in md_text and "\x01" not in html_text
    assert "path.json" not in md_text and "path.json" not in html_text
