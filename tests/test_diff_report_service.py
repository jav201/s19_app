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

Element-style thresholds are inline on each test.

Confidentiality (F-S-07): every fixture is a synthetic in-memory byte run —
never operator firmware.
"""

from __future__ import annotations

import inspect
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
from s19_app.tui.services import diff_report_service
from s19_app.tui.services.compare_service import ArtifactNote, ArtifactUsage
from s19_app.tui.services.diff_report_service import (
    DIFF_REPORT_FILENAME_REGEX,
    DIFF_REPORT_HTML_FILENAME_REGEX,
    DiffReportResult,
    generate_diff_report,
    generate_diff_report_html,
    list_diff_reports,
)

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
