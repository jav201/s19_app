"""FB-P1b (batch-60) flow-run report generation — composer tests (Inc-1).

Layer-A tests over the Textual-free ``flow_report_service`` composer.

The load-bearing test is the markup oracle (AMD-1/AMD-2): rather than asserting a
list of escaped characters — a moving target against a parser we do not own — the
composed report is **rendered through the real parser** (``MarkdownIt("gfm-like")``,
the grammar ``textual.widgets.Markdown`` builds) and the **token stream** is
asserted to carry no live structure. That assertion stays true even when the
escape set is wrong in a way nobody predicted, which is exactly how the Phase-2
review caught the original CommonMark-only escape set (bare URLs autolinked and
``~~x~~`` struck through in a ledger cell).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest
from markdown_it import MarkdownIt

from s19_app.tui.services import flow_report_service as frs
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BlockResult,
    Finding,
)
from s19_app.tui.services.flow_report_service import (
    MAX_REPORT_CELL_CHARS,
    MAX_REPORT_FINDINGS_PER_BLOCK,
    SECTION_HEADINGS,
    STATUS_CLEAN,
    STATUS_FAILED,
    STATUS_ISSUES,
    FlowReportState,
    _md_safe,
    compose_flow_report,
)

_AT = datetime(2026, 7, 24, 22, 40, 0, tzinfo=timezone.utc)

#: Live-structure token types — the markup oracle's reject set (AMD-2).
_LIVE_TOKENS = {"link_open", "s_open", "code_inline", "heading_open", "html_inline",
                "html_block", "image"}


def _render_tokens(markdown: str) -> List[str]:
    """Flatten the real parser's token stream (inline children included)."""
    md = MarkdownIt("gfm-like")
    types: List[str] = []
    for token in md.parse(markdown):
        types.append(token.type)
        for child in token.children or []:
            types.append(child.type)
    return types


def _live_structures(markdown: str) -> set:
    """Live markdown structures in ``markdown``, EXCLUDING headings.

    Headings are handled separately by :func:`_heading_count`: the report has its
    own ``#``/``##`` lines, so their mere presence proves nothing — an INJECTED
    heading is detected as a heading COUNT above the benign baseline. Discarding
    the token type outright (the first version of this helper) made the
    ``# INJECTED heading`` payload assert nothing at all.
    """
    return (set(_render_tokens(markdown)) & _LIVE_TOKENS) - {"heading_open"}


def _heading_count(markdown: str) -> int:
    """How many headings the parser sees — the injected-heading discriminator."""
    return _render_tokens(markdown).count("heading_open")


def _state(**kwargs) -> FlowReportState:
    base = dict(
        flow_name="nightly-release",
        block_results=[
            BlockResult(0, "source", BLOCK_STATUS_OK, "loaded prg.s19"),
            BlockResult(1, "write-out", BLOCK_STATUS_OK, "wrote prg_patched.s19"),
        ],
        image_ranges=[(0x8000, 0x8FFF)],
    )
    base.update(kwargs)
    return FlowReportState(**base)


# --------------------------------------------------------------------------- #
# TC-001u — structure, determinism, one row per block
# --------------------------------------------------------------------------- #

def test_tc001u_sections_present_in_order() -> None:
    """All five sections present, in the declared order. Driven with a finding so
    the conditional Findings section is materialised (its omission when empty is
    pinned separately by test_tc001u_findings_section_omitted_when_none)."""
    state = _state(block_results=[
        BlockResult(0, "source", BLOCK_STATUS_NOTICES, "loaded prg.s19",
                    findings=[Finding("warning", "unresolved region")]),
    ])
    report = compose_flow_report(state, _AT)
    positions = [report.find(h) for h in SECTION_HEADINGS]
    assert all(p >= 0 for p in positions), positions       # every section present
    assert positions == sorted(positions)                  # in the declared order
    assert report.startswith("# Flow report")              # header first


def test_tc001u_one_ledger_row_per_block_derived() -> None:
    """The row count is DERIVED from block_results — a fixed template fails this."""
    blocks = [BlockResult(i, f"k{i}", BLOCK_STATUS_OK, f"s{i}") for i in range(5)]
    report = compose_flow_report(_state(block_results=blocks), _AT)
    body_rows = [ln for ln in report.splitlines()
                 if ln.startswith("| ") and not ln.startswith("| # ")
                 and not ln.startswith("|---")]
    assert len(body_rows) == 5
    for i in range(5):
        assert f"K{i}" in report


def test_tc001u_composition_is_deterministic() -> None:
    """HLR-001 says deterministic — same state + same instant ⇒ byte-identical."""
    assert compose_flow_report(_state(), _AT) == compose_flow_report(_state(), _AT)


def test_tc001u_findings_section_omitted_when_none() -> None:
    report = compose_flow_report(_state(), _AT)
    assert "## Findings" not in report


# --------------------------------------------------------------------------- #
# TC-013a/b — status oracle keyed on the EXPLICIT aborted flag (AMD-4)
# --------------------------------------------------------------------------- #

def test_tc013a_record_error_shaped_abort_is_failed() -> None:
    """All 9 abort sites yield FAILED — including the 8 `_record_error` shapes
    whose summaries are NOT the literal "error" (the proxy the review killed)."""
    for summary in ("source unresolved", "no source", "change doc unresolved",
                    "no image", "write failed", "config unresolved",
                    "config malformed", "unknown block", "error"):
        state = _state(
            block_results=[BlockResult(0, "source", BLOCK_STATUS_ERROR, summary)],
            aborted=True,
        )
        assert f"**Status:** {STATUS_FAILED}" in compose_flow_report(state, _AT), summary


def test_tc013b_non_aborting_error_is_issues_not_failed() -> None:
    """NEGATIVE CONTROL: a CHECK own-op error is `error` but does NOT abort —
    it must read COMPLETED WITH ISSUES, proving the rule is not "any error"."""
    state = _state(
        block_results=[BlockResult(0, "check", BLOCK_STATUS_ERROR,
                                   "check operation invalid")],
        aborted=False,
    )
    report = compose_flow_report(state, _AT)
    assert f"**Status:** {STATUS_ISSUES}" in report
    assert STATUS_FAILED not in report


def test_tc013_clean_and_issues_labels() -> None:
    assert f"**Status:** {STATUS_CLEAN}" in compose_flow_report(_state(), _AT)
    noticed = _state(block_results=[BlockResult(0, "source", BLOCK_STATUS_NOTICES, "x")])
    assert f"**Status:** {STATUS_ISSUES}" in compose_flow_report(noticed, _AT)
    found = _state(block_results=[
        BlockResult(0, "source", BLOCK_STATUS_OK, "x", findings=[Finding("warning", "w")])
    ])
    assert f"**Status:** {STATUS_ISSUES}" in compose_flow_report(found, _AT)


# --------------------------------------------------------------------------- #
# TC-004 — the MARKUP ORACLE: no live structure under the real parser (AMD-1/2)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("payload", [
    "http://evil.example/x",            # linkify: scheme
    "https://evil.example/x",
    "//evil.example/x",                 # linkify: protocol-relative
    # linkify: FUZZY — no scheme, no slash. The final-gate F1 gap: the first
    # battery had 11 payloads and not one of them exercised this branch, so the
    # oracle was correct while the INPUT SET was blind (C-31 on ourselves).
    "www.evil.com",
    "evil.com",
    "ops@evil.example",                 # fuzzy email → mailto:
    "банк.рф",                          # IDN fuzzy link
    "a.b.c@d.co.uk",
    "~~approved~~ rejected.json",       # strikethrough = deception in an audit record
    "calib`code`.json",                 # code span
    "# INJECTED heading",               # heading
    "[link](http://evil.example)",      # inline link
    "![img](http://evil.example/i.png)",  # image
    "<script>alert(1)</script>",        # raw HTML (html=True in gfm-like)
    "a | b | c",                        # table-structure break
    "*em* _em_ **strong**",             # emphasis
])
def test_tc004_hostile_payload_injects_no_live_structure(payload: str) -> None:
    """Per-branch battery (C-31): each payload targets ONE grammar feature, so a
    regression dropping any single escape goes RED (the batch-53 M-1 lesson)."""
    def _compose(text: str) -> str:
        return compose_flow_report(_state(
            flow_name=text,
            block_results=[
                BlockResult(0, "patch", BLOCK_STATUS_NOTICES, f"applied {text}",
                            findings=[Finding("warning", f"unresolved in {text}")]),
            ],
            written_paths=[Path(text)],
        ), _AT)

    report = _compose(payload)
    assert _live_structures(report) == set(), payload
    # An injected heading is a heading COUNT above the benign baseline — the
    # report's own headings are constant, so this is falsifiable (F4).
    assert _heading_count(report) == _heading_count(_compose("benign.txt")), payload


def test_tc004_ledger_row_column_count_preserved_under_hostile_summary() -> None:
    """A pipe-bearing summary must not break the row into extra cells."""
    md = MarkdownIt("gfm-like")
    benign = compose_flow_report(_state(), _AT)
    hostile = compose_flow_report(
        _state(block_results=[
            BlockResult(0, "patch", BLOCK_STATUS_OK, "a | b | c | d | e"),
            BlockResult(1, "write-out", BLOCK_STATUS_OK, "ok"),
        ]), _AT)
    assert sum(t.type == "td_open" for t in md.parse(hostile)) == \
           sum(t.type == "td_open" for t in md.parse(benign))


def test_tc006_benign_text_stays_readable() -> None:
    """NEGATIVE CONTROL — `_md_safe` must not blanket-mangle ordinary text: the
    escapes render INVISIBLY, so the reader sees the original string."""
    md = MarkdownIt("gfm-like")
    state = _state(block_results=[
        BlockResult(0, "source", BLOCK_STATUS_OK, "loaded out/prg_patched.s19 (2 ranges)")
    ])
    rendered = md.render(compose_flow_report(state, _AT))
    assert "loaded out/prg_patched.s19 (2 ranges)" in rendered
    assert "\\" not in rendered  # no stray backslash reaches the reader


# --------------------------------------------------------------------------- #
# TC-014 — written paths are NOT backtick-wrapped (AMD-5 code-span context)
# --------------------------------------------------------------------------- #

def test_tc014_backtick_bearing_written_path_is_inert_and_clean() -> None:
    state = _state(written_paths=[Path("a`b`c.s19")])
    report = compose_flow_report(state, _AT)
    assert "code_inline" not in _render_tokens(report)   # no span opened at all
    assert _live_structures(report) == set()


def test_tc014_benign_written_path_round_trips_character_identical() -> None:
    """The fidelity half: a normal path renders with no stray backslash."""
    md = MarkdownIt("gfm-like")
    state = _state(written_paths=[Path("out/prg_patched.s19")],
                   project_dir=None)
    rendered = md.render(compose_flow_report(state, _AT))
    assert "prg_patched.s19" in rendered
    assert "\\" not in rendered


# --------------------------------------------------------------------------- #
# TC-015 — size policy boundary PAIR (AMD-7)
# --------------------------------------------------------------------------- #

def test_tc015_cell_truncation_boundary_pair() -> None:
    exact = "x" * MAX_REPORT_CELL_CHARS
    over = "x" * (MAX_REPORT_CELL_CHARS + 1)
    assert "truncated" not in _md_safe(exact)      # exactly at cap: untouched
    assert "truncated" in _md_safe(over)           # one over: marked


def test_tc015_findings_cap_suppresses_with_a_visible_note() -> None:
    many = [Finding("warning", f"err {i}") for i in range(MAX_REPORT_FINDINGS_PER_BLOCK + 5)]
    state = _state(block_results=[
        BlockResult(0, "source", BLOCK_STATUS_NOTICES, "loaded", findings=many)
    ])
    report = compose_flow_report(state, _AT)
    assert "5 more findings omitted" in report


def test_tc015_large_run_stays_within_the_viewer_cap() -> None:
    """A 64-block run with many findings must stay under the budget — otherwise
    the report is refused by the very viewer US-002 promises."""
    blocks = [
        BlockResult(i, "source", BLOCK_STATUS_NOTICES, "x" * 200,
                    findings=[Finding("warning", "y" * 200) for _ in range(50)])
        for i in range(64)
    ]
    report = compose_flow_report(_state(block_results=blocks), _AT)
    assert len(report.encode("utf-8")) <= frs.FLOW_REPORT_MAX_TOTAL_BYTES


# --------------------------------------------------------------------------- #
# TC-016 — no absolute host path leaks into a shareable record (AMD-8)
# --------------------------------------------------------------------------- #

def test_tc016_written_paths_render_relative_not_absolute(tmp_path: Path) -> None:
    project = tmp_path / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True)
    written = project / "out" / "prg_patched.s19"
    written.parent.mkdir(parents=True)
    written.write_text("x", encoding="utf-8")

    report = compose_flow_report(
        _state(written_paths=[written], project_dir=project), _AT)
    # Assert on the RENDERED text: the path is escaped in the source markdown
    # (out\/prg\_patched.s19) but renders as the readable relative path.
    rendered = MarkdownIt("gfm-like").render(report)
    assert "out/prg_patched.s19" in rendered
    # The leak assertions hold on the raw markdown too — nothing absolute is in it.
    assert "Users" not in report
    assert ":\\" not in report and str(tmp_path) not in report


def test_tc016b_exception_diagnostics_do_not_leak_absolute_paths() -> None:
    """F2: `_display_path` guards `written_paths`, but an OSError message reaches
    the report through a block's FINDINGS and carries the full host path
    (username + local layout) into a document meant to be shareable."""
    leaky = (r"FileExistsError: [WinError 183] Cannot create a file when that "
             r"file already exists: 'C:\Users\jjgh8\AppData\Local\Temp\x\reports'")
    state = _state(block_results=[
        BlockResult(0, "report", BLOCK_STATUS_ERROR, "report write failed",
                    findings=[Finding("error", leaky)]),
    ])
    report = compose_flow_report(state, _AT)
    assert "Users" not in report
    assert "jjgh8" not in report
    assert "C:" not in report
    # The useful part survives — this is redaction, not deletion.
    assert "FileExistsError" in report and "reports" in report


# --------------------------------------------------------------------------- #
# Image footprint sources + the pre-CRC asymmetry (AMD-9, composer half)
# --------------------------------------------------------------------------- #

def test_footprint_omits_before_crc_until_a_crc_has_run() -> None:
    pre = compose_flow_report(_state(pre_crc_ranges=()), _AT)
    assert "Before CRC" not in pre
    post = compose_flow_report(
        _state(pre_crc_ranges=[(0x8000, 0x8FFF)], image_ranges=[(0x8000, 0x9FFF)]), _AT)
    assert "Before CRC" in post
    assert "8,192 bytes" in post   # the grown Final total


def test_footprint_none_when_no_image() -> None:
    assert "**Final:** (none)" in compose_flow_report(_state(image_ranges=None), _AT)


# --------------------------------------------------------------------------- #
# Unicode + empty-name edge cases (m-4 / m-5)
# --------------------------------------------------------------------------- #

def test_unicode_survives_composition() -> None:
    state = _state(block_results=[
        BlockResult(0, "source", BLOCK_STATUS_OK, "cargó 校验 ✅ prg​.s19")
    ])
    report = compose_flow_report(state, _AT)
    assert "校验" in report and "✅" in report


def test_name_that_sanitises_to_nothing_renders_empty_marker() -> None:
    assert _md_safe("   ") == "(empty)"
    assert "(empty)" in compose_flow_report(_state(flow_name="```"), _AT)
