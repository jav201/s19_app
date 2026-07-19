"""CHECKS view tests — batch-49 · US-083 · HLR-084 (Inc-2, presentational).

Inc-2 adds the dedicated CHECKS screen's data accessor + presentational widgets
(no app wiring — that is Inc-3/Inc-4):

- ``ChangeService.check_display_rows()`` → ``list[CheckDisplayRow]`` (LLR-084.2).
- ``checks_view.GroupedChecksPanel`` / ``CheckRow`` / ``CheckGroupHeader``
  (LLR-084.1) and ``build_checks_aggregate_strip`` (LLR-084.4).

These are white-box widget/accessor tests: synthetic ``CheckRunResult`` /
``CheckRunEntry`` objects are constructed directly (no real check run — that is
Inc-4's through-surface ``AT-084a``). The mounting tests use a minimal Textual
harness App holding a bare ``GroupedChecksPanel``.
"""

from __future__ import annotations

import asyncio

from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Static

from s19_app.tui.changes.model import CheckRunEntry, CheckRunResult
from s19_app.tui.checks_view import (
    _CHECK_DISPLAY_MAX,
    _GROUP_LABEL,
    CHECK_GROUP_ORDER,
    CheckGroupHeader,
    CheckRow,
    GroupedChecksPanel,
    build_checks_aggregate_strip,
)
from s19_app.tui.color_policy import css_class_for_severity
from s19_app.tui.services.change_service import ChangeService, CheckDisplayRow
from s19_app.validation import ValidationSeverity

#: INDEPENDENT oracle (test-side literal): the intended result→severity policy.
#: Production single-sources the header/row colour from the accessor's
#: ``_CHECK_RESULT_SEVERITY`` (there is no ``_GROUP_SEVERITY`` in the view any
#: more), so hand-deriving the expected class here is a genuine cross-check, not
#: a tautology.
_EXPECTED_SEVERITY = {
    "fail": ValidationSeverity.ERROR,
    "uncheckable": ValidationSeverity.WARNING,
    "pass": ValidationSeverity.OK,
}


# --------------------------------------------------------------------------- #
# Synthetic fixtures                                                            #
# --------------------------------------------------------------------------- #


def _entry(
    result: str,
    address_start: int = 0x100,
    *,
    linkage_symbol: object = None,
    reason: object = None,
    actual: object = None,
) -> CheckRunEntry:
    """Build a synthetic ``CheckRunEntry`` (no real check engine involved)."""
    return CheckRunEntry(
        entry_type="bytes",
        address_start=address_start,
        address_end=address_start + 1,
        expected_bytes=(0x00,),
        actual_bytes=actual,
        result=result,
        linkage="standalone",
        linkage_symbol=linkage_symbol,
        reason=reason,
    )


def _result(entries: list[CheckRunEntry]) -> CheckRunResult:
    """Wrap ``entries`` in a synthetic ``CheckRunResult`` with derived aggregates."""
    aggregates = {
        "passed": sum(1 for e in entries if e.result == "pass"),
        "failed": sum(1 for e in entries if e.result == "fail"),
        "uncheckable": sum(1 for e in entries if e.result == "uncheckable"),
    }
    return CheckRunResult(
        source_path=None,
        timestamp_utc="2026-07-18T00:00:00+00:00",
        variant_id=None,
        aggregates=aggregates,
        entries=entries,
    )


def _service_with(entries: list[CheckRunEntry]) -> ChangeService:
    """A ``ChangeService`` whose ``last_check_result`` is the synthetic run."""
    service = ChangeService()
    service.last_check_result = _result(entries)
    return service


class _ChecksHarness(App):
    """Minimal app holding a bare ``GroupedChecksPanel`` so it can mount."""

    def compose(self) -> ComposeResult:
        yield GroupedChecksPanel(id="checks_grouped")


def _static_content(node: Static) -> object:
    """Return the renderable a ``Static`` was built with (its ``safe_text``)."""
    return node.content


# --------------------------------------------------------------------------- #
# TC-084.2 — check_display_rows accessor (LLR-084.2)                            #
# --------------------------------------------------------------------------- #


def test_tc084_2_check_display_rows_one_per_entry_address_and_class() -> None:
    """TC-084.2 / LLR-084.2 — one row per entry, address preserved, class per result, [] when None.

    Intent: ``check_display_rows`` returns one ``CheckDisplayRow`` per entry in
    order; each row's ``.address`` equals the entry's ``address_start`` and its
    ``.css_class`` is the class for that result's severity (derived here through
    the test-side ``_EXPECTED_SEVERITY`` oracle + ``css_class_for_severity``,
    not hand-listed — C-31); and it returns ``[]`` when no run is current.
    """
    # Empty return when no run is current.
    assert ChangeService().check_display_rows() == []

    entries = [
        _entry("fail", 0x102),
        _entry("uncheckable", 0x9000, reason="outside image"),
        _entry("pass", 0x200),
    ]
    rows = _service_with(entries).check_display_rows()

    assert len(rows) == len(entries)
    for row, entry in zip(rows, entries):
        assert isinstance(row, CheckDisplayRow)
        assert row.result == entry.result
        assert row.address == entry.address_start
        expected_class = css_class_for_severity(_EXPECTED_SEVERITY[entry.result])
        assert row.css_class == expected_class, (entry.result, row.css_class)

    # The uncheckable row folds its file-derived reason into text; the others
    # carry no reason suffix, and linkage rides its own field (None here).
    unchk = rows[1]
    assert "outside image" in unchk.text
    assert unchk.linkage_symbol is None


# --------------------------------------------------------------------------- #
# TC-084.1 — grouped render order + per-row/header colours (LLR-084.1)          #
# --------------------------------------------------------------------------- #


def test_tc084_1_render_groups_order_and_severity_classes() -> None:
    """TC-084.1 / LLR-084.1 — groups render fail→uncheckable→pass, each carries its sev class.

    Intent: over a synthetic run with fails + uncheckables + passes supplied in
    NON-grouped order, ``render_groups`` regroups them into the fixed
    fail→uncheckable→pass order; each group HEADER and every ROW within a group
    carries the ``sev-error``/``sev-warning``/``sev-ok`` class for that result —
    both asserted against the test-side ``_EXPECTED_SEVERITY`` oracle (F1: the
    header colour is now single-sourced in production from a row's class, so the
    header assertion cross-checks the wiring, not a duplicate map). The expected
    present-group set/order is DERIVED from the entries (C-31), not hand-listed.
    """
    # Deliberately interleaved input order so grouping is exercised, not luck.
    entries = [
        _entry("fail", 0x100),
        _entry("pass", 0x200),
        _entry("uncheckable", 0x300, reason="no image"),
        _entry("fail", 0x110),
        _entry("pass", 0x210),
    ]
    rows = _service_with(entries).check_display_rows()

    # C-31: derive the expected present groups + order from the entries.
    present = [t for t in CHECK_GROUP_ORDER if any(e.result == t for e in entries)]
    expected_labels = [_GROUP_LABEL[t] for t in present]

    async def _drive() -> tuple[list[str], list[tuple[str, bool]], list[tuple[str, bool]]]:
        app = _ChecksHarness()
        async with app.run_test() as pilot:
            panel = app.query_one(GroupedChecksPanel)
            panel.render_groups(rows)
            await pilot.pause()

            header_order: list[str] = []
            header_classed: list[tuple[str, bool]] = []
            row_classed: list[tuple[str, bool]] = []
            current: object = None
            for child in panel.children:
                if isinstance(child, CheckGroupHeader):
                    current = child.result_label
                    header_order.append(child.result_label)
                    token = present[len(header_order) - 1]
                    want = css_class_for_severity(_EXPECTED_SEVERITY[token])
                    header_classed.append((child.result_label, child.has_class(want)))
                elif isinstance(child, CheckRow):
                    # every row sits under the header for its own result
                    assert _GROUP_LABEL[child.row.result] == current, (
                        child.row.result,
                        current,
                    )
                    want = css_class_for_severity(_EXPECTED_SEVERITY[child.row.result])
                    row_classed.append((child.row.result, child.has_class(want)))
            return header_order, header_classed, row_classed

    header_order, header_classed, row_classed = asyncio.run(_drive())

    assert header_order == expected_labels, header_order
    assert all(ok for _, ok in header_classed), header_classed
    assert row_classed, "rows must be mounted"
    assert all(ok for _, ok in row_classed), row_classed
    # every entry became a mounted row (none dropped under the 5-entry budget)
    assert len(row_classed) == len(entries)


# --------------------------------------------------------------------------- #
# TC-084.4 — aggregate strip counts + bar + zero (LLR-084.4)                    #
# --------------------------------------------------------------------------- #


def test_tc084_4_aggregate_strip_counts_bar_and_zero() -> None:
    """TC-084.4 / LLR-084.4 — strip counts exact, bar monotone in passed/total, total=0 safe.

    Intent: ``build_checks_aggregate_strip`` reports each aggregate count
    verbatim; its micro-bar filled-cell count is monotone non-decreasing in
    ``passed/total``; and ``total == 0`` renders an empty bar with no exception.
    """
    plain = build_checks_aggregate_strip(
        {"passed": 2, "failed": 1, "uncheckable": 3}
    ).plain
    assert "Pass 2" in plain and "Fail 1" in plain and "Uncheck 3" in plain, plain

    previous = -1
    for passed in range(0, 7):
        filled = build_checks_aggregate_strip(
            {"passed": passed, "failed": 6 - passed, "uncheckable": 0}
        ).plain.count("█")
        assert filled >= previous, (passed, filled, previous)
        previous = filled

    zero = build_checks_aggregate_strip(
        {"passed": 0, "failed": 0, "uncheckable": 0}
    ).plain
    assert "Pass 0 / Fail 0 / Uncheck 0" in zero, zero
    assert "█" not in zero, zero


# --------------------------------------------------------------------------- #
# TC-084.10 (DoS) — mount cap for an oversized run (LLR-084.1)                  #
# --------------------------------------------------------------------------- #


def test_tc084_10_render_groups_caps_mounted_rows() -> None:
    """TC-084.10 (DoS) / LLR-084.1 — an oversized run mounts <= _CHECK_DISPLAY_MAX rows + a note.

    Intent: a run of more than ``_CHECK_DISPLAY_MAX`` entries mounts at most
    ``_CHECK_DISPLAY_MAX`` ``CheckRow`` widgets (the cap constant, cited — MIN-3)
    and appends a truncation note, so a hostile/huge run cannot flood the pump.
    """
    oversized = _CHECK_DISPLAY_MAX + 5
    entries = [_entry("fail", 0x100 + i) for i in range(oversized)]
    rows = _service_with(entries).check_display_rows()
    assert len(rows) == oversized  # the accessor itself is uncapped

    async def _drive() -> tuple[int, str]:
        app = _ChecksHarness()
        async with app.run_test() as pilot:
            panel = app.query_one(GroupedChecksPanel)
            panel.render_groups(rows)
            await pilot.pause()
            mounted = len(list(app.query(CheckRow)))
            notes = [
                str(_static_content(w).plain if isinstance(_static_content(w), Text) else "")
                for w in app.query(Static)
                if w.has_class("checks-truncation-note")
            ]
            return mounted, " ".join(notes)

    mounted, note = asyncio.run(_drive())
    assert mounted <= _CHECK_DISPLAY_MAX, mounted
    assert note, "an oversized run must show a truncation note"


# --------------------------------------------------------------------------- #
# C-17 seed (widget-level) — hostile linkage_symbol/reason render literal        #
# --------------------------------------------------------------------------- #


def test_c17_seed_hostile_linkage_and_reason_render_literal() -> None:
    """C-17 seed / LLR-084.8 — hostile ``linkage_symbol``/``reason`` render literal in their cells.

    Intent (widget-level guard; the through-surface AT-084g comes in Inc-4): a
    synthetic uncheckable entry carries a hostile ``linkage_symbol`` and a
    hostile ``reason``; through ``check_display_rows`` → ``CheckRow.compose`` the
    detail cell (which folds in the reason) and the dedicated linkage cell each
    render as literal ``safe_text`` — ``.plain`` contains the payload verbatim
    and ``spans == []`` (no injected link/bold/OSC-8 span, no ``MarkupError``).
    """
    entries = [
        _entry(
            "uncheckable",
            0x100,
            linkage_symbol="x[link=file:///etc]",
            reason="[/nope]",
        )
    ]
    rows = _service_with(entries).check_display_rows()
    assert len(rows) == 1
    row = rows[0]
    # reason folded into text; linkage carried apart (its own cell).
    assert "[/nope]" in row.text, row.text
    assert row.linkage_symbol == "x[link=file:///etc]"

    cells = [w for w in CheckRow(row).compose() if isinstance(w, Static)]
    detail = next(w for w in cells if w.has_class("check-detail"))
    linkage = next(w for w in cells if w.has_class("check-linkage"))

    detail_content = _static_content(detail)
    assert isinstance(detail_content, Text), type(detail_content)
    assert "[/nope]" in detail_content.plain, detail_content.plain
    assert list(detail_content.spans) == [], detail_content.spans

    linkage_content = _static_content(linkage)
    assert isinstance(linkage_content, Text), type(linkage_content)
    assert linkage_content.plain == "x[link=file:///etc]", linkage_content.plain
    assert list(linkage_content.spans) == [], linkage_content.spans
