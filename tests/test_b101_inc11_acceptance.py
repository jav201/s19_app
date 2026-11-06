"""Black-box acceptance of batch-101 Inc 11, driven through keys and dialogs.

The release demo (``tools/synth/make_release_case.py``, seed 20260001, 10 MB,
standard library only) is generated into ``tmp_path``, placed in the work area
as a project and loaded through the Load dialog (``p``). The screens the user
guide captured are then read as painted:

- Issues report (``5``): severity groups, the strip, the summary, paging (PgDn).
- Split / Join / Export window: the a2l source chip and rows.
- A2L Explorer (``2``): the Region column and the CURVE description (``d``).

Expected values are the requirement's exact values
(``.dev-flow/2026-11-01-batch-101/inc-11/02-test-cases.md``, acceptance cases 1-6).
Waits use ``tests/support/timing.py::wait_until``.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
import time
from pathlib import Path
from typing import List, Optional

import pytest
from textual.widgets import Button, DataTable, Static

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.tui.a2l_describe import CurveDescriptionScreen  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.issues_view import GroupedIssuesPanel, IssueGroupHeader, IssueRow  # noqa: E402

from tests.support import b100_load_dialog as ld  # noqa: E402
from textual.pilot import WaitForScreenTimeout  # noqa: E402

from tests.support.timing import POLL_S  # noqa: E402

SEED = 20260001
SIZE_MB = 10.0
UNRECOGNIZED = "A2L_UNRECOGNIZED_BLOCK"
NOTE_TEXT = "x: point index (axis points unavailable)"
ROW_SUFFIX = "(index (axis points unavailable))"

CLEAN = {
    "firmware.s19": "firmware.s19",
    "firmware.a2l": "firmware.a2l",
    "firmware.mac": "firmware.mac",
}
FAULTY = {
    "firmware.s19": "firmware.s19",
    "firmware_issues.a2l": "firmware_issues.a2l",
    "firmware_issues.mac": "firmware_issues.mac",
}

async def wait_until(pilot, predicate, failure, *, timeout: float = 300.0) -> None:
    """Poll ``predicate`` like ``tests/support/timing.py::wait_until`` but ride out a
    ``WaitForScreenTimeout``: loading the 10 MB demo keeps the app busy for longer
    than Textual's 30 s pause limit on a loaded shared host. The deadline still
    bounds the wait."""
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return
        if time.monotonic() > deadline:
            raise AssertionError(failure() if callable(failure) else failure)
        await asyncio.sleep(POLL_S)
        try:
            await pilot.pause()
        except WaitForScreenTimeout:
            pass


async def _press(pilot, *keys: str) -> None:
    """``pilot.press`` that rides out a ``WaitForScreenTimeout`` (see wait_until)."""
    try:
        await pilot.press(*keys)
    except WaitForScreenTimeout:
        pass


async def settle_workers(pilot) -> None:
    """Every running worker finishes (bounded), then the deferred installs run."""
    await asyncio.wait_for(pilot.app.workers.wait_for_complete(), 300)
    await wait_until(pilot, lambda: True, "settle", timeout=1)
    for _ in range(2):
        try:
            await pilot.pause()
        except WaitForScreenTimeout:
            pass


@pytest.fixture(scope="module")
def demo_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("b101_inc11_acceptance_demo")
    gen.generate(d, SEED, SIZE_MB)
    return d


# ---------------------------------------------------------------------------
# Drivers and readers
# ---------------------------------------------------------------------------


def _plain(widget) -> str:
    rendered = widget.render()
    return getattr(rendered, "plain", str(rendered))


async def _load_demo(pilot, app: S19TuiApp, demo_dir: Path, files: dict, name: str) -> None:
    """Place the demo files as a work-area project and load it through the Load dialog."""
    project = Path(app.workarea) / name
    project.mkdir(parents=True, exist_ok=True)
    for dst, src in files.items():
        shutil.copy2(demo_dir / src, project / dst)
    await pilot.pause()
    await _press(pilot, "p")
    await ld.wait_for_dialog(pilot, app)
    await wait_until(
        pilot,
        lambda: any(name in p for p in ld.section_prompts(app.screen, "Projects")),
        lambda: f"no project row for {name!r}: {ld.option_prompts(app.screen)!r}",
    )
    label = next(p for p in ld.section_prompts(app.screen, "Projects") if name in p)
    await ld.highlight_row(pilot, app, label)
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await ld.wait_for_dialog_closed(pilot, app)
    await wait_until(
        pilot,
        lambda: app.current_file is not None and bool(app.current_a2l_data),
        "the demo project (image and A2L) loaded",
    )
    await settle_workers(pilot)
    await wait_until(
        pilot,
        lambda: len(app._validation_issues) > 0,
        "the validation issues of the loaded demo",
    )
    await settle_workers(pilot)
    # the project load ends with the load-result window; close it with Esc
    from s19_app.tui.screens import LoadResultScreen

    if isinstance(app.screen, LoadResultScreen):
        await _press(pilot, "escape")
        await wait_until(
            pilot,
            lambda: not isinstance(app.screen, LoadResultScreen),
            "the load-result window closed",
        )


def _summary(app: S19TuiApp) -> str:
    return _plain(app.query_one("#validation_issues_summary"))


def _panel(app: S19TuiApp) -> GroupedIssuesPanel:
    return app.query_one("#validation_issues_groups", GroupedIssuesPanel)


def _headers(app: S19TuiApp) -> List[str]:
    return [_plain(c) for c in _panel(app).children if isinstance(c, IssueGroupHeader)]


def _rows_under_headers(app: S19TuiApp) -> List[tuple]:
    out: List[tuple] = []
    for child in _panel(app).children:
        if isinstance(child, IssueGroupHeader):
            out.append((_plain(child), []))
        elif isinstance(child, IssueRow) and out:
            out[-1][1].append(child)
    return out


def _first_row(app: S19TuiApp) -> Optional[IssueRow]:
    rows = list(_panel(app).query(IssueRow))
    return rows[0] if rows else None


async def _open_issues(pilot, app: S19TuiApp) -> None:
    await _press(pilot, "5")
    await wait_until(
        pilot,
        lambda: _summary(app).startswith("total=") and len(_headers(app)) > 0,
        lambda: f"Issues screen not painted: {_summary(app)!r}",
    )


async def _pages(pilot, app: S19TuiApp, total_pages: int):
    """Yield (page number, headers, rows-per-header) for every page, using PgDn."""
    for n in range(1, total_pages + 1):
        if n > 1:
            previous = _first_row(app)
            await _press(pilot, "pagedown")
            await wait_until(
                pilot,
                lambda: f"page {n}/{total_pages}" in _summary(app)
                and _first_row(app) is not None
                and _first_row(app) is not previous,
                lambda: f"page {n} not painted: {_summary(app)!r}",
            )
        yield n, _headers(app), _rows_under_headers(app)


def _screen_text(app: S19TuiApp) -> str:
    return " ".join(_plain(s) for s in app.screen.query(Static))


# ---------------------------------------------------------------------------
# Issues report
# ---------------------------------------------------------------------------


def test_at_i11_1_clean_demo_issues_without_standard_blocks(tmp_path: Path, demo_dir: Path) -> None:
    """The clean demo's Issues report holds real findings only: one WARNINGS group, no INFO group
    on any page, no unrecognized-block issue, no note about a triage (base: total=364, 102 INFO)."""

    async def _go() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _load_demo(pilot, app, demo_dir, CLEAN, "demo_clean")
            await _open_issues(pilot, app)
            assert _summary(app) == (
                "total=262 | errors=0 | warnings=262 | info=0 | filter=all | page 1/7 rows 1-40/262"
            )
            strip = _plain(app.query_one("#issues_severity_strip", Static))
            assert "Errors 0" in strip and "Warnings 262" in strip and "Info 0" in strip, strip
            assert [i.code for i in app._validation_issues if i.code == UNRECOGNIZED] == []
            async for n, headers, groups in _pages(pilot, app, 7):
                assert headers == ["⚠ WARNINGS  (262)"], (n, headers)
                codes = {r.issue.code for _, rows in groups for r in rows}
                assert UNRECOGNIZED not in codes, (n, codes)
                assert "Cambio4" not in _screen_text(app), n

    asyncio.run(_go())


def test_at_i11_2_faulty_demo_errors_first(tmp_path: Path, demo_dir: Path) -> None:
    """The faulty demo lists its 8 errors on page 1, before the warnings; no later page
    shows an ERRORS group (base: 5 error rows on page 1, 3 on page 6)."""

    async def _go() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _load_demo(pilot, app, demo_dir, FAULTY, "demo_faulty")
            await _open_issues(pilot, app)
            assert _summary(app) == (
                "total=285 | errors=8 | warnings=277 | info=0 | filter=all | page 1/8 rows 1-40/285"
            )
            async for n, headers, groups in _pages(pilot, app, 8):
                if n == 1:
                    assert headers == ["✗ ERRORS  (8)", "⚠ WARNINGS  (277)"], headers
                    assert [len(rows) for _, rows in groups] == [8, 32], [len(r) for _, r in groups]
                else:
                    assert not any("ERRORS" in h for h in headers), (n, headers)

    asyncio.run(_go())


def test_at_i11_3_warnings_filter_lists_warnings_only(tmp_path: Path, demo_dir: Path) -> None:
    """The Warnings button on the faulty demo lists 277 warnings over 7 pages, no INFO and
    no ERRORS group on any page (base: rows 1-40/379)."""

    async def _go() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _load_demo(pilot, app, demo_dir, FAULTY, "demo_faulty")
            await _open_issues(pilot, app)
            # A real pointer click on the Warnings button (OR-8, E4 integration).
            assert await pilot.click("#issues_filter_warning"), "click missed #issues_filter_warning"
            await wait_until(
                pilot,
                lambda: "filter=warning" in _summary(app) and len(_headers(app)) > 0,
                lambda: f"filter not applied: {_summary(app)!r}",
            )
            assert _summary(app).endswith("filter=warning | page 1/7 rows 1-40/277"), _summary(app)
            async for n, headers, _groups in _pages(pilot, app, 7):
                assert not any("INFO" in h or "ERRORS" in h for h in headers), (n, headers)

    asyncio.run(_go())


# ---------------------------------------------------------------------------
# Split / Join, A2L Explorer
# ---------------------------------------------------------------------------


def test_at_i11_4_split_join_lists_four_demo_segments(tmp_path: Path, demo_dir: Path) -> None:
    """The a2l source of the clean demo lists its 4 MEMORY_SEGMENTs (base: a2l(0))."""

    async def _go() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _load_demo(pilot, app, demo_dir, CLEAN, "demo_clean")
            # Command palette (OR-8, E4 integration): ctrl+k, type, Enter runs the first match.
            from textual.widgets import TextArea

            from s19_app.tui.command_bar import CommandBar
            from s19_app.tui.segment_split_view import _SegTable

            await _press(pilot, "ctrl+k")
            await wait_until(pilot, lambda: app.query_one(CommandBar).palette_is_open, "the palette opened")
            await _press(pilot, *"join")
            await _press(pilot, "enter")
            await wait_until(
                pilot,
                lambda: app.focused is not None and app.focused.id == "sje_table",
                "the Split / Join / Export table focused",
            )
            table = app.query_one("#sje_table", _SegTable)
            # `t` on the manual tab focuses its localities box (keyboard-first,
            # segment_split_view.action_cycle_tab), so a second `t` would be typed there:
            # the user leaves the box with Tab, then `t` again (seam ruling SR-1).
            await _press(pilot, "t")  # ranges -> manual
            await wait_until(
                pilot,
                lambda: isinstance(app.focused, TextArea),
                "the manual localities box focused",
            )
            await _press(pilot, "tab")
            await wait_until(
                pilot,
                lambda: app.focused is not None and not isinstance(app.focused, TextArea),
                lambda: f"focus still in the box: {app.focused!r}",
            )
            await _press(pilot, "t")  # manual -> a2l
            await wait_until(
                pilot,
                lambda: "a2l(4)" in _plain(app.query_one("#sje_tabs")),
                lambda: f"chip line: {_plain(app.query_one('#sje_tabs'))!r}",
            )
            body = lambda: _plain(table.query_one(Static))  # noqa: E731
            wanted = ("0x00000000", "0x00040000", "0x00800000", "0x00C00000")
            await wait_until(
                pilot,
                lambda: all(w in body() for w in wanted),
                lambda: f"table body: {body()!r}",
            )
            text = body()
            for name in ("boot", "app", "cal", "config"):
                assert name in text, text

    asyncio.run(_go())


def _first_row_of_type(app: S19TuiApp, char_type: str) -> Optional[int]:
    table = app.query_one("#a2l_tags_list", DataTable)
    for i in range(table.row_count):
        row_key, _ = table.coordinate_to_cell_key((i, 0))
        tag = app._a2l_row_key_to_tag.get(str(getattr(row_key, "value", row_key)))
        if isinstance(tag, dict) and str(tag.get("char_type") or "").upper() == char_type:
            return i
    return None


def test_at_i11_5_curve_description_index_note_once(tmp_path: Path, demo_dir: Path) -> None:
    """The first CURVE's description states the index note once, above the table, and the
    rows carry none (base: the note on every row)."""

    async def _go() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _load_demo(pilot, app, demo_dir, CLEAN, "demo_clean")
            await _press(pilot, "2")
            await wait_until(
                pilot,
                lambda: app.query_one("#a2l_tags_list", DataTable).row_count > 0,
                "the A2L Explorer rows",
            )
            # the table is paged and the demo lists its 208 VALUE tags first:
            # PgDn until a page holds a CURVE row.
            for _ in range(20):
                if _first_row_of_type(app, "CURVE") is not None:
                    break
                first = app.query_one("#a2l_tags_list", DataTable).coordinate_to_cell_key((0, 0))
                await _press(pilot, "pagedown")
                await wait_until(
                    pilot,
                    lambda: app.query_one("#a2l_tags_list", DataTable).coordinate_to_cell_key((0, 0)) != first,
                    "the next A2L Explorer page",
                    timeout=15,
                )
            assert _first_row_of_type(app, "CURVE") is not None, "no CURVE row on any page"
            table = app.query_one("#a2l_tags_list", DataTable)
            table.move_cursor(row=_first_row_of_type(app, "CURVE"))
            await settle_workers(pilot)
            await _press(pilot, "d")
            await wait_until(
                pilot,
                lambda: isinstance(app.screen, CurveDescriptionScreen),
                "the description window",
            )
            text = _plain(app.screen.query_one("#a2l_curve_desc_body", Static))
            assert text.count(NOTE_TEXT) == 1, text
            assert text.count(ROW_SUFFIX) == 0, text

    asyncio.run(_go())


def test_at_i11_6_a2l_explorer_region_flash(tmp_path: Path, demo_dir: Path) -> None:
    """The Region cell of the first 10 tag rows of the clean demo reads flash (base: unknown)."""

    async def _go() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _load_demo(pilot, app, demo_dir, CLEAN, "demo_clean")
            await _press(pilot, "2")
            await wait_until(
                pilot,
                lambda: app.query_one("#a2l_tags_list", DataTable).row_count >= 10,
                "10 A2L Explorer rows",
            )
            table = app.query_one("#a2l_tags_list", DataTable)
            columns = [str(c.label) for c in table.columns.values()]
            region = columns.index("Region")
            cells = [str(getattr(table.get_row_at(i)[region], "plain", table.get_row_at(i)[region])) for i in range(10)]
            assert cells == ["flash"] * 10, cells

    asyncio.run(_go())
