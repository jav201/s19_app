"""Batch-102 Inc 3 — selector A2L compartido y Check Editor usable (TC-B102-SEL-01..07).

E4 tester tests for the shared-picker slice. Oracles come from the Inc 3
design packet: ``.dev-flow/2026-11-03-batch-102/inc-3/01-requirements.md``
(R-B102-SEL-001..007), ``02-test-cases.md`` (TC-B102-SEL-01..07),
``codewire-graph.md`` and the E3 rulings
``.dev-flow/2026-11-03-batch-102/design/E3-rulings-inc3.md`` (máximo 200
filas; debounce 150 ms; conteo en ``#check_param_status``; ids de paginación
nuevos; preservación por firma no nula; ``safe_text`` para nombres hostiles;
``clear_picks``/``load_spec`` a nivel de diseño).

Layer B style (idiom: ``tests/test_b97_check_editor.py``): the shipped chain
is driven under Textual Pilot and the panel's own widgets are read back
black-box; population goes through the panel's ``set_a2l_parameters`` seam (or
the app's own A2L load for the signature-preservation case). No ``s19_app``
source is touched; fixtures are synthetic and public.

RED-in-base expectation (per ``02-test-cases.md`` notas de ejecución):
TC-B102-SEL-01 fails on base because the ledger mounts every filtered row
(10 000 rows mounted); TC-B102-SEL-02/.03/.04/.05 fail because the shared
picker, the 150 ms debounce, the signature preservation and the pagination
ids do not exist on the pre-integration tree. TC-B102-SEL-06/.07 pin
behaviour the base already has (they exist to kill the named mutants — blank
table empty state, inverted empty messages, markup-built cells — and must
stay green today). PC-11: a new id is looked up through ``need()`` (a named
assertion), never ``query_one``, and the shared class is reached as
``sdb.A2LParameterPicker`` through ``getattr``.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Input

from s19_app.tui import screens_directionb as sdb
from s19_app.tui.app import S19TuiApp
from tests.b97_fixtures import open_check_editor
from tests.b97_probes import is_displayed, settle

SIZE = (118, 54)
MIN_SIZE = (80, 24)

EMPTY_LEDGER_LINE = "No A2L parameters — load an A2L (^L) to list them."
NO_MATCH_LINE = "No parameter matches the filter."
TRUNCATED_COUNT = "200 of 10000 shown — refine filter."
PAGE_SIZE = 200

#: A hostile parameter name (E3 ruling 11 / R-B102-SEL-007): markup tokens and
#: C0/C1 control bytes around the ``b102hostile`` sentinel.
HOSTILE_NAME_B102 = "b102hostile[red]x[link=e]z\x07\x1b[31m\x9b1m"
HOSTILE_SENTINEL = "b102hostile[red]x[link=e]z"
MARKUP_SPAN_RE = re.compile(r"link|click|bold|^red$")
PAGE_LABEL_RE = re.compile(r"(\d+)\s*/\s*(\d+)")


# --------------------------------------------------------------------------- #
# Drivers and readers
# --------------------------------------------------------------------------- #


def run(tmp_path: Path, size, body, *, a2l=None):
    """Open the Check Editor at ``size`` and return ``await body(app, pilot, panel)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            panel = await open_check_editor(app, pilot, a2l=a2l)
            return await body(app, pilot, panel)

    return asyncio.run(_drive())


def need(root, selector: str, kind=None):
    """The one widget ``selector`` names, or a named assertion failure (PC-11)."""
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    widget = found[0]
    if kind is not None:
        assert isinstance(widget, kind), f"{selector}: expected {kind.__name__}, got {type(widget).__name__}"
    return widget


async def settled_delay(pilot, predicate, description: str, attempts: int = 120, delay: float = 0.02) -> None:
    """Bounded REAL-delay pump-until (E3 ruling 7: espera real ante el debounce).

    ``pilot.pause()`` alone can elapse less wall time than the 150 ms debounce,
    so each round carries a real delay; on the synchronous base tree the
    predicate already holds at round one.
    """
    for _ in range(attempts):
        await pilot.pause(delay)
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


def synthetic_rows(count: int, prefix: str = "P") -> list:
    """``count`` parameter dicts the panel's population seam normalizes."""
    return [
        {
            "name": f"{prefix}{i:05d}",
            "address": 0x1000 + i * 2,
            "length": 2, "byte_size": 2,
            "compu_method_unit": "rpm",
        }
        for i in range(count)
    ]


def write_wide_a2l(dest_dir: Path, count: int = 250) -> Path:
    """``wide.a2l``: ``count`` CHARACTERISTICs named ``P000..`` with integer
    addresses, parseable by the app's own loader (the signature-preservation
    input: the app must hold a non-None ``_a2l_enriched_key``)."""
    lines = ["/begin PROJECT Demo", "  /begin MODULE Engine"]
    for i in range(count):
        lines += [
            f"    /begin CHARACTERISTIC P{i:03d}",
            f"      ECU_ADDRESS 0x{0x1000 + i * 2:08X}",
            "      LENGTH 2",
            "    /end CHARACTERISTIC",
        ]
    lines += ["  /end MODULE", "/end PROJECT", ""]
    path = dest_dir / "wide.a2l"
    path.write_text("\n".join(lines), encoding="ascii")
    return path


def table_rows(panel) -> int:
    return panel.query_one("#check_param_table", DataTable).row_count


def status_line(panel) -> str:
    """The ``#check_param_status`` render (E3 ruling 3); ``""`` while absent."""
    found = panel.query("#check_param_status")
    return str(found.first().render()) if found else ""


def empty_lines(panel) -> list:
    """The candidate empty-state lines: the legacy full-name line plus the new
    status line (whichever ships paints the message; the other may not exist)."""
    out = []
    for selector in ("#check_full_name_line", "#check_param_status"):
        found = panel.query(selector)
        if found:
            out.append(str(found.first().render()))
    return out


def page_tuple(panel):
    """(current, total) parsed from ``#check_param_page_label``, or None."""
    found = panel.query("#check_param_page_label")
    if not found:
        return None
    match = PAGE_LABEL_RE.search(str(found.first().render()))
    return (int(match.group(1)), int(match.group(2))) if match else None


def picker_class_or_none():
    """The shared picker class, reached as ``sdb.A2LParameterPicker`` (PC-11)."""
    return getattr(sdb, "A2LParameterPicker", None)


def spy_ledger_rebuilds(monkeypatch, counter: dict):
    """Count ``A2LParameterPicker._rebuild_ledger`` calls (mutant control for
    the debounce and the toggle cost); no-op on the pre-integration tree."""
    picker_cls = picker_class_or_none()
    if picker_cls is None:
        return
    original = picker_cls._rebuild_ledger

    def counting(self):
        counter["n"] += 1
        return original(self)

    monkeypatch.setattr(picker_cls, "_rebuild_ledger", counting)


# --------------------------------------------------------------------------- #
# TC-B102-SEL-01 — R-B102-SEL-001 — one page mounted at population
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("count,expected", [(0, 0), (199, 199), (10000, 200)])
def test_tc_b102_sel_01_population_mounts_at_most_one_page(tmp_path: Path, count: int, expected: int) -> None:
    """TC-B102-SEL-01 (R-B102-SEL-001, full): parameter sets of 0, 199 and
    10 000 rows mount ``0``, ``199`` and ``200`` ledger rows — never more than
    one 200-row page per population (E3 ruling: máximo 200 filas).

    RED on base: the ledger re-adds every filtered row, so the 10 000-row set
    mounts 10 000 rows. Mutant: restore the full ``_rebuild_ledger`` loop.
    """

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(synthetic_rows(count))
        await settle(pilot, 2)
        return table_rows(panel)

    mounted = run(tmp_path, SIZE, body, a2l=None)
    assert mounted == expected, (
        f"the picker mounts one page: expected {expected} rows for {count} parameters, got {mounted}"
    )
    assert mounted <= 200, mounted


# --------------------------------------------------------------------------- #
# TC-B102-SEL-02 — R-B102-SEL-002 — debounced filter + truncated count line
# --------------------------------------------------------------------------- #


def test_tc_b102_sel_02_filter_is_debounced_and_reports_truncation(tmp_path: Path, monkeypatch) -> None:
    """TC-B102-SEL-02 (R-B102-SEL-002, full): with 10 000 parameters, one typed
    burst causes exactly one ledger rebuild (after the 150 ms debounce) and the
    count line is exactly ``200 of 10000 shown — refine filter.``; a narrow
    match (<= 200) drops the truncation marker.

    RED on base: no ``#check_param_status``, no debounce — the synchronous
    rebuild never paints the count line. Mutant: rebuild per ``Input.Changed``.
    """
    assert picker_class_or_none() is not None, "sdb.A2LParameterPicker: the shared picker ships (R-B102-SEL-002)"
    rebuilds = {"n": 0}
    spy_ledger_rebuilds(monkeypatch, rebuilds)

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(synthetic_rows(10000))
        await settle(pilot, 2)
        rebuilds["n"] = 0
        filt = panel.query_one("#check_param_filter", Input)
        filt.focus()
        await pilot.press("p")
        await settled_delay(
            pilot,
            lambda: rebuilds["n"] >= 1 and "refine filter" in status_line(panel),
            "the debounced rebuild paints the truncated count line in #check_param_status",
        )
        after_burst = (rebuilds["n"], status_line(panel), table_rows(panel))
        filt.value = "P0123"
        await settled_delay(
            pilot,
            lambda: table_rows(panel) == 10,
            "the narrow match mounts its single page",
        )
        return after_burst + (rebuilds["n"], status_line(panel), table_rows(panel))

    after_burst, status_after_burst, rows_after_burst, total_rebuilds, status_narrow, rows_narrow = run(
        tmp_path, SIZE, body, a2l=None
    )
    assert after_burst == 1, f"one debounced rebuild per typed burst, got {after_burst}"
    assert status_after_burst == TRUNCATED_COUNT, status_after_burst
    assert rows_after_burst == 200, rows_after_burst
    assert total_rebuilds == 2, f"the second filter edit debounces to one more rebuild, got {total_rebuilds}"
    assert "refine filter" not in status_narrow, status_narrow
    assert rows_narrow == 10, rows_narrow


# --------------------------------------------------------------------------- #
# TC-B102-SEL-03 — R-B102-SEL-003 — a toggle touches only the mark + preview
# --------------------------------------------------------------------------- #


def test_tc_b102_sel_03_repeated_includes_touch_only_marks_and_preview(tmp_path: Path, monkeypatch) -> None:
    """TC-B102-SEL-03 (R-B102-SEL-003, full): three consecutive toggles on two
    highlighted rows raise then lower the picked count (0→1→2→1, one duplicate
    toggle) while the ledger rebuild count stays at zero after mount and the
    picked-count preview follows each toggle.

    RED on base: the shared picker does not ship. Mutant: make
    ``_toggle_highlighted`` call ``_rebuild_ledger``.
    """
    assert picker_class_or_none() is not None, "sdb.A2LParameterPicker: the shared picker ships (R-B102-SEL-003)"
    rebuilds = {"n": 0}
    spy_ledger_rebuilds(monkeypatch, rebuilds)

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(synthetic_rows(199))
        await settle(pilot, 2)
        rebuilds["n"] = 0
        table = panel.query_one("#check_param_table", DataTable)
        count = panel.query_one("#check_fields_count")
        picked_after_each, painted_after_each = [], []
        for row in (0, 1, 0):
            table.move_cursor(row=row)
            await settle(pilot, 1)
            panel.query_one("#check_param_include_button", Button).press()
            await settle(pilot, 2)
            picked_after_each.append(list(panel._picked_params))
            painted_after_each.append(str(count.render()))
        mark_cell = str(table.get_row_at(0)[0])
        return rebuilds["n"], picked_after_each, painted_after_each, table.row_count, mark_cell

    rebuilds_after, picked, painted, rows, mark_cell = run(tmp_path, SIZE, body, a2l=None)
    assert picked == [["P00000"], ["P00000", "P00001"], ["P00001"]], picked
    assert [len(p) for p in picked] == [1, 2, 1], picked
    assert rebuilds_after == 0, f"a toggle never rebuilds the ledger, got {rebuilds_after} rebuilds"
    assert rows == 199, rows
    assert [p.split(" ")[0] for p in painted] == ["1", "2", "1"], painted
    assert mark_cell.strip() == "", f"the duplicated toggle cleared the row mark, got {mark_cell!r}"


# --------------------------------------------------------------------------- #
# TC-B102-SEL-04 — R-B102-SEL-004 — re-entry with the same signature preserves
# --------------------------------------------------------------------------- #


def test_tc_b102_sel_04_reentry_with_same_signature_preserves_state(tmp_path: Path) -> None:
    """TC-B102-SEL-04 (R-B102-SEL-004, full; E3 ruling 9: firma no nula): with
    the app's own A2L loaded (a real ``_a2l_enriched_key``), the operator
    filters to two pages, includes two parameters, moves to page 2 and leaves
    for the workspace and back twice: filter text, page, picked names and the
    mounted rows are unchanged and the ledger is not repopulated.

    RED on base: every re-entry calls ``set_a2l_parameters``, which clears the
    picks and remounts the full ledger (250 rows, unfiltered). Mutant: clear
    picks in ``set_a2l_parameters`` unconditionally.
    """

    async def body(app, pilot, panel):
        filt = panel.query_one("#check_param_filter", Input)
        filt.value = "P"
        await settled_delay(
            pilot,
            lambda: table_rows(panel) == PAGE_SIZE,
            "the filter mounts the first page (200 of 250 rows)",
        )
        table = panel.query_one("#check_param_table", DataTable)
        for row in (0, 1):
            table.move_cursor(row=row)
            await settle(pilot, 1)
            panel.query_one("#check_param_include_button", Button).press()
            await settle(pilot, 2)
        need(panel, "#check_param_page_next_button", Button).press()
        await settled_delay(pilot, lambda: table_rows(panel) == 50, "page 2 (50 rows) mounts")
        before = (
            filt.value,
            page_tuple(panel),
            table_rows(panel),
            list(panel._picked_params),
            list(panel._visible_params),
        )
        for _round in range(2):
            app.action_show_screen("workspace")
            await settle(pilot, 4)
            app.action_show_screen("check_editor")
            await settle(pilot, 4)
        after = (
            filt.value,
            page_tuple(panel),
            table_rows(panel),
            list(panel._picked_params),
            list(panel._visible_params),
        )
        return before, after

    wide = write_wide_a2l(tmp_path)
    before, after = run(tmp_path, SIZE, body, a2l=wide)
    assert before[0] == "P" and before[1] == (2, 2) and before[2] == 50, before
    assert len(before[3]) == 2 and len(before[4]) == 50, before
    assert after == before, f"re-entry with the same signature must preserve filter/page/picks/rows:\n{after}"


# --------------------------------------------------------------------------- #
# TC-B102-SEL-05 — R-B102-SEL-005 — pagination boundaries
# --------------------------------------------------------------------------- #

PAGE_TRANSITIONS = [
    # (button, expected page tuple, expected rows, prev disabled, next disabled)
    ("#check_param_page_next_button", (2, 2), 50, False, True),
    ("#check_param_page_prev_button", (1, 2), 200, True, False),
    ("#check_param_page_next_button", (2, 2), 50, False, True),
    ("#check_param_page_next_button", (2, 2), 50, False, True),
]


async def _drive_pagination(panel, pilot):
    table = panel.query_one("#check_param_table", DataTable)
    seen = []
    for button_id, _page, _rows, _prev, _next in PAGE_TRANSITIONS:
        need(panel, button_id, Button).press()
        await settled_delay(
            pilot,
            lambda: page_tuple(panel) is not None and table_rows(panel) in (PAGE_SIZE, 50),
            f"the page settles after {button_id}",
        )
        seen.append(
            (
                button_id,
                page_tuple(panel),
                table.row_count,
                need(panel, "#check_param_page_prev_button", Button).disabled,
                need(panel, "#check_param_page_next_button", Button).disabled,
            )
        )
    return seen


def test_tc_b102_sel_05_pagination_boundaries(tmp_path: Path) -> None:
    """TC-B102-SEL-05 (R-B102-SEL-005, full): 250 filtered parameters on a
    200-row page size — next, previous, next, then next again at the last page
    land on pages 1, 2, 1, 2; previous is disabled on page 1 and next on page
    2, and the out-of-range activation clamps.

    RED on base: no pagination ids ship. Mutant: remove the clamping or the
    disable logic.
    """
    assert picker_class_or_none() is not None, "sdb.A2LParameterPicker: the shared picker ships (R-B102-SEL-005)"

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(synthetic_rows(250))
        await settle(pilot, 2)
        initial = (
            page_tuple(panel),
            table_rows(panel),
            need(panel, "#check_param_page_prev_button", Button).disabled,
            need(panel, "#check_param_page_next_button", Button).disabled,
        )
        return initial, await _drive_pagination(panel, pilot)

    initial, transitions = run(tmp_path, SIZE, body, a2l=None)
    assert initial == ((1, 2), PAGE_SIZE, True, False), initial
    assert transitions == PAGE_TRANSITIONS, transitions


def test_tc_b102_sel_05_pagination_controls_fit_at_80x24(tmp_path: Path) -> None:
    """E3 ruling 6 (80x24): the new status line and the pagination row are
    mounted, displayed and inside the panel at the minimum terminal, and the
    ledger still mounts a single page.

    RED on base: the new ids do not ship.
    """
    assert picker_class_or_none() is not None, "sdb.A2LParameterPicker: the shared picker ships (R-B102-SEL-005)"

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(synthetic_rows(250))
        await settle(pilot, 4)
        controls = [
            need(panel, "#check_param_status"),
            need(panel, "#check_param_page_prev_button", Button),
            need(panel, "#check_param_page_label"),
            need(panel, "#check_param_page_next_button", Button),
        ]
        # The panel is a ScrollableContainer: children may stack below the
        # viewport fold at 80x24, so the oracle is horizontal containment in
        # the panel plus displayed — never vertical containment.
        contained_x = all(
            panel.region.x <= w.region.x and w.region.right <= panel.region.right and w.region.width > 0
            for w in controls
        )
        displayed = all(is_displayed(w) for w in controls)
        return contained_x, displayed, table_rows(panel), panel.region

    contained_x, displayed, rows, region = run(tmp_path, MIN_SIZE, body, a2l=None)
    assert contained_x, f"the status/pagination widgets leave the panel horizontally at 80x24: {region}"
    assert displayed, "the status/pagination widgets are displayed at 80x24"
    assert rows == PAGE_SIZE, rows


# --------------------------------------------------------------------------- #
# TC-B102-SEL-06 — R-B102-SEL-006 — the two empty states
# --------------------------------------------------------------------------- #


def test_tc_b102_sel_06_the_two_empty_states(tmp_path: Path) -> None:
    """TC-B102-SEL-06 (R-B102-SEL-006, full): with no A2L parameters the picker
    renders exactly ``No A2L parameters — load an A2L (^L) to list them.``;
    with a non-empty filter and no matches it renders exactly ``No parameter
    matches the filter.`` (E3 ruling 3: the status line takes the count; the
    message may paint on the shipped full-name line or the new status line).

    Stays green on base (behaviour the base already paints). Mutant: paint a
    blank table without the instruction, or invert the two messages.
    """

    async def body(app, pilot, panel):
        no_a2l = list(empty_lines(panel))
        panel.set_a2l_parameters(synthetic_rows(10))
        await settle(pilot, 2)
        filt = panel.query_one("#check_param_filter", Input)
        filt.value = "missing"
        await settled_delay(
            pilot,
            lambda: any(NO_MATCH_LINE in line for line in empty_lines(panel)),
            "the no-match line paints after the debounce",
        )
        return no_a2l, list(empty_lines(panel))

    no_a2l, no_match = run(tmp_path, SIZE, body, a2l=None)
    assert EMPTY_LEDGER_LINE in no_a2l, no_a2l
    assert NO_MATCH_LINE in no_match, no_match
    assert EMPTY_LEDGER_LINE not in no_match, no_match


# --------------------------------------------------------------------------- #
# TC-B102-SEL-07 — R-B102-SEL-007 — hostile names stay literal
# --------------------------------------------------------------------------- #


def test_tc_b102_sel_07_hostile_parameter_name_reads_literally(tmp_path: Path) -> None:
    """TC-B102-SEL-07 (R-B102-SEL-007, full; E3 ruling 11): a parameter name
    carrying Rich markup and control bytes populates and renders with the
    ``b102hostile`` sentinel kept verbatim in the Parameter cell, zero markup
    spans and zero control bytes — the name went through ``safe_text``/literal
    ``Text``, never a markup path.

    Stays green on base (``_ledger_cells`` already wraps names in ``safe_text``).
    Mutant: build the cell with a markup string.
    """

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(
            [{"name": HOSTILE_NAME_B102, "address": 0x2000, "length": 2, "byte_size": 2, "compu_method_unit": ""}]
        )
        await settle(pilot, 2)
        table = panel.query_one("#check_param_table", DataTable)
        cell = table.get_row_at(0)[1]
        plain = getattr(cell, "plain", str(cell))
        markup_spans = [s for s in getattr(cell, "spans", []) if MARKUP_SPAN_RE.search(str(s.style))]
        control_bytes = [c for c in plain if ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F]
        return plain, markup_spans, control_bytes

    plain, markup_spans, control_bytes = run(tmp_path, SIZE, body, a2l=None)
    assert HOSTILE_SENTINEL in plain, plain
    assert markup_spans == [], markup_spans
    assert control_bytes == [], control_bytes
