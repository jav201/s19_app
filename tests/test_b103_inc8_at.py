"""Batch-103 Inc 8 — acceptance tests of the Patch Editor's edit-by-definition sheet (E4, AT tester).

Cases: ``.dev-flow/2026-11-05-batch-103/inc-8/02-test-cases-AT.md`` (AT-B103-I8-1 ... AT-B103-I8-9, minus the help
window, AT-B103-I8-6, which lives in ``test_b103_inc8_at_help.py``). Requirements: ``01-requirements.md``.
Requirement ids verified end to end here (one name per row of the cases file):
R-PE-DEF.10, R-PE-DEF.13, R-PE-DEF.14, R-PE-DEF.22, R-PE-DEF.23, R-PE-DEF.27, R-PE-DEF.40, R-PE-DEF.42, R-PE-DEF.45,
R-PE-DEF.46, R-PE-DEF.47, R-PE-DEF.48, R-PE-DEF.50, R-PE-DEF.51, R-PE-DEF.52, R-PE-DEF.53, R-PE-DEF.54,
R-PE-DEF.56, R-PE-DEF.57, R-PE-DEF.58, R-PE-DEF.60, R-PE-DEF.63, R-PE-DEF.82, R-PE.34, R-PE.35, R-PE.41.

Black-box. The real app (``S19TuiApp`` under Textual's pilot) loads the synthetic definitions case (DEFC, seed
20260001: ``definitions.a2l`` + ``definitions.s19``) through its own loaders; the operator route is driven by keys
(Tab, arrows, Enter, Escape, typed characters) and the shipped widgets are read back through their ids. No product
module of Inc 8 is imported. Expected bytes, addresses, Δ and refusal messages are computed here by the committed
I-2 model (``a2l_definition``) over the app's own parsed A2L and image, never retyped; the status wording, mark glyphs
and subtitle texts come from the cited requirement rows.

Ids the product ships (graph-inc8.md §Interfaces I-8.4): ``#patch_sheet`` (the sheet), ``#patch_sheet_body`` (the
focusable body), ``#patch_sheet_input`` (the formula input). Existing ids: ``#patch_param_filter`` (the shared
picker's filter), ``#patch_doc_entries_table`` (the ledger), ``#patch_doc_apply_button``.

Control (per file): AT-7 reads the same ledger / status / subtitle / mark surfaces as AT-1 after refusals and must see
"nothing staged, not dirty". Every new-path test is RED on the base tree (no ``#patch_sheet_body``).
"""
from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

import pytest
from textual import events
from textual.widgets import Button, DataTable, Input

from s19_app.tui import a2l_definition as model
from s19_app.tui.app import S19TuiApp
from tests.b97_probes import is_displayed, record_statuses
from tests.support.b100_workers import settle_workers

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

SIZE = (118, 54)
SEED = 20260001

SHEET = "#patch_sheet"
BODY = "#patch_sheet_body"
INPUT = "#patch_sheet_input"
FILTER = "#patch_param_filter"
LEDGER = "#patch_doc_entries_table"
APPLY = "#patch_doc_apply_button"

# Wording the requirements pin (cited per use).
NO_PAGE_LINE = "No parameters on this page: type a filter above."  # R-PE-DEF.13
NO_A2L_LINE = "Load an A2L file to edit parameters by definition."  # R-PE-DEF.14
NO_A2L_STAGE = "Patch Editor: no A2L is loaded — nothing staged."  # R-PE-DEF.63
MAX_FORMULA = 4096  # R-PE-DEF.42

MARKS = "▶●◆"


# --------------------------------------------------------------------------- #
# Fixture, driver, readers
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def defc(tmp_path_factory):
    """The definitions case written by the shipped generator; its A2L text names the parameters."""
    out = tmp_path_factory.mktemp("defc")
    paths = gen.generate_definitions_case(out, SEED)
    text = paths["a2l"].read_text(encoding="utf-8")
    names = re.findall(r"/begin (?:CHARACTERISTIC|MEASUREMENT|AXIS_PTS) (\w+)", text)
    return {"a2l": paths["a2l"], "s19": paths["s19"], "names": names}


def run(tmp_path: Path, defc, body, *, a2l: bool = True, image: bool = True, size=SIZE):
    """Open the Patch Editor with the DEFC A2L and image loaded through the app's loaders and return
    ``await body(app, pilot, panel)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            if a2l:
                app.load_a2l_from_path(Path(defc["a2l"]))
                await settle_workers(pilot)
                assert app._compute_a2l_enriched_tags(), f"the A2L did not load: {list(app.log_lines)[-3:]}"
            if image:
                app.load_from_path(Path(defc["s19"]))
                for _ in range(100):
                    if app.current_file is not None:
                        break
                    await pilot.pause(0.05)
                assert app.current_file is not None, "the image did not load"
            app.action_show_screen("patch")
            await settle(pilot, 6)
            return await body(app, pilot, app.query_one("#patch_editor_panel"))

    return asyncio.run(_drive())


async def settle(pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


def test_reader_control_parse_rows_reads_marks_names_and_skips_header_and_detail() -> None:
    """Control of the readers (no app): the row parser sees the mark of each row, matches a clipped name by its start,
    reads an unmarked row, and skips the header, its rule, the expanded object's lines and the formula bar.

    Retargeted at Inc 8b (R-PE-DEF.90, .91, .107): a `│` gutter closes every column, the header rule is the
    body's second line, and every expanded line starts with the bar `  ┊ `; a name that fills its 26-cell
    column is followed by the gutter with no space."""
    names = ["DISPLAY_0001", "ENUM_0001", "ASAM.C.ASCII.UBYTE.NUMBER_42", "MASK_BIT_0001", "N" * 26]
    # CTX-PE-DEF `mark`: a 2-cell column, cell 1 `▶` or space, cell 2 `●` / `◆` / space, then the Parameter cell.
    text = "\n".join(
        [
            "  Parameter                 │Kind      │Current             │New",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━┿━━━",
            "▶ DISPLAY_0001               │VALUE     │143.5               │·",
            "  ┊ └ LINEAR phys = 0.5*raw · SWORD s16 big-endian · 0x00800020 · 2 B",
            " ●ENUM_0001                  │VALUE     │1 IDLE              │2 RUN",
            "  ┊ ╭─ ENUM_0001 · choose one ─╮",
            " ◆ASAM.C.ASCII.UBYTE.NUMBER…│ASCII     │\"Hello\"",
            "▶●MASK_BIT_0001              │MASK      │1 (0x01)            │0 (0x00)",
            "  " + "N" * 26 + "│VALUE",
            "  new = 25.5   deg C",
        ]
    )
    rows = parse_rows(text, names)
    assert [(m, n) for m, n, _ in rows] == [
        ("▶ ", "DISPLAY_0001"),
        (" ●", "ENUM_0001"),
        (" ◆", "ASAM.C.ASCII.UBYTE.NUMBER_42"),
        ("▶●", "MASK_BIT_0001"),
        ("  ", "N" * 26),
    ], rows
    assert parse_rows("  DISPLAY_0001  VALUE", names)[0][0] == "  "
    assert parse_rows("no rows here", names) == []


async def wait_for(pilot, predicate, description: str, attempts: int = 150, delay: float = 0.02) -> None:
    """Bounded real-delay pump-until (the filter debounce needs wall time)."""
    for _ in range(attempts):
        await pilot.pause(delay)
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


def need(root, selector: str, kind=None):
    """The one widget ``selector`` names, or a named assertion failure."""
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    if kind is not None:
        assert isinstance(found[0], kind), f"{selector}: expected {kind.__name__}, got {type(found[0]).__name__}"
    return found[0]


def plain(widget) -> str:
    """The painted plain text of a static-like widget."""
    rendered = widget.render()
    text = getattr(rendered, "plain", None)
    return text if text is not None else str(rendered)


def sheet_text(panel) -> str:
    """Every static-like line the sheet paints (header, rows, detail, formula bar), as plain text."""
    sheet = need(panel, SHEET)
    parts = []
    for widget in sheet.query("*"):
        if isinstance(widget, Input) or not hasattr(widget, "render") or not widget.display:
            continue
        if list(widget.children):
            continue
        parts.append(plain(widget))
    return "\n".join(parts)


def parse_rows(text: str, names) -> list[tuple[str, str, str]]:
    """(mark, parameter name, full line) of each sheet row in ``text``, in painted order; a name clipped with ``…``
    is matched by its start against the A2L's names. Header and detail lines match no name and are skipped."""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        # CTX-PE-DEF `mark`: the first two cells of a row line (E4 integration: was one stripped glyph,
        # which lost the name of a selected staged or pending row, `▶●NAME`).
        mark = line[:2].ljust(2)
        if any(ch not in MARKS + " " for ch in mark):
            continue
        rest = line[2:]
        # a clipped name fills its cell and ends in `…`, so the next cell may follow it with no space
        token = rest.split()[0].split("…")[0].split("│")[0] if rest.split() else ""
        if len(token) < 4:
            continue
        hits = [n for n in names if n.startswith(token)]
        if len(hits) == 1:
            rows.append((mark, hits[0], line))
    return rows


def body_rows(panel, names) -> list[tuple[str, str, str]]:
    return parse_rows(plain(need(panel, BODY)), names)


def row_names(panel, names) -> list[str]:
    return [name for _, name, _ in body_rows(panel, names)]


def selected(panel, names):
    """The one row carrying ``▶``, or None."""
    marked = [name for mark, name, _ in body_rows(panel, names) if mark[0] == "▶"]
    assert len(marked) <= 1, f"more than one selected row: {marked}"
    return marked[0] if marked else None


def row_line(panel, names, name: str) -> str:
    lines = [line for _, n, line in body_rows(panel, names) if n == name]
    assert len(lines) == 1, f"row {name}: expected one painted line, found {len(lines)}"
    return lines[0]


def row_mark(panel, names, name: str) -> str:
    """The row's state cell (cell 2 of the mark column): `●` staged, `◆` pending, else space."""
    marks = [mark for mark, n, _ in body_rows(panel, names) if n == name]
    assert len(marks) == 1, f"row {name}: expected one painted line, found {len(marks)}"
    return marks[0][1]


def subtitles(app) -> list[str]:
    """Every border subtitle painted in the Patch Editor (the ledger subtitle moved to LANDS IN, R-PE.41)."""
    found = []
    for widget in app.query_one("#patch_editor_panel").query("*"):
        sub = getattr(widget, "border_subtitle", None)
        if sub:
            found.append(str(sub))
    return found


def document_entries(app) -> list:
    return list(app._change_service.document.entries)


def model_encode(app, name: str, text: str, image=None):
    """What I-2 encodes ``text`` to for ``name`` over the app's own A2L and image (or ``image``)."""
    a2l = app.current_file.a2l_data
    definition = model.describe_definition(name, a2l)
    return definition, a2l, model.encode_definition(
        definition, a2l, text, image if image is not None else app.current_file.mem_map
    )


async def focus_filter_and_type(pilot, panel, text: str) -> None:
    need(panel, FILTER, Input).focus()
    await settle(pilot, 2)
    await pilot.press(*text)


async def tab_to(pilot, app, widget_id: str, limit: int = 25) -> None:
    """Move the focus with Tab, as the operator does, until ``widget_id`` holds it."""
    for _ in range(limit):
        if app.focused is not None and app.focused.id == widget_id:
            return
        await pilot.press("tab")
        await settle(pilot, 1)
    assert app.focused is not None and app.focused.id == widget_id, (
        f"Tab never reached #{widget_id} in {limit} presses; focus is on {getattr(app.focused, 'id', app.focused)!r}"
    )


async def select_row(pilot, panel, names, target: str, limit: int = 30) -> None:
    """Press down (or up) on the sheet until ``target`` carries ``▶``."""
    order = row_names(panel, names)
    assert target in order, f"{target} is not on the painted page {order}"
    # A stage leaves the focus in the formula input (I-8.4 select_after: focus unchanged), and up/down move
    # rows only while the sheet holds the focus (R-PE-DEF.45): the operator first goes back with Escape
    # (R-PE-DEF.48). E4 integration, test side: the reader pressed arrows into the input.
    if getattr(pilot.app.focused, "id", None) == "patch_sheet_input":
        await pilot.press("escape")
        await settle(pilot, 2)
        # Inc 9 (E4 integration, test side): a stage advances onto the next row; when that row is a bench row,
        # Escape in its op input gives the bench the focus (R-PE-BENCH.47) and the arrows move the bench cursor,
        # so the operator presses Escape once more to reach the rows (R-PE-BENCH.46).
        state = getattr(need(panel, SHEET), "states", {}).get(selected(panel, names))
        if state is not None and state.focus:
            await pilot.press("escape")
            await settle(pilot, 2)
    for _ in range(limit):
        current = selected(panel, names)
        if current == target:
            return
        key = "down" if current is None or order.index(current) < order.index(target) else "up"
        await pilot.press(key)
        await settle(pilot, 2)
    assert selected(panel, names) == target, f"could not select {target}: selected {selected(panel, names)}"


async def open_sheet(
    pilot, app, panel, names, filter_text: str = "_0001", present: str = "DISPLAY_0001", absent: str = "CURVE_DEF_0002"
) -> list[str]:
    """Filter the picker, wait for the page (``present`` painted, ``absent`` gone), Tab to the sheet; return the
    painted row order."""
    assert list(panel.query(BODY)), f"{BODY}: the staging sheet is not mounted in the Patch Editor"
    await focus_filter_and_type(pilot, panel, filter_text)
    await wait_for(
        pilot,
        lambda: bool(list(panel.query(BODY)))
        and present in row_names(panel, names)
        and absent not in row_names(panel, names),
        f"the sheet paints the page of filter {filter_text!r}",
    )
    await tab_to(pilot, app, "patch_sheet_body")
    return row_names(panel, names)


async def stage_by_keys(pilot, app, panel, names, target: str, text: str) -> None:
    """The operator's stage: select ``target``, Enter, type ``text``, Enter."""
    await select_row(pilot, panel, names, target)
    await pilot.press("enter")
    await settle(pilot, 2)
    assert app.focused is not None and app.focused.id == "patch_sheet_input", (
        f"Enter on the sheet must move the focus to the formula input; focus is on {getattr(app.focused, 'id', None)!r}"
    )
    if text:
        await pilot.press(*text)
        await settle(pilot, 2)
    await pilot.press("enter")
    await settle(pilot, 4)


# --------------------------------------------------------------------------- #
# AT-B103-I8-1 — the whole stage chain
# --------------------------------------------------------------------------- #


def test_at_b103_i8_1_filter_page_row_formula_stage_advances_and_marks_dirty(tmp_path: Path, defc, monkeypatch) -> None:
    """AT-B103-I8-1 (US-103-05; R-PE-DEF.10/2, .22, .23/1, .40/1, .45, .46, .50/1, .53/1, .58/1, .60/1, .82/2,
    R-PE.34/1, R-PE.41/2 and /4).

    Filter `_0001` -> the page's rows -> Tab to the sheet -> down to DISPLAY_0001 -> Enter -> type `25.5` -> the tail
    reads in-limits -> Enter stages: the ledger holds the model's entry, the status line names it, the selection
    moved to the next row, DISPLAY_0001 shows `●` and its staged text, the input is empty again, the ledger
    subtitle shows one entry and the dirty mark.
    """
    statuses = record_statuses(monkeypatch)
    names = defc["names"]

    async def body(app, pilot, panel):
        order = await open_sheet(pilot, app, panel, names)
        # before the trigger: nothing staged, not dirty (the controls of the after-state below)
        before = (len(document_entries(app)), need(panel, LEDGER, DataTable).row_count, list(subtitles(app)))
        marks_before = [m[0] for m, _, _ in body_rows(panel, names)]
        first = selected(panel, names)
        await select_row(pilot, panel, names, "DISPLAY_0001")
        await pilot.press("enter")
        await settle(pilot, 2)
        focus_after_enter = app.focused.id if app.focused is not None else None
        await pilot.press(*"25.5")
        await settle(pilot, 3)
        tail_text = sheet_text(panel)
        typed = need(panel, INPUT, Input).value
        await pilot.press("enter")
        await settle(pilot, 4)
        after = {
            "entries": document_entries(app),
            "ledger_rows": need(panel, LEDGER, DataTable).row_count,
            "subtitles": subtitles(app),
            "selected": selected(panel, names),
            "display_mark": row_mark(panel, names, "DISPLAY_0001"),
            "display_line": row_line(panel, names, "DISPLAY_0001"),
            "input": need(panel, INPUT, Input).value,
        }
        # re-select the staged row: the pending text is cleared (R-PE-DEF.82/2)
        await select_row(pilot, panel, names, "DISPLAY_0001")
        reselected_input = need(panel, INPUT, Input).value
        definition, a2l, encoded = model_encode(app, "DISPLAY_0001", "25.5")
        return order, before, marks_before, first, focus_after_enter, typed, tail_text, after, reselected_input, encoded

    order, before, marks_before, first, focus_after_enter, typed, tail_text, after, reselected_input, encoded = run(
        tmp_path, defc, body
    )
    assert isinstance(encoded, model.Encoded), encoded
    # R-PE-DEF.10/2: one row per parameter of the filtered page, in page order, DISPLAY_0001 among them with a successor
    assert "DISPLAY_0001" in order and order.index("DISPLAY_0001") < len(order) - 1, order
    expected = {n for n in names if "_0001" in n}
    assert {n for n in expected if not n.startswith("AXIS")} <= set(order) <= expected, (order, expected)
    # R-PE-DEF.22: exactly one marked row at start, the first
    assert first == order[0] and marks_before.count("▶") == 1, (first, marks_before)
    assert before[0] == 0 and before[1] == 0 and not any("●" in s for s in before[2]), before
    # R-PE-DEF.46
    assert focus_after_enter == "patch_sheet_input", focus_after_enter
    # R-PE-DEF.40/1 (the wording `✓ in limits` is the tail's pinned phrase)
    assert typed == "25.5", typed
    assert "✓ in limits" in tail_text, tail_text
    # R-PE-DEF.50/1, .53/1: the entry is the model's span, symbol and type
    assert len(after["entries"]) == 1, after["entries"]
    entry = after["entries"][0]
    assert entry.address == encoded.address and tuple(entry.encoded_bytes) == tuple(encoded.data), (entry, encoded)
    assert entry.symbol == "DISPLAY_0001" and entry.entry_type == "bytes", entry
    assert after["ledger_rows"] == 1, after["ledger_rows"]
    # R-PE-DEF.58/1: the status line
    want = f"Patch Editor: DISPLAY_0001 staged as 25.5 ({len(encoded.data)} B at 0x{encoded.address:X})."
    assert want in statuses, (want, statuses[-4:])
    # R-PE-DEF.60/1: the selection advanced to the row after DISPLAY_0001
    assert after["selected"] == order[order.index("DISPLAY_0001") + 1], (after["selected"], order)
    # R-PE-DEF.23/1: staged mark and staged text in the row
    assert after["display_mark"] == "●", after["display_line"]
    assert "25.5" in after["display_line"], after["display_line"]
    # R-PE-DEF.82/2: the pending text is cleared
    assert after["input"] == "" and reselected_input == "", (after["input"], reselected_input)
    # R-PE.41/2, /4 and R-PE.34/1: the ledger subtitle with the dirty mark
    assert "1 entry ●" in after["subtitles"], after["subtitles"]


# --------------------------------------------------------------------------- #
# AT-B103-I8-2 — Escape stays in the sheet
# --------------------------------------------------------------------------- #


def test_at_b103_i8_2_escape_in_the_formula_input_stays_in_the_sheet(tmp_path: Path, defc) -> None:
    """AT-B103-I8-2 (R-PE-DEF.48/1, R-PE-DEF.46/1): with `25.5` typed and its preview shown, Escape returns the focus
    to the sheet body, clears the pending text (no staged text and no Δ in the row, the input empty), leaves the
    document alone, and the Patch Editor is still the screen shown (Escape is not the screen's back action).
    """
    names = defc["names"]

    async def body(app, pilot, panel):
        await open_sheet(pilot, app, panel, names)
        await select_row(pilot, panel, names, "DISPLAY_0001")
        await pilot.press("enter")
        await settle(pilot, 2)
        await pilot.press(*"25.5")
        await settle(pilot, 3)
        pending_line = row_line(panel, names, "DISPLAY_0001")
        stack_before = len(app.screen_stack)
        await pilot.press("escape")
        await settle(pilot, 4)
        return {
            "pending_line": pending_line,
            "line": row_line(panel, names, "DISPLAY_0001"),
            "focus": app.focused.id if app.focused is not None else None,
            "input": need(panel, INPUT, Input).value,
            "entries": len(document_entries(app)),
            "stack": (stack_before, len(app.screen_stack)),
            "shown": is_displayed(panel),
            "selected": selected(panel, names),
        }

    got = run(tmp_path, defc, body)
    assert "25.5" in got["pending_line"], got["pending_line"]       # the pending preview is painted before Escape
    assert got["focus"] == "patch_sheet_body", got["focus"]
    assert got["input"] == "", got["input"]
    assert "25.5" not in got["line"], got["line"]                   # New back to `·`, no preview
    assert "·" in got["line"], got["line"]
    assert got["entries"] == 0, got["entries"]
    assert got["stack"][0] == got["stack"][1] and got["shown"], got
    assert got["selected"] == "DISPLAY_0001", got["selected"]       # still the selected row


# --------------------------------------------------------------------------- #
# AT-B103-I8-3 — arrow keys
# --------------------------------------------------------------------------- #


def test_at_b103_i8_3_arrow_keys_select_rows_and_choose_enum_entries(tmp_path: Path, defc, monkeypatch) -> None:
    """AT-B103-I8-3 (R-PE-DEF.22/2, .45/1-4, .46/1, .47/1-3, .50/2, .58/2, .23/3): up/down move the one `▶` (up on
    the first row keeps it); on ENUM_0001 right/left choose the next/previous table entry and write its text into the
    formula input (right on the last entry keeps it); Enter, Enter stages the chosen entry as the model's byte.
    """
    statuses = record_statuses(monkeypatch)
    names = defc["names"]

    async def body(app, pilot, panel):
        order = await open_sheet(pilot, app, panel, names)
        seen = [selected(panel, names)]
        for key in ("down", "down", "up", "up", "up", "up"):
            await pilot.press(key)
            await settle(pilot, 2)
            seen.append(selected(panel, names))
        await select_row(pilot, panel, names, "ENUM_0001")
        a2l_data = app.current_file.a2l_data
        enum_def = model.describe_definition("ENUM_0001", a2l_data)
        texts = [e.text for e in enum_def.enum_entries]
        current = model.decode_definition(enum_def, a2l_data, app.current_file.mem_map)
        current_word = current.text.split()[-1]
        inp = need(panel, INPUT, Input)
        chosen = []
        for key in ("right", "right", "right", "left"):
            await pilot.press(key)
            await settle(pilot, 2)
            chosen.append(inp.value)
        await pilot.press("enter")
        await settle(pilot, 2)
        focus_in = app.focused.id if app.focused is not None else None
        await pilot.press("enter")
        await settle(pilot, 4)
        _, _, encoded = model_encode(app, "ENUM_0001", chosen[-1])
        return (order, seen, texts, current_word, chosen, focus_in, document_entries(app), encoded,
                row_line(panel, names, "ENUM_0001"))

    order, seen, texts, current_word, chosen, focus_in, entries, encoded, enum_line = run(tmp_path, defc, body)
    assert len(order) >= 3, order
    # R-PE-DEF.45: down, down, up, then three ups: row 1 is kept at the top
    assert seen == [order[0], order[1], order[2], order[1], order[0], order[0], order[0]], (seen, order)
    # R-PE-DEF.47: from the entry the image holds, right twice and once more (no wrap), then left once
    start = texts.index(current_word)
    want = [texts[min(start + 1, len(texts) - 1)]]
    want.append(texts[min(start + 2, len(texts) - 1)])
    want.append(texts[min(start + 3, len(texts) - 1)])
    last = texts.index(want[-1])
    want.append(texts[last - 1])
    assert chosen == want, (chosen, want, texts)
    assert focus_in == "patch_sheet_input", focus_in
    # R-PE-DEF.50/2, .23/3: the staged entry is the model's encoding of the chosen text
    assert isinstance(encoded, model.Encoded), encoded
    assert len(entries) == 1 and entries[0].address == encoded.address and tuple(entries[0].encoded_bytes) == tuple(encoded.data), (
        entries,
        encoded,
    )
    assert chosen[-1] in enum_line, (chosen[-1], enum_line)
    want_status = f"Patch Editor: ENUM_0001 staged as {chosen[-1]} ({len(encoded.data)} B at 0x{encoded.address:X})."
    assert want_status in statuses, (want_status, statuses[-4:])


# --------------------------------------------------------------------------- #
# AT-B103-I8-4 — paste over 4,096 characters
# --------------------------------------------------------------------------- #


def test_at_b103_i8_4_paste_over_4096_characters_is_refused(tmp_path: Path, defc) -> None:
    """AT-B103-I8-4 (R-PE-DEF.42/1, /2): a paste that would make the formula text longer than 4,096 characters
    leaves the text unchanged (the whole paste is refused); a paste of exactly 4,096 characters is accepted
    (control: the refusal is not "always refuse"). The paste is a posted ``events.Paste`` on the focused input; the
    real Windows Terminal bracketed paste is manual item M-2.
    """
    names = defc["names"]

    async def body(app, pilot, panel):
        await open_sheet(pilot, app, panel, names)
        await select_row(pilot, panel, names, "DISPLAY_0001")
        await pilot.press("enter")
        await settle(pilot, 2)
        inp = need(panel, INPUT, Input)
        results = {}
        inp.post_message(events.Paste("9" * 65536))
        await settle(pilot, 4)
        results["huge_into_empty"] = len(inp.value)
        inp.post_message(events.Paste("1" * MAX_FORMULA))
        await settle(pilot, 4)
        results["exactly_4096"] = len(inp.value)
        inp.value = ""
        await settle(pilot, 2)
        inp.value = "1" * 4000
        await settle(pilot, 2)
        inp.post_message(events.Paste("2" * 200))
        await settle(pilot, 4)
        results["200_onto_4000"] = (len(inp.value), inp.value == "1" * 4000)
        return results

    got = run(tmp_path, defc, body)
    assert got["huge_into_empty"] == 0, got
    assert got["exactly_4096"] == MAX_FORMULA, got
    assert got["200_onto_4000"] == (4000, True), got


# --------------------------------------------------------------------------- #
# AT-B103-I8-5 — no A2L
# --------------------------------------------------------------------------- #


def test_at_b103_i8_5a_no_a2l_shows_the_load_line(tmp_path: Path, defc) -> None:
    """AT-B103-I8-5a (R-PE-DEF.14/1): with no A2L loaded the sheet's only content is the load line."""

    async def body(app, pilot, panel):
        await wait_for(pilot, lambda: bool(list(panel.query(BODY))), "the sheet is composed")
        await wait_for(pilot, lambda: NO_A2L_LINE in sheet_text(panel), "the load line")
        return sheet_text(panel), len(document_entries(app))

    text, entries = run(tmp_path, defc, body, a2l=False, image=False)
    assert NO_A2L_LINE in text, text
    assert entries == 0


def test_at_b103_i8_5b_a2l_unloaded_before_enter_stages_nothing(tmp_path: Path, defc, monkeypatch) -> None:
    """AT-B103-I8-5b (R-PE-DEF.63/1): `25.5` typed for DISPLAY_0001, the A2L unloaded (the loaded-artifacts unload
    action), Enter -> `Patch Editor: no A2L is loaded — nothing staged.`, document and dirty flag unchanged.
    """
    statuses = record_statuses(monkeypatch)
    names = defc["names"]

    async def body(app, pilot, panel):
        await open_sheet(pilot, app, panel, names)
        await select_row(pilot, panel, names, "DISPLAY_0001")
        await pilot.press("enter")
        await settle(pilot, 2)
        await pilot.press(*"25.5")
        await settle(pilot, 3)
        # E4 integration (AT-B103-I8-5b reachability, test-at finding 2): once the unload repaints the sheet with the
        # no-A2L line (R-PE-DEF.14) the input is disabled, so a later Enter never reaches a stage. The stage
        # that still acts is the one already posted: Enter's StageRequested is queued, then the A2L is
        # unloaded before the app handles it (R-PE-DEF.63 "when a stage acts").
        from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet

        need(panel, SHEET).post_message(StagingSheet.StageRequested("DISPLAY_0001", "25.5"))
        app._apply_unload("a2l")
        await settle(pilot, 4)
        disabled = need(panel, INPUT, Input).disabled
        return len(document_entries(app)), list(subtitles(app)), disabled

    entries, subs, disabled = run(tmp_path, defc, body)
    assert disabled, "R-PE-DEF.14: after the unload the sheet shows the no-A2L line and the input is disabled"
    assert NO_A2L_STAGE in statuses, statuses[-6:]
    assert entries == 0, entries
    assert not any("●" in s for s in subs), subs


# --------------------------------------------------------------------------- #
# AT-B103-I8-7 — refusals (also the control of AT-1)
# --------------------------------------------------------------------------- #


def test_at_b103_i8_7_refused_formula_stages_nothing(tmp_path: Path, defc, monkeypatch) -> None:
    """AT-B103-I8-7 (R-PE-DEF.56/1-3, .57/1-3, .27/1, R-PE.35/1-2) — negative control of AT-1's readers.

    `abc` and `250` on DISPLAY_0001, `WALK` on ENUM_0001: Enter stages nothing (ledger, document, `●` mark, subtitle
    unchanged and not dirty), the status line is `Patch Editor: <I-2 message>`, the message taken from the model; after
    one good stage (dirty) a later refusal leaves the dirty mark set.
    """
    statuses = record_statuses(monkeypatch)
    names = defc["names"]

    async def body(app, pilot, panel):
        await open_sheet(pilot, app, panel, names)
        results = {}
        for name, text in (("DISPLAY_0001", "abc"), ("DISPLAY_0001", "250"), ("ENUM_0001", "WALK")):
            await stage_by_keys(pilot, app, panel, names, name, text)
            _, _, refusal = model_encode(app, name, text)
            results[(name, text)] = {
                "message": getattr(refusal, "message", None),
                "entries": len(document_entries(app)),
                "ledger": need(panel, LEDGER, DataTable).row_count,
                "dirty": any("●" in s for s in subtitles(app)),
                "mark": row_mark(panel, names, name),
                "line": row_line(panel, names, name),
                "focus": app.focused.id if app.focused is not None else None,
            }
            await pilot.press("escape")
            await settle(pilot, 3)
        # one good stage sets dirty; the next refusal keeps it set (R-PE.35/2)
        await stage_by_keys(pilot, app, panel, names, "DISPLAY_0001", "25.5")
        dirty_after_good = any("●" in s for s in subtitles(app))
        await stage_by_keys(pilot, app, panel, names, "DISPLAY_0001", "abc")
        results["after_good"] = (
            dirty_after_good,
            any("●" in s for s in subtitles(app)),
            len(document_entries(app)),
        )
        return results

    got = run(tmp_path, defc, body)
    for key in (("DISPLAY_0001", "abc"), ("DISPLAY_0001", "250"), ("ENUM_0001", "WALK")):
        result = got[key]
        assert result["message"], (key, result)
        assert f"Patch Editor: {result['message']}" in statuses, (key, result["message"], statuses[-6:])
        assert result["entries"] == 0 and result["ledger"] == 0, (key, result)
        assert result["dirty"] is False, (key, result)
        assert result["mark"] != "●", (key, result["line"])
    assert "✗ refused" in got[("DISPLAY_0001", "250")]["line"], got[("DISPLAY_0001", "250")]["line"]  # R-PE-DEF.27/1
    good_dirty, still_dirty, entries = got["after_good"]
    assert good_dirty is True and still_dirty is True and entries == 1, got["after_good"]


# --------------------------------------------------------------------------- #
# AT-B103-I8-8 — two masked fields of one word
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "order",
    [
        pytest.param((("MASK_FIELD_0001", "255"), ("MASK_BIT_0001", "0")), id="field_then_bit"),
        pytest.param((("MASK_BIT_0001", "0"), ("MASK_FIELD_0001", "255")), id="bit_then_field"),
    ],
)
def test_at_b103_i8_8_two_masked_fields_stage_over_the_overlay(tmp_path: Path, defc, order, monkeypatch) -> None:
    """AT-B103-I8-8 (R-PE-DEF.51/1-2, .52/2, .54/1): the two masked fields of one word staged in either order and
    applied both decode as typed (`255` and `0`); the document holds one entry at the word's address, keeping the first
    staged field's symbol; the word is what the model computes by encoding the two texts one over the other
    (expected `1F F6` of E1's example, not retyped).
    """
    statuses = record_statuses(monkeypatch)
    names = defc["names"]

    async def body(app, pilot, panel):
        await open_sheet(pilot, app, panel, names, filter_text="MASK", present="MASK_FIELD_0001", absent="DISPLAY_0001")
        image0 = dict(app.current_file.mem_map)
        for name, text in order:
            await stage_by_keys(pilot, app, panel, names, name, text)
        entries = document_entries(app)
        need(panel, APPLY, Button).press()
        await wait_for(
            pilot, lambda: any(re.search(r"Apply: [1-9]\d* applied", s) for s in statuses), "the Apply status line"
        )
        await settle(pilot, 4)
        applied = dict(app.current_file.mem_map)
        # expected word: the model, one encode over the other, starting from the original image
        scratch = dict(image0)
        decoded_after = {}
        for name, text in order:
            definition, a2l, encoded = model_encode(app, name, text, scratch)
            assert isinstance(encoded, model.Encoded), (name, encoded)
            scratch.update({encoded.address + i: b for i, b in enumerate(encoded.data)})
        a2l = app.current_file.a2l_data
        for name, _ in order:
            definition = model.describe_definition(name, a2l)
            decoded_after[name] = model.decode_definition(definition, a2l, applied)
        return entries, applied, scratch, decoded_after

    entries, applied, scratch, decoded_after = run(tmp_path, defc, body)
    first_name = order[0][0]
    assert len(entries) == 1, entries
    assert entries[0].symbol == first_name, entries[0]                       # R-PE-DEF.54/1
    word_address = entries[0].address
    span = range(word_address, word_address + len(entries[0].encoded_bytes))
    assert [applied[a] for a in span] == [scratch[a] for a in span], ([applied[a] for a in span], [scratch[a] for a in span])
    for name, text in order:                                                  # R-PE-DEF.51: both decode as typed
        got = decoded_after[name]
        assert isinstance(got, model.Decoded) and got.text.split()[0] == text, (name, got)


# --------------------------------------------------------------------------- #
# AT-B103-I8-9 — a filter that matches nothing
# --------------------------------------------------------------------------- #


def test_at_b103_i8_9_filter_matching_nothing_shows_the_line(tmp_path: Path, defc) -> None:
    """AT-B103-I8-9 (R-PE-DEF.13/1): a filter no parameter matches leaves the sheet with the type-a-filter line and no
    row; clearing it brings the rows back (control: the line is not stuck)."""
    names = defc["names"]

    async def body(app, pilot, panel):
        await wait_for(pilot, lambda: bool(row_names(panel, names)), "the unfiltered page")
        await focus_filter_and_type(pilot, panel, "zzzz")
        await wait_for(pilot, lambda: NO_PAGE_LINE in sheet_text(panel), "the no-match line")
        none_rows = row_names(panel, names)
        need(panel, FILTER, Input).value = ""
        await wait_for(pilot, lambda: bool(row_names(panel, names)), "the rows are back")
        return none_rows, NO_PAGE_LINE in sheet_text(panel)

    none_rows, line_stuck = run(tmp_path, defc, body)
    assert none_rows == [], none_rows
    assert line_stuck is False
