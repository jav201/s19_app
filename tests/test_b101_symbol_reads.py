"""batch-101 Inc 4 - documents resolve their symbols through the loaded A2L.

Written by the independent tester (E4) from the approved design only:
``inc-4/01-requirements.md`` (rows and thresholds), ``02-test-cases.md`` (the
cases and their expected results), ``codewire/graph-inc4.md`` (examples),
``E1-rulings.md`` and ``E3-rulings.md`` (rulings that bind the tests). No line
of the Inc 4 implementation was read to decide what to assert.

Covers (one test per case of ``02-test-cases.md``; the case id is in each
docstring):
  - R-CHG-SYM.9   - six session reads (file load, paste, whole-document Edit
                    JSON, per-entry Edit JSON, Check Editor pick, A2B Diff
                    pick) resolve symbol entries through the loaded A2L.
  - R-CHG-SYM.10  - the same six reads with no A2L loaded declare none (the
                    negative control; holds on the base revision).
  - R-CHG-SYM.11  - a variant run (service level, Execute scope by keys, the
                    project report run) declares the project's A2L file.
  - R-CHG-SYM.12  - a project with no A2L file declares none (holds on base).
  - R-CHG-SYM.13  - the tag-name index is built once per read (call counter)
                    and a 1 000-entry read of a 220 040-tag A2L is bounded.
  - R-TUI-058.9   - the per-entry confirm refused for want of an A2L ends on
                    the plain-language line, and only then.

Oracles are observable: the status log (every ``set_status`` message), the
entries table and the service document the handlers produced, the painted
panel status, the bytes of the patched file the product wrote (read with the
independent S19 reader), the report file, and the check aggregates. Waits poll
with ``tests/support/timing.py::wait_until``; no bare ``pilot.pause()`` is
counted as a wait. Every case runs on the LAN Linux host (operator rule); the
timing arms carry ``serial_timing`` and report their margin through
``report_margin``.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402
from s19_app.tui.changes import io as io_mod  # noqa: E402
from s19_app.tui.changes.io import parse_change_document  # noqa: E402
from s19_app.tui.services import variant_execution_service as ves  # noqa: E402
from s19_app.tui.workspace import build_variant_set, validate_project_files  # noqa: E402
from tests.support import b100_load_dialog as ld  # noqa: E402
from tests.support import b100_projects as projects  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402
from tests.support.independent_reader import read_s19  # noqa: E402
from tests.support.timing import report_margin, timing_bound, wait_until  # noqa: E402

SEED = 20260001
SIZE_MB = 1.0

PATCH = "demo_patch.changes.json"
CHECK = "demo_check.chk.json"
CHECK_FAILS = "demo_check_fails.chk.json"

EM = "—"
NO_CTX = "no A2L context is declared for this change-set"
UNRESOLVED = "CHG-SYMBOL-UNRESOLVED"
LOADED_7 = "Loaded change: 7 entries, 0 error(s)"
REJECTED = "Patch Editor: entry edit rejected - see findings."
PLAIN = (
    "Patch Editor: the entry names an A2L symbol and no A2L is loaded - "
    "load the A2L, then edit the entry again."
)
EDIT_REFUSED_2 = (
    f"Edit JSON refused: change text carries 2 error(s) {EM} the document is unchanged."
)
ONE_ENTRY = '{"type": "bytes", "address": "0x100", "bytes": "01"}'


# ---------------------------------------------------------------------------
# Case 08 and small readers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def case08(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The release demo case, generated once (seed 20260001, 1.0 MB)."""
    folder = tmp_path_factory.mktemp("b101_case08")
    gen.generate(folder, SEED, SIZE_MB)
    return folder


def doc_json(case: Path, name: str) -> dict:
    return json.loads((case / name).read_text(encoding="utf-8"))


def doc_text(case: Path, name: str) -> str:
    return (case / name).read_text(encoding="utf-8")


def symbol_rows(case: Path, name: str) -> list:
    """``[(entry index, entry object), ...]`` of the entries naming a symbol."""
    return [
        (index, entry)
        for index, entry in enumerate(doc_json(case, name)["entries"])
        if "symbol" in entry
    ]


def entry_address(entry: dict) -> int:
    return int(entry["address"], 16)


def entry_data(entry: dict) -> bytes:
    return bytes.fromhex(entry["bytes"].replace(" ", ""))


def finding_no_ctx(index: int, symbol: str) -> str:
    """The painted R-CHG-SYM.2 finding line (no A2L declared)."""
    return (
        f"[{UNRESOLVED}] error: entry {index}: the symbol {symbol!r} cannot be "
        f"resolved {EM} {NO_CTX} {EM} the entry was skipped"
    )


def finding_no_tag(index: int, symbol: str) -> str:
    """The painted R-CHG-SYM.3 finding line (A2L declared, no such tag)."""
    return (
        f"[{UNRESOLVED}] error: entry {index}: the symbol {symbol!r} resolves "
        f"to no tag in the declared A2L {EM} the entry was skipped"
    )


def unresolved_lines(lines: list) -> list:
    return [line for line in lines if line.startswith(f"[{UNRESOLVED}]")]


# ---------------------------------------------------------------------------
# Session drivers
# ---------------------------------------------------------------------------


def run(tmp_path: Path, scenario, name: str = "app"):
    base = tmp_path / name
    base.mkdir(parents=True, exist_ok=True)

    async def _with_log(app, pilot, log):
        app._test_status_log = log  # read by the draft helper
        return await scenario(app, pilot, log)

    return projects.run_app(base, _with_log)


async def settle(pilot, count: int = 6) -> None:
    for _ in range(count):
        await pilot.pause()


async def lines_after(pilot, log, mark: int, done, what: str) -> list:
    """Wait until ``done(lines since mark)``; return those lines after a short
    flush, so a line that would follow the awaited one is also captured."""
    await wait_until(
        pilot,
        lambda: done(log.since(mark)),
        lambda: f"timed out waiting for {what}; lines: {log.since(mark)!r}",
    )
    await settle(pilot)
    return log.since(mark)


def stage(app, case: Path, *names: str) -> None:
    """Copy case documents into the common patches folder (before the screen
    that lists them is shown)."""
    patches = app._patches_dir()
    patches.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy(case / name, patches / name)


async def load_through_dialog(pilot, app, path: Path, until, what: str) -> None:
    """``l``, type the path, click Load - with a layout settle between the
    dialog opening and the click (a click on a dialog whose layout has not
    settled misses ``#load_path``)."""
    await pilot.press("l")
    await ld.wait_for_dialog(pilot, app)
    await wait_until(
        pilot,
        lambda: len(app.screen.query("#load_path")) > 0
        and app.screen.query_one("#load_path").region.width > 0,
        "timed out waiting for the Load dialog layout",
    )
    await settle(pilot, 4)
    await ld.type_into_path(pilot, app, str(path))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await wait_until(
        pilot,
        lambda: not ld.is_load_dialog(app.screen) and until(),
        f"timed out waiting for {what}",
    )
    await settle_workers(pilot)


async def attach_image(pilot, app, case: Path, *, by_dialog: bool = False) -> None:
    path = case / "firmware.s19"
    if by_dialog:
        await load_through_dialog(
            pilot,
            app,
            path,
            lambda: app.current_file is not None
            and app.current_file.path.name == "firmware.s19",
            "the image load",
        )
    else:
        await projects.load_image(pilot, app, path)


async def attach_a2l(pilot, app, case: Path) -> None:
    await load_through_dialog(
        pilot,
        app,
        case / "firmware.a2l",
        lambda: app.current_a2l_data is not None,
        "the A2L load",
    )


async def click(pilot, target, what: str) -> None:
    """A mouse click that must land on ``target`` (a selector or a widget)."""
    assert await pilot.click(target), f"click missed {what}"


async def unload_a2l(pilot, app, back: str | None = None) -> None:
    """Unload the A2L from the Workspace "Loaded" panel's ``[u]`` control
    (key ``1``, click the A2L slot's unload button); then, when ``back`` is
    given, press that rail key to return to the screen the case runs on."""
    from textual.widgets import Button

    await pilot.press("1")
    await wait_until(
        pilot,
        lambda: any(
            b.name == "a2l" and b.region.width > 0
            for b in app.query("Button.loaded-unload")
        ),
        "timed out waiting for the Loaded panel's A2L unload control",
    )
    (button,) = [b for b in app.query("Button.loaded-unload") if b.name == "a2l"]
    assert isinstance(button, Button)
    await click(pilot, button, "the Loaded panel's A2L [u]")
    await wait_until(
        pilot, lambda: app.current_a2l_data is None, "timed out waiting for the A2L unload"
    )
    await settle(pilot)
    if back is not None:
        await pilot.press(back)
        await settle(pilot)


async def pick_by_keys(pilot, app, select_id: str, value: str) -> None:
    """Pick ``value`` in a dropdown the way the operator does: click the
    dropdown open, move with the arrow keys, press enter (no ``Select.value``
    write)."""
    from textual.widgets import Select
    from textual.widgets._select import SelectCurrent, SelectOverlay

    select = app.query_one(select_id, Select)
    values = [option_value for _prompt, option_value in select._options]
    assert value in values, (value, values)
    target = values.index(value)
    # The click goes to the dropdown's face (``SelectCurrent``). The widget
    # under the mouse may be the face or one of its children (a compact face
    # has no border), and ``pilot.click`` reports a hit only for the exact
    # widget, so the hit is checked here by ancestry.
    face = select.query_one(SelectCurrent)
    under, _region = app.get_widget_at(face.region.x, face.region.y)
    assert under is face or face in under.ancestors, (select_id, under)
    await pilot.click(face)
    overlay = select.query_one(SelectOverlay)
    await wait_until(
        pilot,
        lambda: select.expanded and app.focused is overlay,
        f"timed out waiting for the {select_id} dropdown to open",
    )
    for _ in range(len(values) + 1):
        if overlay.highlighted == target:
            break
        current = -1 if overlay.highlighted is None else overlay.highlighted
        await pilot.press("down" if current < target else "up")
    assert overlay.highlighted == target, (overlay.highlighted, target, values)
    await pilot.press("enter")
    await wait_until(
        pilot,
        lambda: not select.expanded and select.value == value,
        f"timed out waiting for {select_id} to take {value!r}",
    )


async def paste_into(pilot, app, area_id: str, text: str) -> None:
    """Click the text area, select all (``f7``) and paste ``text`` through the
    app's paste event (the route a terminal paste takes)."""
    from textual import events
    from textual.widgets import TextArea

    area = app.screen.query_one(area_id, TextArea)
    await click(pilot, area, area_id)
    await wait_until(pilot, lambda: app.focused is area, f"timed out focusing {area_id}")
    await pilot.press("f7")
    app.post_message(events.Paste(text))
    await wait_until(
        pilot, lambda: area.text == text, f"timed out waiting for the paste into {area_id}"
    )


async def show_tab(pilot, app, tab: str, pane: str) -> None:
    """Click a Patch Editor inspector tab chip and wait for its pane."""
    await click(pilot, f"#{tab}", tab)
    await wait_until(
        pilot,
        lambda: app.query_one(f"#{pane}").region.width > 0,
        f"timed out waiting for #{pane} after the {tab} click",
    )
    await settle(pilot, 2)


async def show_screen(pilot, app, key: str, widget_id: str) -> None:
    await pilot.press(key)
    await wait_until(
        pilot,
        lambda: len(app.query(widget_id)) > 0,
        f"timed out waiting for {widget_id} after key {key!r}",
    )
    await settle(pilot)


def service(app):
    return app._change_service


def table_rows(app) -> int:
    from textual.widgets import DataTable

    return app.query_one("#patch_doc_entries_table", DataTable).row_count


async def install_draft(pilot, app, text: str, a2l_context=None) -> None:
    """Make ``text`` the pasted draft (source_path None) the operator's way:
    the JSON tab, a paste into the paste field, a click on Parse paste.

    E5 corrective (C-6, BB-3/BB-4): the draft used to be installed through the
    service seam with an explicit context. The paste reads with the session's
    A2L (R-CHG-SYM.9 alternative 2 / R-CHG-SYM.10), so ``a2l_context`` is now a
    precondition check: it must be the A2L the session holds."""
    assert a2l_context is app.current_a2l_data, "the paste reads the session A2L"
    log = app._test_status_log
    await show_tab(pilot, app, "patch_tab_json", "patch_paste_text")
    await paste_into(pilot, app, "#patch_paste_text", text)
    mark = len(log.messages)
    await click(pilot, "#patch_paste_parse_button", "Parse paste")
    lines = await lines_after(
        pilot, log, mark,
        lambda ls: any(line.startswith("Loaded change:") for line in ls),
        "the draft's paste parse",
    )
    assert unresolved_lines(lines) == [], lines
    assert service(app).document is not None


def entry_state(entry) -> tuple:
    return (entry.entry_type, entry.address, tuple(entry.encoded_bytes), entry.symbol)


async def entry_json_confirm(pilot, app, log, row: int, replacement=None) -> list:
    """Choose ``row`` in the ledger by keys, open the per-entry JSON popup with
    a click, optionally replace its text by a paste, click Confirm, and return
    the status lines the confirm painted."""
    from textual.widgets import Button, DataTable

    from s19_app.tui.screens import EntryJsonScreen

    await show_tab(pilot, app, "patch_tab_inspector", "patch_entry_edit_json_button")
    table = app.query_one("#patch_doc_entries_table", DataTable)
    await click(pilot, table, "the ledger")
    await wait_until(pilot, lambda: app.focused is table, "timed out focusing the ledger")
    for _ in range(table.row_count + 1):
        if table.cursor_row == row:
            break
        await pilot.press("down" if table.cursor_row < row else "up")
        await settle(pilot, 1)
    assert table.cursor_row == row, (table.cursor_row, row)
    await settle(pilot, 2)
    button = app.query_one("#patch_entry_edit_json_button", Button)
    await wait_until(pilot, lambda: not button.disabled, "timed out: per-entry Edit JSON disabled")
    await click(pilot, button, "per-entry Edit JSON")

    def _ready() -> bool:
        if not isinstance(app.screen, EntryJsonScreen):
            return False
        return len(app.screen.query("#entry_json_confirm")) > 0

    await wait_until(pilot, _ready, "timed out waiting for the per-entry JSON popup")
    await settle(pilot, 2)
    if replacement is not None:
        await paste_into(pilot, app, "#entry_json_text", replacement)
    mark = len(log.messages)
    await click(pilot, "#entry_json_confirm", "the per-entry Confirm")
    await wait_until(
        pilot,
        lambda: not isinstance(app.screen, EntryJsonScreen),
        "timed out waiting for the per-entry popup to close",
    )
    await settle(pilot)
    return log.since(mark)


async def whole_document_confirm(pilot, app, log, replacement=None) -> list:
    """Click Edit JSON on the JSON tab (the popup is seeded from the paste
    buffer), optionally replace its text by a paste, click Confirm; return the
    lines painted."""
    from textual.widgets import Button

    from s19_app.tui.screens import ChangeSetJsonScreen

    await show_tab(pilot, app, "patch_tab_json", "patch_edit_json_button")
    button = app.query_one("#patch_edit_json_button", Button)
    await wait_until(pilot, lambda: not button.disabled, "timed out: Edit JSON disabled")
    await click(pilot, button, "Edit JSON")

    def _ready() -> bool:
        if not isinstance(app.screen, ChangeSetJsonScreen):
            return False
        return len(app.screen.query("#changeset_json_confirm")) > 0

    await wait_until(pilot, _ready, "timed out waiting for the whole-document popup")
    await settle(pilot, 2)
    if replacement is not None:
        await paste_into(pilot, app, "#changeset_json_text", replacement)
    mark = len(log.messages)
    await click(pilot, "#changeset_json_confirm", "the whole-document Confirm")
    await wait_until(
        pilot,
        lambda: not isinstance(app.screen, ChangeSetJsonScreen),
        "timed out waiting for the whole-document popup to close",
    )
    await settle(pilot)
    await app.workers.wait_for_complete()
    await settle(pilot)
    return log.since(mark)


# ---------------------------------------------------------------------------
# R-CHG-SYM.9 - six session reads resolve through the loaded A2L
# ---------------------------------------------------------------------------


def test_r_chg_sym_9_patch_editor_file_load_resolves_symbols_through_the_loaded_a2l(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.9/1 (black-box): picking ``demo_patch`` in the Patch
    Editor File dropdown with the case-08 image and A2L loaded reports
    ``Loaded change: 7 entries, 0 error(s)`` and no finding line; the ledger
    lists 7 rows and the JSON view holds both symbols.

    Why: the shipped demo document must load as delivered (F-01). Negative
    control: the load passing no A2L paints ``5 entries, 2 error(s)`` and two
    finding lines (the base) -> RED. Drive (E5 C-6, BB-1): the dropdown is
    opened with a click and the file is picked with the arrow keys and enter."""
    from textual.widgets import TextArea

    symbols = [entry["symbol"] for _i, entry in symbol_rows(case08, PATCH)]
    assert len(symbols) == 2

    async def scenario(app, pilot, log):
        stage(app, case08, PATCH)
        await attach_image(pilot, app, case08, by_dialog=True)
        await attach_a2l(pilot, app, case08)
        await show_screen(pilot, app, "6", "#patch_doc_file_select")
        mark = len(log.messages)
        await pick_by_keys(pilot, app, "#patch_doc_file_select", PATCH)
        lines = await lines_after(
            pilot, log, mark,
            lambda ls: any(line.startswith("Loaded change:") for line in ls),
            "the Patch Editor file load",
        )
        rows = table_rows(app)
        await show_tab(pilot, app, "patch_tab_json", "patch_json_view")
        view = app.query_one("#patch_json_view", TextArea).text
        return lines, rows, view

    lines, rows, view = run(tmp_path, scenario)
    assert lines.count(LOADED_7) == 1, lines
    assert unresolved_lines(lines) == [], lines
    assert rows == 7, rows
    for symbol in symbols:
        assert f'"symbol": "{symbol}"' in view, (symbol, view)


def test_r_chg_sym_9_paste_resolves_symbols_through_the_loaded_a2l(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.9/2: pasting the text of ``demo_patch`` and pressing
    Parse paste with the A2L loaded reports ``Loaded change: 7 entries, 0
    error(s)``, no finding line, and the draft's symbol entries carry the
    tag spellings.

    Negative control: the paste arm passing no A2L -> 5 entries, 2 errors.
    Drive (E5 C-6, BB-2): the text is pasted into the paste field through the
    app's paste event and Parse paste is clicked."""
    rows = symbol_rows(case08, PATCH)

    async def scenario(app, pilot, log):
        await attach_image(pilot, app, case08)
        await attach_a2l(pilot, app, case08)
        await show_screen(pilot, app, "6", "#patch_paste_text")
        await show_tab(pilot, app, "patch_tab_json", "patch_paste_text")
        await paste_into(pilot, app, "#patch_paste_text", doc_text(case08, PATCH))
        mark = len(log.messages)
        await click(pilot, "#patch_paste_parse_button", "Parse paste")
        lines = await lines_after(
            pilot, log, mark,
            lambda ls: any(line.startswith("Loaded change:") for line in ls),
            "the paste parse",
        )
        entries = service(app).document.entries
        return lines, [entries[i].symbol if i < len(entries) else None for i, _e in rows], len(entries)

    lines, symbols, count = run(tmp_path, scenario)
    assert lines.count(LOADED_7) == 1, lines
    assert unresolved_lines(lines) == [], lines
    assert count == 7, count
    assert symbols == [entry["symbol"] for _i, entry in rows], symbols


def test_r_chg_sym_9_whole_document_edit_json_confirm_resolves_symbols(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.9/3: confirming the whole-document Edit JSON popup
    unchanged, with the A2L loaded and a 7-entry symbol draft, paints no
    ``Edit JSON refused`` line, paints ``Loaded change: 7 entries, 0
    error(s)`` once, and the draft keeps 7 entries with the symbols.

    Drive (E5 C-6, BB-3): the draft comes from a real paste and Parse paste
    click while the A2L is loaded; Edit JSON and Confirm are clicked.
    Negative control: the pre-check reading with no A2L refuses the confirm
    (the base) -> RED."""
    rows = symbol_rows(case08, PATCH)

    async def scenario(app, pilot, log):
        await attach_image(pilot, app, case08)
        await attach_a2l(pilot, app, case08)
        await show_screen(pilot, app, "6", "#patch_edit_json_button")
        await install_draft(pilot, app, doc_text(case08, PATCH), app.current_a2l_data)
        lines = await whole_document_confirm(pilot, app, log)
        entries = service(app).document.entries
        return lines, len(entries), [
            entries[i].symbol if i < len(entries) else None for i, _e in rows
        ]

    lines, count, symbols = run(tmp_path, scenario)
    assert [l for l in lines if l.startswith("Edit JSON refused")] == [], lines
    assert lines.count(LOADED_7) == 1, lines
    assert count == 7, count
    assert symbols == [entry["symbol"] for _i, entry in rows], symbols


def test_r_chg_sym_9_per_entry_edit_json_confirm_of_a_symbol_entry_succeeds(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.9/4: confirming the per-entry Edit JSON popup of a
    symbol entry unchanged, with the A2L loaded, paints no rejection line and
    no finding line; the entry equals its value before the edit and the draft
    keeps 7 entries. The success status text is not asserted (it is out of
    scope for this increment).

    Second confirm (E5 C-4, the "document is replaced" clause of R-CHG-SYM.9):
    the same entry confirmed with every byte changed and the length kept (so
    it still matches the tag) - entry 2 then holds the new bytes and keeps its
    symbol and address; 7 entries; no rejection, no finding line. A confirm
    that returns without replacing the document leaves the old bytes -> RED.

    Negative control: the confirm passing no A2L rejects the symbol entry
    with the no-context finding (the base) -> RED. Drive (E5 C-6, BB-4): a
    pasted draft, the row chosen with the arrow keys, Edit JSON and Confirm
    clicked, the replacement text pasted into the popup."""
    rows = symbol_rows(case08, PATCH)
    row, entry = rows[0]
    new_data = bytes(byte ^ 0x5A for byte in entry_data(entry))
    changed = json.dumps(dict(entry, bytes=" ".join(f"{b:02X}" for b in new_data)))

    async def scenario(app, pilot, log):
        await attach_image(pilot, app, case08)
        await attach_a2l(pilot, app, case08)
        await show_screen(pilot, app, "6", "#patch_entry_edit_json_button")
        await install_draft(pilot, app, doc_text(case08, PATCH), app.current_a2l_data)
        before = entry_state(service(app).document.entries[row])
        lines = await entry_json_confirm(pilot, app, log, row)
        entries = service(app).document.entries
        first = (lines, before, entry_state(entries[row]), len(entries))
        lines = await entry_json_confirm(pilot, app, log, row, changed)
        entries = service(app).document.entries
        return first, (lines, entry_state(entries[row]), len(entries))

    (lines, before, after, count), (changed_lines, replaced, changed_count) = run(
        tmp_path, scenario
    )
    assert REJECTED not in lines, lines
    assert unresolved_lines(lines) == [], lines
    assert after == before, (before, after)
    assert after[3] == entry["symbol"] and after[1] == entry_address(entry), after
    assert count == 7, count
    assert REJECTED not in changed_lines, changed_lines
    assert unresolved_lines(changed_lines) == [], changed_lines
    assert replaced == (before[0], before[1], tuple(new_data), entry["symbol"]), (
        before, replaced,
    )
    assert changed_count == 7, changed_count


def test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.9/5 (black-box): picking ``demo_check`` in the Check
    Editor Spec dropdown with the image and A2L loaded ends on ``Check Editor:
    loaded 'demo_check.chk.json' (3 fields).``; no ``spec NOT loaded`` line, no
    finding line; the collector holds 3 memory rows today (unlabelled rows -
    Inc 5 re-pins this count when it names them).

    E5 C-6 (R-CHG-SYM.9 "every symbol entry ... in the read document"): the
    collector row of the symbol entry shows that entry's address. The Check
    Editor keeps only address and size per row, so the tag's spelling is not
    observable on this surface (not-testable here; alternatives 1, 2, 3, 4 and
    6 assert the spelling).

    Negative control: the pick passing no A2L -> ``Check Editor: spec NOT
    loaded.`` (the base) -> RED. Drive (E5 C-6, BB-5): the Spec dropdown is
    opened with a click and the file is picked with the arrow keys and enter."""
    from textual.widgets import DataTable

    (check_index, check_entry), = symbol_rows(case08, CHECK)

    async def scenario(app, pilot, log):
        stage(app, case08, CHECK)
        await attach_image(pilot, app, case08, by_dialog=True)
        await attach_a2l(pilot, app, case08)
        await show_screen(pilot, app, "equals_sign", "#check_spec_file_select")
        mark = len(log.messages)
        await pick_by_keys(pilot, app, "#check_spec_file_select", CHECK)
        lines = await lines_after(
            pilot, log, mark,
            lambda ls: any(
                line.startswith("Check Editor:") and "NOT loaded" in line
                or line.startswith("Check Editor: loaded")
                for line in ls
            ),
            "the Check Editor spec pick",
        )
        table = app.query_one("#check_mem_table", DataTable)
        cells = [str(getattr(cell, "plain", cell)) for cell in table.get_row_at(check_index)]
        return lines, table.row_count, cells

    lines, rows, symbol_row = run(tmp_path, scenario)
    assert lines[-1] == f"Check Editor: loaded '{CHECK}' (3 fields).", lines
    assert "Check Editor: spec NOT loaded." not in lines, lines
    assert unresolved_lines(lines) == [], lines
    assert rows == 3, rows
    assert symbol_row[0] == f"0x{entry_address(check_entry):08X}", symbol_row


def test_r_chg_sym_9_ab_diff_check_spec_pick_resolves_symbols(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.9/6: picking ``demo_check`` in the A2B Diff check-spec
    dropdown with the image and A2L loaded paints the panel status ``Check
    spec 'demo_check.chk.json' loaded - 3 declared field(s) will ride the
    report.`` and stashes a 3-entry spec whose entry 2 carries the tag.

    Negative control: the pick passing no A2L paints ``Check spec not loaded -
    [CHG-SYMBOL-UNRESOLVED] ...`` and stashes nothing (the base) -> RED.
    Drive (E5 C-6, BB-6): the check-spec dropdown is opened with a click and
    the file is picked with the arrow keys and enter."""
    (index, entry), = symbol_rows(case08, CHECK)

    async def scenario(app, pilot, log):
        stage(app, case08, CHECK)
        await attach_image(pilot, app, case08)
        await attach_a2l(pilot, app, case08)
        await show_screen(pilot, app, "7", "#diff_check_select")
        await pick_by_keys(pilot, app, "#diff_check_select", CHECK)
        await wait_until(
            pilot,
            lambda: str(app.query_one("#diff_status").render()).startswith("Check spec"),
            lambda: f"timed out waiting for the diff status; got {str(app.query_one('#diff_status').render())!r}",
        )
        await settle(pilot)
        spec = app._diff_check_spec
        return (
            str(app.query_one("#diff_status").render()),
            None if spec is None else len(spec.entries),
            None if spec is None else spec.entries[index].symbol,
        )

    status, count, symbol = run(tmp_path, scenario)
    assert status == (
        f"Check spec '{CHECK}' loaded {EM} 3 declared field(s) will ride the report."
    ), status
    assert count == 3, count
    assert symbol == entry["symbol"], symbol


# ---------------------------------------------------------------------------
# R-CHG-SYM.10 - the same six reads with no A2L loaded declare none
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "surface",
    [
        "file-load",
        "paste",
        "edit-json",
        "entry-json",
        "check-editor",
        "ab-diff-project-a2l-not-implicit",
    ],
)
def test_r_chg_sym_10_reads_with_no_a2l_loaded_declare_none(
    tmp_path: Path, case08: Path, surface: str
) -> None:
    """Cases R-CHG-SYM.10/1 .. /6: each of the six session reads, with no A2L
    loaded, reads the document with no declared A2L: every symbol entry
    paints the no-context finding (2 for ``demo_patch``, 1 for each check
    document: the Check Editor arm picks ``demo_check`` and then
    ``demo_check_fails``, E5 C-6) and nothing resolves. The A2B Diff arm runs inside an open project whose
    folder holds ``firmware.a2l`` with the session A2L unloaded: the project's
    file is not used implicitly.

    Why: the no-implicit-A2L law (R-CHG-SYM.2). This is the negative control
    of the previous group; it holds on the base revision. Negative control of
    this group: a read that declares the last or the project's A2L when none is
    loaded paints 0 findings -> RED.

    Drive (E5 C-6): dropdowns are clicked open and picked with the arrow keys,
    the paste goes through the app's paste event, buttons are clicked, and the
    A2L is unloaded from the Workspace "Loaded" panel's control. The
    per-entry arm pins the full painted list, the R-TUI-058.9 line last (E5
    C-8)."""
    patch_rows = symbol_rows(case08, PATCH)
    (check_index, check_entry), = symbol_rows(case08, CHECK)
    (fails_index, fails_entry), = symbol_rows(case08, CHECK_FAILS)

    def two_findings(lines: list) -> None:
        assert sorted(unresolved_lines(lines)) == sorted(
            finding_no_ctx(i, e["symbol"]) for i, e in patch_rows
        ), lines

    async def scenario(app, pilot, log):
        stage(app, case08, PATCH, CHECK, CHECK_FAILS)
        await attach_image(pilot, app, case08)
        if surface == "file-load":
            await show_screen(pilot, app, "6", "#patch_doc_file_select")
            mark = len(log.messages)
            await pick_by_keys(pilot, app, "#patch_doc_file_select", PATCH)
            lines = await lines_after(
                pilot, log, mark,
                lambda ls: any(line.startswith("Loaded change:") for line in ls),
                "the file load",
            )
            assert "Loaded change: 5 entries, 2 error(s)" in lines, lines
            two_findings(lines)
        elif surface == "paste":
            await show_screen(pilot, app, "6", "#patch_paste_text")
            await show_tab(pilot, app, "patch_tab_json", "patch_paste_text")
            await paste_into(pilot, app, "#patch_paste_text", doc_text(case08, PATCH))
            mark = len(log.messages)
            await click(pilot, "#patch_paste_parse_button", "Parse paste")
            lines = await lines_after(
                pilot, log, mark,
                lambda ls: any(line.startswith("Loaded change:") for line in ls),
                "the paste parse",
            )
            assert "Loaded change: 5 entries, 2 error(s)" in lines, lines
            two_findings(lines)
        elif surface in ("edit-json", "entry-json"):
            await attach_a2l(pilot, app, case08)
            await show_screen(pilot, app, "6", "#patch_edit_json_button")
            await install_draft(pilot, app, doc_text(case08, PATCH), app.current_a2l_data)
            await unload_a2l(pilot, app, back="6")
            before_entries = [entry_state(e) for e in service(app).document.entries]
            if surface == "edit-json":
                lines = await whole_document_confirm(pilot, app, log)
                assert lines.count(EDIT_REFUSED_2) == 1, lines
                two_findings(lines)
            else:
                row, entry = patch_rows[0]
                lines = await entry_json_confirm(pilot, app, log, row)
                assert lines[:2] == [REJECTED, finding_no_ctx(0, entry["symbol"])], lines
                assert lines[2:] == [PLAIN], lines
            assert [entry_state(e) for e in service(app).document.entries] == before_entries
            assert len(before_entries) == 7
        elif surface == "check-editor":
            await show_screen(pilot, app, "equals_sign", "#check_spec_file_select")
            mark = len(log.messages)
            await pick_by_keys(pilot, app, "#check_spec_file_select", CHECK)
            lines = await lines_after(
                pilot, log, mark,
                lambda ls: "Check Editor: spec NOT loaded." in ls,
                "the Check Editor spec pick",
            )
            assert lines == [
                finding_no_ctx(check_index, check_entry["symbol"]),
                "Check Editor: spec NOT loaded.",
            ], lines
            mark = len(log.messages)
            await pick_by_keys(pilot, app, "#check_spec_file_select", CHECK_FAILS)
            lines = await lines_after(
                pilot, log, mark,
                lambda ls: "Check Editor: spec NOT loaded." in ls,
                "the Check Editor pick of demo_check_fails",
            )
            assert lines == [
                finding_no_ctx(fails_index, fails_entry["symbol"]),
                "Check Editor: spec NOT loaded.",
            ], lines
        else:
            raise AssertionError(surface)
        return True

    async def diff_scenario(app, pilot, log):
        # Inside an open project that holds the A2L file; the session A2L is
        # then unloaded. The pick must not fall back to the project's file.
        stage(app, case08, CHECK)
        make_project(app.workarea, "P", case08, [], with_a2l=True)
        await ld.open_project_through_dialog(pilot, app, "P")
        await wait_until(
            pilot,
            lambda: app.current_project == "P" and app.current_a2l_data is not None,
            "timed out waiting for the project install",
        )
        await settle_workers(pilot)
        await dismiss_result_panel_if_open(pilot, app)
        await unload_a2l(pilot, app)
        await show_screen(pilot, app, "7", "#diff_check_select")
        await pick_by_keys(pilot, app, "#diff_check_select", CHECK)
        await wait_until(
            pilot,
            lambda: str(app.query_one("#diff_status").render()).startswith("Check spec"),
            lambda: f"got {str(app.query_one('#diff_status').render())!r}",
        )
        await settle(pilot)
        return str(app.query_one("#diff_status").render())

    if surface == "ab-diff-project-a2l-not-implicit":
        status = run(tmp_path, diff_scenario)
        assert status.startswith(
            f"Check spec not loaded {EM} [{UNRESOLVED}] error: entry {check_index}:"
        ), status
    else:
        assert run(tmp_path, scenario) is True


# ---------------------------------------------------------------------------
# Projects and the variant run
# ---------------------------------------------------------------------------


def make_project(workarea: Path, name: str, case: Path, batch: list, *, with_a2l: bool) -> Path:
    """A project folder ``workarea/name`` with case 08's image, optionally its
    A2L file, the batch documents copied in, and a manifest naming them."""
    folder = workarea / name
    folder.mkdir(parents=True, exist_ok=True)
    shutil.copy(case / "firmware.s19", folder / "firmware.s19")
    if with_a2l:
        shutil.copy(case / "firmware.a2l", folder / "firmware.a2l")
    for document in batch:
        shutil.copy(case / document, folder / document)
    files = {
        item.name: projects.file_record_of(item)
        for item in sorted(folder.iterdir())
        if item.is_file()
    }
    (folder / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "firmware",
                "batch": list(batch),
                "assignments": {},
                "files": files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return folder


def run_variants(root: Path, name: str, case: Path, document: str, *, with_a2l: bool):
    """Build ``<root>/.s19tool/workarea/<name>`` and run Execute scope ``all``
    over it through the service; return ``(project_dir, results)``."""
    workarea = root / ".s19tool" / "workarea"
    workarea.mkdir(parents=True, exist_ok=True)
    project_dir = make_project(workarea, name, case, [document], with_a2l=with_a2l)
    data_files, _a2l, error = validate_project_files(project_dir)
    assert error is None, error
    variant_set = build_variant_set(name, data_files)
    results, _issues = ves.execute_project_variants(
        project_dir, variant_set, scope=ves.SCOPE_ALL
    )
    return project_dir, results


def test_r_chg_sym_11_variant_run_declares_the_project_a2l_file(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.11/1: three Execute-scope-all runs of a project holding
    ``firmware.s19`` and ``firmware.a2l``, the manifest batch naming one
    case-08 document per run. Run 1 (``demo_patch``): 0 unresolved findings,
    no entry blocked, the two symbol entries applied. Run 2 (``demo_check``):
    3 passed. Run 3 (``demo_check_fails``): 3 failed. No run is blocked
    ``doc-fault``.

    One project per run, so that a patched file saved by run 1 is not a second
    variant of a later run. Negative control: the variant run passing no A2L
    blocks every entry of run 1 and blocks runs 2 and 3 ``doc-fault`` (the
    base) -> RED."""
    _dir, results = run_variants(tmp_path / "r1", "p1", case08, PATCH, with_a2l=True)
    assert [r.status for r in results] == ["ok"], [r.status for r in results]
    summary = results[0].change_summaries[0]
    assert [i.code for i in summary.issues if i.code == UNRESOLVED] == [], summary.issues
    assert summary.counts.get("blocked", 0) == 0, summary.counts
    by_address = {entry.address_start: entry for entry in summary.entries}
    for _index, entry in symbol_rows(case08, PATCH):
        applied = by_address.get(entry_address(entry))
        assert applied is not None and applied.disposition == "applied", (
            entry, {hex(k): v.disposition for k, v in by_address.items()},
        )

    for name, document, expected in (
        ("p2", CHECK, {"passed": 3, "failed": 0, "uncheckable": 0}),
        ("p3", CHECK_FAILS, {"passed": 0, "failed": 3, "uncheckable": 0}),
    ):
        _dir, results = run_variants(tmp_path / name, name, case08, document, with_a2l=True)
        check = results[0].check_results[0]
        assert check.run_blocked_reason_code is None, (document, check.run_blocked_reason)
        assert [i.code for i in check.issues if i.code == UNRESOLVED] == [], check.issues
        assert check.aggregates == expected, (document, check.aggregates)


async def execute_scope_all(app, pilot, log) -> list:
    """Click the scope control on the Patch Editor's JSON tab until it reads
    scope ``all``, click Execute scope; return the lines since the click once
    the run's finished line is painted (E5 C-4 / C-6, BB-7: clicks, not
    ``Button.press()``)."""
    from textual.widgets import Button

    await show_tab(pilot, app, "patch_tab_json", "patch_execute_run_button")
    panel = app.query_one("#patch_editor_panel")
    want = f"Scope: {panel._SCOPE_LABELS['all']}"
    scope_button = app.query_one("#patch_execute_scope_button", Button)
    for _ in range(4):
        if str(scope_button.label) == want:
            break
        await click(pilot, scope_button, "the Execute scope control")
        await settle(pilot, 2)
    assert str(scope_button.label) == want, str(scope_button.label)
    mark = len(log.messages)
    await click(pilot, "#patch_execute_run_button", "Execute scope")
    lines = await lines_after(
        pilot, log, mark,
        lambda ls: any(line.startswith("Execute: scope 'all' finished") for line in ls),
        "the Execute scope run",
    )
    await settle_workers(pilot)
    return lines


async def dismiss_result_panel_if_open(pilot, app) -> None:
    """Close the Load-result panel when the project open raised one (a project
    with a clean digest record raises none)."""
    await settle(pilot, 4)
    if len(app.screen.query(projects.LOAD_RESULT_CLOSE)) > 0:
        await projects.dismiss_load_result_panel(pilot, app)


async def open_project(pilot, app, case: Path, *, with_a2l: bool, batch=(PATCH,)) -> Path:
    folder = make_project(app.workarea, "P", case, list(batch), with_a2l=with_a2l)
    await ld.open_project_through_dialog(pilot, app, "P")
    await wait_until(
        pilot,
        lambda: app.current_project == "P" and app.current_file is not None,
        "timed out waiting for the project install",
    )
    await settle_workers(pilot)
    await dismiss_result_panel_if_open(pilot, app)
    return folder


def assert_patched_symbols(folder: Path, case: Path) -> None:
    """The patched variant file exists and holds the symbol entries' bytes."""
    patched = folder / "firmware-patched.s19"
    assert patched.is_file(), sorted(p.name for p in folder.iterdir())
    image = read_s19(patched)
    assert image.errors == [], image.errors
    for _index, entry in symbol_rows(case, PATCH):
        data = entry_data(entry)
        address = entry_address(entry)
        got = [image.data.get(address + k) for k in range(len(data))]
        assert got == list(data), (hex(address), got, list(data))


@pytest.mark.parametrize("arm", ["session-a2l-loaded", "session-a2l-unloaded"])
def test_r_chg_sym_11_execute_scope_applies_symbol_entries_by_keys(
    tmp_path: Path, case08: Path, arm: str
) -> None:
    """Case R-CHG-SYM.11/2 (black-box; arm b is the S4-2 control): the project
    is opened through the Load dialog and Execute scope ``all`` is run from its
    control; the run ends ``Execute: scope 'all' finished - 1 variant(s), 0
    error(s)`` and the project folder holds ``firmware-patched.s19`` whose
    bytes at both symbol addresses are the document's bytes. Arm b: the
    session A2L is unloaded after the project opens and before Execute scope;
    the run still applies (the project's A2L file is used, not the session's).

    Negative control: the variant run passing no A2L writes no patched file
    (the base) -> RED; a run fed the session A2L instead of the project's file
    fails arm b. Drive (E5 C-6, BB-7): scope and Execute are clicked, and arm
    b unloads from the Workspace "Loaded" panel's control. E5 C-4: the run's
    finished line is the last line painted, not just one of them."""

    async def scenario(app, pilot, log):
        folder = await open_project(pilot, app, case08, with_a2l=True)
        assert app.current_a2l_data is not None
        if arm == "session-a2l-unloaded":
            await unload_a2l(pilot, app)
        await show_screen(pilot, app, "6", "#patch_execute_run_button")
        lines = await execute_scope_all(app, pilot, log)
        return folder, lines

    folder, lines = run(tmp_path, scenario)
    assert "Execute: scope 'all' finished - 1 variant(s), 0 error(s)" in lines, lines
    assert lines[-1] == "Execute: scope 'all' finished - 1 variant(s), 0 error(s)", lines
    assert_patched_symbols(folder, case08)


def test_r_chg_sym_11_report_run_declares_the_project_a2l_file(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.11/3 (E3 A-4): the project report run, which executes the
    variants itself when no execution precedes it, declares the project's A2L
    file: the project folder holds ``firmware-patched.s19`` with both symbol
    entries' bytes, the report's consolidated overview counts applied changes
    (at least the two symbol entries), both symbols appear in the report and
    the report carries no unresolved-symbol code.

    E5 C-2: the overview counts exactly 7 applied (every entry of
    ``demo_patch``), and the Modifications table holds 7 rows with no row
    whose Before cell is ``-`` (the report's rendering of an entry that was
    not applied), so 0 entries are ``blocked``. Drive (E5 C-2 / C-6, BB-8): the
    Reports screen opens through its key ``t`` and Generate is clicked.

    Negative control: the report run passing no A2L blocks the change document
    (0 applied, no patched file; the base) -> RED."""
    from s19_app.tui.screens import ReportViewerScreen
    from textual.widgets import Button

    from s19_app.tui.services.report_service import list_project_reports

    async def scenario(app, pilot, log):
        folder = await open_project(pilot, app, case08, with_a2l=True)
        await pilot.press("t")
        await wait_until(
            pilot,
            lambda: isinstance(app.screen_stack[-1], ReportViewerScreen)
            and len(app.screen_stack[-1].query("#report_generate")) > 0,
            "timed out waiting for the Reports screen after key t",
        )
        await settle(pilot, 2)
        await click(
            pilot, app.screen_stack[-1].query_one("#report_generate", Button), "Generate"
        )
        await settle(pilot, 12)
        await app.workers.wait_for_complete()
        await settle(pilot, 12)
        reports = list_project_reports(folder)
        return folder, [p.read_text(encoding="utf-8") for p in reports]

    folder, texts = run(tmp_path, scenario)
    assert len(texts) == 1, len(texts)
    report = texts[0]
    assert_patched_symbols(folder, case08)
    match = re.search(r"^\| firmware \| [^|]+\| (\d+) \|", report, re.MULTILINE)
    assert match is not None, report[:2000]
    assert int(match.group(1)) >= 2, match.group(0)
    assert int(match.group(1)) == len(doc_json(case08, PATCH)["entries"]) == 7, match.group(0)
    modifications = report[report.index("### Modifications"):]
    section = modifications.split("\n### ", 1)[0]
    table = [line for line in section.splitlines() if line.startswith("| 0x")]
    assert len(table) == 7, table
    not_applied = [line for line in table if line.split("|")[3].strip() == "-"]
    assert not_applied == [], not_applied
    for _index, entry in symbol_rows(case08, PATCH):
        data = entry_data(entry)
        row = [
            line for line in modifications.splitlines()
            if line.startswith(f"| 0x{entry_address(entry):08X} |")
        ]
        assert len(row) == 1, (entry, row)
        after = " ".join(f"{byte:02X}" for byte in data)
        assert f"| {len(data)} |" in row[0] and f"| {after} |" in row[0], row[0]
        # The report escapes Markdown (underscores), so the symbol is checked
        # in its escaped spelling.
        assert entry["symbol"].replace("_", "\\_") in row[0], row[0]
    assert UNRESOLVED not in report


def test_r_chg_sym_12_variant_run_without_a_project_a2l_declares_none(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.12/1: the same three runs on a project with no A2L file:
    run 1 paints exactly 2 no-context findings and applies nothing; runs 2 and
    3 record 1 no-context finding each and are blocked ``doc-fault``.

    Holds on the base (negative control). Mutant: a fallback context in the
    variant read resolves the symbols -> findings missing -> RED."""
    _dir, results = run_variants(tmp_path / "r1", "p1", case08, PATCH, with_a2l=False)
    summary = results[0].change_summaries[0]
    findings = [i for i in summary.issues if i.code == UNRESOLVED]
    assert len(findings) == 2, summary.issues
    assert all(NO_CTX in i.message for i in findings), findings
    assert summary.counts.get("applied", 0) == 0, summary.counts
    assert all(e.disposition == "blocked" for e in summary.entries), summary.entries

    for name, document in (("p2", CHECK), ("p3", CHECK_FAILS)):
        _dir, results = run_variants(tmp_path / name, name, case08, document, with_a2l=False)
        check = results[0].check_results[0]
        findings = [i for i in check.issues if i.code == UNRESOLVED]
        assert len(findings) == 1 and NO_CTX in findings[0].message, (document, check.issues)
        assert check.run_blocked_reason_code == "doc-fault", (document, check.run_blocked_reason_code)


def test_r_chg_sym_12_session_a2l_does_not_reach_a_project_without_a2l(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-CHG-SYM.12/2 (black-box, S4-2 converse): a project with no A2L
    file is opened through the Load dialog, ``firmware.a2l`` is attached in the
    session, and Execute scope ``all`` runs: the run ends with its finished
    line, the project folder holds no patched variant file and the session A2L
    stays loaded.

    Holds on the base. Mutant: the session A2L fed to the variant run writes a
    patched file -> RED. E5 C-3: the run ends ``0 error(s)``, so "no patched
    file" cannot come from a run that errored before the document read. Drive
    (E5 C-6, BB-7): scope and Execute are clicked."""

    async def scenario(app, pilot, log):
        folder = await open_project(pilot, app, case08, with_a2l=False)
        assert app.current_a2l_data is None
        await attach_a2l(pilot, app, case08)
        # Observed on the base revision: attaching an A2L while a project is
        # open copies it into the project folder, which would make the project
        # "a project with an A2L file". The case's premise is a project folder
        # with none, so the copied file is removed; the session A2L stays.
        synced = folder / "firmware.a2l"
        synced_before = synced.exists()
        if synced_before:
            synced.unlink()
        await show_screen(pilot, app, "6", "#patch_execute_run_button")
        lines = await execute_scope_all(app, pilot, log)
        return folder, lines, app.current_a2l_data is not None, synced_before

    folder, lines, a2l_kept, synced_before = run(tmp_path, scenario)
    assert any(l.startswith("Execute: scope 'all' finished - 1 variant(s),") for l in lines), lines
    assert lines[-1] == "Execute: scope 'all' finished - 1 variant(s), 0 error(s)", lines
    assert not (folder / "firmware-patched.s19").exists(), sorted(p.name for p in folder.iterdir())
    assert a2l_kept
    assert not (folder / "firmware.a2l").exists(), synced_before


# ---------------------------------------------------------------------------
# R-CHG-SYM.13 - one index per read, bounded at 1 000 entries x 220 040 tags
# ---------------------------------------------------------------------------

TAG_COUNT = 220_040  # case_06's tag count (examples/case_06_large_nested_a2l)
ENTRY_COUNT = 1_000
SAMPLES_13_3 = 5  # R-CHG-SYM.13/3 run count (E5 ruling C-7)


def planted_context(count: int = TAG_COUNT) -> dict:
    return {
        "tags": [
            {"name": f"T{n:06d}", "address": 4096 + 4 * n, "length": 4}
            for n in range(count)
        ]
    }


def planted_document(
    entries: int = ENTRY_COUNT, count: int = TAG_COUNT, *, symbols: bool = True
) -> str:
    step = count // entries
    items = []
    for k in range(entries):
        n = k * step
        item = {
            "type": "bytes",
            "address": f"0x{4096 + 4 * n:08X}",
            "bytes": "01 02 03 04",
        }
        if symbols:
            item["symbol"] = f"T{n:06d}"
        items.append(item)
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": items,
        }
    )


def count_index_builds(monkeypatch: pytest.MonkeyPatch) -> list:
    """Wrap the reader's tag-name index builder with a call counter. On a tree
    without the builder the wrapper is simply never called (count 0)."""
    calls: list = []
    real = getattr(io_mod, "_symbol_name_index", None)

    def _counted(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(io_mod, "_symbol_name_index", _counted, raising=False)
    return calls


@pytest.mark.serial_timing
def test_r_chg_sym_13_symbol_read_of_1000_entries_by_220040_tags_builds_the_index_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Case R-CHG-SYM.13/1: reading a planted document of 1 000 symbol entries
    against a planted context of 220 040 tags builds the tag-name index exactly
    once per read (call counter, the primary oracle), resolves every entry with
    0 findings, and finishes each of 5 runs within the bound (1.0 s, through
    ``report_margin``; serial, on the LAN Linux host).

    Why: the editors read on the screen thread; an index rebuilt per symbol
    entry freezes the screen for minutes at this size. Negative control: the
    base rebuilds the index for every entry (counter 0 on the base because the
    builder does not exist, and a wall clock in the minutes) -> RED; the assert
    message carries the measured first run. E5 C-4: every one of the 1 000
    entries carries its tag's spelling, not only the first and the last."""
    context = planted_context()
    text = planted_document()
    spellings = [f"T{k * (TAG_COUNT // ENTRY_COUNT):06d}" for k in range(ENTRY_COUNT)]
    calls = count_index_builds(monkeypatch)
    times = []
    for run_number in range(5):
        before = len(calls)
        started = time.perf_counter()
        document = parse_change_document(text, a2l_context=context)
        took = time.perf_counter() - started
        times.append(took)
        assert len(calls) - before == 1, (
            f"run {run_number}: the tag-name index was built {len(calls) - before} "
            f"time(s), expected exactly 1 per read; the read took {took:.2f} s"
        )
        assert len(document.entries) == ENTRY_COUNT, len(document.entries)
        assert document.issues == [], document.issues[:3]
        assert document.entries[0].symbol == "T000000"
        assert document.entries[-1].symbol == f"T{(ENTRY_COUNT - 1) * (TAG_COUNT // ENTRY_COUNT):06d}"
        assert [entry.symbol for entry in document.entries] == spellings, run_number
    for took in times:
        assert took < report_margin("symbol read 1000x220040", took, timing_bound(1.0)), times


def test_r_chg_sym_13_read_without_symbol_entries_builds_no_index(
    monkeypatch: pytest.MonkeyPatch, case08: Path
) -> None:
    """Case R-CHG-SYM.13/2 (E3 A-2): the index is lazy. A read of a document
    with no symbol entry builds none (counter 0), against the 220 040-tag
    context; ``demo_patch`` against the case-08 context builds exactly one.

    Negative control: the index built eagerly before the loop counts 1 for
    the address-only document -> RED (the first arm holds on the base; the
    second arm is RED there because the base has no builder).

    Third arm (E5 C-1, the E4 ``index_built`` fix): ``demo_patch`` read with no
    declared A2L calls the builder exactly once (it returns no index) and both
    symbol entries give the R-CHG-SYM.2 finding. Mutant: the lazy gate keyed
    on ``symbol_index is None`` (the pre-fix code) calls it once per symbol
    entry, 2 -> RED."""
    calls = count_index_builds(monkeypatch)
    context = planted_context()
    plain = json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [{"type": "bytes", "address": "0x1000", "bytes": "01"}],
        }
    )
    document = parse_change_document(plain, a2l_context=context)
    assert len(document.entries) == 1 and document.issues == [], document.issues
    assert len(calls) == 0, f"an address-only read built the index {len(calls)} time(s)"

    case_context = parse_a2l_file(case08 / "firmware.a2l")
    document = parse_change_document(doc_text(case08, PATCH), a2l_context=case_context)
    assert len(document.entries) == 7 and document.issues == [], document.issues
    assert len(calls) == 1, f"the symbol read built the index {len(calls)} time(s), expected 1"

    before = len(calls)
    document = parse_change_document(doc_text(case08, PATCH), a2l_context=None)
    assert len(calls) - before == 1, (
        f"a read with no declared A2L called the index builder {len(calls) - before} "
        f"time(s), expected exactly 1"
    )
    findings = [i for i in document.issues if i.code == UNRESOLVED]
    assert len(findings) == 2 and all(NO_CTX in i.message for i in findings), document.issues


@pytest.mark.serial_timing
def test_r_chg_sym_13_whole_document_edit_json_confirm_of_1000_entries_by_220040_tags(
    tmp_path: Path,
) -> None:
    """Case R-CHG-SYM.13/3 (E3 A-7, measurement): the whole-document Edit JSON
    confirm reads the document twice (the pre-check and the posted paste) on
    the screen thread. With the planted 220 040-tag context as the session A2L,
    a confirm of 1 000 symbol entries ends ``Loaded change: 1000 entries, 0
    error(s)``, and the time the symbol resolution adds to the confirm - the
    confirm of the 1 000 symbol entries minus the confirm of the same 1 000
    entries without ``symbol`` (which pays the same table render) - stays
    within its bound: 2 x the E4 measurement of that addition on the LAN Linux
    host, with a ceiling of 1.0 s (E4 ruling OR-2; measured 0.622 s, so the
    ceiling governs).

    Why: the whole confirm costs more than the two reads (the ledger and the
    JSON view render 1 000 rows); that render is not this increment's cost and
    is measured by the plain arm, so the difference isolates the reads.
    E5 C-7: 5 samples (plain then symbolic, after one discarded warm-up), each
    asserted against the bound; the transcript prints every sample and the
    max. The session A2L is planted (``current_a2l_data``) and the confirm
    callback is called directly - a precondition stand-in accepted for this
    measurement row (coverage audit C-12).
    Negative control: the base ignores the session A2L and refuses the confirm
    at once -> RED on the painted result, not on the clock."""
    from textual.widgets import TextArea

    context = planted_context()
    plain = planted_document(symbols=False)
    symbolic = planted_document()

    async def confirm(app, pilot, log, text: str):
        app.query_one("#patch_paste_text", TextArea).text = text
        mark = len(log.messages)
        started = time.perf_counter()
        app._apply_changeset_json_edit(text)
        lines = await lines_after(
            pilot, log, mark,
            lambda ls: any(
                line.startswith("Loaded change:") or line.startswith("Edit JSON refused")
                for line in ls
            ),
            "the whole-document confirm",
        )
        return lines, time.perf_counter() - started

    async def scenario(app, pilot, log):
        await show_screen(pilot, app, "6", "#patch_edit_json_button")
        app.current_a2l_data = context
        await confirm(app, pilot, log, plain)  # warm-up, discarded
        samples = []
        for _sample in range(SAMPLES_13_3):
            plain_lines, plain_took = await confirm(app, pilot, log, plain)
            symbolic_lines, symbolic_took = await confirm(app, pilot, log, symbolic)
            samples.append((plain_lines, plain_took, symbolic_lines, symbolic_took))
        return samples

    samples = run(tmp_path, scenario)
    assert len(samples) == SAMPLES_13_3
    added_all = []
    for number, (plain_lines, plain_took, lines, took) in enumerate(samples):
        assert "Loaded change: 1000 entries, 0 error(s)" in plain_lines, plain_lines[:3]
        assert "Loaded change: 1000 entries, 0 error(s)" in lines, lines[:3]
        added = max(took - plain_took, 0.0)
        added_all.append(added)
        print(
            f"MEASURED sample {number + 1}/{SAMPLES_13_3} whole-document confirm, "
            f"1000 entries x 220040 tags: without symbols {plain_took:.3f} s, "
            f"with symbols {took:.3f} s, resolution adds {added:.3f} s"
        )
    print(f"MEASURED resolution addition max {max(added_all):.3f} s over {SAMPLES_13_3} samples")
    for added in added_all:
        assert added < report_margin(
            "edit json confirm resolution 1000x220040", added, timing_bound(1.0)
        ), added_all


# ---------------------------------------------------------------------------
# R-TUI-058.9 - the plain-language line of a per-entry confirm
# ---------------------------------------------------------------------------


def test_r_tui_058_9_entry_edit_without_a2l_ends_on_the_plain_line(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-TUI-058.9/1: a draft holding symbol entries (pasted while the
    A2L was loaded), the A2L then unloaded, the per-entry Edit JSON of a
    symbol entry confirmed unchanged: the lines painted are, in order, the
    rejection line, the no-context finding line, and the plain-language line
    exactly once, last; the entry is unchanged, and so is the whole document
    (7 entries equal; E5 C-5/C-6, the "document unchanged" clause).

    Negative control: the confirm ends on the finding line (the base); the
    line removed -> RED. Drive (E5 C-6, BB-4): a pasted draft, the unload from
    the Workspace "Loaded" panel's control, the row chosen by keys, clicks."""
    row, entry = symbol_rows(case08, PATCH)[0]

    async def scenario(app, pilot, log):
        await attach_image(pilot, app, case08)
        await attach_a2l(pilot, app, case08)
        await show_screen(pilot, app, "6", "#patch_entry_edit_json_button")
        await install_draft(pilot, app, doc_text(case08, PATCH), app.current_a2l_data)
        await unload_a2l(pilot, app, back="6")
        before = entry_state(service(app).document.entries[row])
        before_all = [entry_state(e) for e in service(app).document.entries]
        lines = await entry_json_confirm(pilot, app, log, row)
        after_all = [entry_state(e) for e in service(app).document.entries]
        return lines, before, entry_state(service(app).document.entries[row]), before_all, after_all

    lines, before, after, before_all, after_all = run(tmp_path, scenario)
    assert lines == [REJECTED, finding_no_ctx(0, entry["symbol"]), PLAIN], lines
    assert after == before
    assert len(before_all) == 7 and after_all == before_all, (before_all, after_all)


def test_r_tui_058_9_entry_edit_with_a_non_string_symbol_paints_no_plain_line(
    tmp_path: Path,
) -> None:
    """Case R-TUI-058.9/2: with no A2L loaded, confirming an entry whose
    ``symbol`` is not a string paints the rejection line and the not-a-string
    finding, and no plain-language line (that finding is R-CHG-SYM.1's, where
    "no A2L is loaded" would be the wrong reason).

    Holds on the base. Mutant: the line keyed on the finding code alone paints
    it here -> RED."""
    not_a_string = f"[{UNRESOLVED}] error: entry 0 declares a 'symbol' that is not a tag name string {EM} the entry was skipped"

    async def scenario(app, pilot, log):
        await show_screen(pilot, app, "6", "#patch_entry_edit_json_button")
        await install_draft(
            pilot, app,
            json.dumps({"format": "s19app-changeset", "version": "2.0", "kind": "change",
                        "encoding": "utf-8", "value_mode": "text",
                        "entries": [json.loads(ONE_ENTRY)]}),
        )
        assert app.current_a2l_data is None
        return await entry_json_confirm(
            pilot, app, log, 0,
            '{"type": "bytes", "address": "0x100", "bytes": "01", "symbol": 7}',
        )

    lines = run(tmp_path, scenario)
    assert lines == [REJECTED, not_a_string], lines
    assert PLAIN not in lines


def test_r_tui_058_9_entry_edit_with_an_unknown_symbol_paints_no_plain_line(
    tmp_path: Path, case08: Path
) -> None:
    """Case R-TUI-058.9/3: with the A2L loaded, confirming an entry whose symbol
    names no tag paints the R-CHG-SYM.3 finding and no plain-language line.
    Arm b (E3 A-5): a symbol that is the text ``no A2L context is declared for
    this change-set`` gives the R-CHG-SYM.3 finding (its message contains that
    text) and still no plain-language line, because the A2L is loaded.

    Negative control: the confirm passing no A2L paints the no-context finding
    instead (the base) -> RED; the "no A2L is loaded" guard dropped paints the
    line in arm b -> RED."""
    envelope = json.dumps({"format": "s19app-changeset", "version": "2.0", "kind": "change",
                           "encoding": "utf-8", "value_mode": "text",
                           "entries": [json.loads(ONE_ENTRY)]})

    def entry_with(symbol: str) -> str:
        return json.dumps({"type": "bytes", "address": "0x100", "bytes": "01", "symbol": symbol})

    async def scenario(app, pilot, log):
        await attach_image(pilot, app, case08)
        await attach_a2l(pilot, app, case08)
        await show_screen(pilot, app, "6", "#patch_entry_edit_json_button")
        await install_draft(pilot, app, envelope, app.current_a2l_data)
        arm_a = await entry_json_confirm(pilot, app, log, 0, entry_with("NO_SUCH_TAG"))
        arm_b = await entry_json_confirm(pilot, app, log, 0, entry_with(NO_CTX))
        return arm_a, arm_b

    arm_a, arm_b = run(tmp_path, scenario)
    assert arm_a == [REJECTED, finding_no_tag(0, "NO_SUCH_TAG")], arm_a
    assert arm_b == [REJECTED, finding_no_tag(0, NO_CTX)], arm_b
    assert PLAIN not in arm_a + arm_b
