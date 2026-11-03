"""Batch-102 Inc 5 — paridad Patch Editor con selector A2L (TC-B102-PE-01..06 + addendas E4).

E4 tester tests for the Patch picker parity slice. Oracles come from the Inc 5
design packet: ``.dev-flow/2026-11-03-batch-102/inc-5/01-requirements.md``
(R-B102-PE-001..006), ``02-test-cases.md`` (TC-B102-PE-01..06),
``codewire-graph.md``, ``prototype.md`` and the E3 rulings
``.dev-flow/2026-11-03-batch-102/design/E3-rulings-inc5.md``.

Layer B style (idiom: ``tests/test_b102_parameter_picker.py``, Inc 3): the
shipped chain is driven under Textual Pilot; the panel's own widgets are read
back black-box; population goes through the app's own A2L/image loaders (or the
shared picker's ``set_parameters`` seam for the 10 000-row mount arm). No
``s19_app`` source is touched; fixtures are synthetic and public.

Contract pinned here (ids the implementer ships):
- Fourth inspector tab: chip ``#patch_tab_a2l`` / pane ``#patch_pane_a2l``.
- The shared picker mounted in ``highlight`` mode with ``id_prefix="patch_param"``:
  ``#patch_param_filter``, ``#patch_param_table``, ``#patch_param_status``,
  ``#patch_param_full_name_line``, ``#patch_param_page_prev_button`` /
  ``#patch_param_page_label`` / ``#patch_param_page_next_button``; the include /
  bulk controls of pick mode do NOT ship (E3 ruling 2).
- Host action button ``#patch_param_use_button`` (``Use parameter``).
- The single marked status surface of E3 ruling 7: ``#patch_param_use_status``
  paints exactly ``Parameter address loaded; image bytes unavailable.`` and
  ``No parameter highlighted.``.

RED-in-base expectation (per ``02-test-cases.md`` notas de ejecución): every
test fails on base for absence of the tab/selector (the named assertions of
``need()`` / ``patch_picker()``). The E3-mandated addendas (load→unload→Use,
partial map without zero-fill, ``byte_size`` over ``MAX_A2L_DECODE_BYTES``,
80x24 containment, ``address=None`` defence) fail for the same absence.
PC-11: a new id is looked up through ``need()`` (a named assertion), never a
bare ``query_one``.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Input

from s19_app.tui import screens_directionb as sdb
from s19_app.tui.a2l import MAX_A2L_DECODE_BYTES
from s19_app.tui.app import S19TuiApp
from tests.b97_probes import is_displayed
from tests.support.b100_workers import settle_workers

SIZE = (118, 54)
MIN_SIZE = (80, 24)
SIZES_BOTH = (MIN_SIZE, SIZE)

PAGE_SIZE = 200

#: The pinned no-image-bytes status (R-B102-PE-004, E3 rulings 6/7).
NO_BYTES_LINE = "Parameter address loaded; image bytes unavailable."
#: The pinned no-usable-row status (codewire ``_use_highlighted_parameter``,
#: E3 ruling 9's ``address=None`` defence lands on the same arm).
NO_HIGHLIGHT_LINE = "No parameter highlighted."
#: The shared empty-state lines (R-B102-PE-006 ships the shared grammar).
EMPTY_LEDGER_LINE = "No A2L parameters — load an A2L (^L) to list them."
NO_MATCH_LINE = "No parameter matches the filter."
TRUNCATED_COUNT = "200 of 10000 shown — refine filter."

#: A hostile parameter name (E3 ruling 11 carry-over / R-B102-PE-006): markup
#: tokens and C0/C1 control bytes around a short sentinel that survives the
#: narrow Patch table-column clip.
HOSTILE_NAME_B102 = "b[red]x\x07\x1b[31m\x9b1m"
HOSTILE_SENTINEL = "b[red]x"
MARKUP_SPAN_RE = re.compile(r"link|click|bold|^red$")
PAGE_LABEL_RE = re.compile(r"(\d+)\s*/\s*(\d+)")

#: The Patch entry inputs ``Use parameter`` writes (codewire modify pins).
ADDRESS_INPUT = "#patch_entry_address_input"
BYTES_INPUT = "#patch_entry_bytes_input"

#: The pinned tab/pane/picker/action/status ids of the increment (see docstring).
A2L_TAB = "#patch_tab_a2l"
PICKER_TABLE = "#patch_param_table"
PICKER_FILTER = "#patch_param_filter"
PICKER_STATUS = "#patch_param_status"
FULL_NAME_LINE = "#patch_param_full_name_line"
USE_BUTTON = "#patch_param_use_button"
USE_STATUS = "#patch_param_use_status"
PAGE_PREV = "#patch_param_page_prev_button"
PAGE_LABEL = "#patch_param_page_label"
PAGE_NEXT = "#patch_param_page_next_button"


# --------------------------------------------------------------------------- #
# Drivers and readers
# --------------------------------------------------------------------------- #


def run(tmp_path: Path, size, body, *, a2l=None, image: dict | None = None):
    """Open the Patch Editor at ``size`` (A2L and/or image preloaded through
    the app's own loaders) and return ``await body(app, pilot, panel)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            if a2l is not None:
                app.load_a2l_from_path(Path(a2l))
                await settle_workers(pilot)  # the A2L attach is a worker
                assert app._compute_a2l_enriched_tags(), (
                    f"the A2L did not load: {list(app.log_lines)[-3:]}"
                )
            if image is not None:
                image_path = write_bytes_s19(tmp_path / "cover.s19", image)
                app.load_from_path(image_path)
                for _ in range(100):
                    if app.current_file is not None:
                        break
                    await pilot.pause(0.05)
                assert app.current_file is not None, "the image did not load"
            app.action_show_screen("patch")
            await settle(pilot, 6)
            return await body(app, pilot, app.query_one("#patch_editor_panel"))

    return asyncio.run(_drive())


def need(root, selector: str, kind=None):
    """The one widget ``selector`` names, or a named assertion failure (PC-11)."""
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    widget = found[0]
    if kind is not None:
        assert isinstance(widget, kind), f"{selector}: expected {kind.__name__}, got {type(widget).__name__}"
    return widget


async def settle(pilot, rounds: int = 4) -> None:
    """Pump the event loop so a press or a mount has run its handlers."""
    for _ in range(rounds):
        await pilot.pause()


async def settled_delay(pilot, predicate, description: str, attempts: int = 120, delay: float = 0.02) -> None:
    """Bounded REAL-delay pump-until (E3 ruling 7 carry-over: the 150 ms
    filter debounce needs real wall time, not only ``pilot.pause()``)."""
    for _ in range(attempts):
        await pilot.pause(delay)
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


def picker_class_or_none():
    """The shared picker class, reached as ``sdb.A2LParameterPicker`` (PC-11)."""
    return getattr(sdb, "A2LParameterPicker", None)


def patch_picker(panel):
    """The one shared picker the Patch panel hosts, or a named assertion."""
    cls = picker_class_or_none()
    assert cls is not None, "sdb.A2LParameterPicker: the shared picker ships (Inc 3)"
    found = [w for w in panel.query(cls)]
    assert len(found) == 1, (
        f"the Patch panel hosts exactly one A2LParameterPicker, found {len(found)}"
    )
    return found[0]


async def show_a2l_tab(panel, pilot) -> None:
    """Select the A2L inspector tab through the shipped chip."""
    need(panel, A2L_TAB).press()
    await settle(pilot, 3)


def synthetic_rows(count: int, prefix: str = "P") -> list:
    """``count`` parameter dicts the picker's population seam normalizes."""
    return [
        {
            "name": f"{prefix}{i:05d}",
            "address": 0x1000 + i * 2,
            "byte_size": 2,
            "compu_method_unit": "rpm",
        }
        for i in range(count)
    ]


def write_wide_a2l(dest_dir: Path, count: int = 250) -> Path:
    """``wide.a2l``: ``count`` CHARACTERISTICs named ``P000..`` with integer
    addresses, parseable by the app's own loader (proven shape of the Inc 3
    fixture)."""
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


PARAMS_A2L_ROWS = (
    ("TorqueMax", 0x1000, 4),
    ("U8One", 0x2000, 1),
    ("U16Two", 0x2002, 2),
)


def write_params_a2l(dest_dir: Path) -> Path:
    """``params.a2l``: the three sized parameters of TC-B102-PE-03 (sizes 4/1/2
    at ``0x1000``/``0x2000``/``0x2002``), bare CHARACTERISTICs whose LENGTH the
    app's loader derives ``byte_size`` from (probed on base)."""
    lines = ["/begin PROJECT Demo", "  /begin MODULE Engine"]
    for name, address, size in PARAMS_A2L_ROWS:
        lines += [
            f"    /begin CHARACTERISTIC {name}",
            f"      ECU_ADDRESS 0x{address:08X}",
            f"      LENGTH {size}",
            "    /end CHARACTERISTIC",
        ]
    lines += ["  /end MODULE", "/end PROJECT", ""]
    path = dest_dir / "params.a2l"
    path.write_text("\n".join(lines), encoding="ascii")
    return path


#: The full-coverage image bytes of TC-B102-PE-03 (``DE AD BE EF`` at 0x1000,
#: ``7F`` at 0x2000, ``12 34`` at 0x2002 — the codewire example's bytes).
FULL_IMAGE = {
    0x1000: 0xDE,
    0x1001: 0xAD,
    0x1002: 0xBE,
    0x1003: 0xEF,
    0x2000: 0x7F,
    0x2002: 0x12,
    0x2003: 0x34,
}


def write_bytes_s19(path: Path, mapping: dict) -> Path:
    """An S19 image holding exactly ``mapping``'s bytes (S2 records, the
    proven-parseable shape of ``write_cover_s19``)."""
    lines = ["S0030000FC"]
    start, chunk = None, []
    for address in sorted(mapping):
        if start is None or address != start + len(chunk):
            if start is not None:
                lines.append(_s2_record(start, chunk))
            start, chunk = address, []
        chunk.append(mapping[address])
    if start is not None:
        lines.append(_s2_record(start, chunk))
    lines.append("S804000000FB")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def _s2_record(address: int, data: list) -> str:
    payload = [3 + len(data) + 1] + list(address.to_bytes(3, "big")) + list(data)
    checksum = (~(payload[0] + sum(payload[1:]))) & 0xFF
    return "S2" + f"{payload[0]:02X}" + "".join(f"{b:02X}" for b in payload[1:]) + f"{checksum:02X}"


def table_rows(panel) -> int:
    return need(panel, PICKER_TABLE, DataTable).row_count


def status_line(panel) -> str:
    """The ``#patch_param_status`` render; ``""`` while absent."""
    return str(need(panel, PICKER_STATUS).render())


def use_status_line(panel) -> str:
    """The single marked use-status surface of E3 ruling 7."""
    return str(need(panel, USE_STATUS).render())


def full_name_line(panel) -> str:
    return str(need(panel, FULL_NAME_LINE).render())


def page_tuple(panel):
    """(current, total) parsed from ``#patch_param_page_label``."""
    match = PAGE_LABEL_RE.search(str(need(panel, PAGE_LABEL).render()))
    assert match, f"{PAGE_LABEL}: no page tuple painted"
    return (int(match.group(1)), int(match.group(2)))


def spy_ledger_rebuilds(monkeypatch, counter: dict) -> None:
    """Count ``A2LParameterPicker._rebuild_ledger`` calls (mutant control for
    'screen activation repopulates'); no-op guard on a missing class."""
    picker_cls = picker_class_or_none()
    if picker_cls is None:
        return
    original = picker_cls._rebuild_ledger

    def counting(self):
        counter["n"] += 1
        return original(self)

    monkeypatch.setattr(picker_cls, "_rebuild_ledger", counting)


async def filter_to_single_row(panel, pilot, name: str) -> None:
    """Type a unique filter and wait for the debounced single-row page."""
    need(panel, PICKER_FILTER, Input).value = name
    await settled_delay(
        pilot,
        lambda: table_rows(panel) == 1,
        f"the filter {name!r} mounts its single row",
    )


async def highlight_row(panel, pilot, row: int = 0) -> None:
    table = need(panel, PICKER_TABLE, DataTable)
    table.move_cursor(row=row)
    await settle(pilot, 1)


def entry_inputs(panel) -> tuple:
    return (
        need(panel, ADDRESS_INPUT, Input).value,
        need(panel, BYTES_INPUT, Input).value,
    )


class _FullCoverMap(Mapping):
    """A mapping that answers every address as covered (value ``address & 0xFF``)
    without materialising ``MAX_A2L_DECODE_BYTES + 1`` entries: the over-MAX
    guard (E3 ruling 5) must fire on the SIZE alone, never iterating a giant
    range or zero-filling."""

    def __getitem__(self, address: int) -> int:
        return address & 0xFF

    def __iter__(self):
        return iter(())

    def __len__(self) -> int:
        return MAX_A2L_DECODE_BYTES + 1

    def __contains__(self, address: object) -> bool:
        return True


# --------------------------------------------------------------------------- #
# TC-B102-PE-01 — R-B102-PE-001 — one page mounted at population
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("count,expected", [(0, 0), (199, 199), (10000, 200)])
def test_tc_b102_pe_01_population_mounts_at_most_one_page(tmp_path: Path, count: int, expected: int, monkeypatch) -> None:
    """TC-B102-PE-01 (R-B102-PE-001, full): parameter sets of 0, 199 and
    10 000 rows mount ``0``, ``199`` and ``200`` ledger rows — never more than
    one 200-row page — and a second population with the same signature is a
    no-op that rebuilds nothing (E3 ruling: se hereda la paginación de Inc 3).

    RED on base: the Patch panel hosts no picker (``patch_picker`` named
    assertion). Mutant: restore the full ``_rebuild_ledger`` loop.
    """
    rebuilds = {"n": 0}
    spy_ledger_rebuilds(monkeypatch, rebuilds)

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)
        assert picker.set_parameters(synthetic_rows(count), ("sig", 1)) is True
        await settle(pilot, 2)
        mounted = table_rows(panel)
        rebuilds["n"] = 0
        again = picker.set_parameters(synthetic_rows(count), ("sig", 1))
        await settle(pilot, 2)
        return mounted, again, rebuilds["n"], table_rows(panel), status_line(panel)

    mounted, again, rebuilds_after, rows_after, status = run(tmp_path, SIZE, body)
    assert mounted == expected, (
        f"the picker mounts one page: expected {expected} rows for {count} parameters, got {mounted}"
    )
    assert mounted <= PAGE_SIZE, mounted
    assert again is False, "a same-signature population is a no-op"
    assert rebuilds_after == 0, f"the no-op rebuilt the ledger {rebuilds_after} times"
    assert rows_after == expected, rows_after
    if count == 10000:
        assert status == TRUNCATED_COUNT, status


def test_tc_b102_pe_01_activation_populates_check_population_and_reentry_preserves(tmp_path: Path, monkeypatch) -> None:
    """TC-B102-PE-01 (R-B102-PE-001/.005, full; mutant control 'se usa una
    población distinta a Check'): with the app's own A2L loaded, activating the
    Patch Editor populates the Patch picker from the loaded measurable
    parameters — the SAME population the Check Editor picker holds — and
    leaving for the workspace and back twice does not repopulate.

    RED on base: no ``#patch_tab_a2l`` / no Patch picker. Mutant: activate
    repopulates (``_rebuild_ledger`` fires on re-entry).
    """
    rebuilds = {"n": 0}
    spy_ledger_rebuilds(monkeypatch, rebuilds)

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)
        measurable = {
            tag["name"]
            for tag in app._compute_a2l_enriched_tags()
            if isinstance(tag.get("address"), int)
        }
        app.action_show_screen("check_editor")
        await settle(pilot, 6)
        check_panel = app.query_one("#check_editor_panel")
        check_picker = patch_picker(check_panel)
        check_names = set(check_picker.param_rows)
        app.action_show_screen("patch")
        await settle(pilot, 6)
        await show_a2l_tab(panel, pilot)
        patch_names = set(picker.param_rows)
        mounted = table_rows(panel)
        rebuilds["n"] = 0
        for _round in range(2):
            app.action_show_screen("workspace")
            await settle(pilot, 4)
            app.action_show_screen("patch")
            await settle(pilot, 6)
        await show_a2l_tab(panel, pilot)
        return measurable, check_names, patch_names, mounted, rebuilds["n"], table_rows(panel)

    measurable, check_names, patch_names, mounted, rebuilds_after, rows_after = run(
        tmp_path, SIZE, body, a2l=write_wide_a2l(tmp_path)
    )
    assert measurable, "the loaded A2L holds measurable parameters"
    assert patch_names == measurable, (
        f"the Patch picker populates from the loaded measurable parameters: "
        f"missing {sorted(measurable - patch_names)[:5]}, extra {sorted(patch_names - measurable)[:5]}"
    )
    assert patch_names == check_names, (
        f"the Patch picker holds the Check picker's population: "
        f"only-check {sorted(check_names - patch_names)[:5]}, only-patch {sorted(patch_names - check_names)[:5]}"
    )
    assert mounted == PAGE_SIZE, mounted
    assert rebuilds_after == 0, f"re-entry with the same signature repopulated {rebuilds_after} times"
    assert rows_after == PAGE_SIZE, rows_after


# --------------------------------------------------------------------------- #
# TC-B102-PE-02 — R-B102-PE-002 — id isolation + highlight mode (E3 ruling 2)
# --------------------------------------------------------------------------- #


def test_tc_b102_pe_02_id_isolation_and_highlight_mode(tmp_path: Path) -> None:
    """TC-B102-PE-02 (R-B102-PE-002, full; E3 rulings 2/3): with both rail
    panels mounted, the composed tree holds zero duplicate ids; every Patch
    picker widget is ``patch_param_*``-prefixed and lives inside the Patch
    panel, and no ``check_param_*`` id leaks into the Patch picker. In
    ``highlight`` mode the picker composes no include/bulk controls, ``space`` /
    ``enter`` on the highlighted row mutate no picks and post no
    ``SelectionChanged``-equivalent state, and ``highlighted_parameter`` is the
    read model.

    RED on base: no ``#patch_tab_a2l`` / no Patch picker. Mutant: reuse a Check
    id in Patch; leave the include bindings active in highlight mode.
    """

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        need(app, "#check_editor_panel")
        need(app, "#patch_editor_panel")
        picker = patch_picker(panel)
        prefixed, leaked, misplaced = [], [], []
        for widget in app.query("*"):
            wid = getattr(widget, "id", None)
            if not wid:
                continue
            if wid.startswith("patch_param"):
                prefixed.append(wid)
                if panel not in widget.ancestors:
                    misplaced.append(wid)
            elif wid.startswith("check_param") and picker in widget.ancestors:
                leaked.append(wid)
        include = list(panel.query("#patch_param_include_button"))
        bulk = list(panel.query("#patch_param_bulk_button"))
        table = need(panel, PICKER_TABLE, DataTable)
        table.focus()
        await settle(pilot, 2)
        await pilot.press("space")
        await settle(pilot, 2)
        await pilot.press("enter")
        await settle(pilot, 2)
        picked_after_keys = list(picker.picked_params)
        await highlight_row(panel, pilot, 0)
        highlighted = picker.highlighted_parameter
        return (
            prefixed,
            leaked,
            misplaced,
            include,
            bulk,
            picked_after_keys,
            highlighted,
        )

    prefixed, leaked, misplaced, include, bulk, picked_after_keys, highlighted = run(
        tmp_path, SIZE, body, a2l=write_wide_a2l(tmp_path)
    )
    assert len(prefixed) > 0, "the Patch picker composes patch-prefixed ids"
    assert leaked == [], f"check_param_* ids leak into the Patch picker: {leaked}"
    assert misplaced == [], f"patch_param_* widgets outside the Patch panel: {misplaced}"
    assert len(set(prefixed)) == len(prefixed), f"duplicate ids inside the patch prefix: {sorted(prefixed)}"
    assert include == [], "highlight mode composes no include control"
    assert bulk == [], "highlight mode composes no bulk-add control"
    assert picked_after_keys == [], f"space/enter mutated the highlight-mode picks: {picked_after_keys}"
    assert isinstance(highlighted, dict), f"highlighted_parameter is the read model, got {highlighted!r}"
    assert highlighted.get("name") == "P000", highlighted
    assert highlighted.get("address") == 0x1000, highlighted
    assert highlighted.get("size") == 2, highlighted


# --------------------------------------------------------------------------- #
# TC-B102-PE-03 — R-B102-PE-003 — Use parameter populates, document untouched
# --------------------------------------------------------------------------- #


def test_tc_b102_pe_03_use_parameter_populates_inputs_without_document_mutation(tmp_path: Path) -> None:
    """TC-B102-PE-03 (R-B102-PE-003, full): for sizes 1/2/4, ``Use parameter``
    with the highlighted row writes Address as ``0x%08X`` and Bytes as the
    current image bytes for the parameter size, and the patch document (entry
    count) and the dirty state are unchanged — 3/3 sizes.

    RED on base: no ``#patch_tab_a2l``. Mutant: add an entry directly or skip
    the bytes.
    """
    expected = {
        "TorqueMax": ("0x00001000", "DE AD BE EF"),
        "U8One": ("0x00002000", "7F"),
        "U16Two": ("0x00002002", "12 34"),
    }

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)
        entries_before = len(app._change_service.document.entries)
        dirty_before = panel._dirty
        ledger_rows_before = need(panel, "#patch_doc_entries_table", DataTable).row_count
        seen = {}
        for name, (want_address, want_bytes) in expected.items():
            await filter_to_single_row(panel, pilot, name)
            await highlight_row(panel, pilot, 0)
            hp = picker.highlighted_parameter
            need(panel, USE_BUTTON, Button).press()
            await settle(pilot, 3)
            seen[name] = (
                hp,
                need(panel, ADDRESS_INPUT, Input).value,
                need(panel, BYTES_INPUT, Input).value,
                len(app._change_service.document.entries),
                panel._dirty,
                need(panel, "#patch_doc_entries_table", DataTable).row_count,
            )
        return seen, entries_before, dirty_before, ledger_rows_before

    seen, entries_before, dirty_before, ledger_rows_before = run(
        tmp_path, SIZE, body, a2l=write_params_a2l(tmp_path), image=dict(FULL_IMAGE)
    )
    assert entries_before == 0 and dirty_before is False and ledger_rows_before == 0, (
        entries_before,
        dirty_before,
        ledger_rows_before,
    )
    for name, (want_address, want_bytes) in expected.items():
        hp, address, bytes_value, entries, dirty, ledger_rows = seen[name]
        assert hp and hp.get("name") == name, (name, hp)
        assert address == want_address, (name, address, want_address)
        assert bytes_value == want_bytes, (name, bytes_value, want_bytes)
        assert entries == entries_before, (name, entries, entries_before)
        assert dirty is False, (name, dirty)
        assert ledger_rows == ledger_rows_before, (name, ledger_rows)


# --------------------------------------------------------------------------- #
# TC-B102-PE-04 — R-B102-PE-004 — missing image bytes arm
# --------------------------------------------------------------------------- #


def test_tc_b102_pe_04_missing_image_bytes_arm(tmp_path: Path) -> None:
    """TC-B102-PE-04 (R-B102-PE-004, full): with no image loaded, ``Use
    parameter`` populates Address, clears Bytes and paints exactly
    ``Parameter address loaded; image bytes unavailable.`` on the marked
    surface (E3 ruling 7).

    RED on base: no ``#patch_tab_a2l``. Mutant: fill Bytes with zeroes as if
    they were real image bytes.
    """

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        await filter_to_single_row(panel, pilot, "TorqueMax")
        await highlight_row(panel, pilot, 0)
        need(panel, USE_BUTTON, Button).press()
        await settle(pilot, 3)
        return (
            need(panel, ADDRESS_INPUT, Input).value,
            need(panel, BYTES_INPUT, Input).value,
            use_status_line(panel),
        )

    address, bytes_value, status = run(tmp_path, SIZE, body, a2l=write_params_a2l(tmp_path))
    assert address == "0x00001000", address
    assert bytes_value == "", f"Bytes must be empty, not zero-filled: {bytes_value!r}"
    assert status == NO_BYTES_LINE, status


# --------------------------------------------------------------------------- #
# TC-B102-PE-05 — R-B102-PE-005 — re-entry preserves filter/page/highlight
# --------------------------------------------------------------------------- #


def test_tc_b102_pe_05_reentry_preserves_filter_page_highlight(tmp_path: Path, monkeypatch) -> None:
    """TC-B102-PE-05 (R-B102-PE-005, full): filter/page/highlight set in the
    Patch A2L tab survive two workspace round-trips with the same A2L signature
    (2/2 reentradas).

    RED on base: no ``#patch_tab_a2l``. Mutant: screen activation resets
    filter/page/highlight (``_rebuild_ledger`` fires on re-entry).
    """
    populations: list = []
    picker_cls = sdb.A2LParameterPicker
    original_populate = picker_cls.set_parameters

    def _counting_populate(self, rows, signature=None):
        result = original_populate(self, rows, signature=signature)
        populations.append(result)
        return result

    monkeypatch.setattr(picker_cls, "set_parameters", _counting_populate)

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)
        need(panel, PICKER_FILTER, Input).value = "P"
        await settled_delay(
            pilot,
            lambda: table_rows(panel) == PAGE_SIZE,
            "the filter mounts the first page (200 of 250 rows)",
        )
        need(panel, PAGE_NEXT, Button).press()
        await settled_delay(pilot, lambda: table_rows(panel) == 50, "page 2 (50 rows) mounts")
        await highlight_row(panel, pilot, 0)
        before = (
            need(panel, PICKER_FILTER, Input).value,
            page_tuple(panel),
            table_rows(panel),
            full_name_line(panel),
            picker.highlighted_parameter.get("name"),
        )
        populations.clear()
        for _round in range(2):
            app.action_show_screen("workspace")
            await settle(pilot, 4)
            app.action_show_screen("patch")
            await settle(pilot, 6)
            await show_a2l_tab(panel, pilot)
        after = (
            need(panel, PICKER_FILTER, Input).value,
            page_tuple(panel),
            table_rows(panel),
            full_name_line(panel),
            picker.highlighted_parameter.get("name"),
        )
        return before, after, populations

    before, after, populations_after = run(tmp_path, SIZE, body, a2l=write_wide_a2l(tmp_path))
    assert before[0] == "P" and before[1] == (2, 2) and before[2] == 50, before
    assert before[4] == "P200", before
    assert after == before, f"re-entry with the same signature must preserve filter/page/highlight:\n{after}"
    assert all(result is False for result in populations_after), (
        f"re-entry must be a same-signature no-op, got populate results {populations_after!r}"
    )


# --------------------------------------------------------------------------- #
# TC-B102-PE-06 — R-B102-PE-006 — shared grammar, empty states, safe names
# --------------------------------------------------------------------------- #


def test_tc_b102_pe_06_shared_grammar_surfaces(tmp_path: Path) -> None:
    """TC-B102-PE-06 (R-B102-PE-006, full): the Patch A2L tab composes the
    shared picker grammar — filter input, paged ledger, full-name line, count /
    status line, page controls and the ``Use parameter`` action — every
    surface mounted and displayed.

    RED on base: no ``#patch_tab_a2l``. Mutant: a different grammar (missing
    surfaces) or another control set.
    """

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)
        picker.set_parameters(synthetic_rows(250), ("gram", 1))
        await settle(pilot, 2)
        surfaces = [
            need(panel, PICKER_FILTER, Input),
            need(panel, PICKER_TABLE, DataTable),
            need(panel, FULL_NAME_LINE),
            need(panel, PICKER_STATUS),
            need(panel, PAGE_PREV, Button),
            need(panel, PAGE_LABEL),
            need(panel, PAGE_NEXT, Button),
            need(panel, USE_BUTTON, Button),
        ]
        displayed = all(is_displayed(w) for w in surfaces)
        return displayed, table_rows(panel), page_tuple(panel)

    displayed, rows, pages = run(tmp_path, SIZE, body)
    assert displayed, "every Patch A2L grammar surface is displayed"
    assert rows == PAGE_SIZE, rows
    assert pages == (1, 2), pages


def test_tc_b102_pe_06_empty_states_mirror_check(tmp_path: Path) -> None:
    """TC-B102-PE-06 (R-B102-PE-006 carry-over; the shared picker's two empty
    states must paint on the patch-prefixed surfaces): with no A2L parameters
    the instruction line paints; a non-matching filter paints exactly ``No
    parameter matches the filter.``

    RED on base: no ``#patch_tab_a2l`` / no Patch picker.
    """

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)

        def lines() -> list:
            return [full_name_line(panel), status_line(panel)]

        no_a2l = lines()
        picker.set_parameters(synthetic_rows(10), ("e", 1))
        await settle(pilot, 2)
        need(panel, PICKER_FILTER, Input).value = "missing"
        await settled_delay(
            pilot,
            lambda: any(NO_MATCH_LINE in line for line in lines()),
            "the no-match line paints after the debounce",
        )
        return no_a2l, lines()

    no_a2l, no_match = run(tmp_path, SIZE, body)
    assert EMPTY_LEDGER_LINE in no_a2l, no_a2l
    assert NO_MATCH_LINE in no_match, no_match
    assert EMPTY_LEDGER_LINE not in no_match, no_match


def test_tc_b102_pe_06_hostile_parameter_name_reads_literally(tmp_path: Path) -> None:
    """TC-B102-PE-06 (R-B102-PE-006, full; E3 ruling 11 carry-over): a hostile
    parameter name renders literally in the Patch ledger — the sentinel kept
    verbatim, zero markup spans, zero control bytes: the name went through
    ``safe_text`` / literal ``Text``, never a markup path.

    RED on base: no ``#patch_tab_a2l`` / no Patch picker. Mutant: build the
    cell with a markup string.
    """

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)
        picker.set_parameters(
            [{"name": HOSTILE_NAME_B102, "address": 0x2000, "byte_size": 2, "compu_method_unit": ""}],
            ("hostile", 1),
        )
        await settle(pilot, 2)
        assert table_rows(panel) == 1
        table = need(panel, PICKER_TABLE, DataTable)
        found = False
        markup_spans, control_bytes = [], []
        for cell in table.get_row_at(0):
            plain = getattr(cell, "plain", str(cell))
            if HOSTILE_SENTINEL not in plain:
                continue
            found = True
            markup_spans += [s for s in getattr(cell, "spans", []) if MARKUP_SPAN_RE.search(str(s.style))]
            control_bytes += [c for c in plain if ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F]
        return found, markup_spans, control_bytes

    found, markup_spans, control_bytes = run(tmp_path, SIZE, body)
    assert found, "the hostile sentinel renders in the Patch ledger"
    assert markup_spans == [], markup_spans
    assert control_bytes == [], control_bytes


# --------------------------------------------------------------------------- #
# E4 addenda — E3 rulings 4/5/6/9 + 80x24 containment (ruling 1)
# --------------------------------------------------------------------------- #


def test_tc_b102_pe_add_unload_clears_image_bytes(tmp_path: Path) -> None:
    """E3 ruling 4 (transición load→unload→Use parameter): after the app's own
    unload (``_apply_unload('all')`` pushes ``mem_map=None`` to the Patch
    panel), ``Use parameter`` still loads Address but leaves Bytes empty and
    paints exactly ``Parameter address loaded; image bytes unavailable.``

    RED on base: no ``#patch_tab_a2l`` / no ``Use parameter``. Mutant: the
    panel keeps the stale image map after the unload.
    """

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        await filter_to_single_row(panel, pilot, "TorqueMax")
        await highlight_row(panel, pilot, 0)
        need(panel, USE_BUTTON, Button).press()
        await settle(pilot, 3)
        loaded = entry_inputs(panel) + (bool(panel._mem_map),)
        app._apply_unload("all")
        await settle(pilot, 4)
        after_unload_map = panel._mem_map
        await filter_to_single_row(panel, pilot, "TorqueMax")
        await highlight_row(panel, pilot, 0)
        need(panel, USE_BUTTON, Button).press()
        await settle(pilot, 3)
        return loaded, after_unload_map, entry_inputs(panel) + (use_status_line(panel),)

    loaded, after_unload_map, after = run(
        tmp_path, SIZE, body, a2l=write_params_a2l(tmp_path), image=dict(FULL_IMAGE)
    )
    assert loaded == ("0x00001000", "DE AD BE EF", True), loaded
    assert after_unload_map is None, f"the unload must push mem_map=None, got {after_unload_map!r}"
    assert after == ("0x00001000", "", NO_BYTES_LINE), after


def test_tc_b102_pe_add_partial_map_is_unavailable_not_zero_filled(tmp_path: Path) -> None:
    """E3 ruling 6 (mapa parcial sin zero-fill): an image covering only
    ``[0x1000, 0x1002)`` of the 4-byte parameter still loads Address, but
    Bytes stays EMPTY (never ``DE AD 00 00``) and the exact unavailable line
    paints.

    RED on base: no ``#patch_tab_a2l`` / no ``Use parameter``. Mutant:
    zero-fill the missing tail as if it were real image.
    """

    async def body(app, pilot, panel):
        retained = panel._mem_map
        await show_a2l_tab(panel, pilot)
        await filter_to_single_row(panel, pilot, "TorqueMax")
        await highlight_row(panel, pilot, 0)
        need(panel, USE_BUTTON, Button).press()
        await settle(pilot, 3)
        return (
            retained.get(0x1000),
            0x1002 in retained,
            need(panel, ADDRESS_INPUT, Input).value,
            need(panel, BYTES_INPUT, Input).value,
            use_status_line(panel),
        )

    head, tail_missing, address, bytes_value, status = run(
        tmp_path,
        SIZE,
        body,
        a2l=write_params_a2l(tmp_path),
        image={0x1000: 0xDE, 0x1001: 0xAD},
    )
    assert head == 0xDE and tail_missing is False, (head, tail_missing)
    assert address == "0x00001000", address
    assert bytes_value == "", f"Bytes must stay empty, not zero-filled: {bytes_value!r}"
    assert status == NO_BYTES_LINE, status


def test_tc_b102_pe_add_oversize_parameter_skips_prefill(tmp_path: Path) -> None:
    """E3 ruling 5 (``byte_size`` sobre ``MAX_A2L_DECODE_BYTES``): a parameter
    one byte over the cap with FULL image coverage still loads Address, but
    Bytes is not prefilled and a status of its own paints — the guard fires on
    the size alone (no giant-range iteration, no silent truncation, no
    zero-fill): the painted status is neither the unavailable line nor the
    no-highlight line.

    RED on base: no ``#patch_tab_a2l`` / no Patch picker. Mutant: iterate or
    truncate — Bytes then holds a (wrong) value and the status arm differs.
    """

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)
        picker.set_parameters(
            [{"name": "HugeParam", "address": 0x1000, "byte_size": MAX_A2L_DECODE_BYTES + 1, "compu_method_unit": ""}],
            ("huge", 1),
        )
        await settle(pilot, 2)
        panel._mem_map = _FullCoverMap()  # full coverage: only the size can block
        await filter_to_single_row(panel, pilot, "HugeParam")
        await highlight_row(panel, pilot, 0)
        hp = picker.highlighted_parameter
        need(panel, USE_BUTTON, Button).press()
        await settle(pilot, 3)
        return (
            hp.get("size"),
            need(panel, ADDRESS_INPUT, Input).value,
            need(panel, BYTES_INPUT, Input).value,
            use_status_line(panel),
        )

    size, address, bytes_value, status = run(tmp_path, SIZE, body)
    assert size == MAX_A2L_DECODE_BYTES + 1, size
    assert address == "0x00001000", address
    assert bytes_value == "", f"an over-MAX parameter must not prefill Bytes: {bytes_value[:40]!r}"
    assert status and status not in (NO_BYTES_LINE, NO_HIGHLIGHT_LINE), status


def test_tc_b102_pe_add_none_address_row_is_not_usable(tmp_path: Path) -> None:
    """E3 ruling 9 (``address=None`` defensivo): a highlighted row whose
    address is not an integer is treated as not usable — ``Use parameter``
    paints ``No parameter highlighted.`` on the marked surface, never attempts
    ``0x%08X`` formatting and leaves both entry inputs untouched.

    RED on base: no ``#patch_tab_a2l`` / no Patch picker. Mutant: format the
    non-integer address (crash or garbage in the Address input).
    """

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)
        picker.set_parameters(
            [{"name": "NoAddrParam", "address": None, "byte_size": 2, "compu_method_unit": ""}],
            ("noadr", 1),
        )
        await settle(pilot, 2)
        assert table_rows(panel) == 1
        await highlight_row(panel, pilot, 0)
        hp = picker.highlighted_parameter
        need(panel, USE_BUTTON, Button).press()
        await settle(pilot, 3)
        return hp, entry_inputs(panel) + (use_status_line(panel),)

    hp, after = run(tmp_path, SIZE, body)
    assert hp is None or hp.get("address") is None, hp
    assert after == ("", "", NO_HIGHLIGHT_LINE), after


@pytest.mark.parametrize("size", SIZES_BOTH)
def test_tc_b102_pe_add_patch_a2l_surfaces_contained(size, tmp_path: Path) -> None:
    """E3 ruling 1 (layout proporcional; verificar 80x24 y 118x54): with the
    A2L tab selected, every Patch A2L surface — filter, ledger, full-name and
    status lines, page controls, ``Use parameter`` and its status line — is
    displayed and horizontally contained in the panel at the minimum terminal
    (and at the wide regime); the ledger still mounts a single page. The panel
    is a scroll container: the oracle is horizontal containment + displayed,
    never vertical.

    RED on base: no ``#patch_tab_a2l``. Mutant: reuse the 118-column default
    layout (the surfaces leave the panel horizontally at 80x24).
    """
    width, _height = size

    async def body(app, pilot, panel):
        await show_a2l_tab(panel, pilot)
        picker = patch_picker(panel)  # noqa: F841 — the picker hosts the surfaces
        surfaces = [
            need(panel, PICKER_FILTER),
            need(panel, PICKER_TABLE),
            need(panel, FULL_NAME_LINE),
            need(panel, PICKER_STATUS),
            need(panel, PAGE_PREV),
            need(panel, PAGE_LABEL),
            need(panel, PAGE_NEXT),
            need(panel, USE_BUTTON),
            need(panel, USE_STATUS),
        ]
        # ``#patch_param_use_status`` is mounted but hidden until a Use-parameter
        # result exists; the containment/display oracle covers the surfaces that
        # are actually visible at rest.
        visible_surfaces = [w for w in surfaces if w.region.width > 0]
        contained = [
            (
                w.id or type(w).__name__,
                w.region,
                w.parent.region if w.parent is not None else None,
            )
            for w in visible_surfaces
            if not (
                panel.region.x <= w.region.x
                and w.region.right <= panel.region.right
            )
        ]
        displayed = all(is_displayed(w) for w in visible_surfaces)
        return contained, displayed, table_rows(panel), panel.region

    contained, displayed, rows, region = run(tmp_path, size, body, a2l=write_wide_a2l(tmp_path))
    assert contained == [], (
        f"the Patch A2L surfaces leave the panel horizontally at {width} cols: "
        f"{contained}; panel={region}"
    )
    assert displayed, f"the Patch A2L surfaces are not all displayed at {width} cols"
    assert rows == PAGE_SIZE, rows
