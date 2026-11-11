"""Batch-102 Inc 4 — bulk add de labels/parámetros en Check Editor (TC-B102-BULK-01..07).

E4 tester tests for the bulk-add slice. Oracles come from the Inc 4 design
packet: ``.dev-flow/2026-11-03-batch-102/inc-4/01-requirements.md``
(R-B102-BULK-001..007), ``02-test-cases.md`` (TC-B102-BULK-01..07),
``codewire-graph.md`` and the E3 rulings
``.dev-flow/2026-11-03-batch-102/design/E3-rulings-inc4.md``:

- ruling 5: the picker composes ``#check_param_bulk_button`` and emits
  ``BulkAddRequested``; the Check Editor host pushes the modal
  (``screens.BulkParameterAddScreen``) — TC-01 queries the button from the
  picker itself.
- ruling 2: the summary is literal ``Text`` through ``safe_text``, never
  markup, and ``first missing`` clips to the modal width — TC-06 plus an
  80x24 containment case.
- ruling 3: ``included`` / ``already_included`` / ``not_found`` classify
  UNIQUE names after parsing (``Gamma\\nGamma`` missing ⇒ ``not found 1``).
- ruling 4: ``include_names`` posts the picker's ``SelectionChanged``; the
  modal close never rebuilds (rulings 6 and 9: escape/cancel ⇒
  ``dismiss(None)`` with no refresh; no ``load_spec`` refresh path).
- ruling 7: ``include_names`` answers membership from a dict/set — no
  ``list.index`` and no ``in self._picked_params`` inside the bulk loop.
- ruling 8: the text area carries the shipped 64 KiB cap and a truncated
  buffer is flagged in the summary.
- ruling 10: neither the pasted buffer nor file-derived names are logged —
  only counts.

Layer B style (idiom: ``tests/test_b102_parameter_picker.py``): the shipped
chain is driven under Textual Pilot black-box; population goes through the
panel's ``set_a2l_parameters`` seam; modal widgets are read by id through
``need()`` (PC-11 — a named assertion, never a bare ``query_one`` miss).

RED-in-base expectation (per ``02-test-cases.md`` notas de ejecución):
TC-B102-BULK-01..07 fail on base because ``#check_param_bulk_button`` and
the modal do not ship; every case exercises the modal, including TC-06
(hostile literal names). The ruling addenda (unique-name counts, 80x24
containment, hash-membership AST pin, 64 KiB cap) fail on base the same
way. Ruling-sanctioned RED also lands in ``tests/test_b97_check_editor.py``
(census 36 ids, TC-B97-45 ``BULK_GROUP``, TC-B97-61 homes/counts) and flips
green with the component, like the Inc 3 census did.
"""
from __future__ import annotations

import ast
import asyncio
import re
from pathlib import Path

import pytest
from textual import events
from textual.widgets import Button, DataTable, Input, Label, Static, TextArea

from s19_app.tui import screens_directionb as sdb
from s19_app.tui.app import S19TuiApp
from tests.b97_fixtures import open_check_editor
from tests.b97_probes import record_statuses, settle

SIZE = (118, 54)
MIN_SIZE = (80, 24)

#: The exact instruction the modal shall paint (R-B102-BULK-001; the E3
#: correction-of-artifact addenda fixes the prototype's wording to this line).
INSTRUCTION = "Separate names with new lines, commas, semicolons or spaces."

#: The exact completion summary for TC-B102-BULK-04 (middle dot counts, em
#: dash before the first-missing detail).
SUMMARY_MISSING_TWO = "Included 1 · already included 0 · not found 2 — first missing: MissingOne"

#: The exact no-match arm (R-B102-BULK-005).
NO_MATCH_LINE = "No listed parameters found."

#: The shipped OS-clipboard cap the CappedTextArea inherits (ruling 8).
CAP_CHARS = 65536

#: A hostile source name (R-B102-BULK-006 / ruling 2): Rich markup tokens and
#: C0/C1 control bytes around the ``b102bulk`` sentinel, no whitespace so the
#: parser keeps it as one exact-match token.
HOSTILE_NAME = "b102bulk[red]x[link=e]z\x07\x1b[31m\x9b1m"
MARKUP_SPAN_RE = re.compile(r"link|click|bold|^red$")
TRUNCATION_RE = re.compile(r"truncat", re.IGNORECASE)


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


def picker_class_or_none():
    """The shared picker class, reached as ``sdb.A2LParameterPicker`` (PC-11)."""
    return getattr(sdb, "A2LParameterPicker", None)


def picker_module():
    """The picker's own module — where the codewire graph pins the parser."""
    from s19_app.tui import a2l_parameter_picker as picker_mod

    return picker_mod


def bulk_modal_class_or_none():
    """The bulk modal class the codewire graph pins in ``s19_app.tui.screens``."""
    from s19_app.tui import screens as tui_screens

    return getattr(tui_screens, "BulkParameterAddScreen", None)


async def open_bulk_modal(app, pilot, panel):
    """Press the picker's bulk-add control and pump until the modal is composed."""
    need(panel._picker, "#check_param_bulk_button", Button).press()
    for _ in range(120):
        await pilot.pause()
        screen = app.screen
        if type(screen).__name__ != "BulkParameterAddScreen":
            continue
        for _ in range(20):
            await pilot.pause()
            if list(screen.query("#bulk_param_include_button")):
                return screen
    raise AssertionError("BulkParameterAddScreen never topped after #check_param_bulk_button")


async def wait_modal_closed(app, pilot):
    """Pump until the bulk modal is dismissed; the caller asserts the aftermath."""
    for _ in range(120):
        await pilot.pause()
        if type(app.screen).__name__ != "BulkParameterAddScreen":
            return
    raise AssertionError("the bulk-add modal never dismissed")


def modal_texts(modal) -> set:
    """Every literal text the modal paints on its Static/Label surfaces."""
    return {str(w.render()) for w in modal.query("*") if isinstance(w, (Static, Label))}


def read_summary(modal):
    """The ``#bulk_param_summary`` widget plus its plain text and spans."""
    widget = need(modal, "#bulk_param_summary", Static)
    rendered = widget.render()
    plain = rendered.plain if hasattr(rendered, "plain") else str(rendered)
    spans = list(getattr(rendered, "spans", []))
    return widget, plain, spans


def control_bytes(text: str) -> list:
    """The C0/C1 control bytes surviving in ``text`` (must always be none)."""
    return [c for c in text if ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F]


def named_rows(*names: str) -> list:
    """Parameter dicts for ``names`` the panel's population seam normalizes."""
    return [
        {"name": name, "address": 0x1000 + i * 2, "length": 2, "byte_size": 2, "compu_method_unit": ""}
        for i, name in enumerate(names)
    ]


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


async def pick_highlighted(panel, pilot) -> None:
    """Include the highlighted ledger row through the shipped Include control."""
    need(panel, "#check_param_include_button", Button).press()
    await settle(pilot, 2)


def spy_ledger_rebuilds(monkeypatch, counter: dict) -> None:
    """Count ``A2LParameterPicker._rebuild_ledger`` calls (mutant control for
    the no-rebuild close contract); no-op on the pre-integration tree."""
    picker_cls = picker_class_or_none()
    if picker_cls is None:
        return
    original = picker_cls._rebuild_ledger

    def counting(self):
        counter["n"] += 1
        return original(self)

    monkeypatch.setattr(picker_cls, "_rebuild_ledger", counting)


def spy_selection_changes(monkeypatch, counter: dict) -> None:
    """Count the panel's ``SelectionChanged`` dispatches (ruling 4: the picker's
    message is the only 'picks changed' contract the modal close may rely on)."""
    panel_cls = getattr(sdb, "CheckEditorPanel", None)
    original = panel_cls._on_a2l_parameter_picker_selection_changed

    def counting(self, event):
        counter["n"] += 1
        return original(self, event)

    monkeypatch.setattr(panel_cls, "_on_a2l_parameter_picker_selection_changed", counting)


def spy_load_spec(monkeypatch, counter: dict) -> None:
    """Count ``CheckEditorPanel.load_spec`` calls (ruling 9: the modal close
    shall never refresh through the spec-load path — it rebuilds the ledger)."""
    panel_cls = getattr(sdb, "CheckEditorPanel", None)
    original = panel_cls.load_spec

    def counting(self, items, source_name):
        counter["n"] += 1
        return original(self, items, source_name)

    monkeypatch.setattr(panel_cls, "load_spec", counting)


# --------------------------------------------------------------------------- #
# TC-B102-BULK-01 — R-B102-BULK-001 — the bulk-add control opens the modal
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("preseed", ["empty", "picked"])
def test_tc_b102_bulk_01_modal_opens_with_instruction_focus(tmp_path: Path, preseed: str) -> None:
    """TC-B102-BULK-01 (R-B102-BULK-001, full; E3 ruling 5): activating
    ``#check_param_bulk_button`` — composed by the picker, which emits
    ``BulkAddRequested``, and pushed by the Check Editor host — opens
    ``BulkParameterAddScreen`` holding a multiline ``#bulk_param_text`` (a
    TextArea, never the one-line filter input), the exact instruction
    ``Separate names with new lines, commas, semicolons or spaces.``, the
    include action ``#bulk_param_include_button`` and the close action
    ``#bulk_param_close_button``, with the focus starting in the text area.
    2/2 aperturas: with an empty pick set and with one pick already included.

    RED on base: the bulk button and the modal do not ship. Mutant: reuse the
    one-line filter input, or drop/alter the exact instruction line.
    """
    assert bulk_modal_class_or_none() is not None, (
        "screens.BulkParameterAddScreen: the bulk modal ships (R-B102-BULK-001)"
    )

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(named_rows("Alpha", "Beta", "Gamma"))
        await settle(pilot, 2)
        if preseed == "picked":
            table = panel.query_one("#check_param_table", DataTable)
            table.move_cursor(row=0)
            await settle(pilot, 1)
            await pick_highlighted(panel, pilot)
        modal = await open_bulk_modal(app, pilot, panel)
        texts = modal_texts(modal)
        area = need(modal, "#bulk_param_text", TextArea)
        one_line_filter_reused = isinstance(area, Input)
        for _ in range(20):
            await pilot.pause()
            if app.focused is area:
                break
        focused_in_area = app.focused is area
        include = need(modal, "#bulk_param_include_button", Button)
        close = need(modal, "#bulk_param_close_button", Button)
        return texts, one_line_filter_reused, focused_in_area, include.id, close.id

    texts, one_line_filter_reused, focused_in_area, include_id, close_id = run(
        tmp_path, SIZE, body, a2l=None
    )
    assert INSTRUCTION in texts, sorted(texts)
    assert not one_line_filter_reused, "the bulk entry must be a multiline TextArea, not the filter Input"
    assert focused_in_area, "the focus starts in the bulk text area"
    assert include_id == "bulk_param_include_button"
    assert close_id == "bulk_param_close_button"


# --------------------------------------------------------------------------- #
# TC-B102-BULK-02 — R-B102-BULK-002 — every separator splits, empties drop
# --------------------------------------------------------------------------- #


def test_tc_b102_bulk_02_separators_split_and_empty_tokens_drop(tmp_path: Path) -> None:
    """TC-B102-BULK-02 (R-B102-BULK-002, full): the parser splits on new
    lines, commas, semicolons and whitespace, trims each token and ignores
    empties, preserving order INCLUDING repeated tokens:
    ``Alpha\\nBeta, Gamma; Delta   Alpha`` → the five parsed names of the TC;
    a noisy buffer adds no ``""`` token. End to end, the same payload pasted
    into the modal includes the four names once, in order.

    RED on base: ``parse_parameter_list`` and the modal do not ship. Mutant:
    parse only new lines, or treat the buffer as one string.
    """
    parse = getattr(picker_module(), "parse_parameter_list", None)
    assert parse is not None, "parse_parameter_list: the bulk parser ships (R-B102-BULK-002)"
    parsed = parse("Alpha\nBeta, Gamma; Delta   Alpha")
    assert parsed == ["Alpha", "Beta", "Gamma", "Delta", "Alpha"], parsed
    assert "" not in parsed, parsed
    noisy = parse("\nAlpha,,\n;  ;Beta \n ,,,")
    assert noisy == ["Alpha", "Beta"], noisy
    assert "" not in noisy, noisy

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(named_rows("Alpha", "Beta", "Gamma", "Delta"))
        await settle(pilot, 2)
        modal = await open_bulk_modal(app, pilot, panel)
        need(modal, "#bulk_param_text", TextArea).text = "Alpha\nBeta, Gamma; Delta   Alpha"
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        _, plain, _ = read_summary(modal)
        return list(panel._picked_params), plain

    picks, summary = run(tmp_path, SIZE, body, a2l=None)
    assert picks == ["Alpha", "Beta", "Gamma", "Delta"], picks
    assert summary == "Included 4 · already included 0 · not found 0", summary


# --------------------------------------------------------------------------- #
# TC-B102-BULK-03 — R-B102-BULK-003 — inclusion semantics, no duplicates
# --------------------------------------------------------------------------- #


def test_tc_b102_bulk_03_inclusion_semantics_and_duplicate_controls(tmp_path: Path, monkeypatch) -> None:
    """TC-B102-BULK-03 (R-B102-BULK-003, full; ruling 10): existing pick
    ``Alpha`` (source ``Alpha`` + ``Beta``); pasting
    ``Beta\\nBeta\\nAlpha\\nGamma`` leaves the picks at ``[Alpha, Beta]`` —
    the existing pick keeps its place, the duplicate token and the duplicate
    paste add nothing, the first new occurrence appends in list order — and
    paints ``Included 1 · already included 1 · not found 1 — first missing:
    Gamma``. No recorded status line carries a pasted name (only counts).

    RED on base: the modal does not ship. Mutant: replace the picks, or
    append duplicates; log the pasted content.
    """
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(named_rows("Alpha", "Beta"))
        await settle(pilot, 2)
        table = panel.query_one("#check_param_table", DataTable)
        table.move_cursor(row=0)  # Alpha
        await settle(pilot, 1)
        await pick_highlighted(panel, pilot)
        modal = await open_bulk_modal(app, pilot, panel)
        need(modal, "#bulk_param_text", TextArea).text = "Beta\nBeta\nAlpha\nGamma"
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        _, plain, _ = read_summary(modal)
        return list(panel._picked_params), plain

    picks, summary = run(tmp_path, SIZE, body, a2l=None)
    assert picks == ["Alpha", "Beta"], picks
    assert summary == "Included 1 · already included 1 · not found 1 — first missing: Gamma", summary
    leaked = [line for line in statuses if "Beta" in line or "Gamma" in line]
    assert leaked == [], f"ruling 10: no pasted name may reach a status line: {leaked}"


def test_tc_b102_bulk_03_unique_name_counts(tmp_path: Path) -> None:
    """E3 ruling 3: the counts classify UNIQUE names after parsing. A missing
    ``Gamma\\nGamma`` paints ``not found 1`` (not 2), and with ``Alpha``
    already picked, ``Alpha\\nAlpha`` paints ``already included 1`` with
    ``included 0`` and no first-missing suffix.

    RED on base: the modal does not ship. Mutant: count tokens, not names.
    """

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(named_rows("Alpha"))
        await settle(pilot, 2)
        table = panel.query_one("#check_param_table", DataTable)
        table.move_cursor(row=0)
        await settle(pilot, 1)
        await pick_highlighted(panel, pilot)
        modal = await open_bulk_modal(app, pilot, panel)
        area = need(modal, "#bulk_param_text", TextArea)
        area.text = "Gamma\nGamma"
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        _, missing_twice, _ = read_summary(modal)
        area.text = "Alpha\nAlpha"
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        _, picked_twice, _ = read_summary(modal)
        return missing_twice, picked_twice, list(panel._picked_params)

    missing_twice, picked_twice, picks = run(tmp_path, SIZE, body, a2l=None)
    assert missing_twice == "Included 0 · already included 0 · not found 1 — first missing: Gamma", (
        missing_twice
    )
    assert picked_twice == "Included 0 · already included 1 · not found 0", picked_twice
    assert picks == ["Alpha"], picks


# --------------------------------------------------------------------------- #
# TC-B102-BULK-04 — R-B102-BULK-004 — the completion summary, bounded
# --------------------------------------------------------------------------- #


def test_tc_b102_bulk_04_summary_with_first_missing(tmp_path: Path) -> None:
    """TC-B102-BULK-04 (R-B102-BULK-004, full): source has ``Alpha``; the list
    ``Alpha\\nMissingOne\\nMissingTwo`` paints exactly ``Included 1 · already
    included 0 · not found 2 — first missing: MissingOne`` — fixed count
    order, first discriminating missing name.

    RED on base: the modal does not ship. Mutant: drop the first-missing
    detail, or permute the counts.
    """

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(named_rows("Alpha"))
        await settle(pilot, 2)
        modal = await open_bulk_modal(app, pilot, panel)
        need(modal, "#bulk_param_text", TextArea).text = "Alpha\nMissingOne\nMissingTwo"
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        _, plain, _ = read_summary(modal)
        return plain

    summary = run(tmp_path, SIZE, body, a2l=None)
    assert summary == SUMMARY_MISSING_TWO, summary


def test_tc_b102_bulk_04_summary_contained_at_80x24(tmp_path: Path) -> None:
    """E3 ruling 2 (contención a 80x24): at the minimum terminal the modal
    fits the screen and the summary stays inside it horizontally; a 400-cell
    missing name is clipped to the modal width (it never paints whole), the
    summary is literal text — zero markup spans, zero control bytes.

    RED on base: the modal does not ship. Mutant: paint the summary as markup,
    or let the first-missing detail overflow the modal.
    """
    long_name = "Missing" + "X" * 400

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(named_rows("Alpha"))
        await settle(pilot, 2)
        modal = await open_bulk_modal(app, pilot, panel)
        need(modal, "#bulk_param_text", TextArea).text = f"Alpha\n{long_name}"
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        widget, plain, spans = read_summary(modal)
        region = widget.region
        screen = modal.region
        fits_screen = (
            0 <= region.x
            and region.right <= screen.width
            and 0 <= region.y
            and region.bottom <= screen.height
        )
        markup = [s for s in spans if MARKUP_SPAN_RE.search(str(s.style))]
        return plain, fits_screen, markup, control_bytes(plain)

    plain, fits_screen, markup, controls = run(tmp_path, MIN_SIZE, body, a2l=None)
    assert fits_screen, f"the summary leaves the modal/screen at 80x24: {plain!r}"
    assert long_name not in plain, "the first-missing name must clip to the modal width"
    assert markup == [], markup
    assert controls == [], controls


# --------------------------------------------------------------------------- #
# TC-B102-BULK-05 — R-B102-BULK-005 — the no-match arm
# --------------------------------------------------------------------------- #


def test_tc_b102_bulk_05_no_match_arm(tmp_path: Path) -> None:
    """TC-B102-BULK-005 (R-B102-BULK-005, full): a buffer that parses to zero
    names (only whitespace/separators) paints exactly ``No listed parameters
    found.`` and leaves the picks untouched. A non-empty list whose names are
    all missing uses the summary with ``not found`` (E3 ruling 3).

    RED on base: the modal does not ship. Mutant: clear the picks, or close
    without feedback.
    """

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(named_rows("Alpha", "Beta"))
        await settle(pilot, 2)
        table = panel.query_one("#check_param_table", DataTable)
        table.move_cursor(row=0)
        await settle(pilot, 1)
        await pick_highlighted(panel, pilot)
        modal = await open_bulk_modal(app, pilot, panel)
        need(modal, "#bulk_param_text", TextArea).text = "  \n,;"
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        _, plain, _ = read_summary(modal)
        return plain, list(panel._picked_params)

    summary, picks = run(tmp_path, SIZE, body, a2l=None)
    assert summary == NO_MATCH_LINE, summary
    assert picks == ["Alpha"], picks


# --------------------------------------------------------------------------- #
# TC-B102-BULK-06 — R-B102-BULK-006 — hostile pasted names render literally
# --------------------------------------------------------------------------- #


def test_tc_b102_bulk_06_hostile_pasted_names_render_literally(tmp_path: Path) -> None:
    """TC-B102-BULK-06 (R-B102-BULK-006, full; ruling 2): a source parameter
    whose name carries Rich markup and C0/C1 control bytes pastes whole —
    the parser keeps it as one token, the exact-name match includes it, and
    the missing token ``[red]`` paints literal in the summary; the summary
    render carries zero markup spans and zero control bytes.

    RED on base: the modal does not ship (the case exercises the modal, per
    the notas de ejecución). Mutant: route the summary through markup, or
    scrub without the exact-name inclusion.
    """

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(named_rows(HOSTILE_NAME))
        await settle(pilot, 2)
        modal = await open_bulk_modal(app, pilot, panel)
        need(modal, "#bulk_param_text", TextArea).text = HOSTILE_NAME + "\n[red]"
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        _, plain, spans = read_summary(modal)
        markup = [s for s in spans if MARKUP_SPAN_RE.search(str(s.style))]
        return list(panel._picked_params), plain, markup, control_bytes(plain)

    picks, summary, markup, controls = run(tmp_path, SIZE, body, a2l=None)
    assert picks == [HOSTILE_NAME], picks
    assert summary.startswith("Included 1 · already included 0 · not found 1"), summary
    assert "[red]" in summary, summary
    assert markup == [], markup
    assert controls == [], controls


# --------------------------------------------------------------------------- #
# TC-B102-BULK-07 — R-B102-BULK-007 — close/apply never rebuilds the ledger
# --------------------------------------------------------------------------- #


def test_tc_b102_bulk_07_close_and_apply_do_not_rebuild_the_ledger(tmp_path: Path, monkeypatch) -> None:
    """TC-B102-BULK-07 (R-B102-BULK-007, full; rulings 4, 6, 9): on a
    10 000-parameter picker, including a valid list updates the picked
    count/preview through exactly one ``SelectionChanged`` dispatch; closing
    the modal afterwards, reopening it and escaping without changes raise the
    ``_rebuild_ledger`` count never, call ``load_spec`` never, repaint the
    preview after the no-change close never, and dispatch no further
    ``SelectionChanged``.

    RED on base: the modal does not ship. Mutant: rebuild the ledger on
    modal close, or refresh through ``load_spec``.
    """
    rebuilds = {"n": 0}
    spy_ledger_rebuilds(monkeypatch, rebuilds)
    selections = {"n": 0}
    spy_selection_changes(monkeypatch, selections)
    load_specs = {"n": 0}
    spy_load_spec(monkeypatch, load_specs)

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(synthetic_rows(10000))
        await settle(pilot, 2)
        rebuilds["n"] = 0
        count = panel.query_one("#check_fields_count")
        modal = await open_bulk_modal(app, pilot, panel)
        need(modal, "#bulk_param_text", TextArea).text = "P00001\nP00002"
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        after_include = str(count.render())
        rebuilds_after_include = rebuilds["n"]
        selections_after_include = selections["n"]
        need(modal, "#bulk_param_close_button", Button).press()
        await wait_modal_closed(app, pilot)
        after_close = str(count.render())
        rebuilds_after_close = rebuilds["n"]
        modal_again = await open_bulk_modal(app, pilot, panel)
        await pilot.press("escape")
        await wait_modal_closed(app, pilot)
        after_escape = str(count.render())
        return (
            after_include,
            rebuilds_after_include,
            selections_after_include,
            after_close,
            rebuilds_after_close,
            after_escape,
            rebuilds["n"],
            selections["n"],
            load_specs["n"],
            list(panel._picked_params),
        )

    (
        after_include,
        rebuilds_after_include,
        selections_after_include,
        after_close,
        rebuilds_after_close,
        after_escape,
        rebuilds_final,
        selections_final,
        load_specs_total,
        picks,
    ) = run(tmp_path, SIZE, body, a2l=None)
    assert picks == ["P00001", "P00002"], picks
    assert after_include.startswith("2 ") and "→ report" in after_include, after_include
    assert selections_after_include == 1, (
        f"ruling 4: include_names dispatches SelectionChanged exactly once, got {selections_after_include}"
    )
    assert rebuilds_after_include == 0, f"an include never rebuilds the ledger: {rebuilds_after_include}"
    assert after_close.startswith("2 ") and "→ report" in after_close, after_close
    assert rebuilds_after_close == 0, f"the Close-after-include rebuilds the ledger: {rebuilds_after_close}"
    assert after_escape == after_close, (
        f"ruling 6: a no-change escape close repaints nothing: {after_escape!r} vs {after_close!r}"
    )
    assert rebuilds_final == 0, f"the modal session rebuilt the ledger {rebuilds_final} times"
    assert selections_final == 1, (
        f"ruling 6: neither close re-dispatches SelectionChanged: {selections_final}"
    )
    assert load_specs_total == 0, f"ruling 9: the modal close must not go through load_spec: {load_specs_total}"


def test_tc_b102_bulk_07_include_names_uses_hash_membership() -> None:
    """E3 ruling 7 (coste): ``A2LParameterPicker.include_names`` answers
    membership from a dict/set — no ``list.index`` call and no
    ``in self._picked_params`` inside the bulk loop — so thousands of pasted
    tokens do not pay O(n²) against the growing pick list.

    RED on base: ``include_names`` does not ship. Mutant: restore list
    membership (``index`` / ``in`` over ``_picked_params``) in the loop.
    """
    from s19_app.tui import a2l_parameter_picker as picker_mod

    source = Path(picker_module().__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "A2LParameterPicker"]
    assert len(classes) == 1, "A2LParameterPicker ships exactly once"
    methods = [
        n
        for n in classes[0].body
        if isinstance(n, ast.FunctionDef) and n.name == "include_names"
    ]
    assert len(methods) == 1, "A2LParameterPicker.include_names ships (R-B102-BULK-003)"
    fn = methods[0]
    banned_index = [
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "index"
    ]
    assert banned_index == [], "ruling 7: no list.index inside include_names"
    banned_in = [
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Compare)
        and any(isinstance(op, (ast.In, ast.NotIn)) for op in n.ops)
        and any(
            isinstance(c, ast.Attribute) and c.attr == "_picked_params" for c in n.comparators
        )
    ]
    assert banned_in == [], "ruling 7: no `in self._picked_params` inside include_names"
    hash_built = [
        n
        for n in ast.walk(fn)
        if isinstance(n, (ast.Set, ast.Dict))
        or (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in ("set", "dict", "frozenset")
        )
    ]
    dict_membership = [
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Compare)
        and any(isinstance(op, (ast.In, ast.NotIn)) for op in n.ops)
        and any(isinstance(c, ast.Attribute) and c.attr == "_param_rows" for c in n.comparators)
    ]
    assert hash_built or dict_membership, (
        "ruling 7: a dict/set must back the bulk membership tests"
    )


# --------------------------------------------------------------------------- #
# E3 ruling 8 — the 64 KiB input cap marks a truncated buffer
# --------------------------------------------------------------------------- #


def test_tc_b102_bulk_cap_input_marks_64kib_truncation(tmp_path: Path) -> None:
    """E3 ruling 8: the modal's text area carries the shipped 64 KiB cap; a
    paste over the cap lands truncated and the summary flags the truncation,
    naming the cap (65536 chars).

    RED on base: the modal does not ship. Mutant: apply no cap, or stay
    silent about the truncated buffer.
    """
    payload = "P00000\n" * 20000  # 140 000 chars — well over the 64 KiB cap

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(synthetic_rows(10000))
        await settle(pilot, 2)
        modal = await open_bulk_modal(app, pilot, panel)
        area = need(modal, "#bulk_param_text", TextArea)
        area.focus()
        await settle(pilot, 1)
        app.post_message(events.Paste(text=payload))
        await settle(pilot, 4)
        capped_len = len(area.text)
        need(modal, "#bulk_param_include_button", Button).press()
        await settle(pilot, 2)
        _, plain, _ = read_summary(modal)
        return capped_len, plain

    capped_len, summary = run(tmp_path, SIZE, body, a2l=None)
    assert capped_len <= CAP_CHARS, f"the paste is capped at 64 KiB, got {capped_len} chars"
    assert "Included" in summary and "not found" in summary, summary
    assert TRUNCATION_RE.search(summary), f"the summary must flag the truncated buffer: {summary}"
    assert str(CAP_CHARS) in summary, f"the summary must name the 65536-char cap: {summary}"
