"""Batch-97 Inc-4 — the Patch Editor as a ledger + inspector (HLR-144).

Covers LLR-144.1..144.12 (TC-B97-01..07, 39..42, 60) and the four acceptance
tests AT-B97-01, -02, -03, -17. Every assertion reads the shipped surface: the
composited strips (C-32, ``b97_probes.painted_rows``), the panel's widgets, the
service document the app holds. The image is the tracked ``prg.s19``, loaded
through the app's own loader; the change-sets are serialised per test (A.5).

PC-11: each test opens with a clause observable on ``main`` (table height,
inputs outside an inspector, 6 of 6 ledger rows, the paste buffer text), and a
new id is looked up through ``need()`` (an assertion), never ``query_one``,
so a run on the base tree fails at a named assertion — not ``NoMatches``.
New module names are reached as ``getattr(sdb, …)`` for the same reason.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Input, Select, TextArea

from s19_app.tui import screens_directionb as sdb
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import DUMMY_CHANGESET_TEXT, serialize_change_document
from tests.b97_fixtures import (
    CALIB_ADDRESSES,
    CALIB_ENTRIES,
    HOSTILE_C1,
    HOSTILE_CONTENT,
    HOSTILE_NAME,
    PE_IDS_9C7BEAF,
    calib_hotfix,
    empty_changeset,
    hostile_content_changeset,
    hostile_name_changeset,
    legacy_v1,
    load_change_file,
    open_patch_editor,
)
from tests.b97_probes import chip_style, is_displayed, painted_rows, painted_style, settle
from tests.test_b97_check_editor import need

SIZES = ((118, 54), (220, 60))
TABS = (
    ("patch_tab_inspector", "patch_pane_inspector"),
    ("patch_tab_json", "patch_win_json"),
    ("patch_tab_checks", "patch_win_checks"),
)
CONTAINER_IDS = (
    "patch_win_script",
    "patch_win_json",
    "patch_win_json_dock_spacer",
    "patch_win_checks",
    "patch_saveback_row",
    "patch_before_after_row",
    "patch_checks_results",
)
#: The PATCH family teal (operator, asked at the Inc-4 gate 2026-10-21): the
#: changed ``now`` bytes and the ``N changed`` count. Compared by hue distance
#: with a tolerance, never by hex equality (PC-7).
PATCH_TEAL = "#56e0d6"
HUE_TOLERANCE = 4.0


def _hsv(hex_color: str) -> tuple:
    import colorsys

    r, g, b = (int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5))
    return colorsys.rgb_to_hsv(r, g, b)


def hue_distance(a: str, b: str) -> float:
    d = abs(_hsv(a)[0] - _hsv(b)[0]) * 360.0 % 360.0
    return min(d, 360.0 - d)


def is_teal(hex_color) -> bool:
    """Saturated and within ``HUE_TOLERANCE`` of the PATCH teal's hue."""
    return bool(hex_color) and _hsv(hex_color)[1] > 0.3 and hue_distance(hex_color, PATCH_TEAL) <= HUE_TOLERANCE


def _style_hex(style) -> "str | None":
    color = getattr(style, "color", None)
    return color.triplet.hex if color is not None and color.triplet else None


STAMP_RE = re.compile(r"^(\d+) entr(?:y|ies) · (\d\d:\d\d:\d\d) · (saved|unsaved changes)$")
HEADER_RE = re.compile(r"^([0-9A-F]{8})((?: \+[0-9A-F])+)\s*$")


# --------------------------------------------------------------------------- #
# Drivers and readers
# --------------------------------------------------------------------------- #


def run(tmp_path: Path, size, body, *, image: bool = True):
    """Open the Patch Editor at ``size`` and return ``await body(app, pilot, panel)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            panel = await open_patch_editor(app, pilot, image=image)
            return await body(app, pilot, panel)

    return asyncio.run(_drive())


async def show_tab(panel, pilot, chip_id: str) -> None:
    """Press an inspector tab chip; absent on the base tree, so a no-op there."""
    chips = panel.query(f"#{chip_id}")
    if chips:
        chips.first().press()
        await settle(pilot, 3)


async def paste_document(panel, pilot, text: str) -> None:
    """Put ``text`` in the paste buffer and press Parse pasted (shipped control)."""
    panel.query_one("#patch_paste_text", TextArea).load_text(text)
    await settle(pilot, 2)
    panel.query_one("#patch_paste_parse_button", Button).press()
    await settle(pilot, 4)


def calib_text(tmp_path: Path) -> str:
    return calib_hotfix(tmp_path / "src").read_text(encoding="utf-8")


def view_text(panel):
    """The read-only JSON view's text, or ``None`` when the view is absent."""
    views = panel.query("#patch_json_view")
    return views.first(TextArea).text if views else None


def stamp(panel) -> str:
    stamps = panel.query("#patch_json_stamp")
    return str(stamps.first().render()).strip() if stamps else ""


def ledger_lines(app, panel) -> list:
    """The ledger rows painted at the current scroll (header excluded)."""
    table = panel.query_one("#patch_doc_entries_table", DataTable)
    if not table.display:
        return []
    return [row for row in painted_rows(app, table)[1:] if row.strip()]


def strip_reading(app, panel) -> list:
    """The strip as painted: one dict per byte row (address, offsets, was, now
    tokens and the ``now`` / ``was`` cells' bold flags)."""
    card = panel.query_one("#patch_before_after_card")
    rows = painted_rows(app, card)
    region = card.region
    out = []
    for index, line in enumerate(rows):
        text = line[1:].rstrip()  # the card's 1-cell left padding
        match = HEADER_RE.match(text)
        if not match or index + 2 >= len(rows):
            continue
        offsets = match.group(2).split()
        reading = {"address": int(match.group(1), 16), "offsets": offsets}
        for label, delta in (("was", 1), ("now", 2)):
            y = region.y + index + delta
            painted = rows[index + delta][1:]
            tokens, bolds, colors = [], [], []
            for col in range(len(offsets)):
                x0 = 9 + 3 * col
                tokens.append(painted[x0:x0 + 2])
                style = painted_style(app, region.x + 1 + x0, y)
                bolds.append(bool(style and style.bold))
                colors.append(_style_hex(style))
            reading[label] = tokens
            reading[label + "_bold"] = bolds
            reading[label + "_color"] = colors
        out.append(reading)
    return out


def _payload_spans(text) -> list:
    return [s for s in getattr(text, "spans", []) if re.search(r"link|click|^bold$|^red$", str(s.style))]


# --------------------------------------------------------------------------- #
# TC-B97-01 — LLR-144.1
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", SIZES)
def test_tc_b97_01_shipped_ids_and_container_types(tmp_path: Path, size) -> None:
    """TC-B97-01 (LLR-144.1): the panel yields all 66 ids frozen from
    ``9c7beaf`` (an id under ``display: none`` counts) and every container id
    of the frozen list keeps its ``Container`` type.

    RED: drop one shipped id from the composition (M1).
    """
    from textual.containers import Container

    async def body(app, pilot, panel):
        ids = {panel.id} | {w.id for w in panel.query("*") if w.id}
        types = {i: isinstance(app.query_one(f"#{i}"), Container) for i in CONTAINER_IDS if i in ids}
        return ids, types

    ids, types = run(tmp_path, size, body)
    assert len(PE_IDS_9C7BEAF) == 66
    assert PE_IDS_9C7BEAF - ids == set(), sorted(PE_IDS_9C7BEAF - ids)
    assert types == {i: True for i in CONTAINER_IDS}, types


# --------------------------------------------------------------------------- #
# TC-B97-02 — LLR-144.2
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", [(118, 54), (118, 53)])
def test_tc_b97_02_ledger_grows_with_the_panel(tmp_path: Path, size) -> None:
    """TC-B97-02 (LLR-144.2): with the 6-entry fixture loaded the ledger table
    is at least ``rows + 1`` and at least 7 rows tall, and all 6 rows paint
    without scrolling. The 118x53 arm is the body height 118x54 keeps once the
    two-row key bar lands (PC-24).

    RED on main: ``table region height 3`` with 6 rows (P-8).
    """

    async def body(app, pilot, panel):
        await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
        table = panel.query_one("#patch_doc_entries_table", DataTable)
        return table.region.height, table.row_count, len(ledger_lines(app, panel))

    height, rows, painted = run(tmp_path, size, body)
    assert rows == 6
    assert height >= rows + 1 and height >= 7, (height, rows)
    assert painted == 6, painted


def test_tc_b97_02_tab_chips_nine_activations(tmp_path: Path) -> None:
    """TC-B97-02 (LLR-144.2, tab arm): each of the three inspector tab chips
    switches the one ``ContentSwitcher`` by click, ``enter`` and ``space`` —
    9 of 9 — showing its pane and hiding the other two.

    RED on main: no tab chip (P-33). Mutation: ``TabChip`` without ``space``.
    """

    async def body(app, pilot, panel):
        switcher = need(panel, "#patch_tab_switcher")
        results = []
        for index, (chip_id, _pane) in enumerate(TABS):
            other = TABS[(index + 1) % 3][0]
            for how in ("click", "enter", "space"):
                await show_tab(panel, pilot, other)
                chip = need(panel, f"#{chip_id}")
                if how == "click":
                    await pilot.click(f"#{chip_id}")
                else:
                    chip.focus()
                    await settle(pilot, 2)
                    await pilot.press(how)
                await settle(pilot, 2)
                shown = [p for _c, p in TABS if is_displayed(panel.query_one(f"#{p}"))]
                results.append((chip_id, how, switcher.current, shown))
        return results

    results = run(tmp_path, (118, 54), body)
    for chip_id, how, current, shown in results:
        pane = dict(TABS)[chip_id]
        assert current == pane and shown == [pane], (chip_id, how, current, shown)
    assert len(results) == 9


# --------------------------------------------------------------------------- #
# TC-B97-03 — LLR-144.3
# --------------------------------------------------------------------------- #


def test_tc_b97_03_columns_once_and_no_geometry_pass(tmp_path: Path) -> None:
    """TC-B97-03 (LLR-144.3): after two shows and a resize the ledger has its
    five columns once, is not a forced 3-row band, the file select and path
    input widths follow the panel (118x54 vs 220x60), and ``app.py`` holds no
    show-time geometry call.

    RED on main: ``table.styles.height = 3`` → a 3-row table at both sizes;
    select / path 30 / 28 at both; ``app.py:6995`` calls the geometry pass.
    """

    async def body(app, pilot, panel):
        await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
        readings = []
        for size in ((118, 54), (220, 60)):
            await pilot.resize_terminal(*size)
            await settle(pilot, 4)
            app.action_show_screen("workspace")
            await settle(pilot, 2)
            app.action_show_screen("patch")
            await settle(pilot, 6)
            table = panel.query_one("#patch_doc_entries_table", DataTable)
            readings.append(
                (
                    len(table.columns),
                    table.region.height,
                    panel.query_one("#patch_doc_file_select").region.width,
                    panel.query_one("#patch_doc_path_input").region.width,
                )
            )
        return readings

    small, large = run(tmp_path, (118, 54), body)
    assert small[0] == large[0] == 5, (small, large)
    assert small[1] > 3 and large[1] > 3, (small, large)
    assert small[2] != large[2] and small[3] != large[3], (small, large)
    app_source = (Path(sdb.__file__).parent / "app.py").read_text(encoding="utf-8")
    assert "_apply_window_geometry" not in app_source


# --------------------------------------------------------------------------- #
# TC-B97-04 — LLR-144.4 (+ the D23 scope guard, Inc-3 F9)
# --------------------------------------------------------------------------- #

STYLES = Path(sdb.__file__).parent / "styles.tcss"

#: The unscoped rule the Check Editor's rows inherit, verbatim at ``98f3c84``
#: (``styles.tcss:1149-1154``). Inc-4 keeps it byte-equal (D23 guard).
DOCKED_RULE_98F3C84 = (
    ".patch-docked-row,\n"
    ".patch-docked-group {\n"
    "    width: 100%;\n"
    "    height: auto;\n"
    "    padding: 0 1;\n"
    "}\n"
)


def css_blocks(text: str) -> list:
    """(selectors, {property: value}) per rule — comments stripped, a selector
    list split on commas (C-42: parsed, never a line grep)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    blocks = []
    for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", text):
        selectors = [s.strip() for s in match.group(1).split(",") if s.strip()]
        props = {}
        for decl in match.group(2).split(";"):
            if ":" in decl:
                key, value = decl.split(":", 1)
                props[key.strip()] = value.strip()
        blocks.append((selectors, props))
    return blocks


def test_tc_b97_04_e3_pairs_absent() -> None:
    """TC-B97-04 (LLR-144.4): ``styles.tcss`` carries none of the four E-3
    selector/declaration pairs: ``#patch_win_script`` ``width: 2fr``,
    ``#patch_doc_entries_table`` ``height: 10``, ``#patch_doc_entry_buttons``
    and ``#patch_doc_controls`` ``layout: grid`` — matched per selector of a
    selector list, whatever the scoping prefix.

    RED on main: 4 of 4 pairs present (P-9). Mutation: restore one pair.
    """
    pairs = (
        ("#patch_win_script", "width", "2fr"),
        ("#patch_doc_entries_table", "height", "10"),
        ("#patch_doc_entry_buttons", "layout", "grid"),
        ("#patch_doc_controls", "layout", "grid"),
    )
    found = []
    for selectors, props in css_blocks(STYLES.read_text(encoding="utf-8")):
        for target, prop, value in pairs:
            if any(s.split()[-1] == target for s in selectors) and props.get(prop) == value:
                found.append((target, prop, value))
    assert found == [], found


def test_tc_b97_04_patch_rules_scoped_and_check_rule_untouched() -> None:
    """TC-B97-04 (D23 guard, Inc-3 F9): the unscoped ``.patch-docked-row,
    .patch-docked-group`` rule — which pads the Check Editor's spec row and
    memory inputs — is byte-equal to ``98f3c84``, and every selector of the
    ``/* batch-97 patch_editor */`` section starts with ``#patch_editor_panel``.

    Why: the Check Editor's rows still carry the Patch classes; an unscoped
    Patch rule would restyle a screen no snapshot cell shows.
    RED: an unscoped ``.patch-docked-row { padding: 0; }`` in the section (M3).
    """
    text = STYLES.read_text(encoding="utf-8")
    assert text.count(DOCKED_RULE_98F3C84) == 1
    marker = "/* batch-97 patch_editor"
    assert marker in text, "the scoped Patch Editor section exists"
    section = text.split(marker, 1)[1]
    following = re.search(r"\n/\* batch-97 (?!patch_editor)", section)
    if following:
        section = section[: following.start()]
    selectors = [s for sels, _p in css_blocks("/*" + section) for s in sels]
    assert len(selectors) >= 20, len(selectors)
    unscoped = [s for s in selectors if not s.startswith("#patch_editor_panel")]
    assert unscoped == [], unscoped


#: The class rules outside the section that stay unscoped on purpose: the
#: Check Editor's rows and labels carry these classes too (Inc-3 F9), and the
#: docked-row rule is the byte-equal ``98f3c84`` guard above.
_UNSCOPED_PATCH_ALLOW = {".patch-docked-row", ".patch-docked-group", ".patch-section-title", ".patch-field-label"}


def test_tc_b97_04_no_unscoped_patch_rule_in_the_whole_stylesheet() -> None:
    """TC-B97-04 (D23 scope arm over the whole file; Inc-4 gate, code-reviewer
    F2): no selector anywhere in ``styles.tcss`` names a ``#patch_*`` id or a
    ``.patch-*`` class without the ``#patch_editor_panel`` root, apart from the
    allow-listed shared class rules — so a dead or duplicate Patch rule cannot
    hide outside the scoped section.

    RED on the pre-fold tree: ``#patch_variant_row``, ``#patch_execute_row``,
    ``#patch_variant_select_row``, ``#patch_doc_issues``,
    ``#patch_checks_results`` (M47 puts one back).
    """
    stray = []
    for selectors, _props in css_blocks(STYLES.read_text(encoding="utf-8")):
        for selector in selectors:
            if selector.startswith("#patch_editor_panel") or selector in _UNSCOPED_PATCH_ALLOW:
                continue
            if "#patch_" in selector or ".patch-" in selector:
                stray.append(selector)
    assert stray == [], stray


# --------------------------------------------------------------------------- #
# TC-B97-05 — LLR-144.5
# --------------------------------------------------------------------------- #


def test_tc_b97_05_json_view_shows_the_loaded_document(tmp_path: Path) -> None:
    """TC-B97-05 (LLR-144.5): after Load the JSON view's text parses to the
    file's six addresses (never the dummy template), typing into the view
    changes nothing, and a Parse of the paste buffer reads the buffer, not the
    view.

    RED on main: the buffer still equals ``DUMMY_CHANGESET_TEXT`` with 2
    address keys after Load (P-4).
    """

    async def body(app, pilot, panel):
        path = calib_hotfix(tmp_path)
        await load_change_file(app, pilot, panel, path)
        buffer_after_load = panel.query_one("#patch_paste_text", TextArea).text
        text = view_text(panel)
        typed = None
        if text is not None:
            await show_tab(panel, pilot, "patch_tab_json")
            view = panel.query_one("#patch_json_view", TextArea)
            view.focus()
            await settle(pilot, 2)
            await pilot.press("x", "y", "enter")
            await settle(pilot, 2)
            typed = view.text
        file_addresses = [e["address"] for e in json.loads(path.read_text(encoding="utf-8"))["entries"]]
        return buffer_after_load, text, typed, file_addresses

    buffer, text, typed, file_addresses = run(tmp_path, (118, 54), body)
    assert file_addresses == CALIB_ADDRESSES
    assert text is not None, f"no JSON view; the buffer still reads the template: {buffer == DUMMY_CHANGESET_TEXT}"
    assert text != DUMMY_CHANGESET_TEXT
    assert [e["address"] for e in json.loads(text)["entries"]] == file_addresses
    assert typed == text, "the view is read-only"


def test_tc_b97_05_cap_note_and_display_only(tmp_path: Path) -> None:
    """TC-B97-05 (LLR-144.5, cap and display-only arms): a 5001-line document
    shows 5000 lines + ``showing 5000 of 5001 lines``; a 5000-line one shows
    no note; a 100,000-entry document is capped; and Parse pasted reads the
    paste buffer (6 entries), never the capped view.

    RED: the cap removed (M5); Parse wired to the view's text (M6).
    """
    view_cls = getattr(sdb, "PatchDocumentView", None)
    assert view_cls is not None, "the I-2/I-3 payload type exists"
    from s19_app.tui.changes.model import ChangeDocument, ChangeEntry

    big = ChangeDocument(
        format="s19app-changeset", version="2.0", kind="change", encoding="utf-8",
        value_mode="text",
        entries=[ChangeEntry(entry_type="bytes", address=0x10000 + 2 * i, encoded_bytes=(i & 0xFF,)) for i in range(100_000)],
    )
    big_text = serialize_change_document(big).decode("ascii")

    async def body(app, pilot, panel):
        out = {}
        for name, text in (
            ("5001", "\n".join(f"line {i}" for i in range(5001))),
            ("5000", "\n".join(f"line {i}" for i in range(5000))),
            ("big", big_text),
        ):
            panel.refresh_entries([], document=view_cls(None, "change", text, 0))
            await settle(pilot, 2)
            out[name] = view_text(panel).split("\n")
        await paste_document(panel, pilot, calib_text(tmp_path))
        out["parsed"] = len(app._change_service.document.entries)
        return out

    out = run(tmp_path, (118, 54), body)
    assert len(out["5001"]) == 5001 and out["5001"][-1] == "showing 5000 of 5001 lines"
    assert len(out["5000"]) == 5000 and not out["5000"][-1].startswith("showing")
    assert len(out["big"]) == 5001 and out["big"][-1].startswith("showing 5000 of ")
    assert out["parsed"] == 6


def test_tc_b97_05_paste_heading_names_the_example(tmp_path: Path) -> None:
    """TC-B97-05 (Inc-4 gate, ux-reviewer Obs 5): while the paste buffer holds
    the shipped example (``DUMMY_CHANGESET_TEXT``) its heading reads ``PASTE
    BUFFER · example``, whole beside the gauge on one row inside the 41-cell
    pane at 118 columns; the first edit turns it to ``PASTE BUFFER ·
    editable``. Why: the template is not the operator's text, and the heading
    is the one place that says so.

    RED on the pre-fold tree: the heading reads ``editable`` from the start
    (M43).
    """

    async def body(app, pilot, panel):
        await show_tab(panel, pilot, "patch_tab_json")
        head = panel.query_one("#patch_paste_head")
        buffer = panel.query_one("#patch_paste_text", TextArea)
        first = (buffer.text == DUMMY_CHANGESET_TEXT, painted_rows(app, head)[0], head.region)
        buffer.focus()
        await settle(pilot, 2)
        await pilot.press("end", "z")
        await settle(pilot, 3)
        return first, painted_rows(app, head)[0], panel.query_one("#patch_inspector").content_region

    (is_dummy, before, region), after, inspector = run(tmp_path, (118, 54), body)
    assert is_dummy
    assert before.startswith("PASTE BUFFER · example"), before
    assert "…" not in before and re.search(r"\d", before), before  # the gauge is whole on the row
    assert inspector.contains_region(region), (region, inspector)
    assert after.startswith("PASTE BUFFER · editable"), after


def test_tc_b97_05_text_area_scrollbars_are_muted(tmp_path: Path) -> None:
    """Inc-4 gate (ux-reviewer 4a): the JSON view's and the paste buffer's
    scrollbars paint a muted DGRAY tone (thumb, hover and active), not the
    theme's accent; the view still scrolls sideways (no soft wrap) and neither
    hides its x overflow.

    RED on the pre-fold tree: the theme scrollbar colours (M44).
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            panel = await open_patch_editor(app, pilot, image=False)
            out = {}
            for wid in ("patch_json_view", "patch_paste_text"):
                styles = panel.query_one(f"#{wid}", TextArea).styles
                area = panel.query_one(f"#{wid}", TextArea)
                out[wid] = (
                    [styles.scrollbar_color.hex[:7], styles.scrollbar_color_hover.hex[:7],
                     styles.scrollbar_color_active.hex[:7]],
                    styles.overflow_x,
                    area.soft_wrap,
                )
            return out

    out = asyncio.run(_drive())
    for wid, (colours, overflow_x, soft_wrap) in out.items():
        for colour in colours:
            assert _hsv(colour)[1] < 0.25, (wid, colour)
            assert hue_distance(colour, sdb.DGRAY) <= 12.0 or _hsv(colour)[1] < 0.05, (wid, colour)
        assert overflow_x != "hidden", (wid, overflow_x)
    # The read-only view keeps its sideways scroll (no soft wrap, D3); the
    # paste buffer keeps its shipped soft wrap.
    assert out["patch_json_view"][2] is False and out["patch_paste_text"][2] is True, out


# --------------------------------------------------------------------------- #
# TC-B97-06 — LLR-144.6
# --------------------------------------------------------------------------- #


def _clock(monkeypatch):
    """Monkeypatch the panel's clock seam to 00:00:01, 00:00:02, … (A.4)."""
    ticks = iter(range(1, 10_000))
    # raising=False: on the base tree the seam is absent, and the arm must fail
    # at its own clause (PC-11), not at the monkeypatch.
    monkeypatch.setattr(sdb, "_json_clock", lambda: f"00:00:{next(ticks):02d}"[-8:], raising=False)


def _arm(app, panel) -> dict:
    service = app._change_service
    text = view_text(panel)
    match = STAMP_RE.match(stamp(panel))
    return {
        "view": json.loads(text) if text and text.startswith("{") else None,
        "service": json.loads(serialize_change_document(service.document)),
        "stamp": stamp(panel),
        "n": int(match.group(1)) if match else None,
        "time": match.group(2) if match else None,
        "state": match.group(3) if match else None,
        "dirty": panel._dirty,
        "text": text,
    }


def test_tc_b97_06_every_writer_refreshes_the_view_at_once(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-06 (LLR-144.6, writer arms): each writer of the document —
    paste-parse, Add, Edit, Remove, Undo, Redo, edit-entry-JSON, Load and
    ``add_symbol_entry`` (service + the I-3 seam) — leaves the view equal to
    the serialised document with no further press, the stamp's N equal to the
    parsed count and its state ``saved`` iff the dirty flag is clear.

    RED: the Undo site's ``document=`` dropped (M7) → the Undo arm keeps the
    pre-undo view.
    """
    _clock(monkeypatch)

    async def body(app, pilot, panel):
        arms = {}
        await paste_document(panel, pilot, calib_text(tmp_path))
        arms["paste"] = _arm(app, panel)
        form = {
            "#patch_entry_address_input": "0xED80",
            "#patch_entry_bytes_input": "11 22",
            "#patch_entry_value_input": "",
        }
        for selector, value in form.items():
            panel.query_one(selector, Input).value = value
        panel.query_one("#patch_entry_add_button", Button).press()
        await settle(pilot, 4)
        arms["add"] = _arm(app, panel)
        panel.query_one("#patch_entry_bytes_input", Input).value = "33 44 55"
        panel.query_one("#patch_entry_edit_button", Button).press()
        await settle(pilot, 4)
        arms["edit"] = _arm(app, panel)
        panel.query_one("#patch_entry_remove_button", Button).press()
        await settle(pilot, 4)
        arms["remove"] = _arm(app, panel)
        panel.query_one("#patch_undo_button", Button).press()
        await settle(pilot, 4)
        arms["undo"] = _arm(app, panel)
        panel.query_one("#patch_redo_button", Button).press()
        await settle(pilot, 4)
        arms["redo"] = _arm(app, panel)
        entry = json.dumps({"type": "bytes", "address": "0xEB10", "bytes": "01 02 03 04"})
        app._apply_entry_json_edit(0, entry)
        await settle(pilot, 4)
        arms["entry_json"] = _arm(app, panel)
        from tests.test_changes_symbol_entries import _A2L_TEXT
        from s19_app.tui.a2l_parse import parse_a2l_file

        a2l = tmp_path / "cal.a2l"
        a2l.write_text(_A2L_TEXT, encoding="utf-8")
        added = app._change_service.add_symbol_entry("Speed", "210", parse_a2l_file(a2l))
        assert added.ok, added.message
        app._refresh_patch_history_view()
        await settle(pilot, 4)
        arms["symbol"] = _arm(app, panel)
        await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
        # The document is dirty, so Load asks first (LLR-005.2): accept the loss.
        if app.screen.query("#load_guard_accept"):
            app.screen.query_one("#load_guard_accept", Button).press()
            await settle(pilot, 6)
        arms["load"] = _arm(app, panel)
        return arms

    arms = run(tmp_path, (118, 54), body)
    assert list(arms) == ["paste", "add", "edit", "remove", "undo", "redo", "entry_json", "symbol", "load"]
    for name, arm in arms.items():
        assert arm["view"] == arm["service"], name
        assert arm["n"] == len(arm["service"]["entries"]), (name, arm["stamp"])
        assert arm["state"] == ("unsaved changes" if arm["dirty"] else "saved"), (name, arm["stamp"])
    # Named supersession (Inc-4 gate, ux-reviewer H1): a parsed paste is a
    # draft nobody saved, so its stamp reads ``unsaved changes`` (was ``saved``).
    assert arms["paste"]["state"] == "unsaved changes" and arms["load"]["state"] == "saved"
    assert arms["add"]["state"] == "unsaved changes" and arms["add"]["n"] == 7
    assert arms["undo"]["n"] == arms["edit"]["n"] and arms["redo"]["n"] == arms["remove"]["n"]
    assert len({arm["time"] for arm in arms.values()}) == len(arms), "every new payload restamps"


def test_tc_b97_06_paste_parse_marks_the_document_unsaved(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-06 (LLR-144.6 as amended at the Inc-4 gate, ux-reviewer H1):
    Parse pasted replaces the document with one no file holds, so the stamp
    reads ``unsaved changes`` and the ribbon ``draft`` — the two never
    disagree — and a Load afterwards asks first (the guard reads the same flag).

    RED: the parse clears the dirty flag (``mark_loaded``, the pre-fold wiring)
    → ``saved`` beside ``draft`` (M42).
    """
    _clock(monkeypatch)

    async def body(app, pilot, panel):
        await paste_document(panel, pilot, calib_text(tmp_path))
        ribbon = str(need(panel, "#patch_identity_ribbon").render())
        arm = _arm(app, panel)
        await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
        guarded = bool(app.screen.query("#load_guard_accept"))
        return ribbon, arm, guarded

    ribbon, arm, guarded = run(tmp_path, (118, 54), body)
    assert arm["view"] == arm["service"] and arm["n"] == 6, arm["stamp"]
    assert "draft" in ribbon, ribbon
    assert arm["state"] == "unsaved changes" and arm["dirty"] is True, (ribbon, arm["stamp"])
    assert guarded, "a Load over a parsed paste must ask first (LLR-005.2)"


def test_tc_b97_06_dirty_flag_arms_save_and_typing(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-06 (LLR-144.6, the two dirty-flag arms, PC-18): after an Add,
    Save turns the stamp to ``saved`` with N, the time and the view text
    unchanged (the document is byte-equal, so only ``mark_saved`` reaches the
    stamp); one character typed into the paste buffer turns it to ``unsaved
    changes`` with the view unchanged.

    RED: the stamp recomposed by the document path only (M8) → the Save arm
    stays ``unsaved changes`` and the typing arm stays ``saved``.
    """
    _clock(monkeypatch)

    async def body(app, pilot, panel):
        await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
        panel.query_one("#patch_entry_address_input", Input).value = "0xED80"
        panel.query_one("#patch_entry_bytes_input", Input).value = "11 22"
        panel.query_one("#patch_entry_add_button", Button).press()
        await settle(pilot, 4)
        added = _arm(app, panel)
        panel.query_one("#patch_doc_save_button", Button).press()
        await settle(pilot, 4)
        saved = _arm(app, panel)
        await show_tab(panel, pilot, "patch_tab_json")
        paste = panel.query_one("#patch_paste_text", TextArea)
        paste.focus()
        await settle(pilot, 2)
        await pilot.press("z")
        await settle(pilot, 3)
        typed = _arm(app, panel)
        return added, saved, typed

    added, saved, typed = run(tmp_path, (118, 54), body)
    assert added["state"] == "unsaved changes" and added["n"] == 7, added["stamp"]
    assert saved["text"] == added["text"] and saved["time"] == added["time"], (added["stamp"], saved["stamp"])
    assert saved["state"] == "saved" and saved["n"] == 7, saved["stamp"]
    assert typed["text"] == saved["text"], "typing in the paste buffer leaves the view alone"
    assert typed["state"] == "unsaved changes" and typed["time"] == saved["time"], typed["stamp"]


def test_tc_b97_06_equal_payload_and_fresh_start(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-06 (LLR-144.6, equal-payload and fresh-start arms): before any
    document the view holds one state line and the stamp reads ``no document
    yet``; after a Load, a Validate with the document unchanged leaves the view
    text, its scroll offset and the stamp unchanged.

    RED: an equal payload repainted (M9) → the time moves and ``scroll_y``
    returns to 0.
    """
    _clock(monkeypatch)

    async def body(app, pilot, panel):
        fresh = (view_text(panel), stamp(panel))
        await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
        await show_tab(panel, pilot, "patch_tab_json")
        view = panel.query_one("#patch_json_view", TextArea) if panel.query("#patch_json_view") else None
        before = after = None
        if view is not None:
            view.scroll_to(y=10, animate=False)
            await settle(pilot, 2)
            before = (view.text, view.scroll_y, stamp(panel))
            panel.query_one("#patch_doc_validate_button", Button).press()
            await settle(pilot, 4)
            after = (view.text, view.scroll_y, stamp(panel))
        return fresh, before, after

    fresh, before, after = run(tmp_path, (118, 54), body, image=False)
    assert fresh[0] is not None and fresh[0].strip().count("\n") == 0, fresh
    assert fresh[0].strip() == "No document yet: Load, paste or Add.", fresh
    assert fresh[1] == "no document yet", fresh
    assert before is not None and before[1] == 10, before
    assert after == before, (before, after)


# --------------------------------------------------------------------------- #
# TC-B97-07 — LLR-144.7
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("arm", ["name", "content"])
def test_tc_b97_07_file_derived_text_renders_literally(tmp_path: Path, arm: str) -> None:
    """TC-B97-07 (LLR-144.7): a markup-laden file name and entry content read
    literally on the ribbon, the ledger row, the JSON view and the issues
    line, with 0 ``MarkupError``, 0 spans originating in the payload and 0
    C0/C1 control characters painted.

    RED: the ribbon built with ``Text.from_markup`` (M10).
    """

    async def body(app, pilot, panel):
        path = hostile_name_changeset(tmp_path) if arm == "name" else hostile_content_changeset(tmp_path)
        await load_change_file(app, pilot, panel, path)
        ribbon = need(panel, "#patch_identity_ribbon").render()
        table = panel.query_one("#patch_doc_entries_table", DataTable)
        cells = [table.get_row_at(i) for i in range(table.row_count)]
        issues = panel.query_one("#patch_doc_issues").render()
        painted = "\n".join(painted_rows(app, panel))
        await show_tab(panel, pilot, "patch_tab_json")
        return ribbon, cells, issues, view_text(panel), painted, list(app.log_lines)

    ribbon, cells, issues, view, painted, log = run(tmp_path, (118, 54), body)
    assert not any("MarkupError" in line for line in log), log[-3:]
    assert not [c for c in painted if (ord(c) < 0x20 and c != "\n") or 0x7F <= ord(c) <= 0x9F]
    surfaces = [("ribbon", ribbon), ("issues", issues)] + [
        (f"ledger {i}.{j}", cell) for i, row in enumerate(cells) for j, cell in enumerate(row)
    ]
    for name, text in surfaces:
        assert hasattr(text, "spans"), name
        assert _payload_spans(text) == [], (name, text.spans)
    if arm == "name":
        assert HOSTILE_NAME in ribbon.plain, ribbon.plain
    else:
        values = [cell.plain for row in cells for cell in row]
        assert any("[bold]x[/]y" in v for v in values), values
        assert "[bold]x[/]y" in issues.plain, issues.plain
        assert view is not None and HOSTILE_CONTENT.split("\x07")[0] in json.loads(view)["entries"][0]["value"]


# --------------------------------------------------------------------------- #
# TC-B97-39 — LLR-144.8 + the D5 grid
# --------------------------------------------------------------------------- #


def test_tc_b97_39_strip_follows_the_highlight(tmp_path: Path) -> None:
    """TC-B97-39 (LLR-144.8, D5): moving the ledger highlight down over three
    rows repaints the strip for each: its ``now`` bytes are the entry's bytes,
    its ``was`` bytes the image's at those addresses, every changed byte of
    the span is bold on the ``now`` line, and no unchanged or context byte is
    bold; rows are aligned to the row width (8 at 118 columns).

    RED on main: no strip in an inspector. Mutation: the strip bound to row 0
    (M11); bold on an unchanged byte (M12); bold on a context byte (M13).
    """

    async def body(app, pilot, panel):
        await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
        table = panel.query_one("#patch_doc_entries_table", DataTable)
        table.focus()
        await settle(pilot, 2)
        mem = app.current_file.mem_map
        readings = []
        for _ in range(3):
            await pilot.press("down")
            await settle(pilot, 3)
            readings.append((table.cursor_row, strip_reading(app, panel)))
        return readings, mem

    readings, mem = run(tmp_path, (118, 54), body)
    assert [row for row, _r in readings] == [1, 2, 3]
    for row, reading in readings:
        address, run_bytes = CALIB_ENTRIES[row]
        assert reading, f"row {row}: no strip painted"
        span = range(address, address + len(run_bytes))
        for byte_row in reading:
            assert byte_row["address"] % 8 == 0 and len(byte_row["offsets"]) == 8, byte_row
            for col in range(8):
                at = byte_row["address"] + col
                image = mem.get(at)
                was_token = "--" if image is None else f"{image:02X}"
                assert byte_row["was"][col] == was_token, (row, hex(at), byte_row)
                if at in span:
                    write = run_bytes[at - address]
                    assert byte_row["now"][col] == f"{write:02X}", (row, hex(at))
                    changed = image is None or image != write
                    assert byte_row["now_bold"][col] is changed, (row, hex(at), byte_row)
                    # Inc-4 gate, operator decision 1: a changed ``now`` byte is
                    # painted teal; an unchanged one is not.
                    assert is_teal(byte_row["now_color"][col]) is changed, (row, hex(at), byte_row["now_color"])
                else:
                    assert byte_row["now"][col] == was_token
                    assert byte_row["now_bold"][col] is False, (row, hex(at))
                    assert not is_teal(byte_row["now_color"][col]), (row, hex(at))
                assert not is_teal(byte_row["was_color"][col]), (row, hex(at))
                assert byte_row["was_bold"][col] is False
        assert sum(byte_row["now_bold"].count(True) for byte_row in reading) >= 1


def test_tc_b97_39_long_entry_stacks_rows_and_follows_a_resize(tmp_path: Path) -> None:
    """TC-B97-39 (D5 (b)(c)(f), PC-19): a 20-byte entry at ``0xEB14`` paints
    3 stacked byte rows at 118 columns and 2 at 220 (16 bytes per row), re-read
    after each resize, never elided to its first bytes.

    RED: rows elided to the first 8 bytes (the shipped ``max_bytes`` path,
    M14); the strip not re-rendered on resize (M15).
    """

    async def body(app, pilot, panel):
        panel.query_one("#patch_entry_address_input", Input).value = "0xEB14"
        panel.query_one("#patch_entry_bytes_input", Input).value = " ".join(f"{i:02X}" for i in range(20))
        panel.query_one("#patch_entry_add_button", Button).press()
        await settle(pilot, 4)
        out = []
        for size in ((118, 54), (220, 60), (118, 54)):
            await pilot.resize_terminal(*size)
            await settle(pilot, 6)
            out.append([(r["address"], len(r["offsets"])) for r in strip_reading(app, panel)])
        return out

    small, large, back = run(tmp_path, (118, 54), body)
    assert small == [(0xEB10, 8), (0xEB18, 8), (0xEB20, 8)], small
    assert large == [(0xEB10, 16), (0xEB20, 16)], large
    assert back == small


def test_tc_b97_39_strip_builder_states_and_cap() -> None:
    """TC-B97-39 (D5 (c)(d)(h), layer 0): the three state lines fit the 38-cell
    card; a 200-byte run paints 8 rows + ``showing 64 of 200 bytes``; the
    summary counts changed bytes over the whole span.

    RED: no cap (M16); a state line wider than the card.
    """
    for line in (sdb.CARD_NO_SELECTION, sdb.CARD_NO_IMAGE, getattr(sdb, "CARD_NO_ENTRIES", "")):
        assert 0 < len(line) <= 38, line
    after = [0x11] * 200
    before = [0x11] * 100 + [0x22] * 100
    text = sdb.before_after_card_text(0x1000, before, after, 8)
    lines = text.plain.split("\n")
    headers = [line for line in lines if HEADER_RE.match(line)]
    assert len(headers) == getattr(sdb, "STRIP_ROW_CAP", 0) == 8
    assert "showing 64 of 200 bytes" in lines
    assert lines[-1] == "200 B @ 0x00001000 · 100 changed"
    assert all(len(line) <= 3 * 8 + 8 for line in lines[:-2])


def _bold_tokens(text, line_index: int) -> list:
    """(token, bold) for each 2-char byte token of one line of a strip ``Text``."""
    plain = text.plain
    starts = [0] + [i + 1 for i, c in enumerate(plain) if c == "\n"]
    start = starts[line_index]
    line = plain.split("\n")[line_index]
    out = []
    for col in range((len(line) - 9 + 1) // 3):
        offset = start + 9 + 3 * col
        bold = any(
            s.start <= offset < s.end and "bold" in str(s.style) for s in text.spans
        )
        out.append((line[9 + 3 * col:11 + 3 * col], bold))
    return out


def test_tc_b97_39_bold_marks_only_changed_span_bytes() -> None:
    """TC-B97-39 (LLR-144.8, layer 0): on the ``now`` line only a changed span
    byte is bold — not an unchanged span byte, not a context byte, never on the
    ``was`` line. Why: the attribute is how a byte that changes is told apart
    from one that does not without colour.

    RED: bold on an unchanged span byte (M12); bold on a context byte (M13).
    """
    # row 0x1000: lead 0x10 0x11, span 0x12 (same) 0x13 (changed), trail rest
    text = sdb.before_after_card_text(
        0x1002, [0x12, 0x13], [0x12, 0xFF], 8, lead=[0x10, 0x11], trail=[0x14, 0x15, 0x16, 0x17]
    )
    now = _bold_tokens(text, 2)
    was = _bold_tokens(text, 1)
    assert [t for t, _b in now] == ["10", "11", "12", "FF", "14", "15", "16", "17"], now
    assert [b for _t, b in now] == [False, False, False, True, False, False, False, False], now
    assert not any(b for _t, b in was), was


def _span_style_at(text, offset: int) -> str:
    return " ".join(str(s.style) for s in text.spans if s.start <= offset < s.end)


def test_tc_b97_39_changed_bytes_and_count_paint_teal() -> None:
    """TC-B97-39 (D5 (e) as amended at the Inc-4 gate, operator decision 1,
    layer 0): a changed span byte on the ``now`` line and the ``N changed``
    count paint the PATCH teal and bold; an unchanged span byte, a context
    byte and every ``was`` byte never paint teal; ``0 changed`` stays DGRAY and
    not bold. Why: the teal is the patch family's cue for "this byte is what
    the patch writes", so it must mark exactly the bytes that change.

    RED on the pre-fold tree: the changed byte paints ``bold VALUE`` (white)
    and the count ``VALUE``. Mutation: the ``now`` byte back to ``VALUE``
    (M40); the count not teal (M41).
    """
    text = sdb.before_after_card_text(
        0x1002, [0x12, 0x13], [0x12, 0xFF], 8, lead=[0x10, 0x11], trail=[0x14, 0x15, 0x16, 0x17]
    )
    plain = text.plain
    lines = plain.split("\n")
    starts = [0] + [i + 1 for i, c in enumerate(plain) if c == "\n"]
    for line_index, teal_cols in ((1, set()), (2, {3})):
        for col in range(8):
            style = _span_style_at(text, starts[line_index] + 9 + 3 * col)
            colours = [w for w in style.split() if w.startswith("#")]
            teal = any(is_teal(c) for c in colours)
            assert teal is (col in teal_cols), (line_index, col, style)
            if col in teal_cols:
                assert "bold" in style.split(), style
    summary = lines[-1]
    assert summary == "2 B @ 0x00001002 · 1 changed", summary
    count_at = starts[-1] + summary.index("1 changed")
    count_style = _span_style_at(text, count_at).split()
    assert "bold" in count_style and any(is_teal(c) for c in count_style if c.startswith("#")), count_style
    same = sdb.before_after_card_text(0x1000, [0x11], [0x11], 8, trail=[0] * 7)
    zero_at = same.plain.rindex("0 changed")
    zero_style = _span_style_at(same, zero_at).split()
    assert "bold" not in zero_style and not any(is_teal(c) for c in zero_style if c.startswith("#")), zero_style
    assert hue_distance(sdb.DGRAY, [c for c in zero_style if c.startswith("#")][0]) <= HUE_TOLERANCE


# --------------------------------------------------------------------------- #
# TC-B97-40 — LLR-144.9
# --------------------------------------------------------------------------- #

FORM = (
    ("patch_entry_address_input", "Address"),
    ("patch_entry_value_input", "String"),
    ("patch_entry_bytes_input", "Bytes"),
)
CHIPS = ("patch_entry_add_button", "patch_entry_edit_button", "patch_entry_remove_button", "patch_entry_edit_json_button")


@pytest.mark.parametrize("size", [(118, 54), (118, 53)])
def test_tc_b97_40_labelled_form_and_chips_in_the_inspector(tmp_path: Path, size) -> None:
    """TC-B97-40 (LLR-144.9): the three entry inputs and the four entry chips
    sit inside the Inspector pane, each input beside a label naming its field
    on its own row, the four chips on one row.

    RED on main: the inputs sit in ``#patch_doc_entry_inputs`` inside the JSON
    window, outside any inspector pane.
    """
    from textual.widgets import Label

    async def body(app, pilot, panel):
        ancestors = {
            wid: [a.id for a in panel.query_one(f"#{wid}").ancestors if getattr(a, "id", None)]
            for wid, _l in FORM
        }
        # PC-11: the main-observable clause (the inputs' ancestry) is asserted
        # before the NEW pane id is looked up, so the base tree fails there.
        if not all("patch_pane_inspector" in a for a in ancestors.values()):
            return ancestors, None, {}, {}
        pane = need(panel, "#patch_pane_inspector")
        regions = {wid: panel.query_one(f"#{wid}").region for wid in [w for w, _ in FORM] + list(CHIPS)}
        labels = {}
        for wid, _name in FORM:
            region = regions[wid]
            labels[wid] = [
                str(lab.render()).strip()
                for lab in panel.query(Label)
                if is_displayed(lab) and lab.region.y == region.y and lab.region.right <= region.x
            ]
        address = regions["patch_entry_address_input"]
        backgrounds = (
            painted_style(app, address.x + address.width - 2, address.y).bgcolor.triplet.hex,
            painted_style(app, pane.region.right - 2, pane.region.y).bgcolor.triplet.hex,
        )
        return ancestors, pane.region, regions, labels, backgrounds

    ancestors, pane, regions, labels, backgrounds = run(tmp_path, size, body)
    for wid, _name in FORM:
        assert "patch_pane_inspector" in ancestors[wid], (wid, ancestors[wid])
    for wid, region in regions.items():
        assert pane.contains_region(region), (wid, region, pane)
    for wid, name in FORM:
        assert labels[wid] and labels[wid][-1] == name, (wid, labels[wid])
    assert len({regions[c].y for c in CHIPS}) == 1
    assert len({regions[w].y for w, _ in FORM}) == 3
    # Inc-4 gate, operator decision 2: one spacer row between the three
    # input rows, and the inputs on a background lighter than the pane's,
    # the stylesheet's ``$rule`` token (RED pre-fold: consecutive rows, the
    # theme's #1e1e1e — M45, M46).
    ys = [regions[w].y for w, _ in FORM]
    assert [b - a for a, b in zip(ys, ys[1:])] == [2, 2], ys
    field_bg, pane_bg = backgrounds
    assert _luminance(field_bg) > _luminance(pane_bg), backgrounds
    assert field_bg == _css_token("rule"), (backgrounds, _css_token("rule"))


def _luminance(hex_color: str) -> float:
    r, g, b = (int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _css_token(name: str) -> str:
    match = re.search(rf"^\${name}:\s*(#[0-9a-fA-F]{{6}})", STYLES.read_text(encoding="utf-8"), re.M)
    assert match, name
    return match.group(1).lower()


#: Rows the Add / Edit / Remove chips sit below the pane's fold at scroll 0
#: when the strip is at its 8-row cap (an entry of >= 57 bytes): the cost the
#: operator accepted for the spaced form (Inc-4 gate 2026-10-21, decision 2).
_CHIPS_BELOW_FOLD = {(118, 53): 2, (118, 54): 1}


@pytest.mark.parametrize("size", [(118, 54), (118, 53)])
def test_tc_b97_40_capped_strip_chips_reachable(tmp_path: Path, size) -> None:
    """TC-B97-40 (LLR-144.9; Inc-4 gate, operator decision 2): with a 64-byte
    entry selected the strip paints its 8 capped rows and its note; the entry chips then sit
    exactly the accepted rows below the pane's fold at scroll 0 (2 at 118x53,
    1 at 118x54) and come inside by ``tab`` focus and by scrolling the pane.

    RED on the pre-fold tree: -1 / 0 rows (no spacer rows; the chips inside).
    """

    async def body(app, pilot, panel):
        # 64 bytes from 0xEB14 span 9 aligned rows: the strip paints its cap
        # of 8 and the note line — its tallest form.
        panel.query_one("#patch_entry_address_input", Input).value = "0xEB14"
        panel.query_one("#patch_entry_bytes_input", Input).value = " ".join(["5A"] * 64)
        panel.query_one("#patch_entry_add_button", Button).press()
        await settle(pilot, 4)
        pane = need(panel, "#patch_pane_inspector")
        pane.scroll_home(animate=False)
        await settle(pilot, 3)
        rows = len(strip_reading(app, panel))
        bottom = pane.content_region.bottom
        below = max(panel.query_one(f"#{c}").region.bottom for c in CHIPS[:3]) - bottom
        panel.query_one("#patch_entry_bytes_input", Input).focus()
        await settle(pilot, 2)
        reached = []
        for chip in CHIPS[:3]:
            await pilot.press("tab")
            await settle(pilot, 3)
            focused = app.focused
            reached.append(
                (getattr(focused, "id", None), pane.content_region.contains_region(focused.region))
            )
        pane.scroll_home(animate=False)
        await settle(pilot, 2)
        pane.scroll_end(animate=False)
        await settle(pilot, 3)
        scrolled = all(
            pane.content_region.contains_region(panel.query_one(f"#{c}").region) for c in CHIPS[:3]
        )
        return rows, below, reached, scrolled

    rows, below, reached, scrolled = run(tmp_path, size, body)
    assert rows == 8, rows
    assert below == _CHIPS_BELOW_FOLD[size], (size, below)
    assert reached == [(c, True) for c in CHIPS[:3]], reached
    assert scrolled


# --------------------------------------------------------------------------- #
# TC-B97-41 — LLR-144.10
# --------------------------------------------------------------------------- #

HEADER = ("open_folder_patch", "window_help_patch")
FILE_ROW = ("patch_doc_file_select", "patch_doc_path_input", "patch_doc_load_button", "patch_doc_refresh_button")
DOC_CONTROLS = ("patch_doc_validate_button", "patch_doc_apply_button", "patch_doc_save_button")
TAB_CHIPS = tuple(c for c, _p in TABS)


def _groups(tab: str) -> list:
    middle = {
        "patch_tab_inspector": [
            ("patch_entry_address_input", "patch_entry_value_input", "patch_entry_bytes_input"),
            CHIPS,
        ],
        "patch_tab_json": [
            ("patch_json_view",),
            ("patch_paste_text",),
            ("patch_paste_parse_button", "patch_edit_json_button"),
            ("patch_undo_button", "patch_redo_button"),
            ("patch_execute_scope_button", "patch_execute_run_button"),
        ],
        "patch_tab_checks": [("patch_win_checks_body", "patch_checks_run_button")],
    }[tab]
    return [HEADER, ("patch_doc_entries_table",), TAB_CHIPS] + middle + [FILE_ROW, DOC_CONTROLS]


def _reference_set(app, panel) -> set:
    """Every displayed, enabled control of the panel and its header, by type
    (contract §4 method (b)), independent of ``can_focus``."""
    screen = app.query_one("#screen_patch")
    found = set()
    for root in list(screen.query(".db-screen-header")) + [panel]:
        for w in root.query("*"):
            if not w.id or not is_displayed(w) or w.disabled or w.region.width == 0:
                continue
            if isinstance(w, (Button, Input, Select, DataTable, TextArea)):
                found.add(w.id)
    body = panel.query("#patch_win_checks_body")
    if body and is_displayed(body.first()):
        found.add("patch_win_checks_body")
    return found


def test_tc_b97_41_keyboard_order_enter_and_chip_states(tmp_path: Path) -> None:
    """TC-B97-41 (LLR-144.10): per tab state the focus chain runs header chips
    → ledger → tab chips → that tab's groups → file row → document controls
    with no inversion and no displayed control left out; ``enter`` acts on one
    member of each button group; the arrow keys scroll the JSON view; a
    focused chip paints differently from an unfocused one and a tab chip's
    four states (unfocused, focused, selected, focused + selected) are
    pairwise distinct.

    RED on main (P-33): no tab chip in the chain. Mutation: ``can_focus =
    False`` on a control (M17).
    """

    async def body(app, pilot, panel):
        await paste_document(panel, pilot, calib_text(tmp_path))
        report = {"order": {}, "missing": {}}
        for tab in TAB_CHIPS:
            await show_tab(panel, pilot, tab)
            chain = [w.id for w in app.screen.focus_chain if w.id]
            groups = _groups(tab)
            index = {wid: g for g, ids in enumerate(groups) for wid in ids}
            seq = [index[w] for w in chain if w in index]
            report["order"][tab] = (seq, [sum(1 for w in chain if w in ids) for ids in groups])
            report["missing"][tab] = sorted(_reference_set(app, panel) - set(chain))
        enters = {}
        table = panel.query_one("#patch_doc_entries_table", DataTable)

        async def enter_on(wid):
            panel.query_one(f"#{wid}").focus()
            await settle(pilot, 2)
            await pilot.press("enter")
            await settle(pilot, 4)

        await show_tab(panel, pilot, "patch_tab_inspector")
        panel.query_one("#patch_entry_address_input", Input).value = "0xED80"
        panel.query_one("#patch_entry_bytes_input", Input).value = "11 22"
        await enter_on("patch_entry_add_button")
        enters["add"] = table.row_count
        await enter_on("patch_tab_json")
        enters["tab"] = panel.query_one("#patch_tab_switcher").current if panel.query("#patch_tab_switcher") else None
        await enter_on("patch_undo_button")
        enters["undo"] = table.row_count
        await enter_on("patch_execute_scope_button")
        enters["scope"] = str(panel.query_one("#patch_execute_scope_button", Button).label)
        panel.query_one("#patch_paste_text", TextArea).load_text(calib_text(tmp_path))
        await enter_on("patch_paste_parse_button")
        enters["parse"] = table.row_count
        view = panel.query("#patch_json_view")
        if view:
            view.first().focus()
            await settle(pilot, 2)
            for _ in range(30):
                await pilot.press("down")
            await settle(pilot, 2)
            enters["arrows"] = view.first().scroll_y
        await enter_on("patch_doc_refresh_button")
        enters["refresh"] = app.log_lines[-1] if app.log_lines else ""
        await enter_on("patch_doc_validate_button")
        enters["validate"] = app.log_lines[-1] if app.log_lines else ""
        await show_tab(panel, pilot, "patch_tab_checks")
        await enter_on("patch_checks_run_button")
        enters["checks"] = str(panel.query_one("#patch_checks_status").render())
        # chip states
        states = {}
        anchor = panel.query_one("#patch_doc_path_input")
        await show_tab(panel, pilot, "patch_tab_inspector")
        for chip_id in ("patch_tab_json", "patch_entry_add_button", "patch_doc_save_button"):
            if not panel.query(f"#{chip_id}"):
                continue
            chip = panel.query_one(f"#{chip_id}")
            anchor.focus()
            await settle(pilot, 2)
            unfocused = chip_style(app, chip)
            chip.focus()
            await settle(pilot, 2)
            states[chip_id] = [unfocused, chip_style(app, chip)]
        if "patch_tab_json" in states:
            await show_tab(panel, pilot, "patch_tab_json")
            anchor.focus()
            await settle(pilot, 2)
            chip = panel.query_one("#patch_tab_json")
            states["patch_tab_json"].append(chip_style(app, chip))
            chip.focus()
            await settle(pilot, 2)
            states["patch_tab_json"].append(chip_style(app, chip))
        return report, enters, states

    report, enters, states = run(tmp_path, (118, 54), body)
    for tab, (seq, members) in report["order"].items():
        assert all(n >= 1 for n in members), (tab, members)
        assert seq == sorted(seq), (tab, seq)
        assert report["missing"][tab] == [], (tab, report["missing"][tab])
    assert enters["add"] == 7, enters
    assert enters["tab"] == "patch_win_json", enters
    assert enters["undo"] == 6, enters
    assert enters["scope"] == "Scope: all variants", enters
    assert enters["parse"] == 6, enters
    assert enters.get("arrows", 0) > 0, enters
    assert "file list refreshed" in enters["refresh"], enters
    assert enters["validate"] and enters["validate"] != enters["refresh"], enters
    assert enters["checks"] and enters["checks"] != sdb.PatchEditorPanel.CHECKS_NO_RUN_TEXT, enters
    for chip_id, styles in states.items():
        assert styles[0] != styles[1], (chip_id, styles)
    assert len(set(states.get("patch_tab_json", []))) == 4, states.get("patch_tab_json")


# --------------------------------------------------------------------------- #
# TC-B97-42 — LLR-144.11
# --------------------------------------------------------------------------- #


def test_tc_b97_42_save_is_the_one_filled_element(tmp_path: Path) -> None:
    """TC-B97-42 (LLR-144.11): on each tab state the only filled element
    besides the ledger is ``#patch_doc_save_button``, and the active tab
    chip's background differs from the fill.

    RED on main: no filled element. Mutation: a second filled chip (M18); the
    active chip given the fill class (M19).
    """

    async def body(app, pilot, panel):
        out = {}
        for chip_id, _pane in TABS:
            await show_tab(panel, pilot, chip_id)
            panel.query_one("#patch_doc_path_input").focus()
            await settle(pilot, 2)
            filled = [
                w.id
                for w in panel.query("*")
                if is_displayed(w)
                and (w.has_class("fill-accent") or (isinstance(w, Button) and w.variant == "primary"))
            ]
            chip = panel.query(f"#{chip_id}")
            out[chip_id] = (
                filled,
                chip_style(app, chip.first())[1] if chip else None,
                chip_style(app, panel.query_one("#patch_doc_save_button"))[1],
            )
        return out

    for chip_id, (filled, chip_bg, save_bg) in run(tmp_path, (118, 54), body).items():
        assert filled == ["patch_doc_save_button"], (chip_id, filled)
        assert chip_bg is not None and chip_bg != save_bg, (chip_id, chip_bg, save_bg)


# --------------------------------------------------------------------------- #
# TC-B97-60 — LLR-144.12
# --------------------------------------------------------------------------- #

HOMES = {
    "patch_win_script": (("patch_doc_entries_table",), (), None),
    "patch_pane_inspector": (
        ("patch_entry_address_input", "patch_entry_value_input", "patch_entry_bytes_input") + CHIPS,
        ("patch_before_after_card",),
        "patch_tab_inspector",
    ),
    "patch_win_json": (
        ("patch_json_view", "patch_paste_text", "patch_paste_parse_button", "patch_edit_json_button",
         "patch_undo_button", "patch_redo_button", "patch_execute_scope_button", "patch_execute_run_button"),
        ("patch_json_stamp", "patch_paste_gauge", "patch_history_strip", "patch_scope_line"),
        "patch_tab_json",
    ),
    "patch_win_checks": (
        ("patch_checks_run_button",),
        ("patch_doc_issue_count", "patch_doc_issues", "patch_checks_status", "patch_checks_strip", "patch_checks_help"),
        "patch_tab_checks",
    ),
    "patch_doc_file_row": (FILE_ROW, (), None),
    "patch_doc_controls": (DOC_CONTROLS, (), None),
}
SAVEBACK = ("patch_saveback_name_input", "patch_saveback_width_button",
            "patch_saveback_confirm_button", "patch_saveback_decline_button")


def _check_homes(app, panel, tab, homes, problems, seen_c, seen_r) -> None:
    chain = {w.id for w in app.screen.focus_chain}
    for home_id, (controls, readouts, when) in homes.items():
        if when is not None and when != tab:
            continue
        home = panel.query_one(f"#{home_id}")
        for wid in controls + readouts:
            w = panel.query_one(f"#{wid}")
            region = w.region
            if not (is_displayed(w) and region.width and home.region.contains_region(region)):
                problems.append((tab, home_id, wid, region, home.region))
            if wid in controls:
                seen_c.add(wid)
                if wid not in chain:
                    problems.append((tab, wid, "not in focus chain"))
            else:
                seen_r.add(wid)


@pytest.mark.parametrize("size", [(118, 54), (220, 60), (118, 53)])
def test_tc_b97_60_every_control_displayed_in_its_home(tmp_path: Path, size) -> None:
    """TC-B97-60 (LLR-144.12): per tab state every control and read-out of the
    table is displayed inside its home when its condition holds and every
    displayed control is in the focus chain (29 controls, 11 read-outs over
    the states: a refused load, a pasted document on each tab, the save-back
    offer and the before/after report offered); every control-typed shipped id
    lies in the controls column; the paste buffer stays editable and Parse
    reads it.

    RED: a control left under a hidden pane (M20); the paste buffer read-only
    (M21); a shipped control dropped from the table (subset guard).
    """
    async def body(app, pilot, panel):
        problems, seen_c, seen_r = [], set(), set()
        typed = {
            i for i in PE_IDS_9C7BEAF
            if isinstance(app.query_one(f"#{i}"), (Button, Input, Select, TextArea, DataTable))
        }
        if not panel.query("#patch_tab_switcher"):
            return typed, seen_c, seen_r, ["no tab switcher (base tree)"], None, None
        # state A: a refused load — the ledger's state line and the issues
        await load_change_file(app, pilot, panel, legacy_v1(tmp_path))
        empty = panel.query_one("#patch_doc_empty_state")
        if not is_displayed(empty) or not panel.query_one("#patch_win_script").region.contains_region(empty.region):
            problems.append(("refused", "patch_doc_empty_state"))
        seen_r.add("patch_doc_empty_state")
        await show_tab(panel, pilot, "patch_tab_checks")
        _check_homes(app, panel, "patch_tab_checks", {"patch_win_checks": HOMES["patch_win_checks"]}, problems, seen_c, seen_r)
        # state B: a pasted document (every control enabled), each tab
        await show_tab(panel, pilot, "patch_tab_json")
        paste = panel.query_one("#patch_paste_text", TextArea)
        read_only = paste.read_only
        await paste_document(panel, pilot, calib_text(tmp_path))
        parsed = len(app._change_service.document.entries)
        # The issues listing is displayed while the document has findings (its
        # shipped condition), so it is read in state A, not on a clean paste.
        controls, readouts, when = HOMES["patch_win_checks"]
        clean = dict(HOMES, patch_win_checks=(controls, tuple(r for r in readouts if r != "patch_doc_issues"), when))
        for chip_id, _pane in TABS:
            await show_tab(panel, pilot, chip_id)
            _check_homes(app, panel, chip_id, clean, problems, seen_c, seen_r)
        # state C: the save-back offer (Apply on the loaded image)
        await show_tab(panel, pilot, "patch_tab_json")
        panel.query_one("#patch_doc_apply_button", Button).press()
        await settle(pilot, 6)
        _check_homes(app, panel, "patch_tab_json", {"patch_win_json": (SAVEBACK, (), None)}, problems, seen_c, seen_r)
        # state D: the before/after report offered (Write file)
        panel.query_one("#patch_saveback_confirm_button", Button).press()
        await settle(pilot, 8)
        _check_homes(app, panel, "patch_tab_json", {"patch_win_json": (("patch_before_after_button",), (), None)}, problems, seen_c, seen_r)
        return typed, seen_c, seen_r, problems, read_only, parsed

    typed, controls, readouts, problems, read_only, parsed = run(tmp_path, size, body)
    assert problems == [], problems[:6]
    assert len(controls) == 29 and len(readouts) == 11, (len(controls), len(readouts))
    column = {c for home in HOMES.values() for c in home[0]} | set(SAVEBACK) | {"patch_before_after_button"}
    assert len(typed) == 28 and typed <= column, sorted(typed - column)
    assert read_only is False and parsed == 6


# --------------------------------------------------------------------------- #
# Acceptance — AT-B97-01, -02, -03, -17
# --------------------------------------------------------------------------- #


def test_at_b97_01_load_shows_every_entry_and_the_document(tmp_path: Path) -> None:
    """AT-B97-01 (HLR-144): the engineer picks ``calib_hotfix.json`` in the
    file list, and on the JSON tab reads the document: at 118x54 the ledger
    paints all 6 rows, the read-only view parses to the file's six addresses,
    and the stamp reads ``6 entries · HH:MM:SS · saved``.

    RED on main: 2 of 6 rows painted, and the buffer stays the dummy template
    (P-4).
    """

    async def body(app, pilot, panel):
        calib_hotfix(app._patches_dir())
        app.action_show_screen("workspace")
        await settle(pilot, 2)
        app.action_show_screen("patch")
        await settle(pilot, 6)
        panel.query_one("#patch_doc_file_select", Select).value = "calib_hotfix.json"
        await settle(pilot, 6)
        rows = ledger_lines(app, panel)
        if panel.query("#patch_tab_json"):
            await pilot.click("#patch_tab_json")
            await settle(pilot, 3)
        return rows, view_text(panel), stamp(panel), panel.query_one("#patch_paste_text", TextArea).text

    rows, text, stamp_text, buffer = run(tmp_path, (118, 54), body)
    assert len(rows) == 6, rows
    assert text is not None and buffer is not None
    assert [e["address"] for e in json.loads(text)["entries"]] == CALIB_ADDRESSES
    match = STAMP_RE.match(stamp_text)
    assert match and match.group(1) == "6" and match.group(3) == "saved", stamp_text


def test_at_b97_02_add_save_empty_and_legacy(tmp_path: Path) -> None:
    """AT-B97-02 (HLR-144): after Load, typing an entry and pressing Add shows
    7 entries in the view with ``unsaved changes`` at once; Save turns the
    stamp to ``7 entries · … · saved``; an empty change-set shows
    ``"entries": []`` and the ledger's state line; a legacy v1 file shows the
    empty document and its one ERROR finding.

    RED: the stamp fed by the document writers only (P-57) → ``unsaved
    changes`` after Save.
    """

    async def body(app, pilot, panel):
        await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
        panel.query_one("#patch_entry_address_input", Input).value = "0xED80"
        panel.query_one("#patch_entry_bytes_input", Input).value = "11 22"
        await pilot.click("#patch_entry_add_button")
        await settle(pilot, 4)
        added = (view_text(panel), stamp(panel))
        await pilot.click("#patch_doc_save_button")
        await settle(pilot, 4)
        saved = stamp(panel)
        await load_change_file(app, pilot, panel, empty_changeset(tmp_path))
        empty = (view_text(panel), [r.strip() for r in painted_rows(app, panel.query_one("#patch_doc_empty_state")) if r.strip()])
        await load_change_file(app, pilot, panel, legacy_v1(tmp_path))
        legacy = (view_text(panel), app._change_service.issue_lines())
        return added, saved, empty, legacy

    added, saved, empty, legacy = run(tmp_path, (118, 54), body)
    assert added[0] is not None and len(json.loads(added[0])["entries"]) == 7
    assert re.match(r"^7 entries · \d\d:\d\d:\d\d · unsaved changes$", added[1]), added[1]
    assert re.match(r"^7 entries · \d\d:\d\d:\d\d · saved$", saved), saved
    assert json.loads(empty[0])["entries"] == [] and len(empty[1]) == 1, empty
    assert json.loads(legacy[0])["entries"] == [] and len(legacy[1]) == 1, legacy


@pytest.mark.parametrize("arm", ["name", "content"])
def test_at_b97_03_hostile_name_and_content_read_literally(tmp_path: Path, arm: str) -> None:
    """AT-B97-03 (HLR-144): a markup-laden file name and entry content, loaded
    and highlighted, paint literally on the ribbon, the ledger, the inspector
    and the JSON tab, with no markup error.

    RED: ``Text.from_markup`` on the ribbon (M10).
    """

    async def body(app, pilot, panel):
        path = hostile_name_changeset(tmp_path) if arm == "name" else hostile_content_changeset(tmp_path)
        await load_change_file(app, pilot, panel, path)
        table = panel.query_one("#patch_doc_entries_table", DataTable)
        table.focus()
        await pilot.press("down")
        await settle(pilot, 3)
        painted = "\n".join(painted_rows(app, panel))
        await show_tab(panel, pilot, "patch_tab_json")
        return painted, view_text(panel), list(app.log_lines)

    painted, view, log = run(tmp_path, (118, 54), body)
    assert not any("MarkupError" in line for line in log)
    if arm == "name":
        assert "b97[bold]x[red]y" in painted, painted[:400]
    else:
        assert "b97[bold]x[/]y" in painted
        assert view is not None and "[link=https://e.invalid]" in view


def test_at_b97_17_first_task_from_the_keyboard(tmp_path: Path) -> None:
    """AT-B97-17 (HLR-144): with the keyboard only the engineer picks the file
    in the list, opens the JSON tab with ``space``, types in the paste buffer
    and moves the ledger highlight with ``down``: the view parses to the file,
    the buffer took the text, and the strip follows the highlight.

    RED on main: no tab chip in the focus chain (P-33).
    """
    from tests.test_b97_check_editor import _focus_by_tab

    async def body(app, pilot, panel):
        calib_hotfix(app._patches_dir())
        app.action_show_screen("workspace")
        await settle(pilot, 2)
        app.action_show_screen("patch")
        await settle(pilot, 6)
        reached = {}
        reached["select"] = await _focus_by_tab(app, pilot, "patch_doc_file_select", 80)
        await pilot.press("enter")
        await settle(pilot, 3)
        await pilot.press("down")
        await settle(pilot, 2)
        await pilot.press("enter")
        await settle(pilot, 6)
        reached["json"] = await _focus_by_tab(app, pilot, "patch_tab_json", 80)
        await pilot.press("space")
        await settle(pilot, 3)
        reached["paste"] = await _focus_by_tab(app, pilot, "patch_paste_text", 80)
        await pilot.press("q", "w")
        await settle(pilot, 2)
        buffer = panel.query_one("#patch_paste_text", TextArea).text
        reached["ledger"] = await _focus_by_tab(app, pilot, "patch_doc_entries_table", 80)
        card = panel.query_one("#patch_before_after_card")
        first = str(card.render())
        await pilot.press("down")
        await settle(pilot, 3)
        second = str(card.render())
        return reached, view_text(panel), buffer, first, second

    reached, text, buffer, first, second = run(tmp_path, (118, 54), body)
    assert reached == {"select": True, "json": True, "paste": True, "ledger": True}, reached
    assert [e["address"] for e in json.loads(text)["entries"]] == CALIB_ADDRESSES
    assert "qw" in buffer
    assert first != second and "0x0000EB40" in second, (first, second)
