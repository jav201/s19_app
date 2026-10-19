"""Patch Editor three-window layout tests — batch-46 (Inc-1), batch-94 (pe_b).

Supersedes the batch-22 2x2 four-pane geometry tests. Verdicts HLR-063/064
(US-U8/US-B2) through the Pilot region oracle at the 80x24 floor and 120x30:

- **AT-063a** (120x30): batch-94 (LLR-003.1, the pe_b row-focus doctrine)
  made the narrow STACK the ONLY regime — at 120x30 the three windows sit
  VERTICALLY stacked (one distinct ``region.x``, ascending ``region.y`` in
  script/json/checks order), each full-width and content-height (``auto``),
  non-overlapping, no right-edge clip. (Was: three-across at the comfortable
  width — the three-column regime retired with the capped side pane.)
- **AT-063b** (80x24): the three windows STACK — one distinct ``region.x``
  and three ascending ``region.y`` — each full-width and above the usable
  floor. Unchanged: the stack batch-94 generalized to every regime.
- **AT-063c** (80x24 + 120x30): reparent-safety — every must-preserve leaf id
  resolves to exactly one widget at its batch-94 home (the change-file row
  docks in the SCRIPT window; the entry-input band + the before/after card
  ride the JSON window BODY; the history strip / Undo-Redo / execute-scope
  group dock in the JSON window), and one action per window routes to an
  OBSERVABLE effect (FOLD-3): PATCH SCRIPT ``add_entry`` grows the table;
  CHECKS ``run_checks`` emits a ``Checks:`` log line; JSON EDIT
  ``parse_paste`` populates the change document.
- **AT-064a** (80x24) / **AT-064b** (120x30) / **AT-064c** (80x24, revealed
  save-back + before/after rows): every named action button is
  REACHABLE-UNDER-SCROLL (FOLD-8) — the B2 invariant holds STRUCTURALLY
  (every panel button is a descendant of a ``#patch_win_*`` window and NEVER
  of a ``.patch-window-body`` — a docked row is a sibling of its window's
  body), and at 120x30 the SCRIPT window's three docked rows are fully
  visible at panel scroll 0 while the JSON window's docked rows are reached
  by scrolling the PANEL. ``off == []`` at scroll 0 is deliberately NOT
  asserted (operator-amended contract, FOLD-8). MEASURED note (batch-94,
  the three source-level fixes landed): the entry chips now ALL paint at
  height 1 — the forced-height zero-row deficit is GONE (finding A fixed),
  so Add/Edit carry their own reachability. The ONE remaining measured
  deficit: ``#patch_doc_refresh_button`` — its home ``#patch_doc_file_line2``
  renders one row BELOW ``#patch_doc_file_row``'s content region (the row's
  forced height 3 still pays the tcss ``padding-top: 1``, leaving 2 content
  rows for a 2+1 line split), so the button lands under
  ``#patch_doc_entry_buttons`` and is never ``_fully_visible`` at EITHER
  regime — carried as an explicit per-regime expectation below, reported
  upstream, not silently asserted away. (The pre-fix form of this deficit
  was the 80x24 HORIZONTAL clip of the one-line file row — finding B fixed
  that by splitting the row in two lines; the Load button now rides BESIDE
  the path input, fully on-screen at both regimes.)
- **TC-46.1** (layout-agnostic): each window = a title + a scrollable body + a
  docked button-row that is a SIBLING of the body; the ``width-narrow`` reflow
  rule exists in ``styles.tcss`` (no ``layout.name`` pinned — the wide token is
  a Phase-3 design call, M-A3).
- **TC-46.2** (FOLD-4): the paste editor's first line is in-viewport at its
  window-body scroll 0.

# AT-80

RED counterfactual (recorded, run against the pre-restructure 2x2 tree): the
three ``#patch_win_*`` ids are ABSENT (AT-063a/b/c cardinality-0 fail), and the
change-file / entry / variant buttons sit below the starved ``1fr`` grid-cell
fold with NO window scroll able to reach them — ``_reach`` leaves them
``_fully_visible == False`` (AT-064a/b/c fail). The preserved pane-lead ids
(``#patch_pane_*``) still resolve, so the 2-vs-3-column discriminator is real
(q-m2).

batch-94 (HLR-006) note: the variant group (``#patch_variant_row`` /
``#patch_pane_variant`` / ``#patch_variant_select`` /
``#patch_variant_info_button``) RETIRED — its ids left the must-preserve
census, and ``#patch_variant_scope_line`` renamed to ``#patch_scope_line``
(scope-only line). The retirement census lives in
``tests/test_tui_patch_variant.py``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.containers import VerticalScroll
from textual.widgets import Button, DataTable, Label, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import PatchEditorPanel

# The three window ids created by the batch-46 restructure.
_WINDOW_IDS = ("patch_win_script", "patch_win_checks", "patch_win_json")

# Pilot-measured usable floor (M-Q1 / C-23). Measured window minimums:
# wide @120x30 → widths {44, 22, 23}, heights all 11; narrow @80x24 →
# width 68 (full), heights {28, 14, 7}. The floor sits comfortably below every
# measured value yet rejects a window starved to a few columns/rows (the
# 0-width-passes-distinct-x hole).
_MIN_USABLE_W = 15
_MIN_USABLE_H = 5

# Every must-preserve id (LLR-063.4 + FOLD-1), batch-94 tree: the
# wiring-critical leaf ids, the census-pinned leaf/section ids, the
# .hidden-toggled rows, the preserved structural grouping sub-containers, and
# the execute row. batch-94 (HLR-006) RETIRED the variant group — its ids
# (``patch_variant_select`` / ``patch_variant_info_button`` /
# ``patch_pane_variant`` / ``patch_variant_row``) left this census, and
# ``patch_variant_scope_line`` renamed to ``patch_scope_line``.
_MUST_PRESERVE_IDS = (
    # wiring-critical leaf ids (14)
    "patch_edit_json_button",
    "patch_undo_button",
    "patch_redo_button",
    "patch_entry_edit_json_button",
    "patch_doc_file_select",
    "patch_doc_entries_table",
    "patch_doc_empty_state",
    "patch_doc_issue_count",
    "patch_doc_issues",
    "patch_saveback_name_input",
    "patch_saveback_width_button",
    "patch_checks_status",
    "patch_checks_results",
    # census-pinned leaf ids
    "patch_doc_path_input",
    "patch_doc_load_button",
    "patch_doc_refresh_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
    "patch_doc_save_button",
    "patch_checks_run_button",
    "patch_checks_help",
    "patch_paste_text",
    "patch_paste_parse_button",
    "patch_entry_address_input",
    "patch_entry_value_input",
    "patch_entry_bytes_input",
    "patch_entry_add_button",
    "patch_entry_edit_button",
    "patch_entry_remove_button",
    "patch_execute_scope_button",
    "patch_execute_run_button",
    "patch_saveback_confirm_button",
    "patch_saveback_decline_button",
    "patch_before_after_button",
    "patch_scope_line",
    # section labels + preserved structural containers (FOLD-1)
    "patch_script_section_label",
    "patch_checks_section_label",
    "patch_doc_controls",
    "patch_checks_controls",
    "patch_pane_entries",
    "patch_doc_file_row",
    "patch_doc_file_line1",
    "patch_doc_file_line2",
    "patch_doc_entry_buttons",
    "patch_execute_row",
    # batch-94 additions: the entry-input band + card (JSON body), the
    # history strip / undo-redo (JSON dock), the paste-controls row
    "patch_doc_entry_inputs",
    "patch_before_after_card",
    "patch_history_strip",
    "patch_history_controls",
    "patch_paste_controls",
    # .hidden-toggled rows
    "patch_saveback_row",
    "patch_before_after_row",
)

# The batch-94 RE-PARENT map: ids that MOVED homes in the pe_b rework must
# resolve exactly once AND sit at their new home — the "no id re-parented
# silently" intent of AT-063c.
_MOVED_ID_HOMES = {
    # the change-file row DOCKS in the SCRIPT window (annotation 6 / HLR-008)
    # and splits in TWO lines (finding B of the independent review, fixed):
    # line 1 = the Select + the path input + Load BESIDE the input; line 2 =
    # Refresh + the section label. (Pre-fix the row was one Horizontal line
    # that clipped Refresh + the label past the 80x24 window edge.)
    "patch_doc_file_row": "patch_win_script",
    "patch_doc_file_line1": "patch_doc_file_row",
    "patch_doc_file_line2": "patch_doc_file_row",
    "patch_doc_file_select": "patch_doc_file_line1",
    "patch_doc_path_input": "patch_doc_file_line1",
    "patch_doc_load_button": "patch_doc_file_line1",
    "patch_doc_refresh_button": "patch_doc_file_line2",
    "patch_script_section_label": "patch_doc_file_line2",
    # the per-entry input band + the before/after card ride the JSON BODY
    "patch_doc_entry_inputs": "patch_win_json_body",
    "patch_entry_address_input": "patch_doc_entry_inputs",
    "patch_entry_value_input": "patch_doc_entry_inputs",
    "patch_entry_bytes_input": "patch_doc_entry_inputs",
    "patch_before_after_card": "patch_win_json_body",
    # the history strip / Undo-Redo / execute-scope group DOCK in the JSON window
    "patch_history_strip": "patch_win_json",
    "patch_history_controls": "patch_win_json",
    "patch_undo_button": "patch_history_controls",
    "patch_redo_button": "patch_history_controls",
    "patch_execute_row": "patch_win_json",
    "patch_execute_scope_button": "patch_execute_buttons",
    "patch_execute_run_button": "patch_execute_buttons",
    "patch_scope_line": "patch_execute_row",
}

# Every named ACTION button whose reachability HLR-064 guards. batch-94
# (HLR-006): ``patch_variant_info_button`` retired with the variant group.
# MEASURED (batch-94, textual==8.2.8, after the three source-level fixes
# landed) — the entry chips (Add / Edit / Remove / Edit JSON) ALL paint at
# height 1 at both regimes (the forced-height zero-row deficit is GONE,
# finding A fixed), and the two-line change-file row put Load BESIDE the
# path input (finding B fixed — pre-fix the one-line row clipped Refresh +
# the section label past the 66-cell window edge at 80x24). The ONE shipped
# paint deficit left, reported upstream rather than silently asserted away:
#   * ``patch_doc_refresh_button`` at BOTH regimes — its home
#     ``#patch_doc_file_line2`` renders one row BELOW
#     ``#patch_doc_file_row``'s content region: the row's forced height 3
#     still pays the tcss ``padding-top: 1`` (styles.tcss), leaving TWO
#     content rows for the 2+1 line split, so line 2 spills beneath the
#     row and lands under ``#patch_doc_entry_buttons`` (the compositor
#     reports the entry-buttons row topmost at the button's cell). Vertical
#     scroll therefore cannot make it ``_fully_visible`` — the deficit is
#     VERTICAL (it was the horizontal file-row clip pre-fix), carried as an
#     explicit per-regime expectation below.
_NAMED_BUTTONS = (
    "patch_entry_remove_button",
    "patch_entry_edit_json_button",
    "patch_undo_button",
    "patch_redo_button",
    "patch_doc_load_button",
    "patch_doc_refresh_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
    "patch_doc_save_button",
    "patch_execute_scope_button",
    "patch_execute_run_button",
    "patch_checks_run_button",
    "patch_paste_parse_button",
    "patch_edit_json_button",
)

# The per-regime reachability expectation for the measured
# unreachable-under-scroll deficit (see the census note above): at BOTH
# regimes ``patch_doc_refresh_button`` rides line 2 of the file row, which
# renders below the row's 2-row content region — every OTHER named button
# must be reachable.
_UNREACHABLE_UNDER_SCROLL: dict[tuple[int, int], tuple[str, ...]] = {
    (80, 24): ("patch_doc_refresh_button",),
    (120, 30): ("patch_doc_refresh_button",),
}


def _fully_visible(app: S19TuiApp, w: object) -> bool:
    """True if ``w`` is fully on screen AT THE CURRENT SCROLL.

    Lifted from ``prototypes/patch_editor_layout.prototype.py:243-259``: the
    widget's region must be non-empty, contained by the screen, AND contained
    by every scrollable ancestor's visible ``content_region`` — so a button
    scrolled below a fold counts as NOT visible (the B2 defect). Returns False
    on a 0-area (unmapped / fully-scrolled-out) region.
    """
    r = w.region
    if r.area == 0:
        return False
    if not app.screen.region.contains_region(r):
        return False
    node = w.parent
    while node is not None and node is not app.screen:
        if getattr(node, "is_scrollable", False):
            if not node.content_region.contains_region(r):
                return False
        node = node.parent
    return True


def _scrollers(app: S19TuiApp, w: object) -> list:
    """Return ``w``'s ancestors that ACTUALLY scroll (innermost first).

    In this app ``is_scrollable`` is True for every container (widget-type
    based), so it cannot single out the real scroll container.
    ``show_vertical_scrollbar`` is the accurate signal — it is True only when
    the container's content overflows its slot (the PATCH SCRIPT window @wide,
    the panel @narrow). That is what the operator scrolls to reach a docked
    button.
    """
    out = []
    node = w.parent
    while node is not None and node is not app.screen:
        if getattr(node, "show_vertical_scrollbar", False):
            out.append(node)
        node = node.parent
    return out


async def _reach(app: S19TuiApp, pilot: object, w: object) -> None:
    """Scroll ``w``'s real scrolling ancestors so ``w`` enters the viewport.

    The reachable-under-scroll primitive (FOLD-8): drive each real scroller's
    ``scroll_y`` directly (``scroll_visible`` / ``scroll_to_widget`` are
    unreliable across the nested auto-scroll containers here) to bring ``w`` to
    the scroller's content top, iterating so the region shift settles.
    """
    for _ in range(6):
        for sc in _scrollers(app, w):
            sc.scroll_y = max(
                0, w.region.y - sc.content_region.y + sc.scroll_offset.y
            )
        await pilot.pause()
    await pilot.pause()


def _changeset_text() -> str:
    """A minimal valid ``s19app-changeset`` document (paste seed)."""
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {"type": "string", "address": "0x200", "value": "REV_A"}
            ],
        }
    )


# ---------------------------------------------------------------------------
# AT-063a / AT-063b — the three-window layout geometry
# ---------------------------------------------------------------------------


def _drive_window_geometry(
    tmp_path: Path, size: tuple[int, int]
) -> dict[str, object]:
    """Show the patch screen at ``size`` and capture window geometry."""

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            counts = {wid: len(app.query(f"#{wid}")) for wid in _WINDOW_IDS}
            regions: dict[str, tuple[int, int, int, int]] = {}
            auto_heights: dict[str, bool] = {}
            for wid in _WINDOW_IDS:
                if counts[wid] == 1:
                    window = app.query_one(f"#{wid}")
                    r = window.region
                    regions[wid] = (r.x, r.y, r.width, r.height)
                    auto_heights[wid] = window.styles.is_auto_height
            return {
                "regions": regions,
                "counts": counts,
                "auto_heights": auto_heights,
                "host_content_w": panel.content_region.width,
                "panel_right": panel.region.right,
            }

    return asyncio.run(_run())


def _assert_no_overlap(regions: dict, size_label: str) -> None:
    items = list(regions.items())
    for i in range(len(items)):
        wid_a, (ax, ay, aw, ah) = items[i]
        for j in range(i + 1, len(items)):
            wid_b, (bx, by, bw, bh) = items[j]
            overlap = (
                ax < bx + bw and bx < ax + aw and ay < by + bh and by < ay + ah
            )
            assert not overlap, (
                f"@{size_label}: {wid_a} and {wid_b} windows overlap "
                f"({(ax, ay, aw, ah)} vs {(bx, by, bw, bh)})"
            )


def test_at063a_three_across_at_120(tmp_path: Path) -> None:
    """AT-063a — three windows VERTICALLY stacked, content-height, at 120x30.

    Intent (HLR-063, batch-94 LLR-003.1 form): the pe_b row-focus doctrine
    retired the three-column regime — the narrow STACK is the ONLY regime, so
    at the comfortable width the three windows lay out as ONE column (exactly
    one distinct ``region.x``), ascending in script/json/checks order, each
    full-width, content-height (``auto`` — the panel scrolls as a whole,
    FOLD-8 at every regime), at/above the pilot-measured usable floor, no
    overlap, no right-edge clip. Counterfactual on the pre-batch-94 tree:
    three distinct x's (the 3-across regime) -> RED; a window pinned to a
    fixed height -> the auto-height assert goes RED.
    """
    dims = _drive_window_geometry(tmp_path, (120, 30))
    counts, regions = dims["counts"], dims["regions"]
    assert all(counts[wid] == 1 for wid in _WINDOW_IDS), (
        f"@120x30: each window id must resolve once, got {counts}"
    )
    xs = {r[0] for r in regions.values()}
    assert len(xs) == 1, (
        f"@120x30: the batch-94 stack needs ONE column x at every regime, got "
        f"{sorted(xs)} from {regions}"
    )
    ys = {wid: r[1] for wid, r in regions.items()}
    assert (
        ys["patch_win_script"]
        < ys["patch_win_json"]
        < ys["patch_win_checks"]
    ), (
        f"@120x30: the stack order must be script above json above checks, "
        f"got y's {ys}"
    )
    for wid in _WINDOW_IDS:
        assert dims["auto_heights"][wid] is True, (
            f"@120x30: {wid} must be content-height (styles auto) so the "
            "panel scrolls as a whole (FOLD-8 at every regime)"
        )
    panel_right, host_w = dims["panel_right"], dims["host_content_w"]
    for wid, (x, _y, w, h) in regions.items():
        assert w >= _MIN_USABLE_W, (
            f"@120x30: {wid} width {w} below usable floor {_MIN_USABLE_W}"
        )
        assert h >= _MIN_USABLE_H, (
            f"@120x30: {wid} height {h} below usable floor {_MIN_USABLE_H}"
        )
        assert w <= host_w, (
            f"@120x30: {wid} width {w} exceeds host content {host_w}"
        )
        assert x + w <= panel_right, (
            f"@120x30: {wid} right edge {x + w} clips past panel "
            f"right {panel_right}"
        )
    _assert_no_overlap(regions, "120x30")


def test_at063b_stacked_at_80(tmp_path: Path) -> None:
    """AT-063b — three windows STACK (1 column, 3 ascending rows) at 80x24.

    Intent: HLR-063 — at the narrow floor the ``width-narrow`` reflow stacks the
    windows vertically: one distinct ``region.x``, three ascending ``region.y``,
    each full-width. Counterfactual on the 2x2 tree: two distinct x's (a grid),
    not one → RED.
    """
    dims = _drive_window_geometry(tmp_path, (80, 24))
    counts, regions = dims["counts"], dims["regions"]
    assert all(counts[wid] == 1 for wid in _WINDOW_IDS), (
        f"@80x24: each window id must resolve once, got {counts}"
    )
    xs = {r[0] for r in regions.values()}
    ys = sorted(r[1] for r in regions.values())
    assert len(xs) == 1, (
        f"@80x24: stacked windows need ONE column x, got {sorted(xs)}"
    )
    assert ys == sorted(set(ys)) and len(ys) == 3, (
        f"@80x24: three windows need three ascending row y's, got {ys}"
    )
    for wid, (_x, _y, w, h) in regions.items():
        assert w >= _MIN_USABLE_W, (
            f"@80x24: {wid} width {w} below usable floor {_MIN_USABLE_W}"
        )
        assert h >= _MIN_USABLE_H, (
            f"@80x24: {wid} height {h} below usable floor {_MIN_USABLE_H}"
        )
    _assert_no_overlap(regions, "80x24")


# ---------------------------------------------------------------------------
# AT-063c — reparent-safety: leaf ids resolve + one action per window routes
# ---------------------------------------------------------------------------


def _drive_reparent_safety(
    tmp_path: Path, size: tuple[int, int]
) -> dict[str, object]:
    """Census every must-preserve id + assert the moved ids' new homes."""

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            counts = {
                wid: len(app.query(f"#{wid}")) for wid in _MUST_PRESERVE_IDS
            }
            # batch-94 re-parent census: each moved id exists exactly once AND
            # sits at its new home (no id re-parented silently).
            wrong_homes = []
            for wid, home in _MOVED_ID_HOMES.items():
                matches = app.query(f"#{wid}")
                if len(matches) != 1:
                    wrong_homes.append(f"{wid} (count {len(matches)})")
                    continue
                ancestor_ids = {
                    getattr(a, "id", None)
                    for a in matches[0].ancestors_with_self
                }
                if home not in ancestor_ids:
                    wrong_homes.append(f"{wid} (not under {home})")
            table = app.query_one("#patch_doc_entries_table", DataTable)

            # PATCH SCRIPT — add_entry grows the entries table.
            before = table.row_count
            app.query_one("#patch_entry_address_input").value = "0x100"
            app.query_one("#patch_entry_bytes_input").value = "AA"
            panel.request_action("add_entry")
            await pilot.pause()
            add_grows = table.row_count == before + 1

            # CHECKS — run_checks emits an observable status log line.
            panel.request_action("run_checks")
            await pilot.pause()
            run_checks_routes = any(
                line.startswith("Checks:") for line in app.log_lines
            )

            # JSON EDIT — parse a valid pasted change-set → the document
            # populates (observable effect, not mere presence, FOLD-3).
            app.query_one("#patch_paste_text", TextArea).text = (
                _changeset_text()
            )
            app.query_one("#patch_paste_parse_button", Button).press()
            await pilot.pause()
            parse_populates = len(app._change_service.document.entries) >= 1
            return {
                "counts": counts,
                "wrong_homes": wrong_homes,
                "add_grows": add_grows,
                "run_checks_routes": run_checks_routes,
                "parse_populates": parse_populates,
            }

    return asyncio.run(_run())


def _assert_reparent_safe(dims: dict, size_label: str) -> None:
    missing = [wid for wid, c in dims["counts"].items() if c != 1]
    assert not missing, (
        f"@{size_label}: must-preserve ids not resolving to one widget: "
        f"{missing}"
    )
    assert dims["wrong_homes"] == [], (
        f"@{size_label}: batch-94 re-parent census — ids not at their new "
        f"homes: {dims['wrong_homes']}"
    )
    assert dims["add_grows"], (
        f"@{size_label}: PATCH SCRIPT add_entry did not grow the table"
    )
    assert dims["run_checks_routes"], (
        f"@{size_label}: CHECKS run_checks emitted no 'Checks:' line"
    )
    assert dims["parse_populates"], (
        f"@{size_label}: JSON EDIT parse_paste did not populate the document"
    )


def test_at063c_reparent_safety_at_80(tmp_path: Path) -> None:
    """AT-063c (80x24) — leaf ids resolve + one action per window routes."""
    _assert_reparent_safe(_drive_reparent_safety(tmp_path, (80, 24)), "80x24")


def test_at063c_reparent_safety_at_120(tmp_path: Path) -> None:
    """AT-063c (120x30) — the same reparent-safety holds at 120 cols."""
    _assert_reparent_safe(
        _drive_reparent_safety(tmp_path, (120, 30)), "120x30"
    )


# ---------------------------------------------------------------------------
# AT-064a / AT-064b / AT-064c — reachable-under-scroll (FOLD-8)
# ---------------------------------------------------------------------------


def _drive_button_reachability(
    tmp_path: Path,
    size: tuple[int, int],
    reveal: bool,
    button_ids: tuple[str, ...],
) -> dict[str, object]:
    """Drive the patch screen and test reachable-under-scroll per button.

    Two oracles, per the batch-94 form of HLR-064:

    - STRUCTURAL (the B2 invariant, every panel button incl. the measured
      zero-height pair): each button is a descendant of exactly one
      ``#patch_win_*`` window and NEVER of a ``.patch-window-body`` — its
      docked row is a sibling of the window's scrollable body, so it is never
      trapped below the body's inner fold.
    - REACHABILITY (FOLD-8, the painting named buttons): scroll the panel to
      the button with the established ``_reach`` primitive and assert it
      becomes ``_fully_visible``.
    """

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            if reveal:
                panel = app.query_one(
                    "#patch_editor_panel", PatchEditorPanel
                )
                panel.show_save_prompt("out.s19")
                panel.show_before_after_prompt()
                await pilot.pause()

            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            trapped: list[str] = []
            for button in panel.walk_children(Button):
                node = button.parent
                in_window = False
                in_body = False
                while node is not None and node is not app.screen:
                    if getattr(node, "id", None) in _WINDOW_IDS:
                        in_window = True
                    if "patch-window-body" in (
                        set(getattr(node, "classes", ()) or ())
                    ):
                        in_body = True
                    node = node.parent
                if in_body or not in_window:
                    trapped.append(button.id or type(button).__name__)

            # At 120x30 the SCRIPT window's docked rows are fully visible at
            # panel scroll 0 (the batch-94 stack keeps them in the first
            # screenful); captured BEFORE any scrolling happens.
            script_rows_at_scroll0: list[str] = []
            if size == (120, 30):
                for row_id in (
                    "patch_doc_file_row",
                    "patch_doc_entry_buttons",
                    "patch_doc_controls",
                ):
                    row = app.query_one(f"#{row_id}")
                    if not _fully_visible(app, row):
                        script_rows_at_scroll0.append(row_id)

            unreachable: list[str] = []
            for bid in button_ids:
                btn = app.query_one(f"#{bid}", Button)
                await _reach(app, pilot, btn)
                if not _fully_visible(app, btn):
                    unreachable.append(bid)
            return {
                "unreachable": unreachable,
                "trapped": trapped,
                "script_rows_at_scroll0": script_rows_at_scroll0,
            }

    return asyncio.run(_run())


def test_at064a_reachable_under_scroll_at_80(tmp_path: Path) -> None:
    """AT-064a (80x24) — every named button reachable-under-scroll (FOLD-8).

    Intent: HLR-064 / US-B2, batch-94 form — the B2 invariant holds
    STRUCTURALLY (every panel button rides a ``#patch_win_*`` dock, never a
    ``.patch-window-body``) and every painting named button becomes
    ``_fully_visible`` once the PANEL is scrolled to it (the single vertical
    scroll is the batch-94 regime). ``off == []`` at scroll 0 is NOT asserted
    — the measured ~10-row @80x24 panel viewport cannot show all buttons at
    once (FOLD-8). MEASURED deficit reported upstream (kept explicit, not
    silently dropped): ``#patch_doc_refresh_button`` — its line-2 home renders
    one row BELOW ``#patch_doc_file_row``'s 2-row content region (the forced
    height 3 pays the tcss ``padding-top: 1``), landing under
    ``#patch_doc_entry_buttons``, so it is the one named button vertical
    scroll cannot make ``_fully_visible`` at this regime — asserted via
    ``_UNREACHABLE_UNDER_SCROLL``. (The pre-fix horizontal clip of the
    one-line file row is GONE: Load now rides BESIDE the path input on line 1
    and every entry chip paints.) Counterfactual on the 2x2 tree: buttons
    below the starved ``1fr`` cell fold stay not-``_fully_visible`` -> RED.
    """
    dims = _drive_button_reachability(
        tmp_path, (80, 24), reveal=False, button_ids=_NAMED_BUTTONS
    )
    assert dims["trapped"] == [], (
        f"@80x24: buttons trapped inside a scrollable body (below the inner "
        f"fold), not docked siblings: {dims['trapped']}"
    )
    assert dims["unreachable"] == list(
        _UNREACHABLE_UNDER_SCROLL.get((80, 24), ())
    ), (
        f"@80x24: buttons not reachable-under-scroll: {dims['unreachable']} "
        f"(expected only the measured-unreachable {_UNREACHABLE_UNDER_SCROLL.get((80, 24), ())})"
    )


def test_at064b_reachable_under_scroll_at_120(tmp_path: Path) -> None:
    """AT-064b (120x30) — script rows visible at scroll 0; the JSON window's
    docked rows reachable by scrolling the panel (FOLD-8).

    Intent: HLR-064, batch-94 form. The batch-94 stack is the only regime, so
    at the comfortable width the SCRIPT window's three docked rows (file /
    entry / controls) sit in the first screenful — fully visible at panel
    scroll 0 — while the JSON window's docked rows (paste controls,
    history strip + Undo/Redo, the execute row) and the CHECKS run control
    are reached by scrolling the panel. The B2 invariant is structural (no
    button inside a ``.patch-window-body``). MEASURED: the one unreachable
    named button here (as at 80x24) is ``#patch_doc_refresh_button`` — its
    line-2 home renders below the file row's 2-row content region (see the
    census note). Counterfactual: a JSON docked
    row that needed its WINDOW scrolled (a body fold) or a button outside the
    panel's single scroll -> the reachability assert goes RED.
    """
    dims = _drive_button_reachability(
        tmp_path, (120, 30), reveal=False, button_ids=_NAMED_BUTTONS
    )
    assert dims["trapped"] == [], (
        f"@120x30: buttons trapped inside a scrollable body: {dims['trapped']}"
    )
    assert dims["script_rows_at_scroll0"] == [], (
        f"@120x30: SCRIPT window docked rows must be fully visible at panel "
        f"scroll 0 (the batch-94 first screenful), not visible: "
        f"{dims['script_rows_at_scroll0']}"
    )
    assert dims["unreachable"] == list(
        _UNREACHABLE_UNDER_SCROLL.get((120, 30), ())
    ), (
        f"@120x30: buttons not reachable-under-scroll: {dims['unreachable']} "
        "(expected only the measured-unreachable "
        f"{_UNREACHABLE_UNDER_SCROLL.get((120, 30), ())} — its line-2 home "
        "renders below the file row's 2-row content region)"
    )


def test_at064c_revealed_rows_reachable_at_80(tmp_path: Path) -> None:
    """AT-064c (80x24) — revealed save-back + before/after buttons reachable.

    Intent: HLR-064 / FOLD-5 — after the save-back and before/after rows are
    REVEALED (driven through the panel's ``show_save_prompt`` /
    ``show_before_after_prompt`` reveal path), their docked buttons are still
    siblings of the JSON window body and reachable-under-scroll — a regression
    trapping a revealed row below a fold is the exact B2 class this catches.
    """
    revealed = (
        "patch_saveback_confirm_button",
        "patch_saveback_decline_button",
        "patch_saveback_width_button",
        "patch_before_after_button",
    )
    dims = _drive_button_reachability(
        tmp_path, (80, 24), reveal=True, button_ids=revealed
    )
    assert dims["trapped"] == [], (
        f"@80x24: revealed buttons trapped inside a scrollable body: "
        f"{dims['trapped']}"
    )
    assert dims["unreachable"] == [], (
        f"@80x24: revealed buttons not reachable-under-scroll: "
        f"{dims['unreachable']}"
    )


# ---------------------------------------------------------------------------
# TC-46.1 / TC-46.2 — white-box structure (layout-agnostic) + paste in-viewport
# ---------------------------------------------------------------------------

# The docked button-row / group docked as a sibling of each window's body.
_WINDOW_DOCKED = {
    "patch_win_script": "patch_doc_entry_buttons",
    "patch_win_checks": "patch_checks_controls",
    "patch_win_json": "patch_paste_controls",
}
_WINDOW_BODY = {
    "patch_win_script": "patch_win_script_body",
    "patch_win_checks": "patch_win_checks_body",
    "patch_win_json": "patch_win_json_body",
}


def test_tc46_1_window_structure_layout_agnostic(tmp_path: Path) -> None:
    """TC-46.1 (white-box, layout-agnostic) — window structure + reflow rule.

    Intent: LLR-063.1 / LLR-064.1 (q-m3) — each window SELF-DESCRIBES with a
    constant title, holds a ``VerticalScroll`` body, and has a docked
    button-row that is a SIBLING of the body (not a descendant); and the
    ``width-narrow`` reflow selector exists in ``styles.tcss``. No
    ``layout.name`` is pinned (the wide token is a design call, M-A3); the AT
    geometry oracle carries the actual arrangement.

    **batch-48 (§6.5 Amendment D) — DELETE-AND-RESTATE, not hide.** This test
    asserted ``any("patch-window-title" in c.classes for c in win.children)``.
    Inc-1 gave each window a ``border_title`` carrying the same constant, so
    the in-body ``Label`` rendered the title a SECOND time; Inc-2 removes the
    Label. The protected property is *each window self-describes* — NOT *a
    Label with a given class exists* — so the assertion is RESTATED on
    ``border_title``, which is strictly stronger:

    - it pins the title's TEXT (the class check passed on an empty Label), and
    - it cannot be satisfied by a hidden widget.

    That last point is why the Label was DELETED rather than hidden via CSS: a
    ``display: none`` Label still satisfies ``"patch-window-title" in
    c.classes``, which would have converted this line into a false-confidence
    test that stays green while the window shows nothing.

    # TC-046.1
    """

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            result: dict[str, object] = {}
            for win_id in _WINDOW_IDS:
                win = app.query_one(f"#{win_id}")
                child_ids = [c.id for c in win.children]
                border_title = str(win.border_title or "")
                # Any direct child re-rendering the window's own name is the
                # duplicate §6.5 Amendment D removed. Matched on the RENDERED
                # TEXT (not the retired `.patch-window-title` class) so a
                # re-added Label cannot dodge it by dropping the class.
                #
                # `Label.render()` -> `Content`, whose `.plain` is the text.
                # NOTE: a `Label` at textual==8.2.8 has NO `.renderable`
                # attribute — an earlier `getattr(c, "renderable", "")` form
                # of this check silently compared "" and passed VACUOUSLY
                # (mutation-caught: it stayed green with the duplicate Label
                # re-added). Read the render path, not a guessed attribute.
                bare_title = border_title.lstrip("¹²³")
                title_labels = [
                    c.id or type(c).__name__
                    for c in win.children
                    if isinstance(c, Label)
                    and c.render().plain.strip() == bare_title
                ]
                body = app.query_one(f"#{_WINDOW_BODY[win_id]}")
                docked = app.query_one(f"#{_WINDOW_DOCKED[win_id]}")
                result[win_id] = {
                    "border_title": border_title,
                    "title_labels": title_labels,
                    "body_is_scroll": isinstance(body, VerticalScroll),
                    "docked_is_body_sibling": (
                        docked.parent is win and body.parent is win
                    ),
                    "docked_not_in_body": docked
                    not in body.walk_children(with_self=False),
                    "child_ids": child_ids,
                }
            return result

    result = asyncio.run(_run())
    for win_id, r in result.items():
        # batch-48 §6.5 Amendment D: the window self-describes on its OWN
        # border chrome. Sourced from the panel's constant, not re-spelled, so
        # a title rename cannot pass here by being copied into the oracle.
        expected = PatchEditorPanel._WINDOW_BORDER_TITLES[win_id]
        assert r["border_title"] == expected, (
            f"{win_id} must self-describe via its constant border_title "
            f"{expected!r}; got {r['border_title']!r}"
        )
        # The de-dup itself: the in-body title Label must NOT come back. The
        # border title is the single title surface — a re-added Label would
        # render the window's name twice (the Inc-1 -> Inc-2 defect).
        assert not r["title_labels"], (
            f"{win_id} carries {r['title_labels']} in-body title Label(s) "
            "duplicating its border_title (§6.5 Amendment D removed them)"
        )
        assert r["body_is_scroll"], (
            f"{win_id} body must be a VerticalScroll, got {r['child_ids']}"
        )
        assert r["docked_is_body_sibling"], (
            f"{win_id} docked row must be a direct child of the window "
            f"(sibling of the body), got children {r['child_ids']}"
        )
        assert r["docked_not_in_body"], (
            f"{win_id} docked row must NOT be a descendant of the body "
            "(the B2 fix)"
        )

    # The narrow reflow reuses the existing width-narrow class (inspection).
    css = (
        Path(__file__).resolve().parents[1]
        / "s19_app"
        / "tui"
        / "styles.tcss"
    ).read_text(encoding="utf-8")
    assert "#workspace_body.width-narrow #patch_editor_panel" in css, (
        "the narrow reflow must reuse the existing width-narrow class on "
        "#patch_editor_panel (mirrors the batch-45 map reflow)"
    )


def test_tc46_2_paste_in_viewport_at_body_scroll0(tmp_path: Path) -> None:
    """TC-46.2 (FOLD-4) — the paste editor's first line is in-viewport.

    Intent: R-TUI-046 (amended) — at the JSON window body's scroll 0 the
    ``#patch_paste_text`` editor's first line lies inside the body's visible
    ``content_region`` (not below a fold), the single authoritative verifier of
    the paste-in-viewport outcome.
    """

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            body = app.query_one("#patch_win_json_body")
            paste = app.query_one("#patch_paste_text", TextArea)
            return {
                "scroll_y": body.scroll_offset.y,
                "content_top": body.content_region.y,
                "content_bottom": body.content_region.bottom,
                "paste_y": paste.region.y,
                "paste_h": paste.region.height,
            }

    d = asyncio.run(_run())
    assert d["scroll_y"] == 0, "the JSON window body must start unscrolled"
    assert d["content_top"] <= d["paste_y"] < d["content_bottom"], (
        f"the paste editor's first line y={d['paste_y']} must lie inside the "
        f"body's visible rows [{d['content_top']}, {d['content_bottom']})"
    )
