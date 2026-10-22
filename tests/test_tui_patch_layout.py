"""Patch Editor layout tests — batch-46 (Inc-1), batch-94 (pe_b), batch-97 (pe_A).

**batch-97 Inc-4 — named supersession of all nine tests (HLR-144, design §3
Patch tree; design-proposal Inc-4 row: "Retires / rewrites
test_tui_patch_layout.py (9 tests)").** The three stacked windows became a
full-height PATCH SCRIPT ledger beside ONE bordered inspector whose
Inspector / JSON / Checks tabs switch a ``ContentSwitcher``; the file row and
the document controls are one-row docks of the panel. Each test keeps its id
and its protected property, restated on the new tree: AT-063a/b — the two
columns side by side, inside the panel, at both regimes (the layout is the
same on both sides of 120, LLR-149.2); AT-063c — every must-preserve id at its
batch-97 home and one routed action per surface; AT-064a/b/c — every named
button reachable on its tab (the measured Refresh deficit is GONE: the file
row is one row); TC-46.1 — each scroll body a ``VerticalScroll`` with its
docked rows as siblings, and the retired ``width-narrow`` reflow rule absent
(D23); TC-46.2 — the paste editor's first line in view on the JSON tab. The
batch-94 text below is kept as history.


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
# batch-97: the two columns of the ledger + inspector composition.
_COLUMN_IDS = ("patch_win_script", "patch_inspector")
# batch-97: every panel button's home — a tab pane of the inspector, the tab
# row, or a one-row dock of the panel; never the ledger's scroll body.
_BUTTON_HOMES = (
    "patch_tabs",
    "patch_pane_inspector",
    "patch_win_json",
    "patch_win_checks",
    "patch_doc_file_row",
    "patch_doc_controls",
)
# batch-97: the tab chip that shows each tab-resident home.
_TAB_FOR_HOME = {
    "patch_pane_inspector": "patch_tab_inspector",
    "patch_win_json": "patch_tab_json",
    "patch_win_checks": "patch_tab_checks",
}

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
    # batch-97: the file row is a one-row dock of the PANEL.
    "patch_doc_file_row": "patch_editor_panel",
    "patch_doc_file_line1": "patch_doc_file_row",
    "patch_doc_file_line2": "patch_doc_file_row",
    "patch_doc_file_select": "patch_doc_file_line1",
    "patch_doc_path_input": "patch_doc_file_line1",
    "patch_doc_load_button": "patch_doc_file_line1",
    "patch_doc_refresh_button": "patch_doc_file_line2",
    "patch_script_section_label": "patch_doc_file_line2",
    # batch-97: the entry form + the before/after strip ride the Inspector pane
    "patch_doc_entry_inputs": "patch_pane_inspector",
    "patch_entry_address_input": "patch_doc_entry_inputs",
    "patch_entry_value_input": "patch_doc_entry_inputs",
    "patch_entry_bytes_input": "patch_doc_entry_inputs",
    "patch_before_after_card": "patch_pane_inspector",
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
    # batch-97: the one-row file row carries Refresh beside Load — the
    # measured line-2 deficit is gone at both regimes.
    (80, 24): (),
    (120, 30): (),
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
            counts = {wid: len(app.query(f"#{wid}")) for wid in _COLUMN_IDS}
            regions: dict[str, tuple[int, int, int, int]] = {}
            auto_heights: dict[str, bool] = {}
            for wid in _COLUMN_IDS:
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


def _assert_two_columns(dims: dict, size_label: str) -> None:
    """batch-97: the ledger (left) and the inspector (right) side by side —
    two distinct x's, one shared y, both at/above the usable floor, inside the
    panel, non-overlapping."""
    counts, regions = dims["counts"], dims["regions"]
    assert all(counts[wid] == 1 for wid in _COLUMN_IDS), (
        f"@{size_label}: each column id must resolve once, got {counts}"
    )
    (lx, ly, lw, lh), (ix, iy, iw, ih) = (regions[w] for w in _COLUMN_IDS)
    assert lx < ix and ly == iy, (
        f"@{size_label}: the ledger must sit LEFT of the inspector on one row, "
        f"got {regions}"
    )
    panel_right = dims["panel_right"]
    for wid, (x, _y, w, h) in regions.items():
        assert w >= _MIN_USABLE_W and h >= _MIN_USABLE_H, (
            f"@{size_label}: {wid} {w}x{h} below the usable floor"
        )
        assert x + w <= panel_right, (
            f"@{size_label}: {wid} right edge {x + w} clips past panel right "
            f"{panel_right}"
        )
    _assert_no_overlap(regions, size_label)


def test_at063a_three_across_at_120(tmp_path: Path) -> None:
    """AT-063a — batch-97 form: the ledger and the inspector side by side at 120x30.

    Intent (HLR-063 restated by HLR-144): the change document and its
    inspector are both on screen. Counterfactual on the batch-94 tree: one
    column x (the stack) -> RED.
    """
    _assert_two_columns(_drive_window_geometry(tmp_path, (120, 30)), "120x30")


def test_at063b_stacked_at_80(tmp_path: Path) -> None:
    """AT-063b — batch-97 form: the same two columns at the 80x24 floor.

    Intent (LLR-149.2 / LLR-149.6): the layout is the same on both sides of the
    120-column breakpoint; below the range the panel scrolls vertically, the
    columns keep their split. Counterfactual on the batch-94 tree: one x.
    """
    _assert_two_columns(_drive_window_geometry(tmp_path, (80, 24)), "80x24")


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
            # batch-97 B2 census: every button has a home of _BUTTON_HOMES and
            # none sits inside the ledger's scroll body.
            trapped: list[str] = []
            for button in panel.walk_children(Button):
                homes = {getattr(a, "id", None) for a in button.ancestors}
                if "patch_win_script_body" in homes or not homes & set(_BUTTON_HOMES):
                    trapped.append(button.id or type(button).__name__)

            # At 120x30 the panel's one-row docks and the Inspector tab's entry
            # chips are fully visible at panel scroll 0 (the first screenful);
            # captured BEFORE any scrolling happens.
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
                homes = {getattr(a, "id", None) for a in btn.ancestors}
                for home, chip in _TAB_FOR_HOME.items():
                    if home in homes:
                        app.query_one(f"#{chip}", Button).press()
                        await pilot.pause()
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

# The docked button-row / group docked as a sibling of each scroll body.
# batch-97: the ledger's docks are the panel's one-row file row and document
# controls, siblings of ``#patch_main`` (which holds the ledger body).
_WINDOW_DOCKED = {
    "patch_win_script": "patch_doc_controls",
    "patch_win_checks": "patch_checks_controls",
    "patch_win_json": "patch_paste_controls",
}
_DOCK_PARENT = {
    "patch_win_script": "patch_editor_panel",
    "patch_win_checks": "patch_win_checks",
    "patch_win_json": "patch_win_json",
}
_WINDOW_BODY = {
    "patch_win_script": "patch_win_script_body",
    "patch_win_checks": "patch_win_checks_body",
    "patch_win_json": "patch_win_json_body",
}


def test_tc46_1_window_structure_layout_agnostic(tmp_path: Path) -> None:
    """TC-46.1 (white-box) — batch-97 form: bodies scroll, docks are siblings.

    Intent: LLR-063.1 / LLR-064.1 restated on the ledger + inspector tree
    (named supersession): the ledger self-describes with its constant border
    title and the inspector's title follows its tab; each scroll body (ledger,
    JSON, Checks) is a ``VerticalScroll``; each dock is NOT a descendant of
    that body (the B2 fix); and the retired ``width-narrow`` reflow of the
    panel is gone — one scoped section replaces it (D23, LLR-149.2).

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
                body = app.query_one(f"#{_WINDOW_BODY[win_id]}")
                docked = app.query_one(f"#{_WINDOW_DOCKED[win_id]}")
                result[win_id] = {
                    "body_is_scroll": isinstance(body, VerticalScroll),
                    "dock_parent": getattr(docked.parent, "id", None),
                    "docked_not_in_body": docked
                    not in body.walk_children(with_self=False),
                }
            titles = {"script": str(app.query_one("#patch_win_script").border_title or "")}
            for chip, key in (("patch_tab_json", "json"), ("patch_tab_checks", "checks")):
                app.query_one(f"#{chip}", Button).press()
                await pilot.pause()
                titles[key] = str(app.query_one("#patch_inspector").border_title or "")
            result["titles"] = titles
            return result

    result = asyncio.run(_run())
    titles = result.pop("titles")
    assert titles["script"] == PatchEditorPanel._WINDOW_BORDER_TITLES["patch_win_script"]
    assert titles["json"] == "JSON" and titles["checks"] == "CHECKS", titles
    for win_id, r in result.items():
        assert r["body_is_scroll"], f"{win_id} body must be a VerticalScroll"
        assert r["dock_parent"] == _DOCK_PARENT[win_id], (win_id, r["dock_parent"])
        assert r["docked_not_in_body"], (
            f"{win_id} docked row must NOT be a descendant of the body (the B2 fix)"
        )

    css = (
        Path(__file__).resolve().parents[1]
        / "s19_app"
        / "tui"
        / "styles.tcss"
    ).read_text(encoding="utf-8")
    assert "#workspace_body.width-narrow #patch_editor_panel" not in css, (
        "D23: the width-narrow reflow of the Patch Editor is retired"
    )
    assert "/* batch-97 patch_editor" in css


def test_tc46_2_paste_in_viewport_at_body_scroll0(tmp_path: Path) -> None:
    """TC-46.2 (FOLD-4) — the paste editor's first line is in-viewport.

    Intent: R-TUI-046 (amended) — at the JSON body's scroll 0 the
    ``#patch_paste_text`` editor's first line lies inside the body's visible
    ``content_region``. batch-97 (named supersession): read on the JSON tab.
    """

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            app.query_one("#patch_tab_json", Button).press()
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
