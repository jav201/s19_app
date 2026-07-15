"""Patch Editor three-window responsive layout tests — batch-46 (Inc-1).

Supersedes the batch-22 2x2 four-pane geometry tests. Verdicts HLR-063/064
(US-U8/US-B2) through the Pilot region oracle at the 80x24 floor and 120x30:

- **AT-063a** (120x30): the three windows sit 3-across — exactly three distinct
  ``region.x`` — each within the host column budget and at/above the
  pilot-measured usable floor (``MIN_USABLE_W`` / ``MIN_USABLE_H``, M-Q1),
  non-overlapping, no right-edge clip.
- **AT-063b** (80x24): the three windows STACK — one distinct ``region.x`` and
  three ascending ``region.y`` — each full-width and above the usable floor.
- **AT-063c** (80x24 + 120x30): reparent-safety — every must-preserve leaf id
  resolves to exactly one widget, and one action per window routes to an
  OBSERVABLE effect (FOLD-3): PATCH SCRIPT ``add_entry`` grows the table;
  CHECKS ``run_checks`` emits a ``Checks:`` log line; JSON EDIT ``parse_paste``
  populates the change document.
- **AT-064a** (80x24) / **AT-064b** (120x30) / **AT-064c** (80x24, revealed
  save-back + before/after rows): every named action button is
  REACHABLE-UNDER-SCROLL (FOLD-8) — its docked row is a SIBLING of (not a
  descendant of) its window's ``VerticalScroll`` body, so it is never trapped
  below the body's inner fold, and it becomes ``_fully_visible`` after its
  window/panel is scrolled to it. The MEASURED ~5-row @80x24 (11-row @120x30)
  panel viewport cannot show all 17 buttons at scroll 0, so ``off == []`` at
  scroll 0 is deliberately NOT asserted (operator-amended contract, FOLD-8).
- **TC-46.1** (layout-agnostic): each window = a title + a scrollable body + a
  docked button-row that is a SIBLING of the body; the ``width-narrow`` reflow
  rule exists in ``styles.tcss`` (no ``layout.name`` pinned — the wide token is
  a Phase-3 design call, M-A3).
- **TC-46.2** (FOLD-4): the paste editor's first line is in-viewport at its
  window-body scroll 0.

RED counterfactual (recorded, run against the pre-restructure 2x2 tree): the
three ``#patch_win_*`` ids are ABSENT (AT-063a/b/c cardinality-0 fail), and the
change-file / entry / variant buttons sit below the starved ``1fr`` grid-cell
fold with NO window scroll able to reach them — ``_reach`` leaves them
``_fully_visible == False`` (AT-064a/b/c fail). The preserved pane-lead ids
(``#patch_pane_*``) still resolve, so the 2-vs-3-column discriminator is real
(q-m2).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.containers import VerticalScroll
from textual.widgets import Button, DataTable, TextArea

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

# Every must-preserve id (LLR-063.4 + FOLD-1): the 14 wiring-critical leaf ids,
# the census-pinned leaf/section ids, the .hidden-toggled rows, the preserved
# structural grouping sub-containers, and the variant/execute rows.
_MUST_PRESERVE_IDS = (
    # wiring-critical leaf ids (14)
    "patch_edit_json_button",
    "patch_undo_button",
    "patch_redo_button",
    "patch_entry_edit_json_button",
    "patch_doc_file_select",
    "patch_variant_select",
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
    "patch_variant_info_button",
    "patch_execute_scope_button",
    "patch_execute_run_button",
    "patch_saveback_confirm_button",
    "patch_saveback_decline_button",
    "patch_before_after_button",
    # section labels + preserved structural containers (FOLD-1)
    "patch_script_section_label",
    "patch_checks_section_label",
    "patch_doc_controls",
    "patch_checks_controls",
    "patch_pane_entries",
    "patch_pane_changefile",
    "patch_pane_variant",
    "patch_doc_file_row",
    "patch_variant_row",
    "patch_execute_row",
    # .hidden-toggled rows
    "patch_saveback_row",
    "patch_before_after_row",
)

# Every named ACTION button whose reachability HLR-064 guards.
_NAMED_BUTTONS = (
    "patch_entry_add_button",
    "patch_entry_edit_button",
    "patch_entry_remove_button",
    "patch_entry_edit_json_button",
    "patch_undo_button",
    "patch_redo_button",
    "patch_doc_load_button",
    "patch_doc_refresh_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
    "patch_doc_save_button",
    "patch_variant_info_button",
    "patch_execute_scope_button",
    "patch_execute_run_button",
    "patch_checks_run_button",
    "patch_paste_parse_button",
    "patch_edit_json_button",
)


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
            for wid in _WINDOW_IDS:
                if counts[wid] == 1:
                    r = app.query_one(f"#{wid}").region
                    regions[wid] = (r.x, r.y, r.width, r.height)
            return {
                "regions": regions,
                "counts": counts,
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
    """AT-063a — three windows 3-across within budget at 120x30.

    Intent: HLR-063 — at the comfortable width the three windows lay out
    horizontally (exactly three distinct ``region.x``), each at/above the
    pilot-measured usable floor and within the host column budget, no overlap,
    no right-edge clip. Counterfactual on the 2x2 tree: the ``#patch_win_*`` ids
    are absent → cardinality-0 → RED.
    """
    dims = _drive_window_geometry(tmp_path, (120, 30))
    counts, regions = dims["counts"], dims["regions"]
    assert all(counts[wid] == 1 for wid in _WINDOW_IDS), (
        f"@120x30: each window id must resolve once, got {counts}"
    )
    xs = {r[0] for r in regions.values()}
    assert len(xs) == 3, (
        f"@120x30: three windows need three distinct column x's, got "
        f"{sorted(xs)} from {regions}"
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
    """Census every must-preserve id + route one action per window."""

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

    For each id: assert its docked row is a SIBLING of its window body (not a
    descendant of the ``VerticalScroll``), then scroll its window/panel to it
    and record whether it becomes ``_fully_visible``.
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

            unreachable: list[str] = []
            trapped: list[str] = []
            for bid in button_ids:
                btn = app.query_one(f"#{bid}", Button)
                # Structural: no VerticalScroll body is an ancestor of the
                # button (its docked row must be a sibling of the body).
                node = btn.parent
                while node is not None and node is not app.screen:
                    if isinstance(node, VerticalScroll):
                        trapped.append(bid)
                        break
                    node = node.parent
                await _reach(app, pilot, btn)
                if not _fully_visible(app, btn):
                    unreachable.append(bid)
            return {"unreachable": unreachable, "trapped": trapped}

    return asyncio.run(_run())


def test_at064a_reachable_under_scroll_at_80(tmp_path: Path) -> None:
    """AT-064a (80x24) — every named button reachable-under-scroll (FOLD-8).

    Intent: HLR-064 / US-B2 — each named action button's docked row is a
    SIBLING of its window body (never trapped below the body's inner fold), and
    the button becomes ``_fully_visible`` once its window/panel is scrolled to
    it. ``off == []`` at scroll 0 is NOT asserted — the measured ~5-row @80x24
    panel viewport cannot show all 17 buttons at once (FOLD-8). Counterfactual
    on the 2x2 tree: the change-file / entry buttons sit below the starved
    ``1fr`` cell fold with no window scroll to reach them → ``_reach`` leaves
    them not-``_fully_visible`` → RED.
    """
    dims = _drive_button_reachability(
        tmp_path, (80, 24), reveal=False, button_ids=_NAMED_BUTTONS
    )
    assert dims["trapped"] == [], (
        f"@80x24: buttons trapped inside a scrollable body (below the inner "
        f"fold), not docked siblings: {dims['trapped']}"
    )
    assert dims["unreachable"] == [], (
        f"@80x24: buttons not reachable-under-scroll: {dims['unreachable']}"
    )


def test_at064b_reachable_under_scroll_at_120(tmp_path: Path) -> None:
    """AT-064b (120x30) — every named button reachable-under-scroll (FOLD-8).

    Intent: HLR-064 — same reachability at the comfortable width. The operator
    target was ``off == []`` at scroll 0, but the MEASURED 11-row @120x30 panel
    viewport vs the ~53-row window content (the 8-line paste editor + 10-line
    entries table dominate the body) makes it unachievable — only 1/17 buttons
    are visible at scroll 0. Per the pre-approved FOLD-8 degradation this window
    set falls back to reachable-under-scroll; the deficit is recorded in the
    increment packet. Reachability (17/17) is the gate.
    """
    dims = _drive_button_reachability(
        tmp_path, (120, 30), reveal=False, button_ids=_NAMED_BUTTONS
    )
    assert dims["trapped"] == [], (
        f"@120x30: buttons trapped inside a scrollable body: {dims['trapped']}"
    )
    assert dims["unreachable"] == [], (
        f"@120x30: buttons not reachable-under-scroll: {dims['unreachable']}"
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

    Intent: LLR-063.1 / LLR-064.1 (q-m3) — each window holds a title ``Label``,
    a ``VerticalScroll`` body, and a docked button-row that is a SIBLING of the
    body (not a descendant), and the ``width-narrow`` reflow selector exists in
    ``styles.tcss``. No ``layout.name`` is pinned (the wide token is a design
    call, M-A3); the AT geometry oracle carries the actual arrangement.
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
                title_ok = any(
                    "patch-window-title" in c.classes for c in win.children
                )
                body = app.query_one(f"#{_WINDOW_BODY[win_id]}")
                docked = app.query_one(f"#{_WINDOW_DOCKED[win_id]}")
                result[win_id] = {
                    "title_ok": title_ok,
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
        assert r["title_ok"], f"{win_id} missing its constant title Label"
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
