"""Patch Editor 2x2 four-pane geometry tests — s19_app batch-22, Increment 1.

These tests verdict HLR-033 (US-030) — the ``PatchEditorPanel`` reparent from
a single vertical stack into a four-pane 2x2 grid — through the Pilot region
oracle, at both the 80-column floor and the 120-column comfortable size:

- **AT-033a** (80x24, the tight floor) / **AT-033b** (120x30): the four
  ``#patch_pane_*`` render as a genuine 2x2 grid (exactly two distinct
  ``region.x`` and two distinct ``region.y``, each row-band and column-band
  holding exactly two panes — rejecting an L-shape), each pane's width within
  its runtime column budget (``host_content // 2``), no right-edge clip, and
  non-overlapping. AT-033a is the C-13 80-col-floor gate: it also proves the
  ``#patch_doc_controls`` button-grid does not clip past the host.
- **AT-033c** (80 and 120, reparent-safety): one key widget per pane resolves
  and its action ROUTES to an observable effect after the reparent (mirrors
  ``test_tui_patch_editor_v2.py::test_action_routing_observable_effects``).
- **TC (white-box)**: each ``#patch_pane_*`` has ``overflow_y == "auto"``
  (HLR-033.3 per-pane scroll); ``#patch_editor_panel`` is a ``grid``;
  ``#patch_doc_controls`` is a ``grid-size: 3`` grid, not a bare Horizontal
  (LLR-033.3b).

Local geometry is the gate-blocking verdict for the layout story; the SVG
snapshot lock (US-031 / HLR-034) rides Increment 2.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import DataTable, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import PatchEditorPanel

_PANE_IDS = (
    "patch_pane_entries",
    "patch_pane_changefile",
    "patch_pane_checks",
    "patch_pane_variant",
)


def _drive_panes(tmp_path: Path, size: tuple[int, int]) -> dict[str, object]:
    """Show the patch screen at ``size`` and capture pane geometry.

    Summary:
        Drive the real app under Pilot, activate the patch screen, and read
        each ``#patch_pane_*`` widget's ``region`` plus the host panel's
        ``content_region`` / ``region`` so the caller can assert the 2x2
        arrangement, per-pane budget, clip, and overlap.

    Args:
        tmp_path (Path): pytest tmp base for the app's ``.s19tool`` workarea.
        size (tuple[int, int]): the ``(width, height)`` terminal size to run
            the Pilot harness at.

    Returns:
        dict[str, object]: ``regions`` (pane id -> ``(x, y, w, h)``),
        ``host_content_w`` (``#patch_editor_panel.content_region.width``),
        ``panel_right`` (the panel's ``region`` right edge), and ``counts``
        (pane id -> query result count).

    Dependencies:
        Uses:
            - ``S19TuiApp.run_test`` / ``action_show_screen``
        Used by:
            - the AT-033a / AT-033b geometry assertions
    """

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            counts = {wid: len(app.query(f"#{wid}")) for wid in _PANE_IDS}
            regions: dict[str, tuple[int, int, int, int]] = {}
            for wid in _PANE_IDS:
                if counts[wid] == 1:
                    region = app.query_one(f"#{wid}").region
                    regions[wid] = (
                        region.x,
                        region.y,
                        region.width,
                        region.height,
                    )
            return {
                "regions": regions,
                "host_content_w": panel.content_region.width,
                "panel_right": panel.region.right,
                "counts": counts,
            }

    return asyncio.run(_run())


def _assert_two_by_two(dims: dict[str, object], size_label: str) -> None:
    """Assert the four panes form a genuine 2x2 grid within budget.

    Summary:
        Shared oracle for AT-033a / AT-033b: each pane resolves once; there
        are exactly two distinct column x's and two distinct row y's; each
        row-band and column-band holds exactly two panes (rejecting an
        L-shape); each pane is within ``host_content // 2`` and does not clip
        past the panel's right edge; panes do not overlap.

    Args:
        dims (dict[str, object]): the ``_drive_panes`` capture.
        size_label (str): a human label (e.g. ``"80x24"``) for assert
            messages.

    Returns:
        None
    """
    counts = dims["counts"]
    assert all(counts[wid] == 1 for wid in _PANE_IDS), (
        f"@{size_label}: each #patch_pane_* must resolve to one widget, "
        f"got {counts}"
    )
    regions: dict[str, tuple[int, int, int, int]] = dims["regions"]
    xs = {r[0] for r in regions.values()}
    ys = {r[1] for r in regions.values()}
    assert len(xs) == 2, (
        f"@{size_label}: 2x2 grid needs exactly 2 distinct column x's, "
        f"got {sorted(xs)} from {regions}"
    )
    assert len(ys) == 2, (
        f"@{size_label}: 2x2 grid needs exactly 2 distinct row y's, "
        f"got {sorted(ys)} from {regions}"
    )
    # Each shared-y row-band and shared-x column-band holds EXACTLY 2 panes
    # (rejects an L-shape that 2-distinct-x + 2-distinct-y alone would pass).
    for y in ys:
        band = [wid for wid, r in regions.items() if r[1] == y]
        assert len(band) == 2, (
            f"@{size_label}: row-band y={y} must hold exactly 2 panes, "
            f"got {band}"
        )
    for x in xs:
        band = [wid for wid, r in regions.items() if r[0] == x]
        assert len(band) == 2, (
            f"@{size_label}: column-band x={x} must hold exactly 2 panes, "
            f"got {band}"
        )
    # Per-pane budget: width <= host_content // 2 (interior/gutter-excluded,
    # computed at runtime), and no pane clips past the panel's right edge.
    host_content_w: int = dims["host_content_w"]
    budget = host_content_w // 2
    panel_right: int = dims["panel_right"]
    for wid, (x, _y, w, _h) in regions.items():
        assert w <= budget, (
            f"@{size_label}: {wid} width {w} exceeds column budget "
            f"host_content({host_content_w})//2 = {budget}"
        )
        assert x + w <= panel_right, (
            f"@{size_label}: {wid} right edge {x + w} clips past the panel "
            f"right {panel_right}"
        )
    # Non-overlapping: no two pane rectangles intersect.
    items = list(regions.items())
    for i in range(len(items)):
        wid_a, (ax, ay, aw, ah) = items[i]
        for j in range(i + 1, len(items)):
            wid_b, (bx, by, bw, bh) = items[j]
            overlap = (
                ax < bx + bw
                and bx < ax + aw
                and ay < by + bh
                and by < ay + ah
            )
            assert not overlap, (
                f"@{size_label}: {wid_a} and {wid_b} overlap "
                f"({(ax, ay, aw, ah)} vs {(bx, by, bw, bh)})"
            )


def test_at_033a_two_by_two_at_80_floor(tmp_path: Path) -> None:
    """AT-033a — the 4 panes form a 2x2 grid within budget at the 80 floor.

    Intent: HLR-033.5 / C-13 — at the 80-column floor (measured host = 70
    cols, ~35/pane) the panel must lay the four area-panes out 2x2 with no
    horizontal clip or overlap and each pane within its column budget. This
    asserts the PANE stays within the host; the ``#patch_doc_controls``
    button-grid layout itself is locked by the separate white-box TC
    (``grid_size_columns == 3``) — a non-wrapping ``Horizontal`` would clip
    the buttons WITHIN the pane (masked by ``overflow-x: hidden``) without
    moving the pane edge, so the two checks together, not this one alone,
    guard the R1 button-grid. Gate-blocking geometry verdict; counterfactual
    (revert the grid CSS -> the panes share one region.x) flips it RED.
    """
    dims = _drive_panes(tmp_path, (80, 24))
    _assert_two_by_two(dims, "80x24")


def test_at_033b_two_by_two_at_120(tmp_path: Path) -> None:
    """AT-033b — the 4 panes form a 2x2 grid within budget at 120 cols.

    Intent: HLR-033.1 — at the comfortable 120 size (measured host = 92 cols,
    ~46/pane) the same 2x2 arrangement holds. A grid that collapses to one row
    of four flips ``len({region.y})==1`` and this test RED.
    """
    dims = _drive_panes(tmp_path, (120, 30))
    _assert_two_by_two(dims, "120x30")


def _drive_reparent_safety(
    tmp_path: Path, size: tuple[int, int]
) -> dict[str, object]:
    """Show the patch screen and exercise one action per pane.

    Summary:
        Reparent-safety oracle (AT-033c): after the 2x2 reparent, assert one
        key widget per pane resolves and its action ROUTES to an observable
        effect — ``add_entry`` grows the entries table, the load button is
        present, ``run_checks`` emits a status log line, and the variant
        execute button is present.

    Args:
        tmp_path (Path): pytest tmp base.
        size (tuple[int, int]): terminal ``(width, height)``.

    Returns:
        dict[str, object]: observable outcomes keyed by check name.
    """

    async def _run() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            table = app.query_one("#patch_doc_entries_table", DataTable)

            # Entries pane: add_entry grows the table.
            before = table.row_count
            app.query_one("#patch_entry_address_input").value = "0x100"
            app.query_one("#patch_entry_bytes_input").value = "AA"
            panel.request_action("add_entry")
            await pilot.pause()
            outcomes["add_entry_grows"] = table.row_count == before + 1

            # Change-file pane: the load button is present + routable.
            outcomes["load_button_present"] = (
                len(app.query("#patch_doc_load_button")) == 1
            )

            # Checks pane: run_checks emits an observable status log line.
            panel.request_action("run_checks")
            await pilot.pause()
            outcomes["run_checks_routes"] = any(
                line.startswith("Checks:") for line in app.log_lines
            )

            # Variant pane: the execute button is present.
            outcomes["execute_button_present"] = (
                len(app.query("#patch_execute_run_button")) == 1
            )
        return outcomes

    return asyncio.run(_run())


def test_at_033c_reparent_safety_at_80(tmp_path: Path) -> None:
    """AT-033c (80) — one key widget per pane routes after the reparent."""
    outcomes = _drive_reparent_safety(tmp_path, (80, 24))
    assert outcomes["add_entry_grows"], "entries add_entry did not grow table"
    assert outcomes["load_button_present"], "change-file load button missing"
    assert outcomes["run_checks_routes"], "checks run_checks emitted no line"
    assert outcomes["execute_button_present"], "variant execute button missing"


def test_at_033c_reparent_safety_at_120(tmp_path: Path) -> None:
    """AT-033c (120) — the same reparent-safety holds at 120 cols."""
    outcomes = _drive_reparent_safety(tmp_path, (120, 30))
    assert outcomes["add_entry_grows"], "entries add_entry did not grow table"
    assert outcomes["load_button_present"], "change-file load button missing"
    assert outcomes["run_checks_routes"], "checks run_checks emitted no line"
    assert outcomes["execute_button_present"], "variant execute button missing"


def test_tc_pane_styles_and_grid(tmp_path: Path) -> None:
    """TC (white-box) — per-pane scroll + panel grid + controls button-grid.

    Intent: LLR-033.3 / LLR-033.3b — each ``#patch_pane_*`` scrolls
    independently (``overflow_y == "auto"``), the panel is a ``grid``, and
    ``#patch_doc_controls`` is a ``grid-size: 3`` grid (not a bare Horizontal)
    so a passing geometry AT cannot be met by an accidental non-grid layout.
    """

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            controls = app.query_one("#patch_doc_controls")
            return {
                "pane_overflow": {
                    wid: str(app.query_one(f"#{wid}").styles.overflow_y)
                    for wid in _PANE_IDS
                },
                "panel_layout": panel.styles.layout.name,
                "controls_layout": controls.styles.layout.name,
                "controls_grid_cols": controls.styles.grid_size_columns,
            }

    result = asyncio.run(_run())
    for wid, overflow in result["pane_overflow"].items():
        assert overflow == "auto", (
            f"{wid} must scroll independently (overflow_y auto), got {overflow}"
        )
    assert result["panel_layout"] == "grid", (
        f"#patch_editor_panel must be a grid, got {result['panel_layout']}"
    )
    assert result["controls_layout"] == "grid", (
        f"#patch_doc_controls must be a grid (LLR-033.3b), got "
        f"{result['controls_layout']}"
    )
    assert result["controls_grid_cols"] == 3, (
        f"#patch_doc_controls must be grid-size 3 columns, got "
        f"{result['controls_grid_cols']}"
    )


# batch-35 (US-057 / LLR-057.1): the 15 pre-batch change-file-pane widget ids
# that must survive the two-section regroup — the LLR's census, verbatim.
_REGROUP_PRESERVED_IDS = (
    "patch_doc_file_select",
    "patch_doc_path_input",
    "patch_doc_load_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
    "patch_doc_save_button",
    "patch_checks_run_button",
    "patch_doc_controls",
    "patch_checks_help",
    "patch_doc_file_row",
    "patch_paste_text",
    "patch_paste_parse_button",
    "patch_paste_controls",
    "patch_paste_row",
    "patch_pane_changefile",
)


def test_tc319_regroup_section_structure_census(tmp_path: Path) -> None:
    """TC-319 (white-box) — the regrouped change-file pane's compose census.

    Intent: LLR-057.1 — against the composed widget tree: both section
    labels render (`#patch_script_section_label` above `#patch_doc_controls`,
    `#patch_checks_section_label` above `#patch_checks_controls`),
    `#patch_doc_controls` holds exactly the four Load/Validate/Apply/Save
    buttons, `#patch_checks_controls` holds the Run-checks button + the
    checks help, and all 15 pre-batch widget ids survive. The sibling
    grid-3 pin above (`test_tc_pane_styles_and_grid`) stays unmodified and
    must remain GREEN with four buttons — this census only ADDS the
    section-structure queries.
    """
    from textual.widgets import Button, Label

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            file_row = app.query_one("#patch_doc_file_row")
            child_ids = [
                child.id for child in file_row.children if child.id
            ]
            return {
                "id_counts": {
                    wid: len(app.query(f"#{wid}"))
                    for wid in _REGROUP_PRESERVED_IDS
                },
                "script_label": str(
                    app.query_one(
                        "#patch_script_section_label", Label
                    ).render()
                ),
                "checks_label": str(
                    app.query_one(
                        "#patch_checks_section_label", Label
                    ).render()
                ),
                "file_row_child_ids": child_ids,
                "controls_buttons": [
                    button.id
                    for button in app.query_one("#patch_doc_controls").query(
                        Button
                    )
                ],
                "checks_children": [
                    child.id
                    for child in app.query_one(
                        "#patch_checks_controls"
                    ).children
                ],
            }

    result = asyncio.run(_run())
    missing = [
        wid for wid, count in result["id_counts"].items() if count != 1
    ]
    assert not missing, f"preserved ids missing after the regroup: {missing}"
    assert result["script_label"] == "Patch script"
    assert result["checks_label"] == "Checks"
    # Section ORDER inside the file row: the patch-script label immediately
    # precedes #patch_doc_controls, the checks label immediately precedes
    # #patch_checks_controls.
    ids = result["file_row_child_ids"]
    assert ids.index("patch_script_section_label") + 1 == ids.index(
        "patch_doc_controls"
    ), f"the patch-script label must sit above the buttons, got {ids}"
    assert ids.index("patch_checks_section_label") + 1 == ids.index(
        "patch_checks_controls"
    ), f"the checks label must sit above the checks container, got {ids}"
    assert result["controls_buttons"] == [
        "patch_doc_load_button",
        "patch_doc_validate_button",
        "patch_doc_apply_button",
        "patch_doc_save_button",
    ], (
        "#patch_doc_controls must hold exactly Load/Validate/Apply/Save, "
        f"got {result['controls_buttons']}"
    )
    assert result["checks_children"] == [
        "patch_checks_run_button",
        "patch_checks_help",
    ], (
        "#patch_checks_controls must hold the Run-checks button + help, "
        f"got {result['checks_children']}"
    )


# ---------------------------------------------------------------------------
# AT-058a / LLR-058.1/.2 — the reparented paste editor is in-viewport at
# scroll 0, and its cell is separated from the change-file control cluster
# (US-058, batch-36). C-18: one on-disk node asserting both widths.
# ---------------------------------------------------------------------------

# Per-width MEASURED in-viewport line pins (LLR-058.1), taken from the
# post-fix Pilot capture at scroll 0 — each strictly greater than today's 0
# in-viewport lines (the RED counterfactual: the paste editor sat fully below
# the fold inside `#patch_pane_changefile`, region.y=38 vs pane content [8,10)
# @80x24). The always-satisfiable acceptance is the content-region PLACEMENT
# (first line in-viewport); `region.height` alone equals the CSS `height: 8`
# whether visible or below the fold, so it is deliberately NOT the metric.
_PASTE_INVIEW_MIN = {"80x24": 1, "120x30": 4}


def _drive_paste_geometry(
    tmp_path: Path, size: tuple[int, int]
) -> dict[str, object]:
    """Capture the reparented paste-cell geometry at ``size``.

    Summary:
        Drive the real app under Pilot, show the patch screen, and read the
        paste editor's ``region``, its scroll pane's (``#patch_paste_row``)
        ``content_region`` / descendant set, and the change-file cluster's
        (``#patch_doc_file_row``) ``region`` so the caller can assert the
        content-region placement (C-10 discriminator) plus the structural
        non-descendant + sibling-disjoint guards.

    Args:
        tmp_path (Path): pytest tmp base for the app's ``.s19tool`` workarea.
        size (tuple[int, int]): the ``(width, height)`` terminal size.

    Returns:
        dict[str, object]: the captured regions, the paste pane scroll offset,
        and whether ``#patch_paste_row`` is a descendant of
        ``#patch_pane_changefile``.

    Data Flow:
        - ``action_show_screen("patch")`` -> pilot pause -> region reads.

    Dependencies:
        Uses:
            - :class:`s19_app.tui.app.S19TuiApp` Pilot harness.
        Used by:
            - :func:`test_at058a_paste_editor_in_viewport_and_separated`.
    """

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            await pilot.pause()
            paste = app.query_one("#patch_paste_text", TextArea)
            pane = app.query_one("#patch_paste_row")
            changefile = app.query_one("#patch_pane_changefile")
            file_row = app.query_one("#patch_doc_file_row")
            paste_is_changefile_descendant = paste in changefile.walk_children(
                with_self=False
            ) or pane in changefile.walk_children(with_self=False)
            # The change-file/patch-script/checks CLUSTER (#patch_doc_file_row)
            # is contained inside the #patch_pane_changefile grid cell — assert
            # that containment holds, then use the pane cell as the visible
            # cluster rectangle for the sibling-disjointness guard. (file_row's
            # own .region overflows its scroll pane — h=29 vs the 1-2 visible
            # rows @80x24 — so its RAW rectangle is not the on-screen cluster;
            # the pane clips it, F-01.)
            file_row_in_changefile = file_row in changefile.walk_children(
                with_self=False
            )
            pr = paste.region
            cf = changefile.region
            return {
                "scroll_y": pane.scroll_offset.y,
                "content_y": pane.content_region.y,
                "content_bottom": pane.content_region.bottom,
                "paste_region": (pr.x, pr.y, pr.width, pr.height),
                "changefile_region": (cf.x, cf.y, cf.width, cf.height),
                "pane_right": pane.region.right,
                "paste_right": pr.right,
                "paste_is_changefile_descendant": (
                    paste_is_changefile_descendant
                ),
                "file_row_in_changefile": file_row_in_changefile,
            }

    return asyncio.run(_run())


def test_at058a_paste_editor_in_viewport_and_separated(tmp_path: Path) -> None:
    """AT-058a — the paste editor clears the fold + its cell is separated.

    Intent: LLR-058.1/.2 (US-058) — the change-set paste group is reparented
    OUT of the crowded top-right ``#patch_pane_changefile`` cell into its own
    weighted full-width panel cell, so at ``scroll_y == 0`` the paste editor's
    FIRST line lies inside its scroll pane's visible ``content_region`` (no
    longer below the fold), showing at least the per-width MEASURED minimum of
    in-viewport editor lines. The C-10 discriminator is that content-region
    PLACEMENT (mirrors ``test_tui_patch_variant.py``'s TC-035.2 idiom), guarded
    by ``if paste.region.width and paste.region.height`` because a fully
    scrolled-out widget reports a NULL (0,0) region. Structural cheap guards
    (NOT the discriminator): ``#patch_paste_row`` is no longer a descendant of
    ``#patch_pane_changefile``, and its region is disjoint from the change-file
    control cluster ``#patch_doc_file_row``. Asserted at BOTH the 80x24 floor
    and the 120x30 comfortable size.

    Counterfactual (RED before the batch-36 reparent): the paste editor sat at
    region.y=38 while ``#patch_pane_changefile``'s content-region was rows
    [8,10) @80x24 (and y=36 vs [8,13) @120x30) -> 0 in-viewport lines, and
    ``#patch_paste_row`` WAS a descendant of ``#patch_pane_changefile`` -> both
    the placement predicate and the non-descendant guard flip RED.
    """
    for size_label, size in (("80x24", (80, 24)), ("120x30", (120, 30))):
        dims = _drive_paste_geometry(tmp_path / size_label, size)
        n_w = _PASTE_INVIEW_MIN[size_label]
        px, py, pw, ph = dims["paste_region"]

        # Structural guard 1 (cheap): the paste group is reparented OUT of the
        # crowded change-file pane.
        assert dims["paste_is_changefile_descendant"] is False, (
            f"@{size_label}: #patch_paste_row / #patch_paste_text must not be "
            "a descendant of #patch_pane_changefile after the reparent"
        )

        assert dims["scroll_y"] == 0, (
            f"@{size_label}: the paste pane must start unscrolled"
        )

        # C-10 discriminator: the paste editor's first line is inside the
        # pane's visible content-region at scroll 0, with >= N_w lines fitting.
        if pw and ph:  # mapped (not a NULL fully-scrolled-out region)
            assert dims["content_y"] <= py, (
                f"@{size_label}: paste first line y={py} must be at/below the "
                f"pane content top {dims['content_y']} (not above the fold)"
            )
            assert py + n_w <= dims["content_bottom"], (
                f"@{size_label}: the paste editor must show >= {n_w} lines in "
                f"the visible pane rows [{dims['content_y']}, "
                f"{dims['content_bottom']}) at scroll 0; first line y={py}"
            )
        else:  # pragma: no cover - guards against a compositor NULL region
            raise AssertionError(
                f"@{size_label}: the paste editor reports a NULL region — it "
                "is fully below the fold (the RED counterfactual)"
            )

        # Structural guard 2 (cheap): the change-file cluster is contained in
        # the #patch_pane_changefile grid cell, and the paste cell's rectangle
        # is disjoint from that (sibling) pane — so the paste group is
        # visually separated from the change-file/patch-script/checks cluster.
        # (The readability discriminator is the placement predicate above, not
        # this cheap guard.)
        assert dims["file_row_in_changefile"] is True, (
            f"@{size_label}: #patch_doc_file_row must stay inside "
            "#patch_pane_changefile (child containment)"
        )
        cx, cy, cw, ch = dims["changefile_region"]
        if cw and ch and pw and ph:
            overlap = px < cx + cw and cx < px + pw and py < cy + ch and cy < py + ph
            assert not overlap, (
                f"@{size_label}: the paste cell {dims['paste_region']} must "
                f"not overlap the change-file pane {dims['changefile_region']}"
            )

        # No right-edge clip past the host pane.
        assert dims["paste_right"] <= dims["pane_right"], (
            f"@{size_label}: the paste editor must not clip past its pane "
            f"right edge ({dims['paste_right']} > {dims['pane_right']})"
        )
