"""Patch Editor variant-dropdown RETIREMENT observer (batch-94, HLR-006).

This file once tested the patch-editor inline variant dropdown (batch-23,
US-028 / HLR-035: AT-035a…c, TC-035.1…7). Batch-94 (HLR-006, the pe_b
doctrine) RETIRED the whole panel-scoped variant machinery:
``patch_variant_select`` / ``patch_variant_info_button`` /
``patch_variant_row`` / ``patch_variant_select_row`` /
``patch_pane_variant`` / ``patch_variant_scope_line`` and the
``VariantSelected`` / ``VariantHelpRequested`` messages are GONE, and so are
the app handlers ``on_patch_editor_panel_variant_selected`` /
``on_patch_editor_panel_variant_help_requested``,
``_refresh_patch_variant_select`` and ``_variant_load_in_flight``.

What SURVIVES, and is observed here (never re-tested in the do-not-touch
siblings — cited, not duplicated):

- the execution-scope row (``#patch_execute_row`` with
  ``#patch_execute_scope_button`` / ``#patch_execute_run_button`` and the
  renamed scope line ``#patch_scope_line`` — "Scope <label>" only, no
  "Variant" segment), and the ``execute_scope`` action in
  ``PATCH_ACTIONS_V2``;
- the app-level variant switch pipeline (``_handle_select_variant``), whose
  end-to-end coverage lives in ``tests/test_tui_variants.py``
  (``test_select_variant_updates_label`` et al.) and whose manifest
  consume-half is pinned by
  ``tests/test_variant_execution.py::test_load_project_honors_manifest_active_variant``;
- the change-file dropdown ``#patch_doc_file_select`` (the panel's only
  ``Select`` now — its own census lives in the AT-030 tests).

Coverage map (test -> AT/TC lineage):

- AT-035a -> ``test_at035a_app_level_switch_updates_label_and_image`` — the
  gate's protective intent (a variant switch moves the project label AND the
  loaded image together) now drives the surviving app-level seam
  (``app._handle_select_variant``); the dropdown half of the surface is
  asserted absent.
- AT-035b -> ``test_at035b_panel_side_absence_after_app_switch`` — the
  persist-on-save chain is the app-level machinery's own property (cited to
  ``tests/test_variant_execution.py``, never duplicated); this file pins the
  panel-side half: after an app-level switch the panel still composes ZERO
  variant widgets and the scope line still names the scope only.
- AT-035c -> ``test_at035c_zero_variant_widgets_every_project_state`` — the
  degenerate-state placeholders are re-pointed at the retirement census
  (zero ``variant`` widgets with no project / N==1 / N>=2; loaded state
  intact; screen navigable).
- TC-035.1 -> ``test_tc_035_1_zero_variant_widgets_compose_presence`` —
  compose presence INVERTED: the panel (and the whole screen DOM) composes
  zero variant ids; the execute group composes exactly (1, 1, 1).
- TC-035.2 -> ``test_tc_035_2_execute_row_geometry_both_sizes`` — the
  execute-row composition order + the scope line's "Scope <label>" render,
  @80x24 and @120x30.
- TC-035.3 -> ``test_tc_035_3_stale_variant_selected_message_is_noop`` — the
  routing-guard census re-pointed at a stale ``VariantSelected``-shaped
  message (duck-typed local class posting the EXACT retired routing key):
  no crash, no activation, no state change.
- TC-035.4 -> ``test_tc_035_4_scope_cycle_and_run_routing`` — the scope
  button is selector-state-only (no action posted); the run button routes
  ``execute_scope`` through ``PATCH_ACTIONS_V2`` exactly once.
- TC-035.5 -> ``test_tc_035_5_scope_row_state_table`` — the disabled-state
  table re-pointed: the surviving scope row is composed and scope-only in
  every project state, and its value is not rebound by project switches.
- TC-035.6 -> ``test_tc_035_6_stale_message_writes_nothing_to_disk`` — the
  no-disk-write guard now rides the stale message + scope cycle.
- TC-035.7 -> ``test_tc_035_7_two_consecutive_loads_bind_one_document`` —
  the load-integrity guard re-pointed at the surviving load path: two
  consecutive Loads leave EXACTLY ONE bound document, and a stale
  ``VariantSelected`` fired between them is still a no-op.

Harness: pytest-asyncio is NOT installed — every drive is a nested
``async def _drive()`` under ``asyncio.run``. Fixtures/helpers are the
ratified ones of ``tests/test_tui_variants.py`` (S19_A / S19_B,
``_make_project``, ``_flush``, ``_project_label``), copied per the
sibling-file convention — no new builders. Gate asserts are black-box
(rendered text / widget public state / disk); private-attr reads appear
only as secondary diagnostics.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.message import Message
from textual.widgets import Button, Select, Static

from s19_app.tui.app import PATCH_ACTIONS_V2, S19TuiApp
from s19_app.tui.screens_directionb import PatchEditorPanel

# Minimal valid S19 images (checksums verified against s19_app.core.S19File).
# Distinguishable at BOTH the address and byte level (tests/test_tui_variants.py).
S19_A = "S107100001020304DE\nS9030000FC\n"  # 01 02 03 04 @ 0x1000
S19_B = "S10720000A0B0C0DAA\nS9030000FC\n"  # 0A 0B 0C 0D @ 0x2000


def _make_project(app: S19TuiApp, name: str, files: dict[str, str]) -> Path:
    """Create ``.s19tool/workarea/<name>/`` with the given text files."""
    project_dir = app.workarea / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so the deferred ``call_later`` apply chain runs."""
    for _ in range(count):
        await pilot.pause()


# batch-79 Inc-8 (LLR-121.4): re-pointed off `#cmdbar_project`, which
# `HLR-118` deletes at Inc-10. IMPORTED rather than redefined — this module and
# `test_tui_variants` carried BYTE-IDENTICAL copies of this helper, so the
# observable had two homes and a re-point could have landed in one of them. One
# definition cannot drift from itself.
from tests.test_tui_variants import _project_label  # noqa: E402


def _statuses(app: S19TuiApp) -> list[str]:
    """Capture every ``set_status`` message into the returned list."""
    captured: list[str] = []
    original = app.set_status
    app.set_status = lambda message: (captured.append(message), original(message))[1]  # type: ignore[method-assign]
    return captured


def _hex_text(app: S19TuiApp) -> str:
    """Rendered workspace hex-view text (tests/test_tui_directionb.py idiom)."""
    return str(app.query_one("#hex_view", Static).content)


class VariantSelected(Message, namespace="patch_editor_panel"):
    """A stale, duck-typed ``VariantSelected`` — the retired message's shape.

    Batch-94 (HLR-006) deleted ``PatchEditorPanel.VariantSelected``; a
    third-party plugin (or an un-rebuilt call site) may still POST a message
    with this exact shape. The ``namespace=...`` keyword reproduces the
    retired routing key byte-for-byte (``handler_name`` resolves to
    ``on_patch_editor_panel_variant_selected``, measured against the shipped
    textual==8.2.8), and ``variant_id`` is the retired payload attribute. The
    retirement contract: posting it to the panel is a TOTAL no-op — no
    handler may exist for this key anymore.
    """

    def __init__(self, variant_id: str) -> None:
        super().__init__()
        self.variant_id = variant_id


def _variant_ids_in(dom_root) -> list[str]:
    """Every widget id under ``dom_root`` containing the substring 'variant'."""
    return sorted(
        w.id
        for w in dom_root.walk_children()
        if getattr(w, "id", None) and "variant" in w.id
    )


async def _switch_via_dropdown(app: S19TuiApp, pilot, variant_id: str) -> None:
    """Drive the surviving app-level seam (the dropdown is retired).

    ``_handle_select_variant`` is the modal ``SelectVariantScreen``'s dismiss
    callback (LLR-005.4); driving it directly is the shipped pipeline minus
    the modal shell (the modal half is covered end-to-end by
    ``tests/test_tui_variants.py::test_select_variant_updates_label``). The
    switch rides the threaded load pipeline, so the proven
    ``wait_for_complete + _flush`` pair follows.
    """
    app._handle_select_variant(variant_id)
    await app.workers.wait_for_complete()
    await _flush(pilot)


# ---------------------------------------------------------------------------
# AT-035a (GATE) — the switch gate re-pointed at the surviving app-level seam
# ---------------------------------------------------------------------------


def test_at035a_dropdown_switch_updates_label_and_image(tmp_path: Path) -> None:
    """AT-035a — switching variant moves the project label AND the image.

    Intent (HLR-035 / AC-1, carried to batch-94): a variant switch is a real
    switch, not a relabel. The dropdown that used to carry this gate retired
    with HLR-006 — the surviving shipped surface is the app's variant-modal
    pipeline, whose handler ``_handle_select_variant`` this drives directly
    (the modal shell around it is covered by
    ``tests/test_tui_variants.py::test_select_variant_updates_label`` — cited,
    not duplicated). After activating ``b`` (C-10: OFF the default ``a``) the
    rendered project label reads ``proj:b (2/2)`` and the workspace hex view
    holds b's bytes (``0A 0B 0C 0D`` @0x2000), no longer a's; and the patch
    panel — observed in the same drive — composes ZERO variant widgets: the
    switch no longer has any dropdown half. Counterfactual: with the app-level
    routing reverted the label stays ``proj:a (1/2)`` and the hex view keeps
    the 0x1000 row -> RED; a re-added panel dropdown is caught by the
    zero-widget census here and by AT-035c/TC-035.1.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            label_before = _project_label(app)
            panel_variant_ids = _variant_ids_in(panel)
            await _switch_via_dropdown(app, pilot, "b")
            label_after = _project_label(app)
            # The hex view lives on the workspace screen (Phase-2 R-1):
            # legitimate user navigation, then read the rendered text.
            app.action_show_screen("workspace")
            await _flush(pilot)
            return label_before, label_after, _hex_text(app), panel_variant_ids

    label_before, label_after, hex_text, panel_variant_ids = asyncio.run(_drive())
    assert "proj:a (1/2)" in label_before, (
        f"precondition: default variant a active, got {label_before!r}"
    )
    assert "proj:b (2/2)" in label_after, (
        f"the app-level switch must relabel to proj:b (2/2), got {label_after!r}"
    )
    assert "0A 0B 0C 0D" in hex_text, (
        "the loaded image must be variant b's bytes (0A 0B 0C 0D @0x2000)"
    )
    assert "01 02 03 04" not in hex_text, (
        "variant a's bytes must be gone — a relabel without a reload is a fail"
    )
    assert panel_variant_ids == [], (
        f"the patch panel must compose ZERO variant widgets after the switch "
        f"(HLR-006), got {panel_variant_ids}"
    )


# ---------------------------------------------------------------------------
# AT-035b (GATE) — panel-side absence after an app-level switch (AC-2)
# ---------------------------------------------------------------------------


def test_at035b_switch_persists_on_save_and_load_consumes(tmp_path: Path) -> None:
    """AT-035b — after an app-level switch the panel stays variant-free.

    Intent (HLR-035 / AC-2, batch-94 form): the original gate rode the
    dropdown switch into the SHIPPED save flow and re-read the handler-written
    ``project.json``. That persist-on-save chain is APP-level machinery — it
    is pinned where it lives, by
    ``tests/test_variant_execution.py::test_load_project_honors_manifest_active_variant``
    (never this file, per the batch-23 sentinel). What the panel owes the gate
    is the other half: after a real switch to ``b`` the panel must not gain
    back any variant surface — zero ``variant`` ids, the scope line still
    names the SCOPE only (``Scope <label>``, no ``Variant`` segment), and the
    loaded single-variant project state stays intact (plain label + a's hex).
    Counterfactual: a re-introduced panel variant widget (dropdown, info
    button, variant-tagged line) -> the census or the line assert goes RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A, "b.s19": S19_B})
        _make_project(app, "single", {"a.s19": S19_A})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            await _switch_via_dropdown(app, pilot, "b")
            line_after = app.query_one("#patch_scope_line", Static).visual.plain
            ids_after = _variant_ids_in(panel)
            label_after = _project_label(app)
            # The single-variant state's plain label + intact image ride along
            # (the N==1 observation the placeholder tests used to pin).
            app._handle_load_project("single")
            await _flush(pilot)
            single_label = _project_label(app)
            app.action_show_screen("workspace")
            await _flush(pilot)
            single_hex = _hex_text(app)
            return line_after, ids_after, label_after, single_label, single_hex

    line_after, ids_after, label_after, single_label, single_hex = asyncio.run(
        _drive()
    )
    assert "Scope" in line_after and "Variant" not in line_after, (
        f"after a switch the scope line must still name the scope only; got "
        f"{line_after!r}"
    )
    assert ids_after == [], (
        f"the panel must stay variant-free after the switch; got {ids_after}"
    )
    assert "proj:b (2/2)" in label_after, (
        f"the app-level switch must have taken effect, got {label_after!r}"
    )
    assert single_label == "single", (
        f"N==1 plain-form label must survive a project switch, got "
        f"{single_label!r}"
    )
    assert "01 02 03 04" in single_hex, "variant a's image must still render"


# ---------------------------------------------------------------------------
# AT-035c (GATE) — degenerate states: zero variant widgets, state intact
# ---------------------------------------------------------------------------


def test_at035c_no_project_disabled_placeholder(tmp_path: Path) -> None:
    """AT-035c — no-project / N==1 / N>=2: zero variant widgets, no false
    affordance, loaded state intact, screen navigable.

    Intent (AC-3 / DoR Q1, batch-94 form): the disabled-placeholder dropdown
    is gone, so the degenerate-state guard is the retirement census itself —
    in EVERY project state the panel composes zero ``variant`` widgets (a
    re-added dropdown would be a false affordance exactly Q1 forbids), the
    screen renders and stays navigable (a show-screen round-trip succeeds),
    and a loaded single-variant project's state is intact (plain label + a's
    rendered hex). Counterfactual: pre-retirement the dropdown id resolves ->
    the census goes RED; an always-enabled re-add likewise.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "single", {"a.s19": S19_A})
        _make_project(app, "multi", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            no_project_ids = _variant_ids_in(panel)
            # Round-trip navigability (no crash, screen machinery intact).
            app.action_show_screen("workspace")
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()

            app._handle_load_project("single")
            await _flush(pilot)
            single_ids = _variant_ids_in(panel)
            single_label = _project_label(app)

            app._handle_load_project("multi")
            await _flush(pilot)
            multi_ids = _variant_ids_in(panel)
            multi_label = _project_label(app)

            app.action_show_screen("workspace")
            await _flush(pilot, 4)
            return (
                no_project_ids,
                single_ids,
                multi_ids,
                single_label,
                multi_label,
                _hex_text(app),
            )

    no_project_ids, single_ids, multi_ids, single_label, multi_label, hex_text = (
        asyncio.run(_drive())
    )
    assert no_project_ids == [], (
        f"no-project state must compose zero variant widgets; got "
        f"{no_project_ids}"
    )
    assert single_ids == [], f"N==1 state must compose zero variant widgets; got {single_ids}"
    assert multi_ids == [], f"N>=2 state must compose zero variant widgets; got {multi_ids}"
    # batch-79 Inc-8: the N==1 plain-form pin (was `== "Project: proj"`; the
    # command-bar prefix died with the bar — the plain form is the pin).
    assert single_label == "single", (
        f"loaded state must stay intact (plain N==1 label), got {single_label!r}"
    )
    assert "multi:a (1/2)" in multi_label, (
        f"the 2-variant project must activate its first variant, got "
        f"{multi_label!r}"
    )
    assert "01 02 03 04" in hex_text, "variant a's image must still render"


# ---------------------------------------------------------------------------
# TC-035.1 / LLR-035.1 — compose presence, inverted: zero variant widgets
# ---------------------------------------------------------------------------


def test_at035c_single_variant_disabled_placeholder(tmp_path: Path) -> None:
    """AT-035c (batch-94 retirement form, second arm) — the single-variant
    the panel free of any variant affordance.

    The batch-23 original drove the disabled placeholder dropdown for the
    N<2 states; the selector retired with HLR-006, so the degenerate-state
    guard now asserts the panel renders no variant widget with exactly one
    project variant (the app-level machinery survives — it is guarded by
    this file's ``test_at035b_switch_persists_on_save_and_load_consumes``
    and ``tests/test_variant_execution.py``).
    """

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            return _variant_ids_in(panel)

    assert asyncio.run(_drive()) == [], (
        "a single-variant project must render zero variant widgets in the "
        "reworked panel"
    )


def test_tc_035_1_compose_presence(tmp_path: Path) -> None:
    """TC-035.1 (batch-94 form) — zero variant widgets; the execute group
    composes; ``execute_scope`` stays routable.

    Intent: the old TC pinned the dropdown's bare-construction invariants
    (one Select, allow_blank, prompt, disabled). The retirement inverts the
    census: on bare first paint the panel — and the whole screen DOM — holds
    ZERO widgets whose id contains ``variant`` (no selector, no help button,
    no variant rows), while the SURVIVING execution-scope group composes
    exactly once (row / scope button / run button) and its ``execute_scope``
    action remains a member of ``PATCH_ACTIONS_V2``. Counterfactual: any
    re-added ``*variant*`` widget -> RED; a retired ``execute_scope`` action
    -> the membership assert goes RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Bare first paint — the patch screen has NOT been activated.
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            bare_panel_ids = _variant_ids_in(panel)
            bare_screen_ids = _variant_ids_in(app.screen)
            bare = (
                len(panel.query("#patch_execute_row")),
                len(panel.query("#patch_execute_scope_button")),
                len(panel.query("#patch_execute_run_button")),
            )
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            loaded_panel_ids = _variant_ids_in(panel)
            return bare_panel_ids, bare_screen_ids, bare, loaded_panel_ids

    bare_panel_ids, bare_screen_ids, bare, loaded_panel_ids = asyncio.run(_drive())
    assert bare_panel_ids == [], (
        f"bare construction must compose zero variant widgets in the panel; "
        f"got {bare_panel_ids}"
    )
    assert bare_screen_ids == [], (
        f"zero variant-widget ids may exist ANYWHERE in the screen DOM; got "
        f"{bare_screen_ids}"
    )
    assert bare == (1, 1, 1), (
        "the surviving execute group must compose exactly once (row / scope "
        f"button / run button), got {bare}"
    )
    assert "execute_scope" in PATCH_ACTIONS_V2, (
        "the execute_scope action must remain in the routable PATCH_ACTIONS_V2 "
        "set after the variant retirement"
    )
    assert loaded_panel_ids == [], (
        f"a project load must not re-introduce variant widgets; got "
        f"{loaded_panel_ids}"
    )


# ---------------------------------------------------------------------------
# TC-035.2 / LLR-035.2 — the execute-row composition + scope-line geometry
# ---------------------------------------------------------------------------


def _drive_variant_geometry(
    tmp_path: Path, size: tuple[int, int]
) -> dict[str, object]:
    """Capture execute-row geometry at ``size`` (the ``_drive_panes`` idiom)."""

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            # batch-97 Inc-4 (named supersession, HLR-144): the execute row
            # lives on the inspector's JSON tab.
            app.query_one("#patch_tab_json").press()
            await pilot.pause()
            row = app.query_one("#patch_execute_row")
            scope_line = app.query_one("#patch_scope_line", Static)
            child_ids = [child.id for child in row.children if child.id]
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            return {
                "child_ids": child_ids,
                "line_plain": scope_line.visual.plain,
                "line_markup": scope_line._render_markup,
                "row_region": (
                    row.region.x,
                    row.region.y,
                    row.region.width,
                    row.region.height,
                ),
                # Structural parentage, not viewport position: the row rides
                # the panel's (single, scrolled) content — at 80x24 its y
                # legitimately lies below the panel's visible fold (FOLD-8).
                "row_in_panel": row in panel.walk_children(),
            }

    return asyncio.run(_run())


def test_tc_035_2_variant_group_above_execute_row(tmp_path: Path) -> None:
    """TC-035.2 — the execute row composes in order; the line reads 'Scope
    <label>' at both regimes.

    Intent (batch-94 form): the variant group's geometry guard (group above
    the execute row, Select's first row on screen at scroll 0) retires with
    the group. What survives and is measured here: at BOTH supported sizes
    ``#patch_execute_row`` composes its buttons group above the scope line
    (``['patch_execute_buttons', 'patch_scope_line']`` — the scope button and
    the run button live inside the group), the line renders ``Scope <label>``
    from the panel's own closed vocabulary (markup disabled — C-17), and the
    row is laid out inside the panel. Counterfactual: re-add a variant row
    above the execute row -> the child-order assert goes RED; a markup-enabled
    or variant-tagged line -> the render asserts go RED.
    """
    for size_label, size in (("80x24", (80, 24)), ("120x30", (120, 30))):
        dims = _drive_variant_geometry(tmp_path / size_label, size)
        assert dims["child_ids"] == [
            "patch_execute_buttons",
            "patch_scope_line",
        ], (
            f"@{size_label}: the execute row must compose the buttons group "
            f"then the scope line, got {dims['child_ids']}"
        )
        assert "Scope" in dims["line_plain"], (
            f"@{size_label}: the line must name the scope; got "
            f"{dims['line_plain']!r}"
        )
        assert "Variant" not in dims["line_plain"], (
            f"@{size_label}: the line must carry NO Variant segment "
            f"(HLR-006); got {dims['line_plain']!r}"
        )
        assert "active variant" in dims["line_plain"], (
            f"@{size_label}: the default scope label must render; got "
            f"{dims['line_plain']!r}"
        )
        assert dims["line_markup"] is False, (
            f"@{size_label}: the scope line must keep markup disabled (C-17)"
        )
        _x, _row_y, _w, row_h = dims["row_region"]
        assert row_h > 0, (
            f"@{size_label}: the execute row must be laid out (non-zero "
            f"height); region={dims['row_region']}"
        )
        assert dims["row_in_panel"] is True, (
            f"@{size_label}: the execute row must live inside the panel's tree"
        )


# ---------------------------------------------------------------------------
# TC-035.3 / LLR-035.3 — the stale-message no-op (routing guards re-pointed)
# ---------------------------------------------------------------------------


def test_tc_035_3_options_order_preselection_and_triggers(tmp_path: Path) -> None:
    """TC-035.3 — a stale ``VariantSelected``-shaped message is a total no-op.

    Intent (batch-94 form): the old TC's populate/preselect/trigger census
    rode the dropdown. Its ROUTING-GUARD half survives as the retirement
    contract: a message carrying the retired shape — the exact routing key
    (``on_patch_editor_panel_variant_selected``, via ``namespace=``) plus a
    ``variant_id`` payload — posted to the panel must do NOTHING: no crash,
    no app-level activation (``_handle_select_variant`` call count stays 0),
    no label movement, no scope-value change, and the surviving change-file
    dropdown's options are untouched. This is the plugin-compat guard: an
    un-rebuilt call site posting the old message must not wedge the editor.
    Counterfactual: any surviving handler for the retired key -> the count or
    label assert goes RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A, "b.s19": S19_B})
        calls: list[str] = []
        original = app._handle_select_variant
        app._handle_select_variant = (  # type: ignore[method-assign]
            lambda vid: (calls.append(vid), original(vid))[1]
        )
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            label_before = _project_label(app)
            select = app.query_one("#patch_doc_file_select", Select)
            options_before = len(select._options)
            scope_before = panel._execute_scope

            panel.post_message(VariantSelected("b"))
            await _flush(pilot, 4)
            await app.workers.wait_for_complete()
            await _flush(pilot, 4)

            label_after = _project_label(app)
            options_after = len(select._options)
            select_after = select.value
            return (
                calls,
                label_before,
                label_after,
                scope_before,
                panel._execute_scope,
                options_before,
                options_after,
                select_after,
            )

    (
        calls,
        label_before,
        label_after,
        scope_before,
        scope_after,
        options_before,
        options_after,
        select_after,
    ) = asyncio.run(_drive())
    assert calls == [], (
        f"a stale VariantSelected must never reach the app-level activation "
        f"pipeline, got calls={calls}"
    )
    assert label_before == label_after and "proj:a (1/2)" in label_after, (
        f"the stale message must not switch the active variant: "
        f"{label_before!r} -> {label_after!r}"
    )
    assert scope_after == scope_before, (
        f"the stale message must not move the execution scope: "
        f"{scope_before!r} -> {scope_after!r}"
    )
    assert options_after == options_before, (
        "the surviving change-file dropdown's options must be untouched by "
        "the stale message"
    )
    assert select_after is Select.NULL, (
        "the change-file dropdown must stay on the blank sentinel (no "
        "false preselection from the stale message)"
    )


# ---------------------------------------------------------------------------
# TC-035.4 / LLR-035.4 — scope cycle posts nothing; the run routes once
# ---------------------------------------------------------------------------


def test_tc_035_4_routing_guards(tmp_path: Path) -> None:
    """TC-035.4 — the scope button is selector-state-only; the run button
    routes ``execute_scope`` exactly once.

    Intent (batch-94 form): the old TC counted activations through the
    dropdown route. The surviving routing facts: pressing
    ``#patch_execute_scope_button`` posts NO action (it cycles
    ``_execute_scope`` and re-renders the two views — button label and scope
    line — itself), while pressing ``#patch_execute_run_button`` routes one
    ``execute_scope`` action through ``PATCH_ACTIONS_V2`` into
    ``_trigger_execute_scope`` carrying the cycled scope. With no project
    loaded the app guard answers one status line — the routed call is counted
    by the white-box probe; the status is the behavioral cross-check.
    Counterfactual: a scope-button that also posts an action -> count > 1 ->
    RED; a run button that drops the action -> RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        triggers: list[str] = []
        original = app._trigger_execute_scope
        app._trigger_execute_scope = (  # type: ignore[method-assign]
            lambda scope: (triggers.append(scope), original(scope))[1]
        )
        statuses = _statuses(app)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            scope_button = app.query_one("#patch_execute_scope_button", Button)
            scope_line = app.query_one("#patch_scope_line", Static)

            assert "active variant" in scope_line.visual.plain
            scope_button.press()
            await pilot.pause()

            after_cycle = (
                panel._execute_scope,
                str(scope_button.label),
                scope_line.visual.plain,
                list(triggers),
            )

            app.query_one("#patch_execute_run_button", Button).press()
            await pilot.pause()
            after_run = (list(triggers), list(statuses))
            return after_cycle, after_run

    after_cycle, after_run = asyncio.run(_drive())
    scope_value, button_label, line_plain, triggers_after_cycle = after_cycle
    triggers_after_run, statuses = after_run

    assert scope_value == "all", (
        f"one press must cycle active -> all, got {scope_value!r}"
    )
    assert "all variants" in button_label, (
        f"the button label must follow the cycle; got {button_label!r}"
    )
    assert "Scope" in line_plain and "all variants" in line_plain, (
        f"the scope line must render the SAME cycled state; got {line_plain!r}"
    )
    assert "Variant" not in line_plain, (
        f"the line must never gain a Variant segment; got {line_plain!r}"
    )
    assert triggers_after_cycle == [], (
        "the scope button is selector-state-only — it must post no routed "
        f"action, got triggers={triggers_after_cycle}"
    )
    assert triggers_after_run == ["all"], (
        f"the run button must route execute_scope exactly once with the "
        f"cycled scope, got {triggers_after_run}"
    )
    assert any("no project variants" in m for m in statuses), (
        f"with no project the execute guard must answer one status line; "
        f"{statuses}"
    )


# ---------------------------------------------------------------------------
# TC-035.5 / LLR-035.5 — the scope row across project states (state table)
# ---------------------------------------------------------------------------


def test_tc_035_5_disabled_state_table(tmp_path: Path) -> None:
    """TC-035.5 — the surviving scope row is state-independent and scope-only.

    Intent (batch-94 form): the old disabled-state table (disabled == N < 2)
    retired with the dropdown. The surviving invariant: the execute row
    composes in EVERY project state (no project / N==1 / N>=2), the scope line
    always reads ``Scope <label>`` — never a ``Variant`` segment, regardless
    of how many variants the project has — and the scope value is the PANEL's
    own selector state: a project switch does not rebind it. The row's
    window's border chrome stays the JSON window (the row now rides the JSON
    window dock). Counterfactual: a variant-count-dependent scope line ->
    RED; a project switch that resets the cycled scope -> RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "single", {"a.s19": S19_A})
        _make_project(app, "multi", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            row = app.query_one("#patch_execute_row")
            no_project = (
                len(panel.query("#patch_execute_row")),
                row.parent.id,
                app.query_one("#patch_scope_line", Static).visual.plain,
            )

            # Cycle the scope BEFORE any project load.
            app.query_one("#patch_execute_scope_button", Button).press()
            await pilot.pause()
            cycled = panel._execute_scope

            app._handle_load_project("multi")
            await _flush(pilot)
            multi = app.query_one("#patch_scope_line", Static).visual.plain
            multi_scope = panel._execute_scope
            row_window_after_multi = row.parent.id

            app._handle_load_project("single")
            await _flush(pilot)
            single = app.query_one("#patch_scope_line", Static).visual.plain
            single_scope = panel._execute_scope
            return (
                no_project,
                cycled,
                multi,
                multi_scope,
                row_window_after_multi,
                single,
                single_scope,
            )

    (
        no_project,
        cycled,
        multi,
        multi_scope,
        row_window_after_multi,
        single,
        single_scope,
    ) = asyncio.run(_drive())
    assert no_project[0] == 1, (
        f"the execute row must compose with no project loaded; got {no_project}"
    )
    assert no_project[1] == "patch_win_json" and row_window_after_multi == (
        "patch_win_json"
    ), (
        "the execute row must ride the JSON window's dock in every state; "
        f"got {no_project[1]!r} / {row_window_after_multi!r}"
    )
    assert "Scope" in no_project[2] and "Variant" not in no_project[2], (
        f"the no-project line must be scope-only; got {no_project[2]!r}"
    )
    assert "Scope" in multi and "Variant" not in multi, (
        f"an N>=2 project's line must STILL name no variant (HLR-006); got "
        f"{multi!r}"
    )
    assert "Scope" in single and "Variant" not in single, (
        f"an N==1 project's line must name no variant either; got {single!r}"
    )
    assert multi_scope == cycled == single_scope == "all", (
        "the scope selector state must survive project switches (it is "
        f"panel-local state): cycled={cycled!r} multi={multi_scope!r} "
        f"single={single_scope!r}"
    )


# ---------------------------------------------------------------------------
# TC-035.6 / LLR-035.6 — no disk write from the stale path (Q2)
# ---------------------------------------------------------------------------


def test_tc_035_6_switch_writes_nothing_to_disk(tmp_path: Path) -> None:
    """TC-035.6 — the stale message and the scope cycle touch no project file.

    Intent (LLR-035.6 / DoR Q2, batch-94 form): the switch's no-disk-write
    guard retires from the dropdown to the surviving surfaces — a stale
    ``VariantSelected`` and a scope cycle are pure in-memory state; for a
    never-saved project the manifest stays ABSENT and the project directory's
    file set and bytes are unchanged (0 bytes changed, 0 files created). The
    positive persist chain stays where it lives (cited to
    ``tests/test_variant_execution.py``). Counterfactual: an Option-C write-on-
    switch path re-wired to the stale message -> RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(app, "proj", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            snapshot_before = {
                p.name: p.read_bytes() for p in sorted(project_dir.iterdir())
            }
            manifest_before = (project_dir / "project.json").exists()

            panel.post_message(VariantSelected("b"))
            for _ in range(2):  # cycle the scope twice (full loop)
                app.query_one("#patch_execute_scope_button", Button).press()
                await pilot.pause()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)

            snapshot_after = {
                p.name: p.read_bytes() for p in sorted(project_dir.iterdir())
            }
            manifest_after = (project_dir / "project.json").exists()
            return (
                manifest_before,
                manifest_after,
                snapshot_before,
                snapshot_after,
            )

    manifest_before, manifest_after, before, after = asyncio.run(_drive())
    assert manifest_before is False, "precondition: never-saved project"
    assert manifest_after is False, (
        "the stale message / scope cycle must NOT create project.json"
    )
    assert before == after, (
        "the stale path must change no project file (0 bytes, 0 files)"
    )


# ---------------------------------------------------------------------------
# TC-035.7 / LLR-035.7 — load integrity: two Loads bind exactly one document
# ---------------------------------------------------------------------------


def _write_v2_document(path: Path, entries: list[dict]) -> Path:
    """Write a v2 ``s19app-changeset`` JSON document fixture."""
    import json

    path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_tc_035_7_rapid_double_pick_stays_consistent(tmp_path: Path) -> None:
    """TC-035.7 — load A then load B: exactly ONE document stays bound, and a
    stale ``VariantSelected`` fired between the loads is still a no-op.

    Intent (LLR-035.7, security F2 — re-pointed): the old guard raced a
    dropdown pick against an in-flight load. The surviving load-integrity
    contract: the panel's load path (typed path + the REAL Load control) is
    re-entrant — loading document B over document A leaves EXACTLY ONE bound
    document (``ChangeService.document.source_path`` is B, the service rows
    and the entries table hold B's entries only, no A residue), the dirty
    flag stays cleared by each successful load (writer w4), and a stale
    ``VariantSelected`` posted between the two loads changes nothing (no
    crash, no extra activation). Counterfactual: a load that stacks a second
    document (or leaves A's rows rendered) -> RED.
    """

    async def _drive() -> tuple:
        import json

        doc_a = _write_v2_document(
            tmp_path / "doc_a.json",
            [{"type": "string", "address": "0x100", "value": "alpha"}],
        )
        doc_b = _write_v2_document(
            tmp_path / "doc_b.json",
            [
                {"type": "string", "address": "0x200", "value": "bravo"},
                {"type": "bytes", "address": "0x300", "bytes": "DE AD"},
            ],
        )
        calls: list[str] = []
        app = S19TuiApp(base_dir=tmp_path)
        original = app._handle_select_variant
        app._handle_select_variant = (  # type: ignore[method-assign]
            lambda vid: (calls.append(vid), original(vid))[1]
        )
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            service = app._change_service

            async def _load(path: Path) -> None:
                app.query_one("#patch_doc_path_input").value = str(path)
                app.query_one("#patch_doc_load_button", Button).press()
                await _flush(pilot, 4)

            await _load(doc_a)
            after_a = (
                service.document.source_path,
                len(service.document.entries),
                panel._dirty,  # the Load guard's own flag (diagnostic read)
            )

            # Stale message BETWEEN the two loads — the F2 race shape.
            panel.post_message(VariantSelected("b"))
            await _flush(pilot, 2)

            await _load(doc_b)
            after_b = (
                service.document.source_path,
                [entry.address for entry in service.document.entries],
                len(service.rows(None)),
                panel._dirty,
            )

            table = app.query_one("#patch_doc_entries_table")
            return after_a, after_b, table.row_count, calls, app

    after_a, after_b, table_rows, calls, _app = asyncio.run(_drive())
    assert after_a[0] is not None and after_a[0].name == "doc_a.json", (
        f"load A must bind document A, got {after_a[0]!r}"
    )
    assert after_a[1] == 1 and after_a[2] is False, (
        f"load A must bind exactly A's one entry and clear the dirty flag "
        f"(writer w4), got {after_a}"
    )
    source_b, addresses_b, rows_b, dirty_b = after_b
    assert source_b is not None and source_b.name == "doc_b.json", (
        f"load B must REPLACE the bound document with B, got {source_b!r}"
    )
    assert len(addresses_b) == 2 and all(
        addr in (0x200, 0x300) for addr in addresses_b
    ), f"no residue of A may stay bound; got entries at {addresses_b}"
    assert rows_b == 2, (
        f"the service rows must render B's two entries only, got {rows_b}"
    )
    assert dirty_b is False, "the second successful load must keep the panel clean"
    assert table_rows == 2, (
        f"the entries table must show exactly B's two rows, got {table_rows}"
    )
    assert calls == [], (
        f"the stale message fired between the loads must stay a no-op; "
        f"activations={calls}"
    )
