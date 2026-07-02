"""Patch Editor inline variant dropdown tests (batch-23, US-028 / HLR-035).

Coverage map (test -> AT/TC -> LLR):

- AT-035a (GATE, C-10) — ``test_at035a_dropdown_switch_updates_label_and_image``:
  picking the NON-default variant in ``Select#patch_variant_select`` switches
  the active variant through the shipped surface — rendered project label
  reads ``proj:b (2/2)`` and the workspace hex view shows variant b's bytes.
- AT-035b (GATE, C-12) — ``test_at035b_switch_persists_on_save_and_load_consumes``:
  dropdown switch -> SHIPPED save flow -> raw ``json.loads`` of the
  HANDLER-WRITTEN ``project.json`` carries ``active_variant == "b"`` -> a
  fresh app's unmodified project load activates b (label observation).
- AT-035c (GATE) — ``test_at035c_no_project_disabled_placeholder`` +
  ``test_at035c_single_variant_disabled_placeholder``: degenerate states
  render a present-but-disabled placeholder dropdown (DoR Q1), no crash,
  loaded state intact.
- TC-035.1 / LLR-035.1 — compose presence (bare + no-project + with-project).
- TC-035.2 / LLR-035.2 — geometry: variant group ABOVE ``#patch_execute_row``,
  Select's FIRST row visible at scroll 0, @80x24 and @120x30 (C-13 measured).
- TC-035.3 / LLR-035.3 — options in model order + active preselection +
  duplicate-stem full-filename ids + BOTH refresh triggers (F-3) + N<2 blank.
- TC-035.4 / LLR-035.4 — routing guards: 1 activation per non-active pick;
  blank / same-as-active / unknown / missing-file fire no activation.
- TC-035.5 / LLR-035.5 — disabled-state table (no project / N==1 / N>=2 /
  project switch re-evaluates).
- TC-035.6 / LLR-035.6 — no disk write on switch (DoR Q2 persist-on-save).
- TC-035.7 / LLR-035.7 — switch-during-load race (security F2): rapid A->B->C
  double pick leaves label == rendered content, 0 files created.

Sentinel note: in the installed textual 8.2.5 the blank ``Select`` value is
``Select.NULL`` (a ``NoSelection`` instance); the spec's ``Select.BLANK``
name resolves to an unrelated inherited bool in this version, so all blank
asserts here bind to ``Select.NULL``.

Harness: pytest-asyncio is NOT installed — every drive is a nested
``async def _drive()`` under ``asyncio.run`` (the ``_drive_panes`` idiom of
``tests/test_tui_patch_layout.py``). Fixtures/helpers are the ratified ones of
``tests/test_tui_variants.py`` / ``tests/test_tui_manifest_save.py`` (S19_A /
S19_B, ``_make_project``, ``_flush``, ``_project_label``, ``_statuses``,
``SaveProjectPayload`` -> ``_handle_save_dialog``), copied per the sibling-file
convention — no new builders. Gate asserts are black-box (rendered text /
widget public state / disk); private-attr reads appear only as secondary
diagnostics.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.widgets import Select, Static

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.command_bar import CommandBar
from s19_app.tui.screens_directionb import PatchEditorPanel

# Minimal valid S19 images (checksums verified against s19_app.core.S19File).
# Distinguishable at BOTH the address and byte level (tests/test_tui_variants.py).
S19_A = "S107100001020304DE\nS9030000FC\n"  # 01 02 03 04 @ 0x1000
S19_B = "S10720000A0B0C0DAA\nS9030000FC\n"  # 0A 0B 0C 0D @ 0x2000
# Minimal valid Intel HEX image (one data record + EOF).
HEX_A = ":0410000001020304E2\n:00000001FF\n"


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


def _project_label(app: S19TuiApp) -> str:
    """Rendered ``#cmdbar_project`` text — the label observable."""
    bar = app.query_one(CommandBar)
    return str(bar.query_one("#cmdbar_project").content)


def _statuses(app: S19TuiApp) -> list[str]:
    """Capture every ``set_status`` message into the returned list."""
    captured: list[str] = []
    original = app.set_status
    app.set_status = lambda message: (captured.append(message), original(message))[1]  # type: ignore[method-assign]
    return captured


def _variant_options(select: Select) -> list[str]:
    """The Select's real option values, excluding the blank sentinel."""
    return [
        value
        for _label, value in select._options
        if value is not Select.NULL
    ]


def _hex_text(app: S19TuiApp) -> str:
    """Rendered workspace hex-view text (tests/test_tui_directionb.py idiom)."""
    return str(app.query_one("#hex_view", Static).content)


async def _switch_via_dropdown(app: S19TuiApp, pilot, variant_id: str) -> None:
    """Drive the shipped surface: assign the Select value, ride the pipeline.

    A value assignment on an enabled ``Select`` posts ``Select.Changed``
    through the real handler chain (the AT-030a idiom). The switch rides the
    threaded load pipeline, so the proven ``wait_for_complete + _flush`` pair
    follows (01b R-2: a bare ``pilot.pause`` is a flake generator here).
    """
    select = app.query_one("#patch_variant_select", Select)
    select.value = variant_id
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)


# ---------------------------------------------------------------------------
# AT-035a (GATE) — switch through the shipped Select (AC-1, C-10)
# ---------------------------------------------------------------------------


def test_at035a_dropdown_switch_updates_label_and_image(tmp_path: Path) -> None:
    """AT-035a — picking the NON-default variant switches label AND image.

    Intent (HLR-035 / AC-1): the dropdown is a real switch surface, not a
    relabel — after picking ``b`` (C-10: OFF the default ``a``; textual emits
    no ``Changed`` on a same-value assignment, so the default is physically
    unexercisable) the rendered project label reads ``proj:b (2/2)`` and the
    workspace hex view holds b's bytes (``0A 0B 0C 0D`` @0x2000), no longer
    a's (``01 02 03 04`` @0x1000). Counterfactual (QC-2): with the
    ``VariantSelected`` routing reverted the label stays ``proj:a (1/2)`` and
    the hex view keeps the 0x1000 row -> RED; pre-implementation the widget id
    does not resolve -> RED.
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
            label_before = _project_label(app)
            await _switch_via_dropdown(app, pilot, "b")
            label_after = _project_label(app)
            # The hex view lives on the workspace screen (Phase-2 R-1):
            # legitimate user navigation, then read the rendered text.
            app.action_show_screen("workspace")
            await _flush(pilot)
            return label_before, label_after, _hex_text(app)

    label_before, label_after, hex_text = asyncio.run(_drive())
    assert "proj:a (1/2)" in label_before, (
        f"precondition: default variant a active, got {label_before!r}"
    )
    assert "proj:b (2/2)" in label_after, (
        f"dropdown switch must relabel to proj:b (2/2), got {label_after!r}"
    )
    assert "0A 0B 0C 0D" in hex_text, (
        "the loaded image must be variant b's bytes (0A 0B 0C 0D @0x2000)"
    )
    assert "01 02 03 04" not in hex_text, (
        "variant a's bytes must be gone — a relabel without a reload is a fail"
    )


# ---------------------------------------------------------------------------
# AT-035b (GATE) — persist-on-save, output-then-consume (AC-2, C-12)
# ---------------------------------------------------------------------------


def test_at035b_switch_persists_on_save_and_load_consumes(tmp_path: Path) -> None:
    """AT-035b — dropdown switch -> shipped save -> manifest -> unmodified load.

    Intent (HLR-035 / AC-2, C-12 output-then-consume): the state the SHIPPED
    save serializes is the dropdown-switched one. Drive the switch to ``b``,
    save through ``_handle_save_dialog`` (the modal's dismiss payload — the
    ratified drive idiom of ``tests/test_tui_manifest_save.py``) into a
    project pre-seeded with ``a.s19`` (binding note: 01b sketched saving back
    into the SAME loaded project, but the shipped save-flow's
    ``copy_into_workarea`` dedup would rename the re-copied active image to
    ``b_1.s19`` — a pre-existing save-flow behavior out of US-028's scope —
    so the drive saves into a sibling project that yields the same 2-variant
    {a, b} shape with no collision). Re-read the HANDLER-WRITTEN
    ``project.json`` with raw ``json.loads`` (not the writer's own oracle):
    ``active_variant == "b"``. Then a FRESH app instance loads the project
    through the unmodified load path and lands on b — ``a`` sorts first, so a
    load that ignores the manifest observably activates ``a`` -> RED.
    Counterfactual: with the dropdown route reverted the in-memory active id
    at save time is still ``a`` -> the manifest carries ``"a"`` -> RED.
    The direct-write consumer guard stays
    ``tests/test_variant_execution.py::test_load_project_honors_manifest_active_variant``
    — never this gate.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A, "b.s19": S19_B})
        # Pre-seed the save target with variant a so the handler-written
        # manifest lands in a 2-variant project (meaningful consume leg).
        _make_project(app, "proj2", {"a.s19": S19_A})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot)
            await _switch_via_dropdown(app, pilot, "b")
            payload = app_module.SaveProjectPayload(
                parent_folder=str(app.workarea), project_name="proj2"
            )
            app._handle_save_dialog(payload)
            await _flush(pilot)
        manifest_path = app.workarea / "proj2" / "project.json"
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))

        # Consume: a fresh app instance, unmodified load path.
        app2 = S19TuiApp(base_dir=tmp_path)
        async with app2.run_test(size=(120, 30)) as pilot2:
            await pilot2.pause()
            app2._handle_load_project("proj2")
            await _flush(pilot2)
            consumed_label = _project_label(app2)
        return raw, consumed_label

    raw, consumed_label = asyncio.run(_drive())
    assert raw.get("active_variant") == "b", (
        f"handler-written project.json must persist the switched variant, "
        f"got {raw.get('active_variant')!r}"
    )
    assert "proj2:b (2/2)" in consumed_label, (
        f"an unmodified project load must consume the manifest and activate "
        f"b (a sorts first), got {consumed_label!r}"
    )


# ---------------------------------------------------------------------------
# AT-035c (GATE) — negative / empty state (AC-3, DoR Q1)
# ---------------------------------------------------------------------------


def test_at035c_no_project_disabled_placeholder(tmp_path: Path) -> None:
    """AT-035c(i) — no project: present, disabled, placeholder; no crash.

    Intent (AC-3 / DoR Q1): the dropdown offers no false affordance — it
    exists, is disabled with the blank placeholder, the screen renders and
    stays navigable (a show-screen round-trip succeeds). Counterfactual:
    pre-implementation the widget is absent -> RED; an always-enabled
    implementation flips ``disabled`` -> RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            select = app.query_one("#patch_variant_select", Select)
            state = (select.disabled, select.value is Select.NULL)
            # Round-trip navigability (no crash, screen machinery intact).
            app.action_show_screen("workspace")
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            return state, len(app.query("#patch_variant_select"))

    (disabled, blank), count = asyncio.run(_drive())
    assert count == 1, "the dropdown must exist exactly once with no project"
    assert disabled, "no-project state must render the Select disabled (Q1)"
    assert blank, "no-project state must show the blank placeholder value"


def test_at035c_single_variant_disabled_placeholder(tmp_path: Path) -> None:
    """AT-035c(ii) — single-variant project: disabled placeholder, state intact.

    Intent (AC-3 / DoR Q1): N==1 offers nothing to switch to — the dropdown is
    disabled with the placeholder (F-2: NO single-id preselection), while the
    loaded state stays intact: the plain back-compat label (LLR-005.3, pinned
    by ``tests/test_tui_variants.py``) and variant a's rendered hex content.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            select = app.query_one("#patch_variant_select", Select)
            state = (select.disabled, select.value is Select.NULL)
            app.action_show_screen("workspace")
            await _flush(pilot, 4)
            return state, _project_label(app), _hex_text(app)

    (disabled, blank), label, hex_text = asyncio.run(_drive())
    assert disabled, "single-variant project must render the Select disabled"
    assert blank, "N==1 must keep the blank placeholder (F-2: no preselection)"
    assert label == "Project: proj", (
        f"loaded state must stay intact (plain N==1 label), got {label!r}"
    )
    assert "01 02 03 04" in hex_text, "variant a's image must still render"


# ---------------------------------------------------------------------------
# TC-035.1 / LLR-035.1 — compose presence
# ---------------------------------------------------------------------------


def test_tc_035_1_compose_presence(tmp_path: Path) -> None:
    """TC-035.1 — the Select exists in the Variant pane in every project state.

    Intent (LLR-035.1): exactly one ``Select#patch_variant_select`` inside
    ``#patch_pane_variant``, constructed ``allow_blank=True`` with a prompt
    and ``disabled=True`` first paint (never handed a populate call — the
    bare-construction invariant), with and without a project; no existing
    ``patch_*`` id in the pane renamed or removed. Counterfactual: widget
    absent pre-implementation -> the query raises -> RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Bare first paint — the patch screen has NOT been activated, so
            # no populate call has run yet (the set_change_files W2 idiom).
            pane = app.query_one("#patch_pane_variant")
            select = pane.query_one("#patch_variant_select", Select)
            bare = (
                len(pane.query("#patch_variant_select")),
                select.disabled,
                select._allow_blank,
                str(select.prompt),
            )
            execute_ids = (
                len(pane.query("#patch_execute_row")),
                len(pane.query("#patch_execute_scope_button")),
                len(pane.query("#patch_execute_run_button")),
            )
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            with_project = len(pane.query("#patch_variant_select"))
            return bare, execute_ids, with_project

    (count, disabled, allow_blank, prompt), execute_ids, with_project = (
        asyncio.run(_drive())
    )
    assert count == 1, "exactly one variant Select on bare construction"
    assert disabled, "first paint must be disabled (LLR-035.1 / F-8)"
    assert allow_blank, "the Select must be constructed allow_blank=True"
    assert prompt, "the Select must carry a placeholder prompt"
    assert execute_ids == (1, 1, 1), (
        "no existing patch_* id in the pane may be renamed or removed"
    )
    assert with_project == 1, "exactly one variant Select with a project loaded"


# ---------------------------------------------------------------------------
# TC-035.2 / LLR-035.2 — top-of-pane composition order + geometry (C-13)
# ---------------------------------------------------------------------------


def _drive_variant_geometry(
    tmp_path: Path, size: tuple[int, int]
) -> dict[str, object]:
    """Capture Variant-pane geometry at ``size`` (the ``_drive_panes`` idiom)."""

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            pane = app.query_one("#patch_pane_variant")
            select = app.query_one("#patch_variant_select", Select)
            vrow = app.query_one("#patch_variant_row")
            erow = app.query_one("#patch_execute_row")
            children = [child.id for child in pane.children]
            return {
                "scroll_y": pane.scroll_offset.y,
                "content_y": pane.content_region.y,
                "content_bottom": pane.content_region.bottom,
                "pane_right": pane.region.right,
                "select_y": select.region.y,
                "select_right": select.region.right,
                "vrow_y": vrow.region.y,
                "erow_region": (
                    erow.region.x,
                    erow.region.y,
                    erow.region.width,
                    erow.region.height,
                ),
                "children": children,
            }

    return asyncio.run(_run())


def test_tc_035_2_variant_group_above_execute_row(tmp_path: Path) -> None:
    """TC-035.2 — the Select renders above the fold, execute group below.

    Intent (LLR-035.2 / C-13 MEASURED): at both supported sizes the variant
    group composes ABOVE ``#patch_execute_row`` and the Select control's
    FIRST row lies within the pane's visible ``content_region`` at scroll 0
    (qa MINOR-3: a border-only overlap is not operable), with no right-edge
    clip. The compose order is asserted structurally (child order) because a
    fully-scrolled-out execute row @80x24 reports the compositor NULL region;
    the ``region.y`` ordering is asserted whenever the row is mapped (always
    @120x30, where the 6-row pane holds both groups). Counterfactual: compose
    the group below the execute row, or lose the ``height: auto`` row rules
    (1fr split clips the Select) -> RED.
    """
    for size_label, size in (("80x24", (80, 24)), ("120x30", (120, 30))):
        dims = _drive_variant_geometry(tmp_path / size_label, size)
        assert dims["children"] == ["patch_variant_row", "patch_execute_row"], (
            f"@{size_label}: compose order must be variant group first, "
            f"got {dims['children']}"
        )
        assert dims["scroll_y"] == 0, f"@{size_label}: pane must start unscrolled"
        assert dims["content_y"] <= dims["select_y"] < dims["content_bottom"], (
            f"@{size_label}: the Select's first row {dims['select_y']} must lie "
            f"within the visible pane rows "
            f"[{dims['content_y']}, {dims['content_bottom']})"
        )
        assert dims["select_right"] <= dims["pane_right"], (
            f"@{size_label}: the Select must not clip past the pane right edge"
        )
        erow_x, erow_y, erow_w, erow_h = dims["erow_region"]
        if erow_w and erow_h:  # mapped (not fully scrolled out of view)
            assert dims["vrow_y"] < erow_y, (
                f"@{size_label}: variant group (y={dims['vrow_y']}) must sit "
                f"above the execute row (y={erow_y})"
            )


# ---------------------------------------------------------------------------
# TC-035.3 / LLR-035.3 — options refresh + active preselection (F-2/F-3/F-4)
# ---------------------------------------------------------------------------


def test_tc_035_3_options_order_preselection_and_triggers(tmp_path: Path) -> None:
    """TC-035.3 — model-order options, active preselect, both F-3 triggers.

    Intent (LLR-035.3): (a) a 3-variant project lists exactly the ordered
    ``(name.lower(), name)`` ids with ``value == active_id`` on patch-screen
    activation (trigger 1); (b) duplicate stems list FULL FILENAMES (the E6
    rule); (c) a variant-set change WHILE the patch screen is shown (external
    load appends a variant) re-populates without re-activation (trigger 2),
    flipping N==1 blank/disabled to the 2-variant enabled state with the new
    active preselected. F-4 rides implicitly: every repopulate here emits the
    ``Changed(NULL)`` + ``Changed(active)`` echo pair and must trigger no
    reload (the label would flap and workers would spawn — TC-035.4 pins the
    count). Counterfactual: drop the populate call -> empty/stale options ->
    RED; preselect a single id at N==1 -> RED.
    """

    async def _drive() -> tuple:
        # (a) ordering trio (tests/test_workspace_variants.py fixture names).
        app = S19TuiApp(base_dir=tmp_path / "t1")
        _make_project(
            app,
            "proj3",
            {"zeta.s19": S19_A, "Alpha.s19": S19_A, "mid.s19": S19_A},
        )
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj3")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            select = app.query_one("#patch_variant_select", Select)
            trio = (_variant_options(select), select.value, select.disabled)

        # (b) duplicate stems -> ids are FULL FILENAMES.
        app_dup = S19TuiApp(base_dir=tmp_path / "t2")
        _make_project(app_dup, "projdup", {"fw.s19": S19_A, "fw.hex": HEX_A})
        async with app_dup.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app_dup._handle_load_project("projdup")
            await _flush(pilot)
            app_dup.action_show_screen("patch")
            await _flush(pilot, 4)
            select = app_dup.query_one("#patch_variant_select", Select)
            dup = (_variant_options(select), select.value)

        # (c) trigger 2 — variant-set change while the patch screen is shown.
        app_grow = S19TuiApp(base_dir=tmp_path / "t3")
        external = tmp_path / "t3" / "b.s19"
        external.write_text(S19_B, encoding="utf-8")
        _make_project(app_grow, "projgrow", {"a.s19": S19_A})
        async with app_grow.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app_grow._handle_load_project("projgrow")
            await _flush(pilot)
            app_grow.action_show_screen("patch")
            await _flush(pilot, 4)
            select = app_grow.query_one("#patch_variant_select", Select)
            before = (
                _variant_options(select),
                select.value is Select.NULL,
                select.disabled,
            )
            app_grow.load_from_path(external)  # appends variant b (E5a-2)
            await app_grow.workers.wait_for_complete()
            await _flush(pilot)
            after = (_variant_options(select), select.value, select.disabled)
        return trio, dup, before, after

    trio, dup, before, after = asyncio.run(_drive())
    assert trio == (["Alpha", "mid", "zeta"], "Alpha", False), (
        f"3-variant options must be the ordered ids with the active "
        f"preselected and the control enabled, got {trio}"
    )
    assert dup == (["fw.hex", "fw.s19"], "fw.hex"), (
        f"duplicate stems must list FULL FILENAMES in order, got {dup}"
    )
    assert before == ([], True, True), (
        f"N==1 must leave empty options + blank value + disabled (F-2), "
        f"got {before}"
    )
    assert after == (["a", "b"], "b", False), (
        f"a variant append while the screen is shown must repopulate to the "
        f"new set with the new active preselected (F-3 trigger 2), got {after}"
    )


# ---------------------------------------------------------------------------
# TC-035.4 / LLR-035.4 — routing guards + echo-loop suppression
# ---------------------------------------------------------------------------


def test_tc_035_4_routing_guards(tmp_path: Path) -> None:
    """TC-035.4 — one activation per real pick; guards fire no activation.

    Intent (LLR-035.4): the route reuses ``_handle_select_variant`` wholesale.
    A non-active pick invokes it exactly once; a blank pick is filtered in
    the panel (never posted); a same-as-active ``VariantSelected`` (the F-4
    repopulate echo) is dropped in the app handler; an unknown id dies at the
    existing unknown-id guard (status line, no crash, active unchanged); a
    missing-file pick dies at the existing missing-file guard. Activation
    count is the white-box probe (a wrapper around the routed method);
    label/active observables are the behavioral cross-check. Counterfactual:
    route raw values without the short-circuits -> the repopulate echo pair
    re-activates on every refresh (count > 1) -> RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(
            app, "proj", {"a.s19": S19_A, "b.s19": S19_B, "c.s19": S19_A}
        )
        statuses = _statuses(app)
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
            select = app.query_one("#patch_variant_select", Select)

            # Non-active pick -> exactly one activation.
            await _switch_via_dropdown(app, pilot, "b")
            after_switch = (list(calls), _project_label(app))

            # Same-as-active echo (the F-4 pair's second half) -> dropped.
            panel.post_message(PatchEditorPanel.VariantSelected("b"))
            await _flush(pilot, 4)
            after_echo = list(calls)

            # Blank pick -> filtered in the panel, nothing posted.
            select.value = Select.NULL
            await _flush(pilot, 4)
            after_blank = list(calls)

            # Unknown/stale id -> existing guard: status, no crash.
            panel.post_message(PatchEditorPanel.VariantSelected("ghost"))
            await _flush(pilot, 4)
            await app.workers.wait_for_complete()
            after_ghost = (list(calls), _project_label(app))

            # Missing file -> existing guard: status, no load.
            (project_dir / "c.s19").unlink()
            panel.post_message(PatchEditorPanel.VariantSelected("c"))
            await _flush(pilot, 4)
            await app.workers.wait_for_complete()
            await _flush(pilot, 4)
            after_missing = (list(calls), _project_label(app))
        return after_switch, after_echo, after_blank, after_ghost, after_missing, statuses

    after_switch, after_echo, after_blank, after_ghost, after_missing, statuses = (
        asyncio.run(_drive())
    )
    assert after_switch[0] == ["b"], (
        f"a non-active pick must invoke the activation pipeline exactly once "
        f"(repopulate echoes absorbed), got {after_switch[0]}"
    )
    assert "proj:b (2/3)" in after_switch[1]
    assert after_echo == ["b"], (
        f"a same-as-active VariantSelected must fire no activation, "
        f"got {after_echo}"
    )
    assert after_blank == ["b"], (
        f"a blank pick must be filtered in the panel, got {after_blank}"
    )
    assert after_ghost[0] == ["b", "ghost"], "unknown id routes to the guard"
    assert "proj:b (2/3)" in after_ghost[1], "unknown id must not switch"
    assert any("Variant not found: ghost" in m for m in statuses), (
        f"the existing unknown-id guard must surface its warning; {statuses}"
    )
    assert "proj:b (2/3)" in after_missing[1], "missing file must not switch"
    assert any("Variant file missing: c.s19" in m for m in statuses), (
        f"the existing missing-file guard must surface its warning; {statuses}"
    )


# ---------------------------------------------------------------------------
# TC-035.5 / LLR-035.5 — disabled-state table (DoR Q1)
# ---------------------------------------------------------------------------


def test_tc_035_5_disabled_state_table(tmp_path: Path) -> None:
    """TC-035.5 — disabled == (N < 2), re-evaluated on project switches.

    Intent (LLR-035.5 / Q1): no project -> disabled + blank; N==1 -> disabled;
    N>=2 -> enabled; switching to another project re-evaluates (the trigger is
    owned by LLR-035.3 per F-3). The pane geometry stays stable across the
    states (same widget, no layout jump — the disabled flag, not removal).
    Counterfactual: invert or omit the N<2 branch -> RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "single", {"a.s19": S19_A})
        _make_project(app, "multi", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            select = app.query_one("#patch_variant_select", Select)
            no_project = (select.disabled, select.value is Select.NULL)
            region_before = app.query_one("#patch_pane_variant").region

            app._handle_load_project("multi")
            await _flush(pilot)
            multi = select.disabled

            app._handle_load_project("single")
            await _flush(pilot)
            single = (select.disabled, select.value is Select.NULL)
            region_after = app.query_one("#patch_pane_variant").region
            return no_project, multi, single, region_before == region_after

    no_project, multi, single, region_stable = asyncio.run(_drive())
    assert no_project == (True, True), "no project -> disabled + blank"
    assert multi is False, "N>=2 -> enabled"
    assert single == (True, True), (
        "switching to a single-variant project must re-evaluate to disabled"
    )
    assert region_stable, "pane geometry must be stable across the states (Q1)"


# ---------------------------------------------------------------------------
# TC-035.6 / LLR-035.6 — persist-on-save only, no disk write on switch (Q2)
# ---------------------------------------------------------------------------


def test_tc_035_6_switch_writes_nothing_to_disk(tmp_path: Path) -> None:
    """TC-035.6 — a dropdown switch alone touches no project file.

    Intent (LLR-035.6 / DoR Q2): the switch updates only in-memory state via
    the existing pipeline; ``project.json`` is written exclusively by the
    save flow. For a never-saved project the manifest stays ABSENT and the
    project directory's file set and bytes are unchanged after a switch
    (0 bytes changed, 0 files created). The positive persist chain is
    AT-035b's gate. Counterfactual: an Option-C write-on-switch creates or
    rewrites the manifest -> RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(
            app, "proj", {"a.s19": S19_A, "b.s19": S19_B}
        )
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            snapshot_before = {
                p.name: p.read_bytes() for p in sorted(project_dir.iterdir())
            }
            manifest_before = (project_dir / "project.json").exists()
            await _switch_via_dropdown(app, pilot, "b")
            snapshot_after = {
                p.name: p.read_bytes() for p in sorted(project_dir.iterdir())
            }
            manifest_after = (project_dir / "project.json").exists()
            return manifest_before, manifest_after, snapshot_before, snapshot_after

    manifest_before, manifest_after, before, after = asyncio.run(_drive())
    assert manifest_before is False, "precondition: never-saved project"
    assert manifest_after is False, (
        "a dropdown switch must NOT create project.json (Q2 persist-on-save)"
    )
    assert before == after, (
        "a dropdown switch must change no project file (0 bytes, 0 files)"
    )


# ---------------------------------------------------------------------------
# TC-035.7 / LLR-035.7 — switch-during-load integrity (security F2)
# ---------------------------------------------------------------------------


def test_tc_035_7_rapid_double_pick_stays_consistent(tmp_path: Path) -> None:
    """TC-035.7 — a pick during an in-flight load is suppressed, state coherent.

    Intent (LLR-035.7, security F2): with picks b then c issued back-to-back
    (c arrives while b's threaded load is in flight), the
    suppress-while-loading guard drops c — the finally-rendered image, the
    stamped active id, and the label all refer to the SAME variant (b), the
    dropdown re-syncs to it, NO file is created in the project directory (the
    phantom ``«stem»_1.s19`` side-door), and the suppression is surfaced in
    the status line. ``c.s19`` deliberately carries variant a's bytes so a
    mislabeled c-load is caught by the content assert. Counterfactual: an
    unguarded single-slot ``_pending_variant_id`` lets c's pick re-stamp
    mid-flight -> mislabeled state or a phantom project-dir copy -> RED.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(
            app, "proj", {"a.s19": S19_A, "b.s19": S19_B, "c.s19": S19_A}
        )
        statuses = _statuses(app)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_show_screen("patch")
            await _flush(pilot, 4)
            select = app.query_one("#patch_variant_select", Select)
            files_before = sorted(p.name for p in project_dir.iterdir())
            # Rapid double pick: no event-loop yield between the two — c's
            # Changed is handled while b's load worker is still in flight.
            select.value = "b"
            select.value = "c"
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            label = _project_label(app)
            value = select.value
            files_after = sorted(p.name for p in project_dir.iterdir())
            active_id = app._variant_set.active_id  # secondary diagnostic
            app.action_show_screen("workspace")
            await _flush(pilot, 4)
            return label, value, files_before, files_after, active_id, statuses, _hex_text(app)

    label, value, files_before, files_after, active_id, statuses, hex_text = (
        asyncio.run(_drive())
    )
    # Timing assumption (review F2): c's queued VariantSelected message is
    # pumped before b's ms-scale parse worker can apply, so the in-flight
    # suppress drops c and b wins. If this node ever flakes on a loaded CI
    # box, a c-coherent outcome is LLR-legal — check this window first.
    assert "proj:b (2/3)" in label, (
        f"the first pick (b) must win and the label must say so, got {label!r}"
    )
    assert "0A 0B 0C 0D" in hex_text and "01 02 03 04" not in hex_text, (
        "the rendered image must be the SAME variant the label names (b)"
    )
    assert value == "b", f"the dropdown must re-sync to the real active id, got {value!r}"
    assert active_id == "b", f"active_id diagnostic disagrees: {active_id!r}"
    assert files_after == files_before, (
        f"the interleaving must create NO project file (phantom copy guard): "
        f"{files_before} -> {files_after}"
    )
    assert any("Variant switch ignored" in m for m in statuses), (
        f"the suppressed pick must be surfaced in the status line; {statuses}"
    )
