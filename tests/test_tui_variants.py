"""Multi-variant project TUI tests (batch-07 E5b — HLR-005).

Coverage map:

- LLR-005.6 — ``test_project_load_activates_first_variant``: project load
  activates the FIRST variant in deterministic ``(name.lower(), name)``
  order, stamps ``LoadedFile.variant_id``, and preserves the MAC follow-up
  load.
- LLR-005.5 — ``test_select_variant_updates_label``: ``action_select_variant``
  opens ``SelectVariantScreen``; choosing variant 2 of 2 routes through the
  existing load pipeline and the project label reads ``proj:b (2/2)``.
  ``test_single_s19_project_label_plain`` pins the N==1 back-compat label
  (no ``(i/N)`` suffix, LLR-005.3).
- LLR-005.4 — ``test_no_new_parse_loaded_file_call_sites``: AST inspection
  that ``_parse_loaded_file`` is called from exactly the two pre-existing
  sites (``load_selected_file`` sync path, ``_start_load_worker`` worker) —
  the variant selector adds ZERO new parse call sites and never parses on
  the UI thread.
- E5a finding 2 — ``test_load_second_s19_appends_variant``: loading a second
  S19 while a project is active APPENDS it as a new variant (sync copies it
  in) with a status line naming the variant — the pre-batch silent skip is
  retired.
- E5a finding 1 — ``test_save_second_s19_into_project_appends_variant``:
  saving an S19/HEX into a project that already holds a primary is a
  legitimate variant addition (cross-suffix guard retired); the status
  reports the saved variant.
- Variant stamping — ``test_direct_load_variant_id_is_none``: non-project
  loads carry ``variant_id is None``.
- Duplicate-stem display — ``test_duplicate_stem_display_uses_filename``:
  when two variants share a filename stem (``fw.s19`` + ``fw.hex``) the
  label falls back to the full filename (display-only disambiguation; the
  duplicate-id model itself is an E6 decision).

Harness: the ``App.run_test()`` pilot pattern of ``tests/test_tui_app.py`` /
``tests/test_tui_directionb.py`` — ``async def _drive()`` wrapped by
``asyncio.run``, asserting on widget state via ``query_one``.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

from textual.widgets import Button, ListView

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.command_bar import CommandBar
from s19_app.tui.screens import SelectVariantScreen

# Minimal valid S19 images (checksums verified against s19_app.core.S19File).
S19_A = "S107100001020304DE\nS9030000FC\n"
S19_B = "S10720000A0B0C0DAA\nS9030000FC\n"
# Minimal valid Intel HEX image (one data record + EOF).
HEX_A = ":0410000001020304E2\n:00000001FF\n"
MAC_A = "A=0x1000\n"


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
    bar = app.query_one(CommandBar)
    return str(bar.query_one("#cmdbar_project").content)


# ---------------------------------------------------------------------------
# LLR-005.6 — project load activates the first variant (deterministic order)
# ---------------------------------------------------------------------------


def test_project_load_activates_first_variant(tmp_path: Path) -> None:
    """Multi-variant project load activates variant 1 of N and keeps the MAC.

    Intent: LLR-005.6 — ``_handle_load_project`` activates the FIRST variant
    in ``(name.lower(), name)`` order (``a`` before ``b`` regardless of
    creation order), stamps ``LoadedFile.variant_id``, and the MAC follow-up
    load still attaches MAC records to the active variant.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"b.s19": S19_B, "a.s19": S19_A, "m.mac": MAC_A})
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            return (
                app.current_file.variant_id if app.current_file else None,
                [v.variant_id for v in app._variant_set.variants],
                app._variant_set.active_id,
                bool(app.current_file and app.current_file.mac_records),
                _project_label(app),
            )

    variant_id, ids, active_id, has_mac, label = asyncio.run(_drive())
    assert variant_id == "a", f"first variant in deterministic order is 'a', got {variant_id!r}"
    assert ids == ["a", "b"]
    assert active_id == "a"
    assert has_mac, "MAC follow-up load must still attach MAC records (LLR-005.6)"
    assert "proj:a (1/2)" in label, f"label must read project:variant (1/2), got {label!r}"


# ---------------------------------------------------------------------------
# LLR-005.5 — selector modal activates variant 2 of 2 via the load pipeline
# ---------------------------------------------------------------------------


def test_select_variant_updates_label(tmp_path: Path) -> None:
    """Choosing variant 2 in ``SelectVariantScreen`` activates it as (2/2).

    Intent: LLR-005.5 — the selector dismisses with the chosen variant id,
    activation routes through ``load_from_path`` -> ``_start_load_worker``
    (worker thread), and after the apply the label reads ``proj:b (2/2)``
    with ``current_file.variant_id == "b"``. The reload must NOT re-append
    the variant to the project (E5a finding 2 skip rule).
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(app, "proj", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.action_select_variant()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, SelectVariantScreen)
            screen.query_one("#variant_list", ListView).index = 1
            await pilot.pause()
            screen.query_one("#variant_ok", Button).press()
            await pilot.pause()
            await app.workers.wait_for_complete()
            await _flush(pilot)
            project_s19 = sorted(p.name for p in project_dir.glob("*.s19"))
            return (
                app.current_file.variant_id if app.current_file else None,
                app._variant_set.active_id,
                _project_label(app),
                project_s19,
            )

    variant_id, active_id, label, project_s19 = asyncio.run(_drive())
    assert variant_id == "b"
    assert active_id == "b"
    assert "proj:b (2/2)" in label, f"label must read (2/2) after switching, got {label!r}"
    assert project_s19 == ["a.s19", "b.s19"], (
        f"variant activation must not duplicate files into the project: {project_s19}"
    )


# ---------------------------------------------------------------------------
# LLR-005.4 — thread contract: zero new _parse_loaded_file call sites
# ---------------------------------------------------------------------------


def test_no_new_parse_loaded_file_call_sites() -> None:
    """``_parse_loaded_file`` is invoked only from the two pre-existing sites.

    Intent: LLR-005.4 — variant activation reuses the existing pipeline;
    parsing happens either in the ``_start_load_worker`` thread worker or in
    the pre-existing synchronous ``load_selected_file`` path. Any additional
    call site would mean a new parse on the UI thread and must fail here.
    """
    source = Path(app_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    call_sites: list[str] = []

    def _walk(node: ast.AST, enclosing: str) -> None:
        for child in ast.iter_child_nodes(node):
            scope = enclosing
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = child.name
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "_parse_loaded_file"
            ):
                call_sites.append(enclosing)
            _walk(child, scope)

    _walk(tree, "<module>")
    assert sorted(call_sites) == ["_start_load_worker", "load_selected_file"], (
        f"unexpected _parse_loaded_file call sites: {sorted(call_sites)} "
        "(LLR-005.4 allows only the pre-existing worker + sync-path sites)"
    )


# ---------------------------------------------------------------------------
# E5a finding 2 — loading a 2nd S19 appends it as a new variant
# ---------------------------------------------------------------------------


def test_load_second_s19_appends_variant(tmp_path: Path) -> None:
    """A direct S19 load while a project is active appends a new variant.

    Intent: E5a finding 2 — the pre-batch silent skip is retired: the loaded
    file is copied into the project, the variant set gains it as the active
    variant, ``variant_id`` is stamped, and the status line names the
    appended variant.
    """
    external = tmp_path / "b.s19"
    external.write_text(S19_B, encoding="utf-8")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(app, "proj", {"a.s19": S19_A})
        statuses: list[str] = []
        original_set_status = app.set_status
        app.set_status = lambda message: (statuses.append(message), original_set_status(message))[1]
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            app.load_from_path(external)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            project_s19 = sorted(p.name for p in project_dir.glob("*.s19"))
            return (
                project_s19,
                [v.variant_id for v in app._variant_set.variants],
                app._variant_set.active_id,
                app.current_file.variant_id if app.current_file else None,
                _project_label(app),
                statuses,
            )

    project_s19, ids, active_id, variant_id, label, statuses = asyncio.run(_drive())
    assert project_s19 == ["a.s19", "b.s19"]
    assert ids == ["a", "b"]
    assert active_id == "b"
    assert variant_id == "b"
    assert "proj:b (2/2)" in label
    assert any("Added variant 'b' to project 'proj'" in message for message in statuses), (
        f"status must name the appended variant; got {statuses}"
    )


# ---------------------------------------------------------------------------
# LLR-005.3 — single-S19 back-compat: no (i/N) suffix
# ---------------------------------------------------------------------------


def test_single_s19_project_label_plain(tmp_path: Path) -> None:
    """A single-S19 project shows the plain project name — no ``(1/1)``.

    Intent: LLR-005.3 — pre-batch single-file projects must render their
    project context label exactly as before the multi-variant model.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"fw.s19": S19_A})
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            return (
                _project_label(app),
                app.current_file.variant_id if app.current_file else None,
            )

    label, variant_id = asyncio.run(_drive())
    assert label == "Project: proj", f"single-variant label must stay plain, got {label!r}"
    assert variant_id == "fw", "variant_id is still stamped on single-variant project loads"


# ---------------------------------------------------------------------------
# Variant stamping — direct (non-project) loads stay None
# ---------------------------------------------------------------------------


def test_direct_load_variant_id_is_none(tmp_path: Path) -> None:
    """A direct file load with no active project carries ``variant_id=None``.

    Intent: ``variant_id`` is the project-membership marker — stamping it on
    plain loads would corrupt the E5a finding-2 append/skip decision and the
    E6 execution mapping.
    """
    source = tmp_path / "fw.s19"
    source.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(source)
            await _flush(pilot)
            return (
                app.current_file.variant_id if app.current_file else "missing",
                app._variant_set,
                _project_label(app),
            )

    variant_id, variant_set, label = asyncio.run(_drive())
    assert variant_id is None
    assert variant_set is None
    assert label == "Project: (none)"


# ---------------------------------------------------------------------------
# E5a finding 1 — saving a 2nd primary into a project appends a variant
# ---------------------------------------------------------------------------


def test_save_second_s19_into_project_appends_variant(tmp_path: Path) -> None:
    """Saving an S19 into a project that already has one is a variant addition.

    Intent: E5a finding 1 — the ``_handle_save_dialog`` cross-suffix guard
    ("Project already has an S19/HEX file.") contradicted the multi-variant
    model and is retired; the save copies the image in, the variant set
    gains it as active, and the status reports the saved variant.
    """
    external = tmp_path / "b.s19"
    external.write_text(S19_B, encoding="utf-8")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(app, "proj", {"a.s19": S19_A})
        statuses: list[str] = []
        original_set_status = app.set_status
        app.set_status = lambda message: (statuses.append(message), original_set_status(message))[1]
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            payload = app_module.SaveProjectPayload(
                parent_folder=str(app.workarea), project_name="proj"
            )
            app._handle_save_dialog(payload)
            await _flush(pilot)
            project_s19 = sorted(p.name for p in project_dir.glob("*.s19"))
            return (
                project_s19,
                [v.variant_id for v in app._variant_set.variants],
                app._variant_set.active_id,
                app.current_file.variant_id if app.current_file else None,
                statuses,
            )

    project_s19, ids, active_id, variant_id, statuses = asyncio.run(_drive())
    assert project_s19 == ["a.s19", "b.s19"], (
        f"save must append the second primary instead of rejecting it: {project_s19}"
    )
    assert ids == ["a", "b"]
    assert active_id == "b"
    assert variant_id == "b"
    assert any("variant 'b'" in message for message in statuses), (
        f"save status must report the saved variant; got {statuses}"
    )
    assert not any("already has an S19/HEX" in message for message in statuses), (
        "the retired cross-suffix rejection must not fire"
    )


# ---------------------------------------------------------------------------
# Duplicate-stem display fallback (E5a flag — model decision rides E6)
# ---------------------------------------------------------------------------


def test_duplicate_stem_display_uses_filename(tmp_path: Path) -> None:
    """Variants sharing a stem are displayed by filename, not by stem.

    Intent: ``fw.s19`` + ``fw.hex`` collapse to one ``variant_id`` (``fw``,
    E5a flagged; E6 decides the model). E5b disambiguates the DISPLAY only:
    the label and the selector options fall back to the full filename.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"fw.s19": S19_A, "fw.hex": HEX_A})
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            options = app._variant_display_options(app._variant_set)
            return (_project_label(app), options)

    label, options = asyncio.run(_drive())
    # Deterministic order: fw.hex < fw.s19; both displays are filenames.
    assert options == [("fw", "fw.hex"), ("fw", "fw.s19")]
    assert "proj:fw.hex (1/2)" in label, f"duplicate-stem label must show the filename, got {label!r}"
