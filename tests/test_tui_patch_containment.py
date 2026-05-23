"""
Patch Editor work-area containment integration tests — s19_app batch-03,
increment 11.

These tests verdict the **integration arm of TC-036** (``01-requirements.md``
§5.7 — method ``I``): the CDFX write-target containment guarantee of LLR-007.7
driven **end-to-end through the running Patch Editor** under
``App.run_test()`` + ``pilot``, rather than at the ``write_cdfx_to_workarea``
function seam (which ``tests/test_cdfx_path_containment.py`` already covers
for increment 8).

What the screen-level arm proves:

- **TC-036 — containment** — a Patch Editor ``"save"`` action produces a
  ``.cdfx`` whose resolved path lies under ``.s19tool/workarea/``.
- **TC-036 — dedup** — a second ``"save"`` onto an already-existing file name
  produces a dedup-suffixed file (``_<N>`` before the suffix); both files
  survive on disk — no silent clobber.
- **TC-036 — reparse-point rejection** — when ``.s19tool/workarea`` is a
  symbolic link to an out-of-containment directory, a ``"save"`` is rejected
  with a ``W-WRITE-CONTAINMENT`` ``ValidationIssue`` surfaced on the status
  path, the Patch Editor never crashes, and **no file is written** outside
  the work area. This arm needs OS privilege to create a symbolic link; it
  carries a recorded-reason ``skipif`` for CI images / accounts that lack it
  (Phase-2 closure CV-03 — a visible skip, never a silent pass).

These are **tests only** — no production behavior changes in this increment.
Every fixture is synthetic and built in-test (constraint C-9).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

# Synthetic enriched A2L tags so a change-list built through the screen
# resolves and the writer emits SW-INSTANCEs (an unresolved entry would be
# excluded by W-INSTANCE-EXCLUDED and produce a backbone-only .cdfx).
# Synthetic only, per constraint C-9 — no client A2L artifact.
_A2L_TAGS = [
    {
        "name": "IGN_ADVANCE_BASE",
        "char_type": "VALUE",
        "decode_type": "UBYTE",
        "element_count": 1,
    },
]


# ---------------------------------------------------------------------------
# Symlink-capability probe — the reparse-point arm needs OS privilege (CV-03).
# ---------------------------------------------------------------------------


def _can_create_symlink(tmp_path: Path) -> bool:
    """Return True when this process can create a directory symbolic link.

    False on CI images / accounts without the privilege (Windows
    ``SeCreateSymbolicLink`` or a POSIX restriction). Mirrors the probe in
    ``tests/test_cdfx_path_containment.py`` so the reparse-point arm gates the
    same way at the unit and integration levels (CV-03).
    """
    probe_target = tmp_path / "_symlink_probe_target"
    probe_link = tmp_path / "_symlink_probe_link"
    try:
        probe_target.mkdir()
        os.symlink(probe_target, probe_link, target_is_directory=True)
    except (OSError, NotImplementedError):
        return False
    finally:
        for path in (probe_link, probe_target):
            try:
                if path.is_symlink() or path.exists():
                    if path.is_dir() and not path.is_symlink():
                        path.rmdir()
                    else:
                        path.unlink()
            except OSError:
                pass
    return True


def _patch_a2l_tags(app: S19TuiApp) -> None:
    """Make ``app`` resolve the Patch Editor change-list against ``_A2L_TAGS``.

    With no real A2L file loaded the Patch Editor handler's
    ``_compute_a2l_enriched_tags`` returns an empty list and every entry is
    ``unresolved-no-a2l`` (the writer then excludes it, producing a
    backbone-only ``.cdfx``). These containment arms need a *resolved* entry so
    the writer emits a real ``SW-INSTANCE``, so this stubs the app's
    enriched-tag source with the synthetic ``_A2L_TAGS`` — the established way
    to simulate a loaded A2L without a real artifact (C-9).
    """
    app._compute_a2l_enriched_tags = lambda: _A2L_TAGS  # type: ignore[method-assign]


async def _save_one_entry_through_screen(
    app: S19TuiApp, pilot: object, value: str = "23"
) -> None:
    """Build a one-entry change-list through the widget and drive ``"save"``.

    Adds ``IGN_ADVANCE_BASE = value`` via the Patch Editor name/value inputs
    and the add control, then drives the save action — the full screen →
    ``app.py`` handler → ``CdfxService`` → writer path.
    """
    app.action_show_screen("patch")
    await pilot.pause()
    panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
    app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
    app.query_one("#patch_index_input").value = ""
    app.query_one("#patch_value_input").value = value
    panel.request_action("add")
    await pilot.pause()
    panel.request_action("save")
    await pilot.pause()


# ===========================================================================
# TC-036 — containment: a screen save resolves under .s19tool/workarea/
# ===========================================================================


def test_tc036_integration_screen_save_resolves_under_workarea(
    tmp_path: Path,
) -> None:
    """A Patch Editor save writes the .cdfx under .s19tool/workarea/ (LLR-007.7).

    Intent: the integration arm of TC-036 — driving the ``"save"`` action of
    the running Patch Editor produces a ``.cdfx`` whose resolved path is
    contained inside ``.s19tool/workarea/``. This is the screen-level arm of
    the function-level containment check; it fails if a future change routed
    the save outside the work-area root.
    """

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _patch_a2l_tags(app)
            await _save_one_entry_through_screen(app, pilot)

    asyncio.run(_drive())

    workarea = (tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR).resolve()
    written = list(workarea.glob("*.cdfx"))
    assert written, "the screen save action must write a .cdfx in the work area"
    assert written[0].resolve().is_relative_to(workarea), (
        f"a screen-saved .cdfx must resolve under .s19tool/workarea/: "
        f"{written[0]}"
    )


# ===========================================================================
# TC-036 — dedup: a second save onto an existing name is suffixed, not clobbered
# ===========================================================================


def test_tc036_integration_repeated_screen_save_dedup_suffixes(
    tmp_path: Path,
) -> None:
    """Two screen saves of the default name produce two distinct files.

    Intent: TC-036 dedup arm — the Patch Editor save action defaults to a
    fixed file name (``patchset.cdfx``); driving ``"save"`` twice must
    dedup-suffix the second file (``patchset_1.cdfx``) so the first is **not**
    silently clobbered. Both files must survive on disk.
    """

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _patch_a2l_tags(app)
            await _save_one_entry_through_screen(app, pilot, value="23")
            # A second save of the same in-progress change-list.
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            panel.request_action("save")
            await pilot.pause()

    asyncio.run(_drive())

    workarea = (tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR).resolve()
    written = sorted(p.name for p in workarea.glob("*.cdfx"))
    assert len(written) == 2, (
        f"two screen saves must produce two distinct .cdfx files, got {written}"
    )
    assert written == ["patchset.cdfx", "patchset_1.cdfx"], (
        f"the second save must be dedup-suffixed, not clobber the first: "
        f"{written}"
    )


# ===========================================================================
# TC-036 — reparse-point rejection through the screen (privilege-gated, CV-03)
# ===========================================================================


def test_tc036_integration_reparse_point_save_rejected_not_crashed(
    tmp_path: Path,
) -> None:
    """A screen save into a symlinked work area is rejected, never a crash.

    Intent: TC-036 reparse-point arm — when ``.s19tool/workarea`` is a
    symbolic link to an out-of-containment directory, the resolved write
    target has no ``.s19tool/workarea`` ancestor and ``copy_into_workarea``
    rejects it. Driven through the Patch Editor ``"save"`` action: the
    rejection surfaces as a ``W-WRITE-CONTAINMENT`` ``ValidationIssue`` on the
    status path, the screen stays usable, and **no file** lands in the
    out-of-containment target.

    The reparse-point arm needs OS privilege to create a symbolic link; it is
    skipped with a recorded reason on CI images / accounts that lack it
    (Phase-2 closure CV-03 — a visible skip, never a silent pass).
    """
    if not _can_create_symlink(tmp_path):
        pytest.skip(
            "no privilege to create a symbolic link on this OS / account — "
            "the reparse-point arm of the TC-036 integration test cannot run "
            "(CV-03)"
        )

    # The real work-area content lives outside any .s19tool/workarea tree.
    real_target = tmp_path / "outside_target"
    real_target.mkdir()
    (real_target / "temp").mkdir()

    # .s19tool/workarea is a symbolic link pointing at that out-of-containment
    # directory — exactly the shape that fails copy_into_workarea's check.
    s19tool = tmp_path / WORKAREA_DIRNAME
    s19tool.mkdir()
    os.symlink(
        real_target, s19tool / WORKAREA_SUBDIR, target_is_directory=True
    )

    async def _drive() -> tuple[list[str], bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _patch_a2l_tags(app)
            await _save_one_entry_through_screen(app, pilot)  # must not crash
            # The screen is still usable after the rejected save.
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_index_input").value = ""
            app.query_one("#patch_value_input").value = "9"
            panel.request_action("edit")
            await pilot.pause()
            from textual.widgets import DataTable

            table = app.query_one("#patch_changelist_table", DataTable)
            return list(app.log_lines), table.row_count == 1

    status_lines, screen_usable = asyncio.run(_drive())

    assert any("W-WRITE-CONTAINMENT" in line for line in status_lines), (
        "a reparse-point-traversing save must surface W-WRITE-CONTAINMENT on "
        f"the status path, log lines were {status_lines}"
    )
    assert screen_usable, (
        "the Patch Editor must stay usable after a rejected containment save"
    )
    # No .cdfx escaped into the out-of-containment target directory.
    escaped = list(real_target.rglob("*.cdfx"))
    assert escaped == [], (
        f"a rejected save must not write any .cdfx outside the work area: "
        f"{escaped}"
    )


def test_tc036_integration_reparse_point_save_is_visible_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A containment rejection is surfaced, never silent — privilege-free arm.

    Intent: TC-036 reparse-point arm, privilege-independent control — the
    actual symlink arm above is OS-privilege-gated (CV-03), so this arm forces
    the rejection deterministically by stubbing the reused
    ``copy_into_workarea`` helper to raise ``WorkareaContainmentError``. The
    Patch Editor save must then catch it, surface ``W-WRITE-CONTAINMENT`` on
    the status path, and never crash — covering the rejection path on every
    CI image regardless of symlink privilege.
    """
    from s19_app.tui import workspace
    from s19_app.tui.cdfx import writer as cdfx_writer

    def reject(*_args: object, **_kwargs: object) -> Path:
        raise workspace.WorkareaContainmentError(
            "Refusing to copy: destination traverses a reparse point"
        )

    monkeypatch.setattr(cdfx_writer, "copy_into_workarea", reject)

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _patch_a2l_tags(app)
            await _save_one_entry_through_screen(app, pilot)  # must not crash
            return list(app.log_lines)

    status_lines = asyncio.run(_drive())
    assert any("W-WRITE-CONTAINMENT" in line for line in status_lines), (
        "a forced containment rejection must surface W-WRITE-CONTAINMENT on "
        f"the status path, log lines were {status_lines}"
    )
