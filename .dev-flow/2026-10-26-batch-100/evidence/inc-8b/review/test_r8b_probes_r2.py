"""Inc 8b code-review probes, round 2 (review-increment-016 ## Round 2).
Throwaway. Each probe prints what it observed; the asserts state the
behaviour the corrective pass claims (P-4) or the one the reviewer suspects
(P-4c)."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import s19_app
import s19_app.tui.app as app_module
from s19_app.tui.screens import SaveProjectPayload
from tests.support import b100_projects as projects
from tests.test_b100_project_homes import _save, _workarea


def test_header():
    print("s19_app.__file__ =", s19_app.__file__)


def test_p4_round1_sequence_save_p_then_q(tmp_path):
    """P-4 exactly as in round 1: P open, image from outside, W/P moved
    away; Save project "P", then "Q"."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")

    async def _scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        await projects.load_image(pilot, app, src / "firmware.s19")
        shutil.move(str(_workarea(base) / "P"), str(tmp_path / "P_moved"))
        same = await _save(pilot, app, log, "P")
        other = await _save(pilot, app, log, "Q")
        return same, other

    same, other = projects.run_app(base, _scenario)
    print("SAVE P:", same)
    print("SAVE Q:", other)
    assert any(m.startswith("Saved project to") for m in same)
    assert any("open project folder 'P' was not found" in m for m in same)
    assert not any("could not be read" in m for m in same + other)
    assert (_workarea(base) / "P" / "firmware.s19").is_file()
    assert any(m.startswith("Saved project to") for m in other)
    assert (_workarea(base) / "Q" / "firmware.s19").is_file()


def test_p4_variant_save_q_first(tmp_path):
    """P-4 variant: W/P gone, Save project "Q" first (no re-created P)."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")

    async def _scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        await projects.load_image(pilot, app, src / "firmware.s19")
        shutil.move(str(_workarea(base) / "P"), str(tmp_path / "P_moved"))
        return await _save(pilot, app, log, "Q"), app.current_project

    other, current = projects.run_app(base, _scenario)
    print("SAVE Q:", other, "current:", current)
    assert any(m.startswith("Saved project to") for m in other)
    assert any("open project folder 'P' was not found" in m and "copy them into 'Q'" in m for m in other)
    assert current == "Q"


def test_p4c_unreadable_open_project_folder_on_save_as(tmp_path, monkeypatch):
    """P-4c (F1 x F7(a)): lstat of the OPEN project's folder W/P raises
    PermissionError (W/P is still there); Save project as Q. Token row 9
    (F7(a), cp1 notes) says: refused, "the open project folder 'P' could
    not be read — pick a project in the list". The suspicion: the F1
    predicate's os.path.lexists swallows the error, so the save proceeds as
    if P were gone and paints "was not found"."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    denied = os.path.normcase(str(_workarea(base) / "P"))
    original = os.lstat

    def _lstat(path, *args, **kwargs):
        if os.path.normcase(str(path)) == denied:
            raise PermissionError(13, "denied", str(path))
        return original(path, *args, **kwargs)

    async def _scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        await projects.load_image(pilot, app, src / "firmware.s19")
        mark = len(log.messages)
        monkeypatch.setattr(app_module.os, "lstat", _lstat)
        try:
            app._handle_save_dialog(
                SaveProjectPayload(parent_folder=str(app.workarea), project_name="Q")
            )
        finally:
            monkeypatch.setattr(app_module.os, "lstat", original)
        for _ in range(6):
            await pilot.pause()
        return log.since(mark), app.current_project

    messages, current = projects.run_app(base, _scenario)
    print("SAVE Q (W/P unreadable):", messages, "current:", current)
    print("Q exists:", (_workarea(base) / "Q").exists(), "P exists:", (_workarea(base) / "P").exists())
    print("row 9 'could not be read' painted:", any("could not be read" in m for m in messages))
    print("'was not found' painted:", any("was not found" in m for m in messages))
