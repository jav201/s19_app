"""Inc 8b code-review probes, part 2 (review-increment-016). Throwaway."""
from __future__ import annotations

import shutil
from pathlib import Path

import s19_app
from tests.support import b100_projects as projects
from tests.test_b100_project_homes import _save, _workarea


def test_header():
    print("s19_app.__file__ =", s19_app.__file__)


def test_probe_missing_source_blocks_every_new_save(tmp_path):
    """The open project folder is removed after the load (renamed away in
    Explorer). Save project under P's own name (now absent -> a 'new'
    target) and under a new name Q are both refused by the save-as walk."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")

    async def _scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        # the session image now comes from outside P, so the image step
        # does not refuse; only the open project folder is gone
        await projects.load_image(pilot, app, src / "firmware.s19")
        print("open project after the image load:", app.current_project, app.current_project_dir)
        shutil.move(str(_workarea(base) / "P"), str(tmp_path / "P_moved"))
        same = await _save(pilot, app, log, "P")
        other = await _save(pilot, app, log, "Q")
        return same, other

    same, other = projects.run_app(base, _scenario)
    print("SAVE P:", same)
    print("SAVE Q:", other)
    assert not any(m.startswith("Saved project to") for m in same + other)
    assert any("could not be read" in m for m in same)
    assert any("could not be read" in m for m in other)
    assert not (_workarea(base) / "P").exists()
    assert not (_workarea(base) / "Q").exists()


def test_probe_r7_unparseable_a2l_only_project_resets_the_session(tmp_path):
    """R-7: an A2L-only folder whose A2L does not parse passes the new
    pre-reset gate (a2l_files non-empty), the session is reset, then the
    retired 'No supported files in project' line is painted. At ebe6d0c the
    same folder was refused before the reset (`if not data_files`)."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.a2l",))
    (_workarea(base) / "P" / "firmware.a2l").write_bytes(b"\x00\xff not an a2l \x00" * 8)
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")

    async def _scenario(app, pilot, log):
        await projects.load_image(pilot, app, src / "firmware.s19")
        before = app.current_file is not None
        mark = len(log.messages)
        app._handle_load_project("P")
        await pilot.pause()
        await pilot.pause()
        return before, app.current_file, app.current_project, log.messages[mark:]

    before, current_file, current_project, lines = projects.run_app(base, _scenario)
    print("BEFORE has file:", before, "AFTER file:", current_file,
          "project:", current_project, "LINES:", lines)
    assert before
    assert current_file is None
    assert any("No supported files in project" in m for m in lines)
