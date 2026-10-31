"""Inc 8b code-review probes (review-increment-016). Throwaway; read-only
toward the source. Each probe prints its facts; assertions encode the
reviewer's claim so a PASS confirms the finding."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

import s19_app
import s19_app.tui.workspace as workspace_module
from tests.support import b100_projects as projects
from tests.test_b100_project_homes import _save, _with, _workarea


def test_header():
    print("s19_app.__file__ =", s19_app.__file__)


def test_probe_d3_save_project_does_not_drop_the_a2l(tmp_path, monkeypatch):
    """D-3: the painted next step for the A2L 'not readable' row is the
    composer's 'replace the file, or Save project to drop it'. Probe: load,
    Save project into P, load again -> the same problem is still listed."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19", "firmware.a2l"))
    a2l_size = (projects.CASE01_DIR / "firmware.a2l").stat().st_size
    monkeypatch.setattr(workspace_module, "DEFAULT_COPY_SIZE_CAP_BYTES", a2l_size - 1)

    async def _load(app, pilot):
        app._route_load_project("P")
        await projects.wait_for(
            pilot, lambda: app.current_project == "P" and app.current_file is not None,
            "load P",
        )
        return projects.flat(await projects.read_load_result_panel(pilot, app))

    async def _scenario(app, pilot, log):
        first = await _load(app, pilot)
        await pilot.press("escape")
        await pilot.pause()
        saved = await _save(pilot, app, log, "P")
        return first, saved

    first, saved = projects.run_app(base, _scenario)
    print("FIRST PANEL:", first)
    print("SAVE LINES:", saved)

    async def _again(app, pilot, log):
        return await _load(app, pilot)

    second = projects.run_app(base, _again)
    print("SECOND PANEL:", second)
    assert "Save project to drop it" in first
    assert "replace the A2L file, then Load again" not in first
    assert any(m.startswith("Saved project to") for m in saved), saved
    assert (_workarea(base) / "P" / "firmware.a2l").exists()
    assert "not readable" in second and "firmware.a2l" in second


@pytest.mark.skipif(sys.platform != "win32", reason="device-stem file needs Windows \\\\?\\ spelling")
def test_probe_i1_crc_template_reaches_the_unrecorded_line(tmp_path):
    """I-1: an active CRC template whose name project.json cannot record
    (device stem) is gathered into templates/ and reaches the
    'copied but not recorded' line end to end, with no batch involved."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    outside = tmp_path / "tpl"
    outside.mkdir()
    template = outside / "con.json"
    with open("\\\\?\\" + str(template), "wb") as handle:
        handle.write(b'{"crc": 1}\n')
    print("template is_file (normal spelling):", template.is_file())

    async def _scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        app._last_template_path = template
        return await _save(pilot, app, log, "P")

    messages = projects.run_app(base, _scenario)
    print("SAVE LINES:", messages)
    lines = _with(messages, "copied but not recorded")
    print("UNRECORDED LINES:", lines)
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert len(lines) == 1 and "templates/con.json" in lines[0], messages


def test_probe_i2_unload_of_an_a2l_only_session_does_nothing(tmp_path):
    """I-2: after D-5 the A2L slot of an A2L-only project is present (with
    its [u] control), but the A2L unload paints 'Nothing to unload.' and
    leaves the A2L attached."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.a2l",))

    async def _scenario(app, pilot, log):
        app._handle_load_project("P")
        await projects.wait_for(pilot, lambda: app.current_a2l_path is not None, "a2l")
        before = app.current_a2l_path
        mark = len(log.messages)
        app._apply_unload("a2l")
        await pilot.pause()
        return before, app.current_a2l_path, log.messages[mark:]

    before, after, lines = projects.run_app(base, _scenario)
    print("BEFORE:", before, "AFTER:", after, "LINES:", lines)
    assert before is not None and after == before
    assert "Nothing to unload." in lines
