"""Reviewer probes for batch-100 Inc 6 (code-reviewer, read-only toward the worktree).

Each probe prints what the tree does; the asserts at the end state the
reviewer's expectation from the contract / the OQ-1 ruling.
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

import pytest
from textual.widgets import Label

import s19_app
from s19_app.tui import app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services import variant_execution_service as service
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

from tests.support import b100_projects as projects

print("s19_app.__file__ =", s19_app.__file__)


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


async def _wait_for(pilot, predicate, what, attempts=200):
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {what}")


def _capture_status(app):
    statuses: list = []
    real = app.set_status

    def _cap(message, *a, **k):
        statuses.append(str(message))
        return real(message, *a, **k)

    app.set_status = _cap
    return statuses


async def _open(pilot, app, name="P"):
    app._handle_load_project(name)
    await _wait_for(pilot, lambda: app.current_project == name and app.current_file is not None, "load")
    for _ in range(6):
        await pilot.pause()


DAMAGED = {
    "unparseable": '{"schema_version":1,"active_variant":"firmware","batch":["patches/cs_seed.json"],',
    "toplevel_list": '[{"schema_version":1,"active_variant":"firmware","batch":["patches/cs_seed.json"]}]',
}


@pytest.mark.parametrize("kind", ["unparseable", "toplevel_list", "oversize"])
@pytest.mark.parametrize("writer", ["a2l_sync", "variant_append", "mac_sync", "save_back"])
def test_p1_damaged_manifest_and_a_writer(tmp_path: Path, monkeypatch, kind: str, writer: str) -> None:
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    manifest_path = project_dir / "project.json"
    if kind in DAMAGED:
        manifest_path.write_text(DAMAGED[kind], encoding="utf-8")
    else:
        # A valid manifest the reader refuses by size (cap lowered for the probe).
        monkeypatch.setattr(service, "MANIFEST_SIZE_CAP_BYTES", 16)
    before = manifest_path.read_bytes()
    a2l_src = projects.copy_sources(tmp_path / "side", projects.CASE01_DIR, "firmware.a2l")
    s19_src = projects.copy_sources(tmp_path / "s19", projects.CASE02_DIR, "firmware.s19")
    mac_src = projects.copy_sources(tmp_path / "mac", projects.CASE01_DIR, "firmware.mac")
    out: dict = {}

    async def _drive():
        app = S19TuiApp(base_dir=base)
        statuses = _capture_status(app)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            await _open(pilot, app)
            statuses.clear()
            if writer == "a2l_sync":
                app.load_a2l_from_path(a2l_src / "firmware.a2l")
                landed = project_dir / "firmware.a2l"
            elif writer == "mac_sync":
                app.load_from_path(mac_src / "firmware.mac")
                landed = project_dir / "firmware.mac"
            elif writer == "save_back":
                from s19_app.tui.screens_directionb import PatchEditorPanel
                app._change_service.add_entry("0x8000007C", "", "DE AD BE EF")
                loaded = app.current_file
                app._change_service.apply(loaded.mem_map, loaded.ranges, loaded.mac_records, None)
                app.on_patch_editor_panel_save_back_decision(
                    PatchEditorPanel.SaveBackDecision("firmware.s19", 32)
                )
                landed = project_dir / "firmware_1.s19"
            else:
                app.load_from_path(s19_src / "firmware.s19")
                landed = project_dir / "firmware_1.s19"
            await _wait_for(pilot, lambda: landed.is_file(), "the placement")
            for _ in range(20):
                await pilot.pause()
            out["statuses"] = list(statuses)
            out["landed"] = landed.is_file()

    asyncio.run(_drive())
    after = manifest_path.read_bytes()
    print(f"\n[P1 {kind} / {writer}] placed file kept: {out['landed']}")
    print(f"[P1 {kind} / {writer}] project.json replaced: {after != before}")
    print(f"[P1 {kind} / {writer}] project.json now: {after.decode('utf-8', 'replace')!r}")
    print(f"[P1 {kind} / {writer}] statuses after the writer: {out['statuses']}")
    # OQ-1 ruling (b): a damaged project.json is not silently replaced; the
    # writer keeps its file, skips the rewrite and says so.
    assert out["landed"]
    assert after == before, "damaged project.json was replaced"
    assert any("damaged" in s and "project.json" in s for s in out["statuses"]), out["statuses"]


def test_p2_manifest_write_fails_after_append(tmp_path: Path) -> None:
    """A read-only project.json (real trigger): the seam's write fails, yet
    the append's status claims Load now opens the new file."""
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    manifest_path = project_dir / "project.json"
    s19_src = projects.copy_sources(tmp_path / "s19", projects.CASE02_DIR, "firmware.s19")
    out: dict = {}

    async def _drive():
        app = S19TuiApp(base_dir=base)
        statuses = _capture_status(app)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            await _open(pilot, app)
            os.chmod(manifest_path, stat.S_IREAD)
            statuses.clear()
            app.load_from_path(s19_src / "firmware.s19")
            await _wait_for(pilot, lambda: any(s.startswith("Added variant") for s in statuses), "append")
            out["statuses"] = list(statuses)
            out["session_active"] = app._variant_set.active_id

    try:
        asyncio.run(_drive())
    finally:
        os.chmod(manifest_path, stat.S_IWRITE | stat.S_IREAD)
    disk_active = projects.read_manifest(project_dir)["active_variant"]
    print(f"\n[P2] statuses: {out['statuses']}")
    print(f"[P2] session active: {out['session_active']!r}; project.json active_variant: {disk_active!r}")
    assert "Manifest write failed" in out["statuses"]
    assert not any("now opens" in s for s in out["statuses"]), "false 'now opens' after a failed write"


def test_p3_partially_malformed_key_dropped_by_rewrite(tmp_path: Path) -> None:
    """A valid manifest object whose ``batch`` is a string (one structure
    finding): after an A2L sync the rewrite has dropped it."""
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    manifest_path = project_dir / "project.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["batch"] = "patches/cs_seed.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    a2l_src = projects.copy_sources(tmp_path / "side", projects.CASE01_DIR, "firmware.a2l")
    out: dict = {}

    async def _drive():
        app = S19TuiApp(base_dir=base)
        statuses = _capture_status(app)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            await _open(pilot, app)
            statuses.clear()
            app.load_a2l_from_path(a2l_src / "firmware.a2l")
            await _wait_for(pilot, lambda: (project_dir / "firmware.a2l").is_file(), "a2l")
            for _ in range(20):
                await pilot.pause()
            out["statuses"] = list(statuses)

    asyncio.run(_drive())
    after = json.loads(manifest_path.read_text(encoding="utf-8"))
    print(f"\n[P3] statuses: {out['statuses']}")
    print(f"[P3] keys after: {sorted(after)}; batch after: {after.get('batch', '<absent>')!r}")
