"""Reviewer probes for batch-100 Inc 7 (code-reviewer, round 1).

Each probe states its expected outcome on the reviewed tree. They import the
repo's own test helpers, so they run with the tree under review first on
sys.path (cwd = the tree, ``python -m pytest``).
"""
from __future__ import annotations

import asyncio
import json
import shutil
import threading
from pathlib import Path

import pytest

import s19_app
import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services import variant_execution_service as service
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

from tests import test_b100_save_guards as sg
from tests import test_b100_save_image as si
from tests.support import b100_projects as projects


def test_r7_import_proof() -> None:
    print("s19_app import:", s19_app.__file__)


# ---------------------------------------------------------------------------
# P1 - the Save plan's manifest keys vs the keys written, when a
# derived_from record is carried (LLR-167.6: "the app passes the keys it
# writes"; TC-B100-59 asserts tuple(written) == plan.manifest_keys).
# Expected on the reviewed tree: FAILS (written holds derived_from; the
# plan, computed with derived=image_step.emit=False, does not).
# ---------------------------------------------------------------------------


def test_p1_plan_keys_equal_written_keys_when_derived_from_is_carried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plans = si._capture_plans(monkeypatch)

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=tmp_path / "app")
        p1 = app.workarea / "P1"
        p1.mkdir(parents=True)
        for name in ("firmware.s19", "firmware.mac"):
            shutil.copy2(si.CASE01_DIR / name, p1 / name)
        (p1 / "project.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "active_variant": "firmware",
                    "files": projects.file_records(p1),
                    "derived_from": {
                        "firmware.s19": {"base": "orig.s19", "sha256": "a" * 64, "differ": 3}
                    },
                }
            ),
            encoding="utf-8",
        )
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await si._load_project(pilot, app, "P1")
            await si._save(pilot, app, "P1")
            await si._wait_for(
                pilot,
                lambda: si._status_text(app).startswith("Saved project to"),
                "the save into the open project",
            )
        return p1

    p1 = asyncio.run(_drive())
    written = json.loads((p1 / "project.json").read_text(encoding="utf-8"))
    plan = plans[-1]
    print("plan.manifest_keys:", plan.manifest_keys)
    print("written keys      :", tuple(written))
    assert tuple(written) == plan.manifest_keys


# ---------------------------------------------------------------------------
# PR - SEC2-10's retry: a PermissionError on the restore that clears within
# the retry window must restore project.json (no .previous copy).
# Expected: PASSES on the reviewed tree; FAILS on reviewer mutant MR (no
# retry). The shipped arms (held for the whole window, no-space) cannot
# tell the two apart.
# ---------------------------------------------------------------------------


def test_pr_restore_retry_lands_when_the_holder_lets_go(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "app"
    timers: list = []

    def _raise(project_dir, *args, **kwargs):
        handle = open(project_dir / "project.json", "rb")
        timer = threading.Timer(0.15, handle.close)
        timer.start()
        timers.append(timer)
        raise OSError("forced verify re-read failure")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = sg._StatusProbe(app)
        src = sg._copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await sg._flush(pilot)
            app._handle_save_dialog(sg._payload(app, "ab"))
            await sg._flush(pilot)
            project_dir = app.workarea / "ab"
            before = (project_dir / "project.json").read_bytes()
            src_b = tmp_path / "sources" / "b.s19"
            src_b.write_text(sg._S19_B, encoding="ascii")
            app.load_selected_file(src_b)
            await sg._flush(pilot)
            monkeypatch.setattr(app_module, "verify_written_manifest", _raise)
            app._handle_save_dialog(sg._payload(app, "ab"))
            await sg._flush(pilot)
            for timer in timers:
                timer.join()
            after = (project_dir / "project.json").read_bytes()
            kept = sorted(project_dir.glob("project.json.previous-*"))
        return probe.messages, before, after, kept

    messages, before, after, kept = asyncio.run(_drive())
    print("statuses:", messages[-3:])
    assert kept == [], kept
    assert after == before
    assert not [m for m in messages if "could not be restored" in m], messages


# ---------------------------------------------------------------------------
# PF - SEC6-5's fold row: 150 escaping entries -> 100 one by one plus ONE
# row counting the other 50 ("nothing is dropped unreported").
# Expected: PASSES on the reviewed tree; FAILS on reviewer mutant MF (the
# fold row dropped). No shipped test asserts the fold row.
# ---------------------------------------------------------------------------


def test_pf_skipped_entries_beyond_the_bound_are_counted(tmp_path: Path) -> None:
    project_dir = tmp_path / "P"
    project_dir.mkdir()
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": None,
                "batch": [f"../escape_{i:03d}.json" for i in range(150)],
            }
        ),
        encoding="utf-8",
    )
    manifest = service.read_project_manifest(project_dir)
    entries = [issue.details.get("entry") for issue in manifest.issues]
    print("issues:", len(manifest.issues), "last:", entries[-1])
    assert len(manifest.issues) == 101
    assert entries[-1] == "50 more recorded entries"


# ---------------------------------------------------------------------------
# PN - boundary of HLR-178: every image unreadable, no MAC. The load must
# not raise; the announcement marks the image not readable; one summary.
# Expected: PASSES.
# ---------------------------------------------------------------------------


def test_pn_every_image_unreadable_no_mac(tmp_path: Path) -> None:
    base = tmp_path / "app"
    project_dir = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "P"
    project_dir.mkdir(parents=True)
    (project_dir / "aaa.s19").write_text("S9030000FC\n", encoding="ascii")
    (project_dir / "project.json").write_text(
        json.dumps(
            {"schema_version": 1, "active_variant": "aaa", "files": projects.file_records(project_dir)}
        ),
        encoding="utf-8",
    )

    async def _drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            app._handle_load_project("P")
            for _ in range(12):
                await pilot.pause()
            return app

    app = asyncio.run(_drive())
    announcement = app._last_load_announcement
    print("announcement:", announcement)
    print("log:", list(app.log_lines)[-3:])
    assert announcement is not None
    assert announcement.unreadable == ("aaa.s19",)
    assert [(p.label, p.file) for p in announcement.problems] == [("not readable", "aaa.s19")]
    assert len([line for line in app.log_lines if line.endswith("details: p")]) == 1


# ---------------------------------------------------------------------------
# PA - an A2L that cannot be read during a project load (parse_a2l_file
# re-raises OSError for read errors). _install_project_image parses the
# image AND the project's A2L in one call and turns any exception into
# "not an S19 or HEX file" for the IMAGE.
# Expected on the reviewed tree: the valid image is reported as
# `not readable: not an S19 or HEX file` (misattributed) and is not opened.
# ---------------------------------------------------------------------------


def test_pa_unreadable_a2l_is_not_blamed_on_the_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "app"
    project_dir = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "P"
    projects.copy_sources(project_dir, projects.CASE01_DIR, "firmware.s19", "firmware.a2l")
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "firmware",
                "files": projects.file_records(project_dir),
            }
        ),
        encoding="utf-8",
    )

    def _denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(app_module, "parse_a2l_file", _denied)

    async def _drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            app._handle_load_project("P")
            for _ in range(12):
                await pilot.pause()
            return app

    app = asyncio.run(_drive())
    announcement = app._last_load_announcement
    print("problems:", announcement.problems)
    print("current_file:", app.current_file and app.current_file.path)
    print("log:", list(app.log_lines)[-3:])
    assert ("not readable", "firmware.s19") not in [
        (p.label, p.file) for p in announcement.problems
    ]


# ---------------------------------------------------------------------------
# PB - SEC6-5's named bound (packet §6: "Panel rows <= 100 + 1 + 1
# manifest-level + 1 per top-level project file"). A manifest whose `files`
# holds 1 000 well-formed records (exactly the cap, so not damaged) for
# files that are not on disk gives one `missing` problem per record; the
# reader's fold does not reach them. Same harness as the shipped SEC6-5 arm.
# Expected on the reviewed tree: rows ~ 1 000 (bound exceeded); timings
# printed.
# ---------------------------------------------------------------------------


def test_pb_files_records_at_the_cap_all_missing(tmp_path: Path) -> None:
    import time

    from tests import test_b100_project_check as pc

    base = tmp_path / "app"
    project_dir = projects.copy_sources(
        base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "P", projects.CASE01_DIR, "firmware.s19"
    )
    records = projects.file_records(project_dir)
    for i in range(999):
        records[f"gone{i:04d}.s19"] = {"size": 1, "sha256": "0" * 64}
    (project_dir / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": "firmware", "files": records}),
        encoding="utf-8",
    )

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        real_load = app._handle_load_project
        timing: list = []

        def _timed(name):
            started = time.perf_counter()
            real_load(name)
            timing.append(time.perf_counter() - started)

        app._handle_load_project = _timed
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            await pc._open_panel_through_the_dialog(pilot, app)
            pressed = time.perf_counter()
            await pc._wait_for(
                pilot,
                lambda: len(app.screen.query("#result_summary")) > 0
                and app.screen.query_one("#result_summary").size.height > 0,
                "the painted Load-result panel",
                attempts=4000,
            )
            painted = time.perf_counter() - pressed
            rows = len(app.screen.query("#result_body .result-problem"))
            return timing, painted, rows

    timing, painted, rows = asyncio.run(_drive())
    print(f"load {timing} s; panel painted {painted:.2f} s; problem rows {rows}")
    assert rows <= 100 + 1 + 1 + 1, rows
