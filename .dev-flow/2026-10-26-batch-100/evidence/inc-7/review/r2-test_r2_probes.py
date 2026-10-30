"""Reviewer probes for batch-100 Inc 7, code-reviewer ROUND 2 (corrective pass 1).

Each probe states what it checks and its expected outcome. They import the
repo's own test helpers, so they run with the tree under review first on
sys.path (PYTHONPATH = the tree; cwd = the tree).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

import s19_app
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services import variant_execution_service as service
from s19_app.tui.services.manifest_writer import check_project_files
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

from tests import test_b100_save_guards as sg
from tests.support import b100_projects as projects


def _hashes() -> None:
    root = Path(s19_app.__file__).parent
    for rel in (
        "tui/services/manifest_writer.py",
        "tui/services/variant_execution_service.py",
        "tui/app.py",
        "tui/screens.py",
    ):
        print(rel, hashlib.sha256((root / rel).read_bytes()).hexdigest()[:16])


def test_r2_import_proof() -> None:
    print("s19_app import:", s19_app.__file__)
    _hashes()


# ---------------------------------------------------------------------------
# Q1 - SEC7-3 refusal path (orchestrator-accepted: "Save project refuses and
# rolls back if it cannot keep the project.json.previous-<UTC> copy").
# P holds a project.json with an unknown top-level key (keep reason) and
# nothing else. The copy cannot be claimed (_keep_previous_manifest -> None).
# Expected on the cp1 tree: "Project NOT saved" line, project.json
# byte-identical, no .previous-* copy, and the image the save copied into P
# is rolled back (P holds only project.json again).
# ---------------------------------------------------------------------------


def test_q1_sec7_3_no_copy_refuses_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "app"
    text = '{"schema_version": 1, "active_variant": null, "custom_user_key": 7}'
    monkeypatch.setattr(
        S19TuiApp, "_keep_previous_manifest", lambda self, path, data: None
    )

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = sg._StatusProbe(app)
        project = app.workarea / "P"
        project.mkdir(parents=True)
        (project / "project.json").write_text(text, encoding="utf-8")
        src = sg._copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await sg._flush(pilot)
            app._handle_save_dialog(sg._payload(app, "P"))
            await sg._flush(pilot)
            after = (project / "project.json").read_text(encoding="utf-8")
            listing = sorted(p.name for p in project.iterdir())
        return probe.messages, after, listing

    messages, after, listing = asyncio.run(_drive())
    print("messages:", messages)
    print("listing:", listing)
    assert after == text
    assert listing == ["project.json"], listing
    assert any(m.startswith("Project NOT saved") for m in messages), messages
    assert not any(m.startswith("Saved project to") for m in messages), messages


# ---------------------------------------------------------------------------
# Q2 - the reader's paths are no longer canonicalised by resolve() (SEC7-1
# walk). A hand-edited `files` key whose case differs from the file on disk
# (Windows: same file) - digest correct.
# Expected on the pre-fix tree: 0 problems. On the cp1 tree: does the check
# now report the same file as `not recorded`?
# ---------------------------------------------------------------------------


def test_q2_files_key_case_differs_from_disk(tmp_path: Path) -> None:
    project_dir = projects.copy_sources(
        tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "P",
        projects.CASE01_DIR,
        "firmware.s19",
    )
    records = projects.file_records(project_dir)
    upper = {key.upper(): value for key, value in records.items()}
    (project_dir / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": "firmware", "files": upper}),
        encoding="utf-8",
    )
    manifest = service.read_project_manifest(project_dir)
    problems = check_project_files(project_dir, manifest)
    print("files keys:", [p.name for p in manifest.files])
    print("problems:", problems)
    assert not manifest.issues
    assert problems == [], problems


# ---------------------------------------------------------------------------
# Q3 - the 2 000-call ceiling vs a well-formed manifest inside every cap.
# batch: 1 000 existing change files under one folder (1 + 1 000 calls);
# assignments[firmware]: 1 000 existing files under another folder
# (1 + 1 000 calls); files: the image's record (1 call). Every array is at or
# under its 1 000-entry cap and every entry is safe and present.
# Expected on the pre-fix tree: every entry accepted, no finding.
# On the cp1 tree: does the ceiling skip valid entries (and the `files`
# record) as "unchecked"?
# ---------------------------------------------------------------------------


def test_q3_ceiling_inside_the_caps(tmp_path: Path) -> None:
    import time

    project_dir = projects.copy_sources(
        tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "P",
        projects.CASE01_DIR,
        "firmware.s19",
    )
    (project_dir / "p").mkdir()
    (project_dir / "q").mkdir()
    batch, assigned = [], []
    for i in range(1000):
        (project_dir / "p" / f"c{i:04d}.json").write_text("{}", encoding="utf-8")
        (project_dir / "q" / f"k{i:04d}.json").write_text("{}", encoding="utf-8")
        batch.append(f"p/c{i:04d}.json")
        assigned.append(f"q/k{i:04d}.json")
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "firmware",
                "batch": batch,
                "assignments": {"firmware": assigned},
                "files": projects.file_records(project_dir),
            }
        ),
        encoding="utf-8",
    )
    begun = time.perf_counter()
    manifest = service.read_project_manifest(project_dir)
    elapsed = time.perf_counter() - begun
    problems = check_project_files(project_dir, manifest)
    print(f"read {elapsed:.2f} s")
    print(
        "batch", len(manifest.batch),
        "assignments", len(manifest.assignments.get("firmware", [])),
        "files", len(manifest.files),
    )
    print("issues:", [(i.code, i.details) for i in manifest.issues][-3:])
    print("problems:", [(p.kind, p.file, p.reason) for p in problems][:5])
    print("rewrite refusal:", service.manifest_rewrite_refusal(manifest))
    assert len(manifest.batch) == 1000
    assert len(manifest.assignments["firmware"]) == 1000
    assert len(manifest.files) == 1
    assert not manifest.issues
