"""Reviewer probes, round 2, batch-100 Inc 8a (code-reviewer). Not shipped tests.

Run with cwd = the worktree and PYTHONPATH = the tree under test.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import s19_app
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

from tests.support import b100_projects as projects


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def test_header() -> None:
    root = Path(s19_app.__file__).parent
    print("\ns19_app:", s19_app.__file__)
    for rel in ("tui/app.py", "tui/services/manifest_writer.py",
                "tui/services/variant_execution_service.py",
                "tui/services/project_gather_service.py"):
        print(hashlib.sha256((root / rel).read_bytes()).hexdigest()[:16], rel)


def _respell(path: Path, how: str) -> str:
    text = str(path)
    if how == "drive":
        return text[0].swapcase() + text[1:]
    if how == "project":
        # ...\workarea\P\patches\boost.json -> ...\workarea\p\patches\boost.json
        parts = list(Path(text).parts)
        parts[-3] = parts[-3].lower()
        return str(Path(*parts))
    raise ValueError(how)


@pytest.mark.skipif(os.name != "nt", reason="case-insensitive Windows volume")
@pytest.mark.parametrize("how", ["drive", "project"])
def test_r2p1_own_document_reopened_with_another_spelling(
    tmp_path: Path, how: str, monkeypatch
) -> None:
    """Load P (reopens patches/boost.json). The user opens the SAME file in
    the Patch Editor by a path spelled in another case (a lower-case drive
    letter, or the project folder in lower case; on this case-insensitive
    volume it is the same file). Save project P. Before cp1 (normcase) the
    document is in_home -> keep, recorded. Probe: what cp1 records and paints."""
    import s19_app.tui.app as app_module

    plans = []
    real = app_module.plan_project_save

    def spy(*args, **kwargs):
        plans.append(real(*args, **kwargs))
        return plans[-1]

    monkeypatch.setattr(app_module, "plan_project_save", spy)
    base = tmp_path / "app"
    project_dir = projects.seed_document_project(_workarea(base))
    before = sorted(projects.tree_files(project_dir))

    async def scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        spelled = _respell(project_dir / "patches" / "boost.json", how)
        result = app._change_service.load(spelled, app.base_dir)
        assert result.ok, result
        print("\nsource_path:", app._change_service.document.source_path)
        messages = await projects.save_project(pilot, app, log, "P")
        return messages

    messages = projects.run_app(base, scenario)
    written = projects.read_manifest(project_dir)
    after = sorted(projects.tree_files(project_dir))
    print("messages:")
    for m in messages:
        print("  ", m)
    print("tree before:", before)
    print("tree after:", after)
    print("active_document written:", written.get("active_document"))
    print("gathered:", written.get("gathered"))
    for row in plans[-1].rows:
        print("plan row:", row.role, row.landing, row.action)
    assert any("Saved project to" in m for m in messages), messages
    assert written.get("active_document") == "patches/boost.json"
    docs_before = [f for f in before if f.startswith("patches/")]
    docs_after = [f for f in after if f.startswith("patches/")]
    assert docs_after == docs_before, (docs_before, docs_after)


@pytest.mark.skipif(os.name != "nt", reason="junctions")
def test_r2p2_file_backed_document_with_junctioned_home(tmp_path: Path, monkeypatch) -> None:
    """SEC8a-3 for the FILE-BACKED (outside) arm: P/patches is a junction to
    Q/patches; the document is boost.json in the common patches folder; Save
    project P. Probe: the save completes, Q unchanged, no active_document,
    one true line."""
    import shutil

    import s19_app.tui.app as app_module
    from tests.support import b100_links

    b100_links.require_junctions()
    plans = []
    real = app_module.plan_project_save

    def spy(*args, **kwargs):
        plans.append(real(*args, **kwargs))
        return plans[-1]

    monkeypatch.setattr(app_module, "plan_project_save", spy)
    src = projects.copy_sources(tmp_path / "sources", projects.CASE01_DIR, "firmware.s19") / "firmware.s19"
    base = tmp_path / "app"
    workarea = _workarea(base)
    q_patches = workarea / "Q" / "patches"
    q_patches.mkdir(parents=True)
    (q_patches / "boost.json").write_bytes(b'{"q": "own file"}')
    project_dir = workarea / "P"
    project_dir.mkdir(parents=True)
    shutil.copy2(src, project_dir / "firmware.s19")
    b100_links.create_junction(project_dir / "patches", q_patches)
    before = sorted((item.name, item.read_bytes()) for item in q_patches.iterdir())

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        common = app.workarea / "patches"
        common.mkdir(parents=True, exist_ok=True)
        document = common / "boost.json"
        document.write_bytes(projects.change_document_bytes())
        result = app._change_service.load(str(document), app.base_dir)
        assert result.ok, result
        return await projects.save_project(pilot, app, log, "P")

    messages = projects.run_app(base, scenario)
    print("\nmessages:")
    for m in messages:
        print("  ", m)
    for row in plans[-1].rows:
        print("plan row:", row.role, row.landing, row.action)
    after = sorted((item.name, item.read_bytes()) for item in q_patches.iterdir())
    print("Q/patches after:", [name for name, _ in after])
    print("active_document:", projects.read_manifest(project_dir).get("active_document"))
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert after == before
    assert "active_document" not in projects.read_manifest(project_dir)
    about = [m for m in messages if "boost" in m]
    assert len(about) == 1, about
