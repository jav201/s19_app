"""Reviewer probes, batch-100 Inc 8a (code-reviewer). Not shipped tests.

Run with cwd = the worktree and PYTHONPATH = the worktree.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import s19_app
import s19_app.tui.app as app_module
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

from tests.support import b100_projects as projects


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _source(tmp_path: Path) -> Path:
    return projects.copy_sources(tmp_path / "sources", projects.CASE01_DIR, "firmware.s19") / "firmware.s19"


def test_header() -> None:
    root = Path(s19_app.__file__).parent
    print("\ns19_app:", s19_app.__file__)
    for rel in ("tui/app.py", "tui/services/manifest_writer.py",
                "tui/services/variant_execution_service.py",
                "tui/services/project_gather_service.py"):
        print(hashlib.sha256((root / rel).read_bytes()).hexdigest()[:16], rel)


def test_q1_held_in_home_document_save_paints_not_recorded_but_records_it(tmp_path: Path) -> None:
    """Load P (reopens patches/boost.json), the file is held by another
    program, Save project into P. Expected by the design: the record is kept
    (R8 refined, io_error). Probe: what the status says about it."""
    base = tmp_path / "app"
    project_dir = projects.seed_document_project(_workarea(base))

    async def scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        assert len(app._change_service.document.entries) == 1
        with projects.held_exclusively(project_dir / "patches" / "boost.json"):
            messages = await projects.save_project(pilot, app, log, "P")
        return messages

    messages = projects.run_app(base, scenario)
    written = projects.read_manifest(project_dir)
    print("\nmessages:")
    for m in messages:
        print("  ", m)
    print("active_document written:", written.get("active_document"))
    print("files keys:", sorted(written.get("files", {})))
    about = [m for m in messages if "boost.json" in m]
    # The defect: one line says the document was NOT recorded while
    # project.json records it.
    assert written.get("active_document") == "patches/boost.json"
    assert not any("was not recorded" in m for m in about), about


def test_q2_outside_txt_document_is_copied_but_line_says_not_placed(tmp_path: Path) -> None:
    """A file-backed change document named boost.txt in the common patches
    folder, Save project P: the gather copies it to P/patches/boost.txt (not
    recorded, the name is outside the form). Probe: the painted line."""
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        common = app.workarea / "patches"
        common.mkdir(parents=True, exist_ok=True)
        document = common / "boost.txt"
        document.write_bytes(projects.change_document_bytes())
        result = app._change_service.load(str(document), app.base_dir)
        assert result.ok, result
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P"

    messages, project_dir = projects.run_app(tmp_path / "app", scenario)
    print("\nmessages:")
    for m in messages:
        print("  ", m)
    print("tree:", sorted(projects.tree_files(project_dir)))
    print("active_document:", projects.read_manifest(project_dir).get("active_document"))
    copied = (project_dir / "patches" / "boost.txt").is_file()
    about = [m for m in messages if "boost.txt" in m]
    assert not (copied and any("could not be placed" in m for m in about)), (copied, about)


def test_q3_change_document_recorded_under_checks_line_contradicts_record(tmp_path: Path) -> None:
    """P records active_document checks/boost.json holding a CHANGE document
    (hand-placed). Load P reopens it; Save project P. Probe: the line vs the
    written record."""
    base = tmp_path / "app"
    project_dir = projects.seed_document_project(_workarea(base), document="checks/boost.json")

    async def scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        reopened = len(app._change_service.document.entries), app._change_service.document.kind
        messages = await projects.save_project(pilot, app, log, "P")
        return reopened, messages

    reopened, messages = projects.run_app(base, scenario)
    written = projects.read_manifest(project_dir)
    print("\nreopened (entries, kind):", reopened)
    for m in messages:
        print("  ", m)
    print("active_document written:", written.get("active_document"))
    about = [m for m in messages if "boost.json" in m]
    assert not (
        written.get("active_document") == "checks/boost.json"
        and any("was not recorded" in m for m in about)
    ), about


def test_q4_plan_keys_vs_written_keys_on_a_document_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A forced pasted-document write failure: the plan's project.json keys
    vs the keys written (LLR-167.6: the plan lists the keys the save writes)."""
    import s19_app.tui.changes.io as changes_io
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    def _refuse(*args, **kwargs):
        return None, [ValidationIssue(code=changes_io.MF_WRITE_CONTAINMENT,
                                      severity=ValidationSeverity.ERROR,
                                      message="forced", artifact="change")]

    monkeypatch.setattr(changes_io, "write_change_document", _refuse)
    monkeypatch.setattr(app_module, "write_change_document", _refuse, raising=False)
    plans: list = []
    original = app_module.plan_project_save

    def _spy(*args, **kwargs):
        plan = original(*args, **kwargs)
        plans.append(plan)
        return plan

    monkeypatch.setattr(app_module, "plan_project_save", _spy)
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        app._change_service.add_entry("0x8000007C", "", "DE AD BE EF")
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P"

    messages, project_dir = projects.run_app(tmp_path / "app", scenario)
    written = tuple(json.loads((project_dir / "project.json").read_text(encoding="utf-8")))
    print("\nplan keys   :", plans[-1].manifest_keys)
    print("written keys:", written)
    for m in messages:
        print("  ", m)
    assert tuple(plans[-1].manifest_keys) == written


def test_q5_round_trip_save_load_save(tmp_path: Path) -> None:
    """Natural path: image + 1 pasted entry, Save P, Load P (reopen), Save P
    with no edit. Probe: does the second save write anything new?"""
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        app._change_service.add_entry("0x8000007C", "", "DE AD BE EF")
        first = await projects.save_project(pilot, app, log, "P")
        tree1 = sorted(projects.tree_files(app.workarea / "P"))
        man1 = projects.read_manifest(app.workarea / "P")
        await projects.load_project(pilot, app, "P")
        reopened = len(app._change_service.document.entries)
        second = await projects.save_project(pilot, app, log, "P")
        tree2 = sorted(projects.tree_files(app.workarea / "P"))
        man2 = projects.read_manifest(app.workarea / "P")
        return first, tree1, man1, reopened, second, tree2, man2

    first, tree1, man1, reopened, second, tree2, man2 = projects.run_app(tmp_path / "app", scenario)
    print("\nfirst save:"); [print("  ", m) for m in first]
    print("tree1:", tree1)
    print("manifest1 active_variant/derived:", man1.get("active_variant"), man1.get("derived_from"))
    print("reopened entries:", reopened)
    print("second save:"); [print("  ", m) for m in second]
    print("tree2:", tree2)
    print("manifest2 active_variant/derived:", man2.get("active_variant"), man2.get("derived_from"))
    assert tree2 == tree1


@pytest.mark.parametrize("doc_name", ["aux.json", "con.json"])
def test_q6_document_with_a_device_stem_refuses_the_whole_save(tmp_path: Path, doc_name: str) -> None:
    """A file-backed change document whose stem is a Windows device name
    (a real, listable file on this host). The app's pre-check
    (is_active_document_form) accepts its landing; the writer's
    _reject_unsafe_entry refuses it. Pre-ruling 2 / R11: the save is never
    refused because of the document."""
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        common = app.workarea / "patches"
        common.mkdir(parents=True, exist_ok=True)
        document = common / doc_name
        document.write_bytes(projects.change_document_bytes())
        assert document.is_file()
        result = app._change_service.load(str(document), app.base_dir)
        assert result.ok, result
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P"

    messages, project_dir = projects.run_app(tmp_path / "app", scenario)
    print("\nmessages:")
    for m in messages:
        print("  ", m)
    print("P exists:", project_dir.exists(), sorted(projects.tree_files(project_dir)))
    assert any(m.startswith("Saved project to") for m in messages), messages
