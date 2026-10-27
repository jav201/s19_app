"""Batch-100 increment 2 — Save project name guards (incl. fix pass 1:
review findings F1–F11 and SEC2-1..3, LED .52 (a)/(b)/(c); fix pass 2:
review round 2 R2-1..R2-5 and SEC2-4; fix pass 3: review round 3
R3-1, R3-2; fix pass 4 (the LED .53 redesign): SEC2-5 and SEC2-6 —
the rollback removes exactly what the save created, never "what the
snapshot lacks"; fix pass 5 (the redesign corrective pass): SEC2-7/8/9
(security round 4) and R5-1/R5-2 (review round 5) — the placement is
the sole reuse judge, the manifest write joins the exact-created lists
the moment it returns, and a gather home created before a failed copy
is recorded and removed.

Covers HLR-164 / LLR-164.1–LLR-164.4:

  - TC-B100-04 — LLR-164.1: reserved homes and Windows device names are
    refused case-folded, on the raw and the sanitised name, before any
    folder is created; the device predicate takes the stem up to the
    FIRST dot with trailing spaces/dots stripped (``con.tar.gz``,
    ``NUL.tar.gz``, ``com1.a.b``, ``CON .txt`` refused; ``COM⁴``
    accepted); the empty name is refused with its tokens;
    ``list_projects`` omits reserved homes case-folded.
  - TC-B100-05 — LLR-164.2: the Q-2 decisions — a disguised clash is
    refused naming both names, an exact-name save into a project that is
    not open adds a variant, the open project's name typed unsanitised
    (or in another case, LED .52(a)) saves into the open project under
    its ON-DISK name, a case-only match against ANOTHER project is still
    a clash, a link/junction target is refused. (The merge carry of
    ``gathered`` / ``active_document`` is Inc 8a's arm, not this
    increment's.)
  - TC-B100-06 — LLR-164.3: the 64-character cap, the full-path limit
    (work area padded to L = 150) and no crash on a 300-character name.
  - TC-B100-07 — LLR-164.4: an AST census over ``_handle_save_dialog``
    (every post-creation return rolls back through the one
    ``_abort_save`` helper — a bare folder-removal call no longer
    passes, R2-4) plus a forced ``OSError`` at each
    post-creation stage and a refused manifest write — 0 folders left,
    the APP STATE (variant ids, variant paths, current variant,
    ``current_project``) restored to its pre-save snapshot (F1), the
    files a failed merge placed into an existing folder removed (F5 /
    LED .52(b)) — EVERY file and folder the save placed, the gather's
    change/check documents with their home folders included, the
    target's recursive tree exactly as the pre-save snapshot and a
    byte-identical file the gather reused at a pre-existing path kept
    (R2-1 / SEC2-4); fix pass 4 (LED .53): the rollback removes EXACTLY
    what THIS save created — the placements whose reuse flag is false
    and the files the gather actually wrote, plus the folders this save
    created while empty — it walks no folder and diffs against no
    snapshot, so a pre-existing file inside a folder that was unreadable
    when the save started survives (SEC2-5, arm R7) and so does a file
    another writer added during the save (SEC2-6, arm R8); a manifest
    verify MISMATCH stays the NEWEST
    painted status line after the success line (R2-5); an unreadable
    work-area folder skipped, never a raise (SEC2-1 / F8); the rollback
    never follows a junction — an outside file a concurrent writer
    dropped into the junction's target survives a failed save, and a
    junction cycle does not block the save (R3-1), plus the
    ``walk_tree_no_links`` unit arm (LLR-171.1's reusable walker).
  - AT-B100-02 — HLR-164 through the shipped Save project dialog, driven
    by keys at 118x54 and 220x60 with notifications on; the acceptance
    scene builds ``prg`` (P2) and ``ab`` by real saves and opens P2
    through the Load project dialog by keys (LED .52(c)).

Byte oracles: on-disk digests are SHA-256 manifest snapshots taken by this
module (a fixture manifest); no ``s19_app`` loader reads them back.
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.widgets import Label

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services import project_gather_service as gather_module
from s19_app.tui.screens import LoadFileScreen
from s19_app.tui.screens import LoadProjectScreen
from s19_app.tui.screens import SaveProjectScreen
from s19_app.tui.services.manifest_writer import MANIFEST_MISMATCH
from s19_app.tui.services.manifest_writer import ManifestVerifyResult
from s19_app.tui.workspace import PROJECT_NAME_MAX_CHARS
from s19_app.tui.workspace import RESERVED_WORKAREA_HOMES
from s19_app.tui.workspace import WORKAREA_DIRNAME
from s19_app.tui.workspace import WORKAREA_PATCHES
from s19_app.tui.workspace import WORKAREA_SUBDIR
from s19_app.tui.workspace import is_windows_device_name

from tests.support import b100_links

ROOT = Path(__file__).resolve().parents[1]
CASE01 = ROOT / "examples" / "case_01_basic_valid" / "firmware.s19"

#: The longest fixed in-project file suffix (LLR-164.3): the before/after
#: report name ``\\reports\\<ts>-NN-before-after-report.html`` costs 53
#: characters beyond the project folder path.
_REPORT_SUFFIX_CHARS = 53
#: The full-path limit (the ``_MAX_FULL_PATH`` idiom, LLR-164.3).
_MAX_FULL_PATH = 259


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _copy_source(tmp_path: Path) -> Path:
    """A scratch copy of the case_01 image — the example stays pristine."""
    src = tmp_path / "sources" / "firmware.s19"
    src.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CASE01, src)
    return src


def _make_project(app: S19TuiApp, name: str, files: dict[str, str]) -> Path:
    """Create ``.s19tool/workarea/<name>/`` with the given text files."""
    project_dir = app.workarea / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="ascii")
    return project_dir


def _digest_manifest(root: Path) -> dict:
    """Every file under ``root`` with its SHA-256 — the unchanged oracle."""
    if not root.exists():
        return {}
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _tree_listing(root: Path) -> dict:
    """Every file AND folder under ``root`` — files carry their SHA-256,
    folders the literal ``"dir"`` (R2-1 / SEC2-4's oracle: a failed
    save leaves the target's recursive tree exactly as the pre-save
    snapshot, with no home folder the gather created left behind)."""
    if not root.exists():
        return {}
    return {
        str(p.relative_to(root)): (
            "dir" if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest()
        )
        for p in sorted(root.rglob("*"))
    }


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so the deferred apply chain runs."""
    for _ in range(count):
        await pilot.pause()


async def _wait_for(pilot, predicate, description: str, attempts: int = 150) -> None:
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


def _status_text(app: S19TuiApp) -> str:
    """The painted newest status line (the ``#log_line_4`` label)."""
    return str(app.query_one("#log_line_4", Label).render())


def _file_status_text(app: S19TuiApp) -> str:
    """The painted durable file-state line (the ``#status_text`` label)."""
    return str(app.query_one("#status_text", Label).render())


class _StatusProbe:
    """Records every ``set_status`` message while painting it for real."""

    def __init__(self, app: S19TuiApp) -> None:
        self.messages: list[str] = []
        original = app.set_status

        def record(message) -> None:
            self.messages.append(str(message))
            original(message)

        app.set_status = record

    @property
    def last(self) -> str:
        return self.messages[-1] if self.messages else ""


def _payload(app: S19TuiApp, name: str) -> "app_module.SaveProjectPayload":
    return app_module.SaveProjectPayload(
        parent_folder=str(app.workarea), project_name=name
    )


async def _load_and_save(
    tmp_path: Path, project_name: str, monkeypatch=None
) -> tuple:
    """One app: load the case_01 image, call the save handler with the
    name, and return (status probe messages, workarea folder names)."""
    base = tmp_path / "app"
    src = _copy_source(tmp_path)

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, project_name))
            await _flush(pilot)
            folders = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
        return probe.messages, folders

    return await _drive()


# ---------------------------------------------------------------------------
# TC-B100-04 — LLR-164.1: reserved homes and device names, case-folded
# ---------------------------------------------------------------------------


def test_tc_b100_04_reserved_homes_refused_in_every_casing(tmp_path: Path) -> None:
    """Every ``RESERVED_WORKAREA_HOMES`` entry in 3 casings: refused before
    any folder is created or written, with the ``reserved name`` and
    ``choose another name`` tokens; the work area's file manifest AND its
    folder list are untouched by every refusal (F9: a refusal placed
    after ``mkdir`` would still pass a file-only oracle)."""
    casings = [str.lower, str.title, str.upper]

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        before = _digest_manifest(app.workarea)
        folders_before = (
            sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
            if app.workarea.exists()
            else []
        )
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            for home in RESERVED_WORKAREA_HOMES:
                for fold in casings:
                    typed = fold(home)
                    app._handle_save_dialog(_payload(app, typed))
                    await _flush(pilot)
                    status = probe.last
                    assert "reserved name" in status, (
                        f"{typed!r}: expected the reserved-name refusal, "
                        f"got {status!r}"
                    )
                    assert "choose another name" in status, (
                        f"{typed!r}: expected the next-step token, "
                        f"got {status!r}"
                    )
                    assert _digest_manifest(app.workarea) == before, (
                        f"{typed!r}: a refused save wrote into the work area"
                    )
            folders_after = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
        return probe.messages, folders_before, folders_after

    messages, folders_before, folders_after = asyncio.run(_drive())
    assert len(messages) == len(RESERVED_WORKAREA_HOMES) * len(casings)
    assert folders_after == folders_before, (
        f"a refused save changed the work-area folders: "
        f"{folders_before} -> {folders_after}"
    )


def test_tc_b100_04_empty_names_refused(tmp_path: Path) -> None:
    """``""``, ``"   "`` and ``"!!!"`` (no usable characters): every
    empty-name refusal paints the ``name is empty`` and
    ``type a project name`` tokens, 0 folders appear, the app keeps
    running (review finding F6 — without this arm reverting the
    empty-name statuses leaves the module green)."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            for typed in ["", "   ", "!!!"]:
                app._handle_save_dialog(_payload(app, typed))
                await _flush(pilot)
                status = probe.last
                assert "name is empty" in status, (
                    f"{typed!r}: expected the empty-name refusal, "
                    f"got {status!r}"
                )
                assert "type a project name" in status, (
                    f"{typed!r}: expected the next-step token, got {status!r}"
                )
            folders = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
        return probe.messages, folders

    messages, folders = asyncio.run(_drive())
    assert len(messages) == 3, messages
    assert folders == ["patches", "temp"], folders


def test_tc_b100_04_device_names_refused_raw_and_sanitised(tmp_path: Path) -> None:
    """``nul``, ``CON``, ``com1``, ``LPT¹`` (superscript), ``con.txt`` (raw
    only — the sanitised name is ``contxt``), ``CONIN$`` (raw),
    ``C O N`` (sanitises to ``CON``) and the multi-dot / trailing-space
    arms ``con.tar.gz``, ``NUL.tar.gz``, ``com1.a.b``, ``CON .txt``
    (F3 / SEC2-2 — Windows matches the stem before the FIRST dot): 11
    refusals with the ``device name`` and ``choose another name`` tokens,
    0 folders."""
    device_names = [
        "nul",
        "CON",
        "com1",
        "LPT¹",
        "con.txt",
        "CONIN$",
        "C O N",
        "con.tar.gz",
        "NUL.tar.gz",
        "com1.a.b",
        "CON .txt",
    ]

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            for typed in device_names:
                app._handle_save_dialog(_payload(app, typed))
                await _flush(pilot)
                status = probe.last
                assert "device name" in status, (
                    f"{typed!r}: expected the device-name refusal, "
                    f"got {status!r}"
                )
                assert "choose another name" in status, (
                    f"{typed!r}: expected the next-step token, got {status!r}"
                )
                leftovers = [
                    item.name
                    for item in app.workarea.iterdir()
                    if item.is_dir() and item.name != "temp"
                ]
                leftovers = [
                    name
                    for name in leftovers
                    if name.casefold() not in {h.casefold() for h in RESERVED_WORKAREA_HOMES}
                ]
                assert leftovers == [], (
                    f"{typed!r}: folders appeared for a refused name: {leftovers}"
                )
        return probe.messages

    messages = asyncio.run(_drive())
    assert len(messages) == len(device_names)


def test_tc_b100_04_device_predicate_stem_before_first_dot() -> None:
    """The one shared predicate (F3 / SEC2-2, frozen at B100-I11): the
    stem up to the FIRST dot, with trailing spaces and dots stripped,
    decides — ``con.tar.gz`` / ``NUL.tar.gz`` / ``com1.a.b`` /
    ``CON .txt`` / ``CON.`` are device names, ``COM⁴`` is not, and the
    superscript digits ¹²³ stay refused (they fold to 123)."""
    refused = ["con.tar.gz", "NUL.tar.gz", "com1.a.b", "CON .txt", "CON.", "LPT¹"]
    accepted = ["COM⁴", "console", "lpt10x", "normal.txt", ""]
    for name in refused:
        assert is_windows_device_name(name), f"{name!r} must be a device name"
    for name in accepted:
        assert not is_windows_device_name(name), (
            f"{name!r} must not be a device name"
        )


def test_tc_b100_04_list_projects_omits_reserved_homes_casefolded(
    tmp_path: Path,
) -> None:
    """Folders ``Splits`` / ``Reports`` exist on disk (``sPlItS`` is the
    same folder as ``Splits`` on a case-insensitive volume, so it cannot
    be a third folder — F9); ``list_projects`` lists 0 of them and keeps
    the real project."""

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path / "app")
        _make_project(app, "Splits", {})
        _make_project(app, "Reports", {})
        project = _make_project(app, "realproject", {"a.s19": "S1131000\n"})
        (project / "a.s19").write_text(
            "S11310000102030405060708090A0B0C0D0E0F1054\nS9030000FC\n",
            encoding="ascii",
        )
        async with app.run_test() as pilot:
            await pilot.pause()
            return app.list_projects()

    assert asyncio.run(_drive()) == ["realproject"]


# ---------------------------------------------------------------------------
# TC-B100-05 — LLR-164.2: Q-2 — clash, merge and the open project
# ---------------------------------------------------------------------------

_S19_A = "S11310000102030405060708090A0B0C0D0E0F1054\nS9030000FC\n"
_S19_B = "S1132000A0B1C2D3E4F5061728394A5B6C7D8E9FD4\nS9030000FC\n"

#: A minimal valid v2 change document (zero entries) — the gathered
#: composition document of the R2-1 / SEC2-4 merge arms, resolved from
#: the common ``patches/`` library the same way the operator's batch does.
_CHANGE_DOC = json.dumps(
    {
        "format": "s19app-changeset",
        "version": "2.0",
        "kind": "change",
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": [],
    }
)


def test_tc_b100_05_disguised_clash_refused_naming_both(tmp_path: Path) -> None:
    """Project ``ab`` exists and is not open; ``a b`` is refused BEFORE any
    write, the refusal names both names with ``already a project`` and
    ``choose another name``, and ``ab/`` is byte-identical afterwards."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
        before = _digest_manifest(project_dir)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "a b"))
            await _flush(pilot)
            status = probe.last
            after = _digest_manifest(project_dir)
            names = sorted(p.name for p in project_dir.iterdir())
        return status, before, after, names

    status, before, after, names = asyncio.run(_drive())
    assert "already a project" in status, status
    assert "choose another name" in status, status
    assert "'a b'" in status and "'ab'" in status, (
        f"the refusal must name both names: {status!r}"
    )
    assert before == after, "a refused save changed the target project"
    assert names == ["a.s19"], names


def test_tc_b100_05_case_only_clash_refused(tmp_path: Path) -> None:
    """``AB`` against folder ``ab`` is a clash too — the typed name differs
    from the folder name; one refusal naming both."""

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        _make_project(app, "ab", {"a.s19": _S19_A})
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "AB"))
            await _flush(pilot)
            return probe.last

    status = asyncio.run(_drive())
    assert "already a project" in status, status
    assert "choose another name" in status, status
    assert "'AB'" in status and "'ab'" in status, status


def test_tc_b100_05_exact_name_adds_a_variant(tmp_path: Path) -> None:
    """``ab`` typed exactly against project ``ab`` (not open): no refusal —
    the save merges, adding the loaded image as one new variant."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
        src = tmp_path / "sources" / "firmware.s19"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(_S19_B, encoding="ascii")
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "ab"))
            await _flush(pilot)
            names = sorted(p.name for p in project_dir.iterdir())
            variant_ids = [v.variant_id for v in app._variant_set.variants]
        return probe.messages, names, variant_ids

    messages, names, variant_ids = asyncio.run(_drive())
    assert "already a project" not in " ".join(messages), messages
    assert names == ["a.s19", "firmware.s19", "project.json"], names
    assert variant_ids == ["a", "firmware"], variant_ids


def test_tc_b100_05_open_project_unsanitised_name_saves_into_it(
    tmp_path: Path,
) -> None:
    """Project ``ab`` is OPEN; ``a b`` typed: saved INTO the open project
    (the unsanitised form of its name), not refused, no folder ``a b``."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("ab")
            await _flush(pilot)
            app.load_selected_file(src)
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "a b"))
            await _flush(pilot)
            status = probe.last
            messages = list(probe.messages)
            names = sorted(p.name for p in project_dir.iterdir())
            a_b_exists = (app.workarea / "a b").exists()
        return status, messages, names, a_b_exists

    status, messages, names, a_b_exists = asyncio.run(_drive())
    assert any("Saved project" in message for message in messages), messages
    assert "already a project" not in " ".join(messages), messages
    assert names == ["a.s19", "firmware.s19", "project.json"], names
    assert not a_b_exists


def test_tc_b100_05_open_project_case_variant_saves_under_on_disk_name(
    tmp_path: Path,
) -> None:
    """LED .52(a) / F4: project ``ab`` is OPEN; ``AB`` typed saves INTO
    the open project under its ON-DISK name — ``current_project`` keeps
    the on-disk spelling, ``current_project_dir`` names the on-disk
    folder and the work-area folder list gains no new folder (on a
    case-insensitive volume ``workarea / "AB"`` IS the ``ab`` folder, so
    the oracle is the folder-name list, compared case-sensitively)."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("ab")
            await _flush(pilot)
            app.load_selected_file(src)
            await _flush(pilot)
            folders_before = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
            app._handle_save_dialog(_payload(app, "AB"))
            await _flush(pilot)
            status = probe.last
            names = sorted(p.name for p in project_dir.iterdir())
            folders_after = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
            current = app.current_project
            current_dir_name = app.current_project_dir.name
        return status, names, folders_before, folders_after, current, current_dir_name

    status, names, folders_before, folders_after, current, current_dir_name = asyncio.run(
        _drive()
    )
    assert "Saved project" in status, status
    assert folders_after == folders_before, (
        f"the case-variant save changed the work-area folders: "
        f"{folders_before} -> {folders_after}"
    )
    assert current == "ab", f"current_project must keep the on-disk spelling: {current!r}"
    assert current_dir_name == "ab", current_dir_name
    assert names == ["a.s19", "firmware.s19", "project.json"], names


def test_tc_b100_05_case_only_match_against_another_project_refused(
    tmp_path: Path,
) -> None:
    """LED .52(a): with project ``cd`` OPEN, ``AB`` against the folder
    ``ab`` — ANOTHER project — is still a disguised clash, refused
    naming both names."""

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        _make_project(app, "ab", {"a.s19": _S19_A})
        _make_project(app, "cd", {"c.s19": _S19_B})
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("cd")
            await _flush(pilot)
            app.load_selected_file(src)
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "AB"))
            await _flush(pilot)
            return probe.last

    status = asyncio.run(_drive())
    assert "already a project" in status, status
    assert "choose another name" in status, status
    assert "'AB'" in status and "'ab'" in status, (
        f"the refusal must name both names: {status!r}"
    )


def test_tc_b100_05_junction_target_refused_without_writing(
    tmp_path: Path,
) -> None:
    """A junction ``evil`` in the work area: Save project into ``evil`` is
    refused with ``link or junction`` and ``choose another name`` before
    any resolve/write; 0 bytes land in the junction's target."""
    b100_links.require_junctions()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        victim = tmp_path / "victim"
        victim.mkdir()
        b100_links.create_junction(app.workarea / "evil", victim)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "evil"))
            await _flush(pilot)
            status = probe.last
            victim_files = _digest_manifest(victim)
        return status, victim_files

    status, victim_files = asyncio.run(_drive())
    assert "link or junction" in status, status
    assert "choose another name" in status, status
    assert victim_files == {}, victim_files


# ---------------------------------------------------------------------------
# TC-B100-06 — LLR-164.3: name cap, path limit and OSError
# ---------------------------------------------------------------------------


def test_tc_b100_06_name_cap_boundary(tmp_path: Path) -> None:
    """64 characters → saved; 65 and 300 → refused with ``name too long``
    and ``shorten the name``, 0 folders, the app keeps running."""
    cap = PROJECT_NAME_MAX_CHARS
    assert cap == 64

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "n" * 64))
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "n" * 65))
            await _flush(pilot)
            refused_65 = probe.last
            app._handle_save_dialog(_payload(app, "n" * 300))
            await _flush(pilot)
            refused_300 = probe.last
            messages = list(probe.messages)
            folders = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
        return messages, refused_65, refused_300, folders

    messages, refused_65, refused_300, folders = asyncio.run(_drive())
    assert any("Saved project" in message for message in messages), messages
    assert "name too long" in refused_65, refused_65
    assert "shorten the name" in refused_65, refused_65
    assert "name too long" in refused_300, refused_300
    assert "shorten the name" in refused_300, refused_300
    assert folders == ["n" * 64, "patches", "temp"], folders


def _padded_base(tmp_path: Path, target_len: int = 150) -> Path:
    """A base folder whose work-area string is exactly ``target_len`` long
    (the L = 150 enabler of the proposal's path-limit arms)."""
    tail = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    pad = target_len - len(str(tail)) - 1
    assert pad > 0, f"tmp_path too deep for the L = 150 enabler: {tail}"
    return tmp_path / ("p" * pad)


def test_tc_b100_06_path_limit_met_and_exceeded(tmp_path: Path) -> None:
    """L = 150: a 55-character name gives 150 + 1 + 55 + 53 = 259 (saved);
    a 56-character name gives 260 — refused with ``path too long`` and
    ``shorten the name``, 0 folders."""
    base = _padded_base(tmp_path)

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        assert len(str(app.workarea)) == 150, len(str(app.workarea))
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "a" * 55))
            await _flush(pilot)
            app._handle_save_dialog(_payload(app, "a" * 56))
            await _flush(pilot)
            refused = probe.last
            messages = list(probe.messages)
            folders = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
        return messages, refused, folders

    messages, refused, folders = asyncio.run(_drive())
    assert any("Saved project" in message for message in messages), messages
    assert "path too long" in refused, refused
    assert "shorten the name" in refused, refused
    assert folders == ["a" * 55, "patches", "temp"], folders


# ---------------------------------------------------------------------------
# TC-B100-07 — LLR-164.4: a refused or failed save leaves no folder
# ---------------------------------------------------------------------------


def _app_module_ast() -> ast.Module:
    source = (ROOT / "s19_app" / "tui" / "app.py").read_text(encoding="utf-8")
    return ast.parse(source)


def _save_handler_ast(tree: ast.Module) -> ast.FunctionDef:
    return next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "_handle_save_dialog"
    )


#: LED .52(b): every post-creation failure exit rolls back through the
#: one ``_abort_save`` helper (which folds the state restore, the
#: exact-created file removal and the created-folder removal, LED .53).
#: A bare folder-removal call is NOT accepted: an exit that removes the
#: folder while restoring nothing and leaving the placed files behind
#: would otherwise pass the census (review finding R2-4).
_ABORT_HELPERS = {"_abort_save"}


def _contains_abort_call(node: ast.AST) -> bool:
    return any(
        isinstance(sub, ast.Call)
        and isinstance(sub.func, ast.Attribute)
        and sub.func.attr in _ABORT_HELPERS
        for sub in ast.walk(node)
    )


def _contains_folder_removal(node: ast.AST) -> bool:
    return any(
        isinstance(sub, ast.Attribute) and sub.attr == "rmdir"
        for sub in ast.walk(node)
    )


def test_tc_b100_07_ast_census_every_post_creation_return_removes(
    tmp_path: Path,
) -> None:
    """The census: every ``return`` after the folder's creation sits in a
    block that first calls the one ``_abort_save`` rollback (a bare
    folder-removal exit does NOT count — R2-4); exactly one ``except
    OSError`` handler exists AFTER the folder's creation and it rolls
    back too (the pre-creation clash scan keeps its own skip-handler,
    SEC2-1); the one ``_abort_save`` helper removes exactly the files and
    folders the save created (LED .53 — ``unlink`` on the placed list,
    ``rmdir`` on the created folders) and restores the pre-save app
    state."""
    tree = _app_module_ast()
    handler = _save_handler_ast(tree)
    parent_of: dict = {}
    for node in ast.walk(handler):
        for child in ast.iter_child_nodes(node):
            parent_of[child] = node

    mkdir_lines = [
        node.lineno
        for node in ast.walk(handler)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "mkdir"
    ]
    assert mkdir_lines, "the handler must create the project folder"
    first_mkdir = min(mkdir_lines)

    post_creation_returns = [
        node
        for node in ast.walk(handler)
        if isinstance(node, ast.Return) and node.lineno > first_mkdir
    ]
    assert len(post_creation_returns) >= 3, (
        f"expected at least 3 post-creation returns, "
        f"found {len(post_creation_returns)}"
    )
    for node in post_creation_returns:
        block = parent_of.get(node)
        siblings = getattr(block, "body", None)
        assert siblings is not None, node.lineno
        index = next(
            i for i, stmt in enumerate(siblings) if stmt is node
        )
        assert any(
            _contains_abort_call(stmt) for stmt in siblings[:index]
        ), (
            f"return at line {node.lineno} leaves without rolling back "
            f"the failed save"
        )

    # The pre-mkdir clash scan holds its own ``except OSError`` (SEC2-1:
    # an unreadable folder is skipped, it never rolls a save back); the
    # LLR-164.4 census scopes to the handlers AFTER the folder's creation.
    oSError_handlers = [
        node
        for node in ast.walk(handler)
        if isinstance(node, ast.ExceptHandler)
        and node.type is not None
        and getattr(node.type, "id", "") == "OSError"
        and node.lineno > first_mkdir
    ]
    assert len(oSError_handlers) == 1, (
        f"exactly one post-creation OSError handler, "
        f"found {len(oSError_handlers)}"
    )
    assert _contains_abort_call(oSError_handlers[0]), (
        "the post-creation OSError handler must roll the failed save back"
    )

    helpers = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_abort_save"
    ]
    assert len(helpers) == 1, (
        f"exactly one _abort_save helper, found {len(helpers)}"
    )
    helper = helpers[0]
    assert _contains_folder_removal(helper), (
        "_abort_save must remove the folders the save created (LED .53)"
    )
    assert any(
        isinstance(sub, ast.Attribute) and sub.attr == "unlink"
        for sub in ast.walk(helper)
    ), "_abort_save must unlink the files the save placed"
    assert any(
        isinstance(sub, ast.Attribute) and sub.attr == "_variant_set"
        for sub in ast.walk(helper)
    ), "_abort_save must restore the pre-save app state"


def _snapshot_app_state(app: S19TuiApp) -> tuple:
    """The app state a failed save must restore (review finding F1):
    the variant ids and paths, the current variant, the report filter
    and the current project."""
    variant_set = app._variant_set
    return (
        None
        if variant_set is None
        else [v.variant_id for v in variant_set.variants],
        None
        if variant_set is None
        else [str(v.path) for v in variant_set.variants],
        app.current_file.variant_id if app.current_file else None,
        app._report_filter_path,
        app.current_project,
    )


def _force_stage(monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    """Monkeypatch one post-creation stage to fail — an OSError raise for
    the ``OSError`` stages, a ``(None, issues)`` refusal for the manifest
    writer (collect-don't-abort, never a raise)."""

    def _raiser(*args, **kwargs):
        raise OSError(f"forced failure at the {stage} stage")

    original_validate = app_module.validate_project_files
    validate_calls = {"count": 0}

    def _validate_once_then_raise(project_dir):
        validate_calls["count"] += 1
        if validate_calls["count"] > 1:
            raise OSError("forced failure at the variant-rebuild stage")
        return original_validate(project_dir)

    if stage == "validation":
        monkeypatch.setattr(app_module, "validate_project_files", _raiser)
    elif stage == "copies":
        # LED .53 re-pin: the save body places through
        # ``place_into_workarea`` (the reuse flag feeds the exact-list
        # rollback), so the copies-stage break patches that seam.
        monkeypatch.setattr(app_module, "place_into_workarea", _raiser)
    elif stage == "variant-rebuild":
        monkeypatch.setattr(
            app_module, "validate_project_files", _validate_once_then_raise
        )
    elif stage == "gather":
        monkeypatch.setattr(app_module, "gather_project_artifacts", _raiser)
    elif stage == "manifest":
        monkeypatch.setattr(app_module, "write_project_manifest", _raiser)
    elif stage == "manifest-refused":
        monkeypatch.setattr(
            app_module,
            "write_project_manifest",
            lambda *args, **kwargs: (
                None,
                [SimpleNamespace(message="forced manifest refusal")],
            ),
        )
    else:
        raise AssertionError(f"unknown forced stage: {stage}")


@pytest.mark.parametrize(
    "stage",
    [
        "validation",
        "copies",
        "variant-rebuild",
        "gather",
        "manifest",
        "manifest-refused",
    ],
)
def test_tc_b100_07_forced_oserror_leaves_no_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    """A forced failure at each post-creation stage, with a project
    ALREADY open: the handler paints the ``could not save`` tokens,
    removes the folder this call created, restores the app's variant set,
    current variant and current project to their pre-save state (F1 /
    LED .52(b)), raises nothing and the app keeps running."""
    base = tmp_path / "app"
    name = f"stage-{stage}"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        _make_project(app, "pre", {"a.s19": _S19_A})
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("pre")
            await _flush(pilot)
            # The patch goes down only AFTER the project is open, so the
            # load path itself keeps the real functions.
            _force_stage(monkeypatch, stage)
            state_before = _snapshot_app_state(app)
            app._handle_save_dialog(_payload(app, name))
            await _flush(pilot)
            status = probe.last
            state_after = _snapshot_app_state(app)
            folders = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
        return status, folders, state_before, state_after

    status, folders, state_before, state_after = asyncio.run(_drive())
    assert "could not save" in status, f"{stage}: {status}"
    assert "check the folder" in status, f"{stage}: {status}"
    assert folders == ["patches", "pre", "temp"], f"{stage}: {folders}"
    assert state_after == state_before, (
        f"{stage}: the failed save left app state behind — "
        f"before {state_before!r}, after {state_after!r}"
    )
    assert state_before[4] == "pre", state_before


@pytest.mark.parametrize(
    "target,typed,stage",
    [
        ("exact", "ab", "gather"),
        ("exact", "ab", "manifest-refused"),
        ("open-case", "AB", "gather"),
    ],
)
def test_tc_b100_07_failed_merge_removes_placed_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    typed: str,
    stage: str,
) -> None:
    """LED .52(b) / F5 / SEC2-3: a failed save into a folder that already
    existed (the exact-name merge, or the open project typed in another
    case) removes every file it placed — the target's file set and its
    digest are exactly as before — while a byte-identical file the
    placement reused is kept, and the app's state returns to its
    pre-save snapshot."""
    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            if target == "open-case":
                app._handle_load_project("ab")
                await _flush(pilot)
                # the current file is the open project's own a.s19 — its
                # placement into ab is a byte-identical reuse
            else:
                app.load_selected_file(src)
                await _flush(pilot)
            # The patch goes down only AFTER the optional project load,
            # so the load path itself keeps the real functions.
            _force_stage(monkeypatch, stage)
            digest_before = _digest_manifest(project_dir)
            state_before = _snapshot_app_state(app)
            app._handle_save_dialog(_payload(app, typed))
            await _flush(pilot)
            status = probe.last
            digest_after = _digest_manifest(project_dir)
            names = sorted(p.name for p in project_dir.iterdir())
            state_after = _snapshot_app_state(app)
        return status, names, digest_before, digest_after, state_before, state_after

    status, names, digest_before, digest_after, state_before, state_after = (
        asyncio.run(_drive())
    )
    assert "could not save" in status, f"{target}/{stage}: {status}"
    assert "check the folder" in status, f"{target}/{stage}: {status}"
    assert digest_after == digest_before, (
        f"{target}/{stage}: the failed save changed the target's bytes"
    )
    assert names == ["a.s19"], f"{target}/{stage}: {names}"
    assert state_after == state_before, (
        f"{target}/{stage}: the failed save left app state behind"
    )


@pytest.mark.parametrize(
    "case",
    ["merge-gathered", "merge-gathered-reused", "fresh-gathered"],
)
def test_tc_b100_07_failed_save_removes_every_placed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """R2-1 / SEC2-4 (LED .52(b)): a failed save removes EVERY file and
    folder it placed — the copies AND the change/check documents the
    gather copied into ``patches/`` with the home folder it created —
    leaving the target's RECURSIVE tree (files AND folders) exactly as
    the pre-save snapshot. A byte-identical file the gather REUSED at a
    pre-existing path must survive (SEC2-4's trap: a bare-name skip
    test would delete it). A fresh-folder save that fails leaves no
    folder behind."""
    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        common = app.workarea / WORKAREA_PATCHES
        common.mkdir(parents=True, exist_ok=True)
        (common / "hotfix.json").write_text(_CHANGE_DOC, encoding="utf-8")
        merge = case != "fresh-gathered"
        if merge:
            project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
            if case == "merge-gathered-reused":
                # the gather finds a byte-identical sibling at the same
                # path and REUSES it — nothing is written there
                reused_home = project_dir / "patches"
                reused_home.mkdir()
                (reused_home / "hotfix.json").write_text(
                    _CHANGE_DOC, encoding="utf-8"
                )
        else:
            project_dir = app.workarea / "freshp"
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            # The patch goes down only AFTER the load, so the load path
            # itself keeps the real writer.
            _force_stage(monkeypatch, "manifest-refused")
            tree_before = _tree_listing(project_dir)
            payload = app_module.SaveProjectPayload(
                parent_folder=str(app.workarea),
                project_name="ab" if merge else "freshp",
                batch=("hotfix.json",),
            )
            app._handle_save_dialog(payload)
            await _flush(pilot)
            status = probe.last
            tree_after = _tree_listing(project_dir)
            folders = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
        return status, tree_before, tree_after, folders

    status, tree_before, tree_after, folders = asyncio.run(_drive())
    assert "could not save" in status, f"{case}: {status}"
    assert "check the folder" in status, f"{case}: {status}"
    assert tree_after == tree_before, (
        f"{case}: the failed save left placed files or folders behind — "
        f"before {sorted(tree_before)}, after {sorted(tree_after)}"
    )
    if case == "fresh-gathered":
        assert "freshp" not in folders, folders


def test_tc_b100_07_rollback_keeps_denied_folder_content_r7(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC2-5 / LED .53 (R7): ``ab/patches/keep.json`` already exists and
    ``ab/patches`` is read-denied (``icacls /deny …:(RD)``) when the save
    starts; the deny is lifted DURING the save (inside the forced
    manifest writer) and the save is then refused — ``keep.json`` must
    SURVIVE and the file this save placed must still be removed. The
    fix-pass-3 snapshot-diff rollback was blind to the denied folder and
    DELETED ``keep.json`` (this arm is RED there). On non-Windows hosts
    the arm skips (PDR C-QA-6)."""
    if sys.platform != "win32":
        pytest.skip("icacls deny-read is a Windows-only test arm (PDR C-QA-6)")
    user = os.environ.get("USERNAME")
    assert user, "USERNAME is required for the icacls deny arm"
    base = tmp_path / "app"
    app = S19TuiApp(base_dir=base)
    probe = _StatusProbe(app)
    project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
    patches = project_dir / "patches"
    patches.mkdir()
    (patches / "keep.json").write_text("{}", encoding="ascii")
    src = _copy_source(tmp_path)

    def _lift_deny_then_refuse(*args, **kwargs):
        subprocess.run(
            ["icacls", str(patches), "/remove:d", user], check=False
        )
        return None, [SimpleNamespace(message="forced manifest refusal")]

    async def _drive() -> tuple:
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            subprocess.run(
                ["icacls", str(patches), "/deny", f"{user}:(RD)"], check=True
            )
            monkeypatch.setattr(
                app_module, "write_project_manifest", _lift_deny_then_refuse
            )
            try:
                app._handle_save_dialog(_payload(app, "ab"))
                await _flush(pilot)
            finally:
                subprocess.run(
                    ["icacls", str(patches), "/remove:d", user], check=False
                )
            status = probe.last
            names = sorted(p.name for p in project_dir.iterdir())
            patch_names = sorted(p.name for p in patches.iterdir())
        return status, names, patch_names

    status, names, patch_names = asyncio.run(_drive())
    assert "could not save" in status, status
    assert "check the folder" in status, status
    assert patch_names == ["keep.json"], (
        f"the rollback deleted the pre-existing file inside the "
        f"once-denied folder: {patch_names}"
    )
    assert names == ["a.s19", "patches"], (
        f"the file this save placed must be removed: {names}"
    )


def test_tc_b100_07_rollback_keeps_concurrent_writer_file_r8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC2-6 / LED .53 (R8): another writer creates ``ab/notes.txt``
    DURING the save (inside the forced manifest writer); the save is
    then refused — ``notes.txt`` must SURVIVE, byte for byte, while the
    file this save placed is still removed. The fix-pass-3 snapshot-diff
    rollback deleted it (this arm is RED there)."""
    base = tmp_path / "app"

    def _concurrent_writer_then_refuse(_variant_set, project_dir, *args, **kwargs):
        (project_dir / "notes.txt").write_text(
            "user notes from another writer", encoding="utf-8"
        )
        return None, [SimpleNamespace(message="forced manifest refusal")]

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            monkeypatch.setattr(
                app_module,
                "write_project_manifest",
                _concurrent_writer_then_refuse,
            )
            app._handle_save_dialog(_payload(app, "ab"))
            await _flush(pilot)
            status = probe.last
            names = sorted(p.name for p in project_dir.iterdir())
            notes = (project_dir / "notes.txt").read_text(encoding="utf-8")
        return status, names, notes

    status, names, notes = asyncio.run(_drive())
    assert "could not save" in status, status
    assert "check the folder" in status, status
    assert notes == "user notes from another writer", notes
    assert names == ["a.s19", "notes.txt"], (
        f"the file this save placed must be removed: {names}"
    )


def test_tc_b100_07_manifest_mismatch_is_the_newest_status_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2-5 (LLR-004.2): a manifest write that verifies with a MISMATCH
    is reported, not a failure — and the drift report stays the NEWEST
    painted status line: ``Saved project to …`` paints first, then
    ``Manifest verify MISMATCH`` re-paints over it, so the success line
    never buries the mismatch (the notice fires once, inside the verify
    surfacing). Without the re-paint the success line is the newest
    line and this arm fails."""

    def _forced_mismatch(*args, **kwargs):
        return ManifestVerifyResult(
            status=MANIFEST_MISMATCH,
            drift=["active_variant"],
        )

    base = tmp_path / "app"

    async def _drive() -> list:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            monkeypatch.setattr(
                app_module, "verify_written_manifest", _forced_mismatch
            )
            app._handle_save_dialog(_payload(app, "proj"))
            await _flush(pilot)
        return probe.messages

    messages = asyncio.run(_drive())
    assert messages[-1] == "Manifest verify MISMATCH", messages
    assert "Saved project to" in messages[-2], messages


def test_tc_b100_07_unreadable_workarea_folder_skipped(
    tmp_path: Path,
) -> None:
    """SEC2-1 / F8: a work-area folder with read denied (``icacls /deny
    …:(RD)``) is skipped by the clash scan — never a raise, the save of
    a fresh name succeeds — and the deny is lifted afterwards. On
    non-Windows hosts the arm skips (PDR C-QA-6)."""
    if sys.platform != "win32":
        pytest.skip(
            "icacls deny-read is a Windows-only test arm (PDR C-QA-6)"
        )
    user = os.environ.get("USERNAME")
    assert user, "USERNAME is required for the icacls deny arm"
    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        locked = app.workarea / "locked"
        locked.mkdir(parents=True)
        subprocess.run(
            ["icacls", str(locked), "/deny", f"{user}:(RD)"], check=True
        )
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        try:
            async with app.run_test() as pilot:
                await pilot.pause()
                app.load_selected_file(src)
                await _flush(pilot)
                app._handle_save_dialog(_payload(app, "fresh1"))
                await _flush(pilot)
                status = probe.last
                folders = sorted(
                    item.name for item in app.workarea.iterdir() if item.is_dir()
                )
        finally:
            subprocess.run(
                ["icacls", str(locked), "/remove:d", user], check=False
            )
        return status, folders

    status, folders = asyncio.run(_drive())
    assert "Saved project" in status, (
        f"the save must succeed past the unreadable folder, got {status!r}"
    )
    assert "fresh1" in folders, folders
    assert "locked" in folders, folders


def _tree_listing_no_links(root: Path) -> dict:
    """The R3-1 oracle: every file AND folder under ``root``, files with
    their SHA-256 and folders the literal ``"dir"`` — a reparse point (a
    symlink or a junction) is a LEAF of the tree and its target is never
    entered. This test-side walk is deliberately independent of the
    production walker so the oracle stays valid on the unfixed tree."""
    from s19_app.tui.workspace import _is_reparse_point

    if not root.exists():
        return {}
    out: dict = {}
    stack = [root]
    while stack:
        current = stack.pop()
        with os.scandir(current) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            child = current / entry.name
            rel = str(child.relative_to(root))
            if _is_reparse_point(child):
                out[rel] = "dir" if entry.is_dir(follow_symlinks=False) else "link"
            elif entry.is_dir(follow_symlinks=False):
                out[rel] = "dir"
                stack.append(child)
            elif entry.is_file(follow_symlinks=False):
                out[rel] = hashlib.sha256(child.read_bytes()).hexdigest()
            else:
                out[rel] = "other"
    return out


def test_tc_b100_07_rollback_never_touches_junction_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3-1 (LED .50, security finding), kept GREEN by LED .53's redesign:
    the rollback walks no folder at all — it unlinks exactly the files
    the save created — so a junction that pre-exists inside the project
    can never be entered and its target never touched. A concurrent
    writer — simulated inside the gather — drops a file into the TARGET
    of ``ab\\ext`` (outside the work area) and the save then fails; the
    outside file must SURVIVE, and the project tree must equal its
    pre-save listing. On the unfixed tree the ``rglob`` removal walk
    entered the junction and unlinked the outside file — this arm is RED
    there."""
    b100_links.require_junctions()
    victim = tmp_path / "victim"
    base = tmp_path / "app"

    def _concurrent_writer_then_fail(*args, **kwargs):
        (victim / "user-work.txt").write_text(
            "written by another program", encoding="utf-8"
        )
        raise OSError("forced gather failure")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
            victim.mkdir()
            (victim / "keep.txt").write_text("victim", encoding="utf-8")
            b100_links.create_junction(project_dir / "ext", victim)
            app.load_selected_file(src)
            await _flush(pilot)
            tree_before = _tree_listing_no_links(project_dir)
            monkeypatch.setattr(
                app_module, "gather_project_artifacts", _concurrent_writer_then_fail
            )
            app._handle_save_dialog(
                app_module.SaveProjectPayload(
                    parent_folder=str(app.workarea), project_name="ab"
                )
            )
            await _flush(pilot)
            status = probe.last
            tree_after = _tree_listing_no_links(project_dir)
            victim_names = sorted(entry.name for entry in victim.iterdir())
        return status, tree_before, tree_after, victim_names

    status, tree_before, tree_after, victim_names = asyncio.run(_drive())
    assert "could not save" in status, status
    assert "user-work.txt" in victim_names, (
        "the rollback deleted through the junction — outside the work area: "
        f"victim now {victim_names}"
    )
    assert "keep.txt" in victim_names, victim_names
    assert tree_after == tree_before, (
        "the failed save changed the project tree — "
        f"before {sorted(tree_before)}, after {sorted(tree_after)}"
    )


def test_tc_b100_07_junction_cycle_does_not_block_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3-1 (the same cause, second effect): a junction cycle inside the
    project (``ab\\loop`` -> ``ab``) must not make every save into ``ab``
    fail — the unfixed ``rglob`` snapshot recurses ``loop\\loop\\…`` until
    a ~260-character path raises, so the save is refused with a long-path
    error. The non-following walker records the junction as a leaf and the
    exact-name merge saves."""
    b100_links.require_junctions()
    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
            b100_links.create_junction(project_dir / "loop", project_dir)
            app.load_selected_file(src)
            await _flush(pilot)
            tree_before = _tree_listing_no_links(project_dir)
            app._handle_save_dialog(
                app_module.SaveProjectPayload(
                    parent_folder=str(app.workarea), project_name="ab"
                )
            )
            await _flush(pilot)
            status = probe.last
            tree_after = _tree_listing_no_links(project_dir)
        return status, tree_before, tree_after

    status, tree_before, tree_after = asyncio.run(_drive())
    assert "Saved project" in status, (
        f"a junction cycle must not block the save, got {status!r}"
    )
    assert "could not save" not in status, status
    for rel, value in tree_before.items():
        assert tree_after.get(rel) == value, (
            f"a junction cycle save touched the pre-existing path {rel!r} "
            f"({value!r} -> {tree_after.get(rel)!r})"
        )


def test_tc_b100_07_walk_tree_no_links_yields_reparse_point_as_leaf(
    tmp_path: Path,
) -> None:
    """R3-1 / LLR-171.1's reusable walker: ``walk_tree_no_links`` yields
    every file and folder as a path relative to the root, records a reparse
    point (a junction here) as a LEAF, never yields anything inside it —
    and never loops on a junction cycle."""
    b100_links.require_junctions()
    from s19_app.tui.workspace import walk_tree_no_links

    root = tmp_path / "root"
    (root / "real" / "nested").mkdir(parents=True)
    (root / "real" / "nested" / "f.txt").write_text("x", encoding="ascii")
    (root / "top.txt").write_text("t", encoding="ascii")
    victim = tmp_path / "victim"
    (victim / "inner").mkdir(parents=True)
    (victim / "inner" / "secret.txt").write_text("s", encoding="ascii")
    b100_links.create_junction(root / "ext", victim)
    b100_links.create_junction(root / "loop", root)

    rels = sorted(rel.as_posix() for rel in walk_tree_no_links(root))
    assert rels == [
        "ext",
        "loop",
        "real",
        "real/nested",
        "real/nested/f.txt",
        "top.txt",
    ], rels


# ---------------------------------------------------------------------------
# TC-B100-07 arms — fix pass 5: SEC2-7/8/9 (security round 4) and R5-1/R5-2
# (review round 5) on the LED .53 exact-list rollback
# ---------------------------------------------------------------------------


def test_tc_b100_07_gather_reuse_never_ends_in_written(tmp_path: Path) -> None:
    """SEC2-7 (security round 4) census arm: the placement's ``reused``
    flag is the SOLE judge of reuse — a reused byte-identical file never
    lands in ``GatherOutcome.written`` (so the rollback can never delete
    a pre-existing file) and a genuinely written file always does.
    Headless gather; Windows-only (the case-variant reuse limb needs
    case-insensitive names, PDR C-QA-6)."""
    if sys.platform != "win32":
        pytest.skip("case-insensitive names are a Windows-only arm (PDR C-QA-6)")
    workarea = _workarea(tmp_path)
    workarea.mkdir(parents=True)
    project_dir = workarea / "proj"
    project_dir.mkdir()
    home = project_dir / "patches"
    home.mkdir()
    common = workarea / "patches"
    common.mkdir()
    source = common / "boost.json"
    source.write_text(_CHANGE_DOC, encoding="utf-8")
    # a pre-existing byte-identical file under a CASE-VARIANT name —
    # the shape SEC2-7's executed probe deleted
    (home / "BOOST.json").write_text(_CHANGE_DOC, encoding="utf-8")

    def _gather():
        return gather_module.gather_project_artifacts(
            project_dir,
            composition_names=["boost.json"],
            common_patches_dir=common,
            common_templates_dir=tmp_path / "templates",
            workarea_root=workarea,
        )

    reused = _gather()
    assert reused.gathered == {"patches": ["patches/BOOST.json"]}, reused.gathered
    assert reused.written == [], (
        f"a reused byte-identical file must never be recorded as written: "
        f"{reused.written}"
    )
    assert reused.created_homes == [], reused.created_homes
    assert sorted(p.name for p in home.iterdir()) == ["BOOST.json"], (
        "a reuse must write nothing — the case-variant sibling is it"
    )
    # control limb: a fresh write lands in ``written`` exactly once
    (home / "BOOST.json").unlink()
    fresh = _gather()
    assert [p.name for p in fresh.written] == ["boost.json"], fresh.written
    assert fresh.created_homes == [], fresh.created_homes


@pytest.mark.parametrize("case_variant", ["BOOST.json", "boost.JSON"])
def test_tc_b100_07_case_variant_reused_file_survives_failed_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case_variant: str
) -> None:
    """SEC2-7 (security round 4, the HIGH) at the save surface:
    ``ab/patches/<case-variant>`` pre-exists, byte-identical to the
    COMMON ``boost.json`` the save gathers; the save then fails at the
    manifest. The placement REUSES the case-variant file, so the
    rollback must leave it on disk — the old case-sensitive gather
    pre-check reported it as written and the rollback DELETED it (this
    arm is RED there). Windows-only (case-insensitive names, PDR
    C-QA-6)."""
    if sys.platform != "win32":
        pytest.skip("case-insensitive names are a Windows-only arm (PDR C-QA-6)")
    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        common = app.workarea / WORKAREA_PATCHES
        common.mkdir(parents=True, exist_ok=True)
        (common / "boost.json").write_text(_CHANGE_DOC, encoding="utf-8")
        project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
        reused_home = project_dir / "patches"
        reused_home.mkdir()
        variant = reused_home / case_variant
        variant.write_text(_CHANGE_DOC, encoding="utf-8")
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            _force_stage(monkeypatch, "manifest")
            payload = app_module.SaveProjectPayload(
                parent_folder=str(app.workarea),
                project_name="ab",
                batch=("boost.json",),
            )
            app._handle_save_dialog(payload)
            await _flush(pilot)
            status = probe.last
            variant_bytes = variant.read_bytes() if variant.exists() else None
            names = sorted(p.name for p in project_dir.iterdir())
            home_names = sorted(p.name for p in reused_home.iterdir())
        return status, variant_bytes, names, home_names

    status, variant_bytes, names, home_names = asyncio.run(_drive())
    assert "could not save" in status, f"{case_variant}: {status}"
    assert "check the folder" in status, f"{case_variant}: {status}"
    assert variant_bytes == _CHANGE_DOC.encode("utf-8"), (
        f"{case_variant}: the failed save deleted the pre-existing file "
        f"the placement reused"
    )
    assert home_names == [case_variant], (
        f"{case_variant}: the home gained or lost files: {home_names}"
    )
    assert names == ["a.s19", "patches"], (
        f"{case_variant}: the placed image must be removed: {names}"
    )


def test_tc_b100_07_failed_verify_leaves_no_folder_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC2-8 (security round 4): a FRESH save whose manifest WRITE
    succeeds but whose VERIFY re-read raises — this save created
    ``project.json``, so the rollback must remove it and leave no
    folder behind. The old rollback unlinked the placements and then
    ``rmdir``ed the project folder while ``project.json`` was still
    inside — the folder stayed, holding only the manifest (this arm is
    RED there)."""

    def _raise(*args, **kwargs):
        raise OSError("forced verify re-read failure")

    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            monkeypatch.setattr(app_module, "verify_written_manifest", _raise)
            app._handle_save_dialog(_payload(app, "freshv"))
            await _flush(pilot)
            status = probe.last
            folders = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
        return status, folders

    status, folders = asyncio.run(_drive())
    assert "could not save" in status, status
    assert "check the folder" in status, status
    assert "freshv" not in folders, (
        f"the failed save left the folder it created behind: {folders}"
    )


def test_tc_b100_07_failed_verify_restores_previous_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC2-9 (security round 4): a MERGE whose manifest write succeeds
    but whose verify raises — the save REPLACED a pre-existing
    ``project.json``; the rollback must put the previous bytes back
    atomically (staged, then ``os.replace``), leaving the project's
    tree byte-identical to its pre-save state. The old rollback kept
    the new manifest — the pre-save bytes were lost (this arm is RED
    there)."""

    def _raise(*args, **kwargs):
        raise OSError("forced verify re-read failure")

    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            # the first save creates ab WITH its manifest
            app._handle_save_dialog(_payload(app, "ab"))
            await _flush(pilot)
            project_dir = app.workarea / "ab"
            before_bytes = (project_dir / "project.json").read_bytes()
            tree_before = _digest_manifest(project_dir)
            # a merging second save loads another image
            src_b = tmp_path / "sources" / "b.s19"
            src_b.write_text(_S19_B, encoding="ascii")
            app.load_selected_file(src_b)
            await _flush(pilot)
            monkeypatch.setattr(app_module, "verify_written_manifest", _raise)
            app._handle_save_dialog(_payload(app, "ab"))
            await _flush(pilot)
            status = probe.last
            after_bytes = (project_dir / "project.json").read_bytes()
            tree_after = _digest_manifest(project_dir)
        return status, before_bytes, after_bytes, tree_before, tree_after

    status, before_bytes, after_bytes, tree_before, tree_after = asyncio.run(_drive())
    assert "could not save" in status, status
    assert "check the folder" in status, status
    assert after_bytes == before_bytes, (
        "the failed merge must restore project.json to its pre-save bytes"
    )
    assert tree_after == tree_before, (
        "the failed merge must leave the project tree byte-identical"
    )


def test_tc_b100_07_gather_home_created_then_copy_fails_no_folder_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R5-1 (review round 5, the disk-full shape): the placement mkdirs
    the gather home and then the staging copy fails (``OSError(28)``,
    no space left); the manifest is refused and the save fails — the
    home the gather created must be recorded and removed, so no folder
    is left behind. Before the fix ``freshp/patches`` stayed on disk,
    holding nothing (this arm is RED there)."""

    def _mkdir_home_then_raise(source, home, **kwargs):
        Path(home).mkdir(parents=True, exist_ok=True)
        raise OSError(28, "No space left on device")

    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        common = app.workarea / WORKAREA_PATCHES
        common.mkdir(parents=True, exist_ok=True)
        (common / "boost.json").write_text(_CHANGE_DOC, encoding="utf-8")
        src = _copy_source(tmp_path)
        # the seam the gather's placement calls — ``place_into_workarea``
        # since fix pass 5, ``copy_into_workarea`` before it (the arm runs
        # RED on both trees)
        seam = getattr(gather_module, "place_into_workarea", None)
        if seam is None:
            seam = gather_module.copy_into_workarea
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            # the gather's placement mkdirs the home, then the copy dies
            monkeypatch.setattr(gather_module, seam.__name__, _mkdir_home_then_raise)
            _force_stage(monkeypatch, "manifest-refused")
            payload = app_module.SaveProjectPayload(
                parent_folder=str(app.workarea),
                project_name="freshp",
                batch=("boost.json",),
            )
            app._handle_save_dialog(payload)
            await _flush(pilot)
            status = probe.last
            folders = sorted(
                item.name for item in app.workarea.iterdir() if item.is_dir()
            )
        return status, folders

    status, folders = asyncio.run(_drive())
    assert "could not save" in status, status
    assert "check the folder" in status, status
    assert folders == ["patches", "temp"], (
        f"the failed save left the folder its gather created behind: {folders}"
    )


def test_tc_b100_07_empty_preexisting_home_survives_failed_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R5-2 (review round 5): ``ab/patches/`` exists and is EMPTY before
    the save; the gather writes a document into it, then the save
    fails — the pre-existing home must survive (only the file the
    gather wrote is removed). Kills mutant Mf, which drops the
    ``home_preexisted`` guard and would rmdir the pre-existing empty
    home."""
    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        probe = _StatusProbe(app)
        common = app.workarea / WORKAREA_PATCHES
        common.mkdir(parents=True, exist_ok=True)
        (common / "boost.json").write_text(_CHANGE_DOC, encoding="utf-8")
        project_dir = _make_project(app, "ab", {"a.s19": _S19_A})
        home = project_dir / "patches"
        home.mkdir()
        src = _copy_source(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(src)
            await _flush(pilot)
            _force_stage(monkeypatch, "manifest-refused")
            payload = app_module.SaveProjectPayload(
                parent_folder=str(app.workarea),
                project_name="ab",
                batch=("boost.json",),
            )
            app._handle_save_dialog(payload)
            await _flush(pilot)
            status = probe.last
            home_exists = home.is_dir()
            home_names = (
                sorted(p.name for p in home.iterdir()) if home_exists else None
            )
        return status, home_exists, home_names

    status, home_exists, home_names = asyncio.run(_drive())
    assert "could not save" in status, status
    assert "check the folder" in status, status
    assert home_exists, "the pre-existing empty home must survive the failed save"
    assert home_names == [], (
        f"the file the gather wrote must be removed: {home_names}"
    )


# ---------------------------------------------------------------------------
# AT-B100-02 — HLR-164 through the shipped Save project dialog (black-box)
# ---------------------------------------------------------------------------


async def _load_file_through_dialog(pilot, app: S19TuiApp, src: Path) -> None:
    """Drive the Load file dialog (rail key ``l``) and wait for the load."""
    await pilot.press("l")
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadFileScreen),
        "the Load file dialog",
    )
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*str(src))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await _wait_for(
        pilot,
        lambda: not isinstance(app.screen, LoadFileScreen)
        and _file_status_text(app).startswith("Loaded "),
        f"the durable load line after loading {src.name}",
    )


async def _save_project_as(pilot, app: S19TuiApp, name: str) -> None:
    """Open the Save project dialog (``ctrl+s``), type the name and press
    Save; wait for the dialog to close and the status to repaint."""
    await pilot.press("ctrl+s")
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, SaveProjectScreen),
        "the Save project dialog",
    )
    assert await pilot.click("#project_name"), "click missed #project_name"
    await pilot.press(*name)
    assert await pilot.click("#save_ok"), "click missed #save_ok"
    await _wait_for(
        pilot,
        lambda: not isinstance(app.screen, SaveProjectScreen),
        "the Save project dialog to close",
    )


async def _open_project_through_dialog(pilot, app: S19TuiApp, name: str) -> None:
    """Open an existing project through the shipped Load project surface:
    rail key ``1`` to the Workspace, then a real click on
    ``#ws_load_project_button`` (the same action as rail key ``p`` — the
    Segment Split window binds ``p`` for its own pad cycle once a file is
    loaded, the documented drive in ``test_b99_load_project``)."""
    await pilot.press("1")
    for _ in range(6):
        await pilot.pause()
    assert await pilot.click(
        "#ws_load_project_button"
    ), "click missed #ws_load_project_button"
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadProjectScreen),
        "the Load project dialog",
    )
    row = next(
        item
        for item in app.screen.query("#project_list ListItem")
        if str(item.query_one(Label).render()) == name
    )
    await pilot.click(row)
    await pilot.pause()
    assert await pilot.click("#project_ok"), "click missed #project_ok"
    await _wait_for(
        pilot,
        lambda: not isinstance(app.screen, LoadProjectScreen),
        f"the Load project dialog to close after loading {name}",
    )


@pytest.mark.parametrize("size", [(118, 54), (220, 60)])
def test_at_b100_02_name_refusals_through_the_save_dialog(
    tmp_path: Path, size: tuple
) -> None:
    """Through the shipped dialog by keys: ``Reports`` → ``reserved name`` /
    ``choose another name`` and no folder; ``CON`` → ``device name``;
    a 300-character name → ``name too long`` and the app keeps running;
    then HLR-164's acceptance scene (LED .52(c)): projects ``prg`` (P2)
    and ``ab`` are built by REAL saves, P2 is opened through the Load
    project dialog by keys — the painted log names ``Loaded project 'prg'``
    — and ``a b`` is refused naming ``ab`` with ``choose another name``,
    ``ab`` byte-identical afterwards. Both sizes, notifications on."""
    base = tmp_path / "app"
    src = _copy_source(tmp_path)

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _load_file_through_dialog(pilot, app, src)
            # 1. a reserved home, mixed case.
            await _save_project_as(pilot, app, "Reports")
            await _wait_for(
                pilot,
                lambda: "reserved name" in _status_text(app)
                and "choose another name" in _status_text(app),
                "the reserved-name refusal tokens",
            )
            assert not (app.workarea / "Reports").exists(), (
                "a reserved-name refusal created a folder"
            )
            # 2. a Windows device name.
            await _save_project_as(pilot, app, "CON")
            await _wait_for(
                pilot,
                lambda: "device name" in _status_text(app)
                and "choose another name" in _status_text(app),
                "the device-name refusal tokens",
            )
            assert not (app.workarea / "CON").exists(), (
                "a device-name refusal created a folder"
            )
            # 3. a 300-character name: refused, the app keeps running.
            await _save_project_as(pilot, app, "x" * 300)
            await _wait_for(
                pilot,
                lambda: "name too long" in _status_text(app)
                and "shorten the name" in _status_text(app),
                "the name-too-long refusal tokens",
            )
            assert not any(
                len(item.name) > 64 for item in app.workarea.iterdir()
            ), "a too-long name created a folder"
            # 4. HLR-164's acceptance scene: P2 (prg) and ab are built by
            #    real saves; P2 is opened through the Load project dialog
            #    by keys, so ANOTHER project is open; the disguised name
            #    a b is refused naming ab.
            await _save_project_as(pilot, app, "prg")
            await _wait_for(
                pilot,
                lambda: "Saved project" in _status_text(app),
                "the P2 save success line",
            )
            await _save_project_as(pilot, app, "ab")
            await _wait_for(
                pilot,
                lambda: "Saved project" in _status_text(app),
                "the ab save success line",
            )
            await _open_project_through_dialog(pilot, app, "prg")
            await _wait_for(
                pilot,
                lambda: "Loaded project 'prg'" in _status_text(app),
                "the painted line naming the opened project P2",
            )
            ab_dir = app.workarea / "ab"
            ab_digest_before = _digest_manifest(ab_dir)
            await _save_project_as(pilot, app, "a b")
            await _wait_for(
                pilot,
                lambda: "already a project" in _status_text(app)
                and "'ab'" in _status_text(app)
                and "choose another name" in _status_text(app),
                "the disguised-clash refusal naming ab",
            )
            ab_digest_after = _digest_manifest(ab_dir)
        return ab_digest_before, ab_digest_after

    ab_digest_before, ab_digest_after = asyncio.run(_drive())
    assert ab_digest_before, "ab must hold its saved files"
    assert ab_digest_after == ab_digest_before, (
        "the refused save changed the not-open project ab"
    )
