"""Project gather + scoped artifact homes (batch-95 change 1, HLR-138 / LLR-138.1..138.4).

Change 1 makes the project folder a self-contained snapshot: on save the
JSON artifacts the project USES (the recorded predicate lives in
``project_gather_service``) are COPYed into per-artifact project homes —
change-sets → ``<project>/patches/``, check documents → ``<project>/checks/``
(the wire ``kind`` discriminator), used CRC templates →
``<project>/templates/`` — while the COMMON originals stay byte-untouched
(the COPY-not-MOVE ruling: the COMMON folders are live libraries the app's
dropdowns scan). NEW artifacts (a patch save, a CRC template save) default
INTO the project the same way; without a project the COMMON homes keep the
writes. Every byte resolves under ``.s19tool/workarea/`` — the shipped
``copy_into_workarea`` containment law.

Coverage map (test -> TC -> LLR):

- TC-699 / LLR-138.1 — ``test_tc699_common_change_set_is_gathered_into_project_patches``:
  a project referencing a COMMON change-set gathers a copy into
  ``<project>/patches/``; the COMMON original stays 100% present (the MOVE
  negative control); the manifest records the gathered rows
  project-relative; the verify-on-write stays green (the reader ignores the
  additive ``gathered`` key).
- TC-699 / LLR-138.1 (assignments limb) —
  ``test_tc699_assignments_referenced_documents_are_gathered``: per-variant
  assignment references gather exactly like project-wide batch ones.
- TC-699 / LLR-138.1 (idempotence) —
  ``test_tc699_resave_is_idempotent_no_dedup_copies``: a re-save produces no
  ``_<N>`` duplicates.
- TC-699 / LLR-138.1 (empty boundary) —
  ``test_tc699_zero_used_artifacts_gathers_nothing``: a plain save writes no
  ``gathered`` key and creates no project homes — never an error.
- TC-700 / LLR-138.2 — ``test_tc700_check_document_gathers_into_project_checks``:
  a referenced COMMON document whose wire ``kind`` is ``"check"`` lands in
  ``<project>/checks/`` — nothing check-ish is dumped into ``patches/``.
- TC-700 / LLR-138.2 (active limb) —
  ``test_tc700_active_editor_document_is_gathered_by_kind``: the document
  loaded in the Patch Editor at save time is gathered into its kind home.
- TC-701 / LLR-138.3 — ``test_tc701_used_template_gathered_into_project_templates``:
  the template recorded as loaded (the CRC Designer's last load) gathers
  into ``<project>/templates/``; the COMMON ``.s19tool/templates`` library
  is byte-untouched.
- TC-702 / LLR-138.4 — ``test_tc702_no_project_keeps_common_homes``: without
  a project a patch save keeps the COMMON ``workarea/patches/`` home and
  nothing is gathered anywhere new (0 files outside the COMMON homes).
- TC-702 / LLR-138.4 (snapshot refresh) —
  ``test_tc702_resave_refreshes_stale_copies``: divergence from later COMMON
  edits is repaired by a re-save (the project copy is refreshed in place).
- HLR-138 scoped homes — ``test_scoped_home_patch_save_with_project_lands_in_project`` /
  ``test_scoped_home_patch_save_without_project_keeps_common`` /
  ``test_scoped_home_template_save_with_project_lands_in_project`` /
  ``test_scoped_home_template_save_without_project_keeps_common_lib``:
  with a project the save dialogs' destinations default INTO the project
  (per-artifact subfolder, ``checks/`` for a check document); without one
  the COMMON homes keep them.
- The containment law — ``test_gather_containment_escape_refuses_without_writing`` /
  ``test_scoped_home_containment_escape_refuses``: a project home outside
  ``.s19tool/workarea/`` refuses — one finding, no bytes, no crash.

Harness: the ``App.run_test()`` pilot pattern of ``tests/test_tui_manifest_save.py``
(the case07 idiom), driving the real ``_handle_save_dialog`` with a
fabricated on-disk project, plus headless service-level limbs for the io
seams.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

from textual.widgets import Button, Input, Static

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import write_change_document
from s19_app.tui.changes.model import ChangeDocument
from s19_app.tui.operations.crc_kernel import SEED_ALGORITHM
from s19_app.tui.services.project_gather_service import (
    GATHER_CONTAINMENT,
    PROJECT_CHECKS_DIR,
    PROJECT_PATCHES_DIR,
    PROJECT_TEMPLATES_DIR,
    gather_project_artifacts,
    scoped_home,
)
from s19_app.tui.services.variant_execution_service import (
    read_project_manifest,
)
from s19_app.tui.workspace import (
    WORKAREA_DIRNAME,
    WORKAREA_PATCHES,
    WORKAREA_SUBDIR,
    WorkareaContainmentError,
    ensure_template_lib,
    sanitize_project_name,
)

#: Minimal valid S19 image (checksum verified against s19_app.core.S19File) —
#: the loadable payload of the save flow, copied from
#: ``tests/test_tui_manifest_save.py``.
S19_A = "S107100001020304DE\nS9030000FC\n"

MF_WRITE_CONTAINMENT = "MF-WRITE-CONTAINMENT"


def _change_doc_text(kind: str = "change") -> str:
    """A minimal valid v2 change/check document body with zero entries."""
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": kind,
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [],
        }
    )


def _change_doc(kind: str = "change") -> ChangeDocument:
    """An in-memory v2 document for the headless writer limbs."""
    return ChangeDocument(
        format="s19app-changeset",
        version="2.0",
        kind=kind,
        encoding="utf-8",
        value_mode="text",
    )


def _write_common_doc(app: S19TuiApp, name: str, kind: str = "change") -> Path:
    """Fabricate one COMMON-library document and return its path."""
    common = app.workarea / WORKAREA_PATCHES
    path = common / name
    path.write_text(_change_doc_text(kind), encoding="utf-8")
    return path


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so the deferred apply chain runs."""
    for _ in range(count):
        await pilot.pause()


def _save_project(app: S19TuiApp, payload) -> None:
    """Drive the real save handler (the case07 idiom)."""
    app._handle_save_dialog(payload)


def _payload(app: S19TuiApp, name: str = "proj", **kwargs):
    return app_module.SaveProjectPayload(
        parent_folder=str(app.workarea), project_name=name, **kwargs
    )


def _manifest_text(project_dir: Path) -> dict:
    return json.loads((project_dir / "project.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# TC-699 / LLR-138.1 — the change-set gather
# --------------------------------------------------------------------------- #


def test_tc699_common_change_set_is_gathered_into_project_patches(
    tmp_path: Path,
) -> None:
    """TC-699 (LLR-138.1): a referenced COMMON change-set gathers into
    ``<project>/patches/``; the COMMON original stays; the manifest records
    the gathered rows project-relative; the verify stays green."""
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        common_doc = _write_common_doc(app, "boost.json", kind="change")
        common_bytes = common_doc.read_bytes()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            _save_project(app, _payload(app, batch=("boost.json",)))
            await _flush(pilot)
            project_dir = app.workarea / "proj"
            gathered_copy = project_dir / PROJECT_PATCHES_DIR / "boost.json"
            manifest = _manifest_text(project_dir)
            manifest_issues = (
                read_project_manifest(project_dir).issues
                if read_project_manifest(project_dir)
                else None
            )
            return (
                gathered_copy.exists(),
                gathered_copy.read_bytes() if gathered_copy.exists() else None,
                common_bytes,
                common_doc.exists(),
                common_doc.read_bytes() if common_doc.exists() else None,
                manifest.get("gathered"),
                manifest.get("batch"),
                manifest_issues,
            )

    copied, copy_bytes, common_bytes, common_exists, common_now, gathered, batch, issues = (
        asyncio.run(_drive())
    )
    assert copied, "the used change-set must be gathered into <project>/patches/"
    assert copy_bytes == common_bytes, "the gathered copy must be byte-identical"
    assert common_exists and common_now == common_bytes, (
        "the COMMON original must stay 100% present (COPY, never MOVE)"
    )
    assert gathered == {PROJECT_PATCHES_DIR: ["patches/boost.json"]}, (
        f"the manifest gathered rows must be project-relative; got {gathered}"
    )
    assert batch == ["boost.json"], "the operator's batch composition is untouched"
    assert issues == [], f"the additive gathered key must re-read clean; got {issues}"


def test_tc699_assignments_referenced_documents_are_gathered(tmp_path: Path) -> None:
    """TC-699 (LLR-138.1, assignments limb): per-variant assignment names
    gather exactly like project-wide batch names (the app flattens the two
    into one composition list)."""
    base = tmp_path
    workarea = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    patches = workarea / WORKAREA_PATCHES
    patches.mkdir(parents=True)
    project = workarea / "proj"
    project.mkdir()
    doc = patches / "per-variant.json"
    doc.write_text(_change_doc_text("change"), encoding="utf-8")

    outcome = gather_project_artifacts(
        project,
        composition_names=["per-variant.json"],  # the flattened batch+assignments union
        common_patches_dir=patches,
        common_templates_dir=base / WORKAREA_DIRNAME / "templates",
    )
    assert outcome.gathered == {PROJECT_PATCHES_DIR: ["patches/per-variant.json"]}
    assert outcome.issues == []
    assert (project / PROJECT_PATCHES_DIR / "per-variant.json").exists()


def test_tc699_resave_is_idempotent_no_dedup_copies(tmp_path: Path) -> None:
    """TC-699 (LLR-138.1, idempotence): a re-save refreshes the same copy —
    never a ``_<N>`` duplicate."""
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple[int, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        _write_common_doc(app, "boost.json", kind="change")
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            _save_project(app, _payload(app, batch=("boost.json",)))
            await _flush(pilot)
            first = _manifest_text(app.workarea / "proj").get("gathered")
            _save_project(app, _payload(app, batch=("boost.json",)))
            await _flush(pilot)
            home = app.workarea / "proj" / PROJECT_PATCHES_DIR
            return len(list(home.glob("*.json"))), first

    count, first_gathered = asyncio.run(_drive())
    assert count == 1, f"a re-save must not dedup-duplicate the copy; found {count}"
    assert first_gathered == {PROJECT_PATCHES_DIR: ["patches/boost.json"]}


def test_tc699_zero_used_artifacts_gathers_nothing(tmp_path: Path) -> None:
    """TC-699 (LLR-138.1, empty boundary): a plain save with no used
    artifacts writes no ``gathered`` key and creates no project homes —
    never an error."""
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple[bool, bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            _save_project(app, _payload(app))
            await _flush(pilot)
            project_dir = app.workarea / "proj"
            manifest = _manifest_text(project_dir)
            return (
                "gathered" in manifest,
                (project_dir / PROJECT_PATCHES_DIR).exists(),
                (project_dir / PROJECT_CHECKS_DIR).exists(),
            )

    has_key, has_patches, has_checks = asyncio.run(_drive())
    assert not has_key, "a zero-used save omits the gathered key (back-compat)"
    assert not has_patches and not has_checks, (
        "a zero-used save creates no project artifact homes"
    )


# --------------------------------------------------------------------------- #
# TC-700 / LLR-138.2 — the check-run gather into the new checks/ home
# --------------------------------------------------------------------------- #


def test_tc700_check_document_gathers_into_project_checks(tmp_path: Path) -> None:
    """TC-700 (LLR-138.2): a referenced document whose wire ``kind`` is
    ``"check"`` gathers into ``<project>/checks/`` — the new home — and
    NOTHING check-ish is dumped into the project ``patches/`` folder."""
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple[bool, bool, dict]:
        app = S19TuiApp(base_dir=tmp_path)
        _write_common_doc(app, "smoke.json", kind="check")
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            _save_project(app, _payload(app, batch=("smoke.json",)))
            await _flush(pilot)
            project_dir = app.workarea / "proj"
            return (
                (project_dir / PROJECT_CHECKS_DIR / "smoke.json").exists(),
                (project_dir / PROJECT_PATCHES_DIR / "smoke.json").exists(),
                _manifest_text(project_dir).get("gathered", {}),
            )

    in_checks, in_patches, gathered = asyncio.run(_drive())
    assert in_checks, "a check document must gather into <project>/checks/"
    assert not in_patches, "a check document must never land in patches/"
    assert gathered == {PROJECT_CHECKS_DIR: ["checks/smoke.json"]}, gathered


def test_tc700_active_editor_document_is_gathered_by_kind(tmp_path: Path) -> None:
    """TC-700 (LLR-138.2, active limb): the document loaded in the Patch
    Editor at save time — here a check document from the COMMON library —
    is gathered into its kind home."""
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple[bool, dict]:
        app = S19TuiApp(base_dir=tmp_path)
        common_doc = _write_common_doc(app, "active-checks.json", kind="check")
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            result = app._change_service.load(str(common_doc), app.base_dir)
            assert result.ok, f"fixture doc must load cleanly: {result.message}"
            _save_project(app, _payload(app))
            await _flush(pilot)
            project_dir = app.workarea / "proj"
            return (
                (project_dir / PROJECT_CHECKS_DIR / "active-checks.json").exists(),
                _manifest_text(project_dir).get("gathered", {}),
            )

    in_checks, gathered = asyncio.run(_drive())
    assert in_checks, "the active editor document must be gathered into checks/"
    assert gathered == {PROJECT_CHECKS_DIR: ["checks/active-checks.json"]}, gathered


# --------------------------------------------------------------------------- #
# TC-701 / LLR-138.3 — the used-CRC-template gather
# --------------------------------------------------------------------------- #


def test_tc701_used_template_gathered_into_project_templates(tmp_path: Path) -> None:
    """TC-701 (LLR-138.3): the template the project uses (the CRC Designer's
    last load) gathers into ``<project>/templates/``; the COMMON
    ``.s19tool/templates`` library stays byte-untouched."""
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple[bool, bytes, bytes, dict]:
        app = S19TuiApp(base_dir=tmp_path)
        common_lib = ensure_template_lib(app.base_dir)
        template = common_lib / "seed.crc.json"
        template.write_bytes(b'{"name":"seed"}\n')
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            app.record_template_load(template)
            _save_project(app, _payload(app))
            await _flush(pilot)
            project_dir = app.workarea / "proj"
            copy = project_dir / PROJECT_TEMPLATES_DIR / "seed.crc.json"
            return (
                copy.exists(),
                copy.read_bytes() if copy.exists() else None,
                template.read_bytes(),
                _manifest_text(project_dir).get("gathered", {}),
            )

    copied, copy_bytes, common_now, gathered = asyncio.run(_drive())
    assert copied, "the used template must gather into <project>/templates/"
    assert copy_bytes == b'{"name":"seed"}\n', "the gathered copy must be byte-identical"
    assert common_now == b'{"name":"seed"}\n', (
        "the COMMON template library must stay byte-untouched"
    )
    assert gathered == {PROJECT_TEMPLATES_DIR: ["templates/seed.crc.json"]}, gathered


# --------------------------------------------------------------------------- #
# TC-702 / LLR-138.4 — no-project mode + the snapshot refresh
# --------------------------------------------------------------------------- #


def test_tc702_no_project_keeps_common_homes(tmp_path: Path) -> None:
    """TC-702 (LLR-138.4): with NO project a patch save keeps the COMMON
    ``workarea/patches/`` home, the scoped-home seam resolves to the COMMON
    homes, and nothing is gathered anywhere new (0 files outside the COMMON
    homes)."""
    base = tmp_path
    doc = _change_doc(kind="change")
    path, issues = write_change_document(doc, base, file_name="noproj.json")
    assert issues == []
    common = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_PATCHES / "noproj.json"
    assert path == common, f"without a project the COMMON home keeps the write: {path}"
    # The scoped-home seam resolves to the COMMON homes without a project.
    common_patches = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_PATCHES
    assert scoped_home(None, PROJECT_PATCHES_DIR, common_patches) == common_patches
    # Nothing anywhere new: the only file created lives under the workarea.
    outside = [
        p
        for p in base.rglob("*")
        if p.is_file()
        and WORKAREA_SUBDIR not in p.parts
        and "templates" not in p.parts
    ]
    assert outside == [], f"no-project mode must create nothing outside the COMMON homes: {outside}"


def test_tc702_resave_refreshes_stale_copies(tmp_path: Path) -> None:
    """TC-702 (LLR-138.4, snapshot refresh): divergence from a later COMMON
    edit is repaired by a re-save — batch-99 Inc 3b re-pin (LLR-155.3,
    LED-2026-10-25-batch-99.7): the drifted copy is PLACED through HLR-155's
    placement and takes the next free ``_<N>`` name; the previously placed
    copy is immutable (never overwritten), so a re-save with drifted bytes
    keeps both files and the manifest records the name actually placed."""
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple[bytes, int]:
        app = S19TuiApp(base_dir=tmp_path)
        common_doc = _write_common_doc(app, "boost.json", kind="change")
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            _save_project(app, _payload(app, batch=("boost.json",)))
            await _flush(pilot)
            # Later COMMON edit after the first snapshot — the save's re-gather
            # must place the drifted copy under the next free name.
            common_doc.write_text(
                _change_doc_text("change") + " ", encoding="utf-8"
            )
            _save_project(app, _payload(app, batch=("boost.json",)))
            await _flush(pilot)
            home = app.workarea / "proj" / PROJECT_PATCHES_DIR
            copies = list(home.glob("boost*.json"))
            return common_doc.read_bytes(), len(copies)

    common_now, copy_count = asyncio.run(_drive())
    assert copy_count == 2, (
        f"a drifted re-save keeps the placed copy and adds the next free "
        f"_<N> name; found {copy_count}"
    )
    refreshed = (tmp_path / ".s19tool" / "workarea" / "proj" / "patches" / "boost_1.json")
    assert refreshed.read_bytes() == common_now, (
        "a re-save must place the drifted copy at the next free name, "
        "holding the COMMON original's bytes"
    )
    original = (tmp_path / ".s19tool" / "workarea" / "proj" / "patches" / "boost.json")
    assert original.read_bytes() != common_now, (
        "the previously placed copy is immutable once placed (LLR-155.3)"
    )


# --------------------------------------------------------------------------- #
# HLR-138 — the scoped homes (the save dialogs' default destinations)
# --------------------------------------------------------------------------- #


def test_scoped_home_patch_save_with_project_lands_in_project(tmp_path: Path) -> None:
    """HLR-138 (scoped homes): with a project, a NEW change-set save lands in
    ``<project>/patches/`` — and in ``<project>/checks/`` when the document
    is a check document (the wire ``kind``)."""
    base = tmp_path
    project = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "proj"
    project.mkdir(parents=True)
    common_patches = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_PATCHES

    change_path, issues = write_change_document(
        _change_doc("change"), base, file_name="cal.json",
        dest_dir=project / PROJECT_PATCHES_DIR,
    )
    assert issues == []
    assert change_path == project / PROJECT_PATCHES_DIR / "cal.json"
    check_path, issues = write_change_document(
        _change_doc("check"), base, file_name="smoke.json",
        dest_dir=project / PROJECT_CHECKS_DIR,
    )
    assert issues == []
    assert check_path == project / PROJECT_CHECKS_DIR / "smoke.json"
    # The COMMON library gained nothing from the scoped saves.
    assert list(common_patches.glob("*.json")) == []

    # The app's save-dialog destination routing follows the same project
    # context and kind discriminator.
    async def _drive() -> tuple[Optional[Path], Optional[Path], Optional[Path]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            none_home = app._change_doc_save_home()
            app.current_project = "proj"
            app.current_project_dir = project
            patches_home = app._change_doc_save_home()
            app._change_service.document.kind = "check"
            checks_home = app._change_doc_save_home()
            return none_home, patches_home, checks_home

    none_home, patches_home, checks_home = asyncio.run(_drive())
    assert none_home is None, "without a project the writer keeps the COMMON home"
    assert patches_home == project / PROJECT_PATCHES_DIR, patches_home
    assert checks_home == project / PROJECT_CHECKS_DIR, checks_home


def test_scoped_home_patch_save_without_project_keeps_common(tmp_path: Path) -> None:
    """HLR-138 (scoped homes, no-project limb): without a project the patch
    save keeps the COMMON ``workarea/patches/`` home — the shipped default
    is unchanged."""
    base = tmp_path
    path, issues = write_change_document(
        _change_doc("change"), base, file_name="plain.json"
    )
    assert issues == []
    assert path == base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_PATCHES / "plain.json"


def test_scoped_home_template_save_with_project_lands_in_project(
    tmp_path: Path,
) -> None:
    """HLR-138 (scoped homes): with a project, the CRC Designer's Save
    defaults INTO ``<project>/templates/`` — the COMMON library gains
    nothing."""
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")
    template_name = f"{sanitize_project_name(SEED_ALGORITHM.name)}.crc.json"

    async def _drive() -> tuple[bool, bool, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            _save_project(app, _payload(app))
            await _flush(pilot)
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_field_name", Input).value = "ProjTpl"
            await pilot.pause()
            app.query_one("#crc_save_btn", Button).press()
            await pilot.pause()
            project_dir = app.workarea / "proj"
            in_project = (project_dir / PROJECT_TEMPLATES_DIR / "ProjTpl.crc.json").exists()
            common_lib = ensure_template_lib(app.base_dir)
            in_common = (common_lib / "ProjTpl.crc.json").exists()
            status = str(app.query_one("#crc_loadsave_status", Static).content)
            return in_project, in_common, status

    in_project, in_common, status = asyncio.run(_drive())
    assert in_project, (
        f"with a project the template save must land in <project>/templates/ "
        f"({template_name} is the default-name form); status={status!r}"
    )
    assert not in_common, "with a project the COMMON library must not gain the save"
    assert "Saved" in status, f"the save must report success; got {status!r}"


def test_scoped_home_template_save_without_project_keeps_common_lib(
    tmp_path: Path,
) -> None:
    """HLR-138 (scoped homes, no-project limb): without a project the CRC
    Designer's Save keeps the COMMON ``.s19tool/templates`` library."""
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple[bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            # No project save — only the image is loaded.
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_field_name", Input).value = "CommonTpl"
            await pilot.pause()
            app.query_one("#crc_save_btn", Button).press()
            await pilot.pause()
            common_lib = ensure_template_lib(app.base_dir)
            in_common = (common_lib / "CommonTpl.crc.json").exists()
            stray_projects = [
                p
                for p in app.workarea.iterdir()
                if p.is_dir() and (p / PROJECT_TEMPLATES_DIR / "CommonTpl.crc.json").exists()
            ]
            return in_common, bool(stray_projects)

    in_common, stray = asyncio.run(_drive())
    assert in_common, "without a project the template save must keep the COMMON lib"
    assert not stray, "without a project no project folder may gain the save"


# --------------------------------------------------------------------------- #
# The containment law — everything resolves under .s19tool/workarea/
# --------------------------------------------------------------------------- #


def test_gather_containment_escape_refuses_without_writing(tmp_path: Path) -> None:
    """The containment law: a project home OUTSIDE ``.s19tool/workarea/``
    refuses the gather — one ``GATHER-CONTAINMENT`` finding, no bytes
    written, no exception (collect-don't-abort)."""
    base = tmp_path
    patches = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_PATCHES
    patches.mkdir(parents=True)
    doc = patches / "boost.json"
    doc.write_text(_change_doc_text("change"), encoding="utf-8")
    outside_project = base / "outside" / "proj"
    outside_project.mkdir(parents=True)

    outcome = gather_project_artifacts(
        outside_project,
        composition_names=["boost.json"],
        common_patches_dir=patches,
        common_templates_dir=base / WORKAREA_DIRNAME / "templates",
    )
    assert outcome.gathered == {}, "an escape attempt must gather nothing"
    assert [i.code for i in outcome.issues] == [GATHER_CONTAINMENT], (
        f"the escape must be reported as one containment finding; got {outcome.issues}"
    )
    assert not (outside_project / PROJECT_PATCHES_DIR).exists(), (
        "the refused gather must not create the home directory"
    )


def test_scoped_home_containment_escape_refuses(tmp_path: Path) -> None:
    """The containment law on the scoped homes: a project-scoped save home
    outside ``.s19tool/workarea/`` refuses — ``scoped_home`` raises and the
    change-document writer reports one ``MF-WRITE-CONTAINMENT`` finding,
    never a crash and never a byte outside the work area."""
    base = tmp_path
    outside_project = base / "elsewhere" / "proj"
    outside_project.mkdir(parents=True)

    try:
        scoped_home(outside_project, PROJECT_PATCHES_DIR, base / "common")
    except WorkareaContainmentError:
        pass
    else:
        raise AssertionError(
            "scoped_home must refuse a project home outside .s19tool/workarea/"
        )

    path, issues = write_change_document(
        _change_doc("change"),
        base,
        file_name="escape.json",
        dest_dir=outside_project / PROJECT_PATCHES_DIR,
    )
    assert path is None, "the escape write must produce no path"
    assert any(i.code == MF_WRITE_CONTAINMENT for i in issues), (
        f"the escape must report MF-WRITE-CONTAINMENT; got {issues}"
    )
    assert not (outside_project / PROJECT_PATCHES_DIR / "escape.json").exists(), (
        "no byte may land outside the work area"
    )
