"""Batch-97 folder chips and help chips (HLR-148).

Inc-1 arms only: the ``flows`` / ``session`` families (LLR-148.1, 148.2), the
per-family no-project message (LLR-148.3), the ``id_suffix`` mechanism of
LLR-148.4, the real-directory guard (LLR-148.8) and the folder labels over the
four shipped chip instances plus the no-project arm (LLR-148.10). The help-chip
arms (LLR-148.5..148.7, 148.9) and AT-B97-12/13/14/23 land with Inc-3..6.

Every test opens with a clause that is observable on ``main`` (a family
membership, a signature, an attribute) so a run on the base tree fails at a
named assertion, never at an import or a widget lookup (PDR condition PC-11).
New service names are reached as ``fos.<name>`` inside the tests for the same
reason. The OS boundary is spied with the ``SeamSpy`` idiom; everything else
is read from the shipped surface: the chip and the status line.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
import shutil
from pathlib import Path
from typing import List

import pytest

from s19_app.tui import open_folder_chip as ofc
from s19_app.tui.app import S19TuiApp
from s19_app.tui.open_folder_chip import OpenFolderChip
from s19_app.tui.screens import ReportViewerScreen
from s19_app.tui.services import folder_open_service as fos
from s19_app.tui.services.flow_persistence_service import FLOWS_SUBDIR
from s19_app.tui.services.project_gather_service import (
    PROJECT_CHECKS_DIR,
    PROJECT_PATCHES_DIR,
    PROJECT_TEMPLATES_DIR,
)
from s19_app.tui.services.report_service import REPORTS_DIR_NAME
from s19_app.tui.workspace import (
    WORKAREA_DIRNAME,
    WORKAREA_PATCHES,
    WORKAREA_SUBDIR,
    WORKAREA_TEMPLATES,
)
from tests.b97_fixtures import load_project, make_junction, make_project
from tests.b97_probes import CHIP_TEST_SIZE, chip_label, last_status, mount_chip, settle
from tests.test_open_folder_chips import SeamSpy

NO_PROJECT_TAIL = ": no active project — load a project first."


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


# --------------------------------------------------------------------------- #
# TC-B97-27 — LLR-148.1, the `flows` family
# --------------------------------------------------------------------------- #


def test_tc_b97_27_flows_family_targets_project_flows_dir(tmp_path: Path) -> None:
    """TC-B97-27 (LLR-148.1, layer 0): ``flows`` is a chip family whose target
    is ``<project>/flows`` with a project and ``None`` without one.

    Why: the Flow Builder chip must open the folder flows are saved in
    (``FLOWS_SUBDIR``), and must have nothing to open with no project.
    RED on main: ``"flows" not in CHIP_FAMILIES``. Mutation: target
    ``project_dir`` instead of ``project_dir / FLOWS_SUBDIR``.
    """
    assert "flows" in fos.CHIP_FAMILIES
    project = tmp_path / "p"
    kwargs = dict(family="flows", workarea=_workarea(tmp_path), base_dir=tmp_path)
    assert fos.resolve_chip_target(project, **kwargs) == project / "flows"
    assert fos.resolve_chip_target(None, **kwargs) is None


def test_tc_b97_27_flows_folder_name_imported_never_redeclared() -> None:
    """TC-B97-27 (LLR-148.1, source arm): ``folder_open_service`` imports
    ``FLOWS_SUBDIR`` from ``flow_persistence_service`` and holds no ``"flows"``
    string literal, so the chip and the flow saver cannot disagree on the
    folder (R15).

    RED on main: no import. Mutation: ``CHIP_FAMILY_FLOWS = "flows"``.
    """
    tree = ast.parse(Path(fos.__file__).read_text(encoding="utf-8"))
    imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and (node.module or "").endswith("flow_persistence_service")
        and any(alias.name == "FLOWS_SUBDIR" for alias in node.names)
    ]
    literals = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and node.value == "flows"
    ]
    assert len(imports) == 1, "FLOWS_SUBDIR must be imported exactly once"
    assert literals == [], f'"flows" re-declared at lines {literals}'


def test_tc_b97_27_missing_flows_created_inside_project_then_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-27 (LLR-148.1, boundary): pressing the ``flows`` chip while
    ``flows`` is missing creates it inside the resolved project, then opens it
    with one seam call.

    RED on main: ``"flows" not in CHIP_FAMILIES``. Mutation: skip the
    create-on-press for ``flows`` (the guard then refuses a missing folder,
    0 seam calls).
    """
    assert "flows" in fos.CHIP_FAMILIES
    spy = SeamSpy(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            project_dir = load_project(app)
            chip = await mount_chip(app, pilot, "flows")
            dimmed_before = chip.has_class("-dimmed")
            chip.press()
            await settle(pilot)
            return project_dir, dimmed_before, list(spy.calls)

    project_dir, dimmed_before, calls = asyncio.run(_drive())
    created = project_dir / FLOWS_SUBDIR
    assert dimmed_before, "a missing flows folder renders the chip dimmed"
    assert created.is_dir(), "the press must create <project>/flows"
    assert created.resolve().is_relative_to(project_dir.resolve())
    assert [path for path, _ in calls] == [created], "created, guarded, then opened once"


# --------------------------------------------------------------------------- #
# TC-B97-28 — LLR-148.2, the `session` family
# --------------------------------------------------------------------------- #


def test_tc_b97_28_session_family_targets_project_dir(tmp_path: Path) -> None:
    """TC-B97-28 (LLR-148.2, layer 0): ``session`` targets the project
    directory itself (the value the flow panels show as their session dir)
    and ``None`` without a project.

    RED on main: ``"session" not in CHIP_FAMILIES``. Mutation: target
    ``project_dir / "session"``.
    """
    assert "session" in fos.CHIP_FAMILIES
    project = tmp_path / "p"
    kwargs = dict(family="session", workarea=_workarea(tmp_path), base_dir=tmp_path)
    assert fos.resolve_chip_target(project, **kwargs) == project
    assert fos.resolve_chip_target(None, **kwargs) is None


def test_tc_b97_28_session_never_creates_a_removed_project_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-28 (LLR-148.2, boundary): with the project directory removed
    under the app, a ``session`` press calls ``create_chip_home`` 0 times,
    opens nothing and refuses on the status line naming the folder.

    Why: re-creating a deleted project directory from a chip would fabricate
    an empty project. RED on main: ``"session" not in CHIP_FAMILIES``.
    Mutation: drop the ``session`` exclusion from the create-on-press branch.
    """
    assert "session" in fos.CHIP_FAMILIES
    spy = SeamSpy(monkeypatch)
    creates: List[str] = []
    real_create = fos.create_chip_home

    def _recording_create(*args, **kwargs):
        creates.append(kwargs.get("family", "?"))
        return real_create(*args, **kwargs)

    monkeypatch.setattr(fos, "create_chip_home", _recording_create)
    monkeypatch.setattr(ofc, "create_chip_home", _recording_create)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            project_dir = load_project(app)
            chip = await mount_chip(app, pilot, "session")
            enabled_before = not chip.disabled
            shutil.rmtree(project_dir)
            chip.press()
            await settle(pilot)
            return project_dir, enabled_before, last_status(app), chip.tooltip

    project_dir, enabled_before, status, tooltip = asyncio.run(_drive())
    assert enabled_before, "with a project the session chip is enabled"
    # The create-offer tooltip would promise a press the chip refuses
    # (gate F2). Mutation: drop the session tooltip branch.
    assert tooltip == "project folder is missing", tooltip
    assert creates == [], "the session chip never creates a folder"
    assert spy.calls == [], "a removed project dir is not opened"
    assert not project_dir.exists(), "the project dir must not be re-created"
    assert status.startswith("Refused to open "), status
    assert str(project_dir) in status, "the refusal names the folder"


# --------------------------------------------------------------------------- #
# TC-B97-29 — LLR-148.3, the no-project message names the family's folder
# --------------------------------------------------------------------------- #

#: The folder each project-only family's message must name.
_NO_PROJECT_FOLDER = {"reports": "reports/", "flows": "flows/", "session": "session"}


def test_tc_b97_29_no_project_reason_names_each_family_folder() -> None:
    """TC-B97-29 (LLR-148.3, layer 0): ``no_project_reason(family)`` names
    that family's folder and the Reports constant is its ``reports`` value.

    RED on main: ``CHIP_FAMILIES`` holds 4 families. Mutation: return
    ``REPORTS_NO_PROJECT_REASON`` for every family.
    """
    assert len(fos.CHIP_FAMILIES) >= 6
    assert fos.REPORTS_NO_PROJECT_REASON == fos.no_project_reason("reports")
    for family, folder in _NO_PROJECT_FOLDER.items():
        reason = fos.no_project_reason(family)
        assert folder in reason and reason.endswith(NO_PROJECT_TAIL), (family, reason)
        if family != "reports":
            assert "reports" not in reason.lower(), (family, reason)


def test_tc_b97_29_no_project_chips_disabled_with_their_own_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-29 (LLR-148.3, integration): with no project, every family
    whose target is ``None`` (read from ``CHIP_FAMILIES`` at test time) mounts
    disabled, paints a status naming its own folder and never Reports, and a
    press opens nothing.

    Why: a dimmed Flow chip that says "(Reports)" sends the user to the wrong
    screen. RED on main: ``len(CHIP_FAMILIES) == 4``; the shipped chip sets
    ``REPORTS_NO_PROJECT_REASON`` for any ``None`` target (P-18). Mutation:
    restore that single reason.
    """
    assert len(fos.CHIP_FAMILIES) >= 6
    spy = SeamSpy(monkeypatch)
    none_families = [
        family
        for family in fos.CHIP_FAMILIES
        if fos.resolve_chip_target(
            None, family=family, workarea=_workarea(tmp_path), base_dir=tmp_path
        )
        is None
    ]
    assert set(none_families) == set(_NO_PROJECT_FOLDER), none_families

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        observed = {}
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            for family in none_families:
                chip = await mount_chip(app, pilot, family, id_suffix="tc29")
                observed[family] = (chip.disabled, last_status(app))
                chip.press()
                await settle(pilot)
        return observed

    observed = asyncio.run(_drive())
    assert len(observed) >= 3
    for family, (disabled, status) in observed.items():
        assert disabled, f"{family}: a None target disables the chip"
        assert _NO_PROJECT_FOLDER[family] in status, (family, status)
        assert status.endswith(NO_PROJECT_TAIL), (family, status)
        if family != "reports":
            assert "reports" not in status.lower(), (family, status)
    assert spy.calls == [], "a disabled chip opens nothing"


# --------------------------------------------------------------------------- #
# TC-B97-30 (Inc-1 arm) — LLR-148.4, the id_suffix mechanism
# --------------------------------------------------------------------------- #


def test_tc_b97_30_id_suffix_gives_a_second_checks_chip_its_own_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-30 (LLR-148.4, Inc-1 mechanism arm): ``OpenFolderChip(family,
    id_suffix=...)`` carries ``open_folder_<family>_<suffix>``, so a second
    ``checks`` chip (the Check Editor's, mounted at Inc-3) and the Checks
    screen's chip each hold a unique id and resolve the same ``checks`` home.

    RED on main: no ``id_suffix`` parameter (P-19). Mutation: ignore the
    suffix (two ``open_folder_checks`` ids).
    """
    assert "id_suffix" in inspect.signature(OpenFolderChip.__init__).parameters
    spy = SeamSpy(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            project_dir = load_project(app)
            (project_dir / PROJECT_CHECKS_DIR).mkdir()
            app.action_show_screen("checks")
            await settle(pilot)
            editor_chip = await mount_chip(app, pilot, "checks", id_suffix="editor")
            counts = (
                len(app.query("#open_folder_checks")),
                len(app.query("#open_folder_checks_editor")),
            )
            app.query_one("#open_folder_checks", OpenFolderChip).press()
            await settle(pilot)
            editor_chip.press()
            await settle(pilot)
            return project_dir, counts, list(spy.calls)

    project_dir, counts, calls = asyncio.run(_drive())
    assert OpenFolderChip("checks").id == "open_folder_checks"
    assert counts == (1, 1), f"each chip id must be unique in the app: {counts}"
    home = project_dir / PROJECT_CHECKS_DIR
    assert [path for path, _ in calls] == [home, home], "both chips open the checks home"


# --------------------------------------------------------------------------- #
# TC-B97-57 — LLR-148.8, a chip opens only a real directory inside its root
# --------------------------------------------------------------------------- #


def test_tc_b97_57_family_root_is_project_dir_else_tool_root(tmp_path: Path) -> None:
    """TC-B97-57 (LLR-148.8, layer 0): the guard's trust anchor has one
    producer — the project dir, else ``<base>/.s19tool`` (§1.3 family root).

    Why: a root of ``workarea`` would refuse the no-project templates chip
    (``.s19tool/templates`` lies outside it, H-C3). RED on main: no producer.
    Mutation: return ``base_dir / WORKAREA_DIRNAME / WORKAREA_SUBDIR``.
    """
    assert hasattr(fos, "chip_family_root")
    project = tmp_path / "p"
    assert fos.chip_family_root(project, tmp_path) == project
    assert fos.chip_family_root(None, tmp_path) == tmp_path / WORKAREA_DIRNAME


def test_tc_b97_57_guard_unit_arms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """TC-B97-57 (LLR-148.8, layer 0): ``is_openable_chip_dir`` is True only
    for a real directory, reached through no reparse point below the root,
    whose resolved form lies inside the resolved root.

    Mutations, one per conjunct: drop ``is_dir()`` (the file arm reddens);
    drop the reparse walk (the leaf junction pointing INSIDE the root and
    the intermediate junction redden — containment alone passes them);
    drop the containment (the outside-directory arm reddens); let
    ``OSError`` / ``ValueError`` escape (the raising arms redden).
    """
    assert hasattr(fos, "is_openable_chip_dir")
    guard = fos.is_openable_chip_dir
    root = tmp_path / "root"
    real = root / "real"
    real.mkdir(parents=True)
    a_file = root / "file"
    a_file.write_text("x", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    leaf_in = root / "leaf_in"
    make_junction(leaf_in, root / "elsewhere_inside")
    leaf_out = root / "leaf_out"
    make_junction(leaf_out, outside / "target")
    mid = root / "mid"
    make_junction(mid, root / "mid_target")
    (root / "mid_target" / "child").mkdir()

    assert guard(real, root) is True, "a real directory inside the root opens"
    assert guard(root, root) is True, "the root itself (the session target) opens"
    assert guard(a_file, root) is False, "a file is not a directory"
    assert guard(root / "missing", root) is False, "a missing target is refused"
    assert guard(leaf_in, root) is False, "a leaf junction is refused even pointing inside"
    assert guard(leaf_out, root) is False, "a leaf junction pointing outside is refused"
    assert guard(mid / "child", root) is False, "a junction between target and root is refused"
    assert guard(outside, root) is False, "a real directory outside the root is refused"
    assert guard(root / "a\x00b", root) is False, "a NUL path is refused, never raised"

    def _raise(self, *args, **kwargs):
        raise OSError("target vanished")

    monkeypatch.setattr(Path, "resolve", _raise)
    assert guard(real, root) is False, "an OSError while resolving is a refusal"


@pytest.mark.parametrize("family", ["checks", "flows"])
@pytest.mark.parametrize("case", ["file", "junction", "real", "missing"])
def test_tc_b97_57_chip_press_guarded_in_a_loaded_project(
    family: str, case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-57 (LLR-148.8, integration): in a project opened through the
    app's own load, the family folder as a file or a junction to a directory
    outside the project → 0 seam calls and a refusal naming it; a real
    directory → 1 call; a missing one → created inside the project, guarded,
    1 call. The ``checks`` arms run the shipped Checks chip.

    RED on main (P-34): the shipped guard is ``exists()``, so the ``checks``
    file and junction arms call the seam; the ``flows`` arms stop at the
    membership clause. Mutation: reduce the guard to ``exists()``.
    """
    assert family in fos.CHIP_FAMILIES
    spy = SeamSpy(monkeypatch)
    subdir = {"checks": PROJECT_CHECKS_DIR, "flows": FLOWS_SUBDIR}[family]

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            project_dir = load_project(app)
            folder = project_dir / subdir
            if case == "file":
                folder.write_text("not a folder", encoding="utf-8")
            elif case == "junction":
                make_junction(folder, tmp_path / "outside")
            elif case == "real":
                folder.mkdir()
            if family == "checks":
                app.action_show_screen("checks")
                await settle(pilot)
                chip = app.query_one("#open_folder_checks", OpenFolderChip)
                chip.refresh_target()
            else:
                chip = await mount_chip(app, pilot, family)
            chip.press()
            await settle(pilot)
            return folder, last_status(app)

    folder, status = asyncio.run(_drive())
    if case in ("file", "junction"):
        assert spy.calls == [], f"{case}: the seam must not be called"
        assert status.startswith("Refused to open "), status
        assert str(folder) in status, "the refusal names the folder"
    else:
        assert [path for path, _ in spy.calls] == [folder], f"{case}: one open"
        assert folder.is_dir() and not folder.is_symlink()


def test_tc_b97_57_no_project_patch_common_home_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-57 (LLR-148.8, no-project arm): with no project the root is the
    tool root, so the real COMMON ``workarea/patches`` home opens (1 call)
    and so does the COMMON templates library outside ``workarea``.

    Mutation: root = ``base_dir / .s19tool / workarea`` (the templates arm
    reddens, H-C3); a guard that refuses everything (both arms redden).
    """
    spy = SeamSpy(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            for screen, chip_id in (("patch", "#open_folder_patch"), ("crc_designer", "#open_folder_templates")):
                app.action_show_screen(screen)
                await settle(pilot)
                app.query_one(chip_id, OpenFolderChip).press()
                await settle(pilot)
        return list(spy.calls)

    calls = asyncio.run(_drive())
    assert [path for path, _ in calls] == [
        _workarea(tmp_path) / WORKAREA_PATCHES,
        tmp_path / WORKAREA_DIRNAME / WORKAREA_TEMPLATES,
    ]


async def _press_no_project_patch_chip(base: Path, spy: SeamSpy):
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
        await settle(pilot)
        app.action_show_screen("patch")
        await settle(pilot)
        app.query_one("#open_folder_patch", OpenFolderChip).press()
        await settle(pilot)
        return list(spy.calls), last_status(app)


def test_tc_b97_57_reparse_point_above_the_root_is_not_the_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-57 (LLR-148.8 boundary, gate F1a): with no project, a junction
    ABOVE the tool root (here the base dir itself) is not the guard's — the
    walk stops at ``root.parent`` — so the COMMON patches home opens.

    Why: a workspace under a redirected folder must not lose every
    no-project chip. Mutation: ``stop_at=None`` (the walk reaches the
    junctioned base dir and refuses).
    """
    real_base = tmp_path / "real_base"
    base = tmp_path / "linked_base"
    make_junction(base, real_base)
    spy = SeamSpy(monkeypatch)
    calls, status = asyncio.run(_press_no_project_patch_chip(base, spy))
    assert [path for path, _ in calls] == [_workarea(base) / WORKAREA_PATCHES], status


def test_tc_b97_57_reparse_point_at_the_root_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-57 (LLR-148.8 boundary, gate F1b): with no project, a tool root
    ``.s19tool`` that is itself a junction is refused — the walk checks the
    root and everything below it — with 0 seam calls.

    Mutation: ``stop_at=root`` (the walk stops before the root, and the
    containment check passes because both sides resolve through it).
    """
    base = tmp_path / "base"
    base.mkdir()
    make_junction(base / WORKAREA_DIRNAME, tmp_path / "real_tool")
    spy = SeamSpy(monkeypatch)
    calls, status = asyncio.run(_press_no_project_patch_chip(base, spy))
    assert calls == [], "a junctioned tool root must not be opened through"
    assert status.startswith("Refused to open "), status


# --------------------------------------------------------------------------- #
# TC-B97-65 — LLR-148.10, chips labelled with their folder
# --------------------------------------------------------------------------- #


def test_tc_b97_65_shipped_chips_labelled_with_folder_and_status_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-65 (LLR-148.10, Inc-1: the 4 shipped instances): with a loaded
    project the Patch, Checks, CRC Designer and Reports chips read
    ``📂 Open <folder>/`` from the family constants, and each press paints a
    status line ending with the opened folder's full path.

    Why: four identical ``📂 Open folder`` chips do not say where they go.
    RED on main: every label is ``📂 Open folder`` (P-46). Mutation:
    ``chip_label`` returning the shipped ``📂 Open folder``. (A label never
    recomputed by ``refresh_target`` survives here, because the
    construction-time label already equals the project folder; the
    no-project Checks arm below is the node that kills it.)
    """
    spy = SeamSpy(monkeypatch)
    expected = {
        "patch": PROJECT_PATCHES_DIR,
        "checks": PROJECT_CHECKS_DIR,
        "templates": PROJECT_TEMPLATES_DIR,
        "reports": REPORTS_DIR_NAME,
    }

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        observed = {}
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            project_dir = load_project(app)
            for family, screen in (("patch", "patch"), ("checks", "checks"), ("templates", "crc_designer")):
                app.action_show_screen(screen)
                await settle(pilot)
                chip = app.query_one(f"#open_folder_{family}", OpenFolderChip)
                label = chip_label(chip)
                chip.press()
                await settle(pilot)
                observed[family] = (label, last_status(app))
            modal = ReportViewerScreen("proj1", [])
            app.push_screen(modal)
            await settle(pilot)
            chip = modal.query_one("#open_folder_reports", OpenFolderChip)
            label = chip_label(chip)
            chip.press()
            await settle(pilot)
            observed["reports"] = (label, last_status(app))
        return project_dir, observed

    project_dir, observed = asyncio.run(_drive())
    for family, folder in expected.items():
        label, status = observed[family]
        assert label == f"📂 Open {folder}/", (family, label)
        assert status.endswith(str(project_dir / folder)), (family, status)
    assert len(spy.calls) == 4


def test_tc_b97_65_no_project_checks_chip_names_the_folder_it_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-65 (LLR-148.10, no-project arm, LED-.6): without a project the
    Checks chip opens the COMMON ``workarea/patches`` home, so it reads
    ``📂 Open patches/``; after a project load it reads ``📂 Open checks/``.

    Why: the label must name the folder the press opens (H-C1). RED on main:
    ``📂 Open folder``. Mutation: label from the family constant instead of
    the resolved target's leaf (``📂 Open checks/`` with no project).
    """
    spy = SeamSpy(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            app.action_show_screen("checks")
            await settle(pilot)
            chip = app.query_one("#open_folder_checks", OpenFolderChip)
            no_project_label = chip_label(chip)
            chip.press()
            await settle(pilot)
            load_project(app)
            await settle(pilot)
            return no_project_label, chip_label(chip), list(spy.calls)

    no_project_label, project_label, calls = asyncio.run(_drive())
    assert no_project_label == f"📂 Open {WORKAREA_PATCHES}/"
    assert [path for path, _ in calls] == [_workarea(tmp_path) / WORKAREA_PATCHES]
    assert project_label == f"📂 Open {PROJECT_CHECKS_DIR}/", "label recomputed on refresh"


def test_tc_b97_65_no_project_session_chip_disabled_with_exact_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-65 (LLR-148.10, no-project arm, LED-.6): the ``session`` chip
    reads ``📂 Open session``, is disabled with no project, and the status
    reads ``📂 Open session: no active project — load a project first.``;
    the ``flows`` chip reads ``📂 Open flows/``.

    RED on main: ``"session" not in CHIP_FAMILIES``. Mutation: ``📂 Open
    session/`` (the folder-suffix rule applied to ``session``).
    """
    assert "session" in fos.CHIP_FAMILIES
    spy = SeamSpy(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            flows = await mount_chip(app, pilot, "flows")
            flows_label = chip_label(flows)
            session = await mount_chip(app, pilot, "session")
            state = (chip_label(session), session.disabled, last_status(app))
            session.press()
            await settle(pilot)
            return flows_label, state

    flows_label, (label, disabled, status) = asyncio.run(_drive())
    assert flows_label == f"📂 Open {FLOWS_SUBDIR}/"
    assert label == "📂 Open session"
    assert disabled
    assert status == "📂 Open session: no active project — load a project first."
    assert spy.calls == []
