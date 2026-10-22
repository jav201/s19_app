"""Batch-97 folder chips and help chips (HLR-148).

Inc-1 arms only: the ``flows`` / ``session`` families (LLR-148.1, 148.2), the
per-family no-project message (LLR-148.3), the ``id_suffix`` mechanism of
LLR-148.4, the real-directory guard (LLR-148.8) and the folder labels over the
four shipped chip instances plus the no-project arm (LLR-148.10). Inc-3 adds the
Check Editor arms of LLR-148.4 (the mounted ``open_folder_checks_editor``),
148.5, 148.6, 148.7 and 148.9; Inc-4 the Patch Editor arms; Inc-5 the Flow
Builder arms (the ``flows`` header chip, the ``flow`` help body, the Builder
vocabularies and their WT widths, the region states); the Execution arms and
AT-B97-12/13/14/23 land with Inc-6.

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
from tests.b97_fixtures import load_project, make_junction, make_project, unload_project
from tests.b97_probes import CHIP_TEST_SIZE, chip_label, last_status, mount_chip, record_statuses, settle
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
    disabled and writes no status line at mount (gate fold, operator decision
    1, LED-…97.24); after a project is loaded and then dropped — a
    transition to disabled after mount — the chip's status line names its own
    folder and never Reports; a press of the disabled chip opens nothing.

    Why: a dimmed Flow chip that says "(Reports)" sends the user to the wrong
    screen, and a reason printed at startup for a chip nobody touched reads
    as an error. RED on main: ``len(CHIP_FAMILIES) == 4``; the shipped chip
    sets ``REPORTS_NO_PROJECT_REASON`` for any ``None`` target (P-18). RED on
    the pre-fold Inc-5 tree: the reason is written at mount. Mutation:
    restore that single reason; announce on the first refresh.
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
    statuses = record_statuses(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        observed = {}
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            for family in none_families:
                seen = len(statuses)
                chip = await mount_chip(app, pilot, family, id_suffix="tc29")
                at_mount = [line for line in statuses[seen:] if NO_PROJECT_TAIL in line]
                disabled = chip.disabled
                chip.press()
                await settle(pilot)
                load_project(app)
                await settle(pilot)
                seen = len(statuses)
                unload_project(app)
                await settle(pilot)
                after = [line for line in statuses[seen:] if NO_PROJECT_TAIL in line]
                observed[family] = (disabled, at_mount, after, chip.disabled)
                await chip.remove()
                await settle(pilot)
        return observed

    observed = asyncio.run(_drive())
    assert len(observed) >= 3
    for family, (disabled, at_mount, after, disabled_again) in observed.items():
        assert disabled and disabled_again, f"{family}: a None target disables the chip"
        assert at_mount == [], (family, at_mount)
        assert fos.no_project_reason(family) in after, (family, after)
        assert _NO_PROJECT_FOLDER[family] in fos.no_project_reason(family)
        if family != "reports":
            assert all("reports" not in line.lower() for line in after), (family, after)
    assert spy.calls == [], "a disabled chip opens nothing"


def test_tc_b97_29_no_status_line_at_startup_without_a_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-29 (LLR-148.3 as amended by LED-…97.24, startup arm): an app
    started with no project writes no chip status line while the header chips
    mount — on the workspace and after the Flow Builder (its ``📂 Open
    flows/`` chip) is shown.

    RED on the pre-fold Inc-5 tree: ``📂 Open flows/: no active project —
    load a project first.`` on the status log at startup (PC-10, 29 of 29
    snapshot cells). Mutation: announce on the first refresh.
    """

    statuses = record_statuses(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            at_start = [line for line in statuses if NO_PROJECT_TAIL in line]
            app.action_show_screen("flow")
            await settle(pilot)
            chip = app.query_one("#open_folder_flows", OpenFolderChip)
            shown = [line for line in statuses if NO_PROJECT_TAIL in line]
            return at_start, shown, chip.disabled

    at_start, shown, disabled = asyncio.run(_drive())
    assert disabled, "the no-project flows chip is disabled"
    assert at_start == [] and shown == [], (at_start, shown)


# --------------------------------------------------------------------------- #
# TC-B97-30 — LLR-148.4, chip ids unique; the Check Editor chip mounted (Inc-3)
# --------------------------------------------------------------------------- #


def test_tc_b97_30_check_editor_chip_unique_and_opens_checks_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-30 (LLR-148.4): every mounted open-folder chip carries an id no
    other widget carries — the Check Editor header mounts its ``checks`` chip as
    ``#open_folder_checks_editor`` (D9) beside the Checks screen's
    ``#open_folder_checks`` — and both resolve the same ``checks`` home.

    Named supersession (Inc-3): the Inc-1 arm
    ``test_tc_b97_30_id_suffix_gives_a_second_checks_chip_its_own_id`` mounted a
    stand-in ``id_suffix="editor"`` chip because no screen carried one; with the
    real chip mounted that stand-in would be the duplicate, so the arm now
    reads the mounted chip. The ``id_suffix`` signature clause is kept.

    RED on main (P-19): no Check Editor chip. Mutation: the Check Editor
    mounts ``OpenFolderChip("checks")`` without ``id_suffix`` (two
    ``open_folder_checks``).
    """
    import collections

    assert "id_suffix" in inspect.signature(OpenFolderChip.__init__).parameters
    spy = SeamSpy(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            project_dir = load_project(app)
            (project_dir / PROJECT_CHECKS_DIR).mkdir()
            ids = collections.Counter(w.id for w in app.query(OpenFolderChip))
            presses = []
            for screen, chip_id in (("checks", "open_folder_checks"), ("check_editor", "open_folder_checks_editor")):
                app.action_show_screen(screen)
                await settle(pilot)
                chips = list(app.query(f"#{chip_id}"))
                if len(chips) == 1:
                    chips[0].press()
                    await settle(pilot)
                presses.append(len(chips))
            return project_dir, ids, presses, list(spy.calls)

    project_dir, ids, presses, calls = asyncio.run(_drive())
    assert ids["open_folder_checks_editor"] == 1, f"the Check Editor chip is mounted once: {ids}"
    assert all(count == 1 for count in ids.values()), f"each chip id unique in the app: {ids}"
    assert presses == [1, 1]
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
    """TC-B97-65 (LLR-148.10, no-project arm, LED-.6; LLR-148.3 as amended by
    LED-…97.24): the ``session`` chip reads ``📂 Open session``, is disabled
    with no project and writes no status line at mount; after a project is
    loaded and dropped, the status reads ``📂 Open session: no active project
    — load a project first.``; the ``flows`` chip reads ``📂 Open flows/``.

    RED on main: ``"session" not in CHIP_FAMILIES``. RED on the pre-fold
    Inc-5 tree: the reason is written at mount. Mutation: ``📂 Open
    session/`` (the folder-suffix rule applied to ``session``).
    """
    assert "session" in fos.CHIP_FAMILIES
    spy = SeamSpy(monkeypatch)
    statuses = record_statuses(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            flows = await mount_chip(app, pilot, "flows")
            flows_label = chip_label(flows)
            seen = len(statuses)
            session = await mount_chip(app, pilot, "session")
            at_mount = list(statuses[seen:])
            state = (chip_label(session), session.disabled)
            session.press()
            await settle(pilot)
            load_project(app)
            await settle(pilot)
            seen = len(statuses)
            unload_project(app)
            await settle(pilot)
            after = list(statuses[seen:])
            return flows_label, state, at_mount, after, session.disabled

    flows_label, (label, disabled), at_mount, after, disabled_again = asyncio.run(_drive())
    assert flows_label == f"📂 Open {FLOWS_SUBDIR}/"
    assert label == "📂 Open session"
    assert disabled and disabled_again
    assert [line for line in at_mount if NO_PROJECT_TAIL in line] == [], at_mount
    assert "📂 Open session: no active project — load a project first." in after, after
    assert spy.calls == []


# --------------------------------------------------------------------------- #
# Inc-3 — the Check Editor arms of LLR-148.5, 148.6, 148.7, 148.9
# --------------------------------------------------------------------------- #

CHECK_TABS = ("check_tab_fields", "check_tab_json", "check_tab_addendum")


def test_tc_b97_31_check_editor_header_carries_both_chips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-31 (LLR-148.5, Check arm): the Check Editor header is a
    ``titled_header`` row holding one ``OpenFolderChip`` and one
    ``WindowHelpChip``; with a project, a click and an ``enter`` on the folder
    chip each make exactly one seam call with ``resolve_chip_target``'s target.

    RED on main (P-20): the header is a bare ``Label`` — 0 chips.
    """
    from s19_app.tui.window_help import WindowHelpChip

    spy = SeamSpy(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        make_project(app)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            project_dir = load_project(app)
            (project_dir / PROJECT_CHECKS_DIR).mkdir()
            app.action_show_screen("check_editor")
            await settle(pilot)
            screen = app.query_one("#screen_check_editor")
            headers = list(screen.query(".db-screen-header"))
            counts = (
                sum(len(h.query(OpenFolderChip)) for h in headers),
                sum(len(h.query(WindowHelpChip)) for h in headers),
            )
            if counts[0] == 1:
                chip = headers[0].query_one(OpenFolderChip)
                await pilot.click(f"#{chip.id}")
                await settle(pilot)
                chip.focus()
                await pilot.press("enter")
                await settle(pilot)
            target = fos.resolve_chip_target(
                project_dir, family="checks", workarea=app.workarea, base_dir=tmp_path
            )
            return counts, target, list(spy.calls)

    counts, target, calls = asyncio.run(_drive())
    assert counts == (1, 1), f"one folder chip and one help chip in the header: {counts}"
    assert [path for path, _ in calls] == [target, target]


def _check_help_lines() -> dict:
    from s19_app.tui.window_help import section_body_text

    lines = {}
    for raw in section_body_text("check_editor").split("\n"):
        text = raw.strip()
        text = text.split(". ", 1)[1] if text[:1].isdigit() and ". " in text else text
        if " — " in text:
            label, effect = text.split(" — ", 1)
            lines[label.strip()] = effect.strip()
    return lines


def _strip_glyph(label: str) -> str:
    """A button label without its leading glyph prefix (``📂 Open checks/``)."""
    text = label.strip()
    while text and not (text[0].isalnum() or text[0] in "?."):
        text = text[1:].lstrip()
    return text


def test_tc_b97_32_check_editor_help_names_every_label(tmp_path: Path) -> None:
    """TC-B97-32 (LLR-148.6, Check arm): the ``check_editor`` help body holds one
    ``label — effect`` line, effect non-empty, for every button, tab chip, input
    and select label the screen renders over its three tab states, every key it
    binds (``space``, ``enter``, ``?``) and every glyph of ``CHECK_GLYPHS``; the
    control subset counts >= 12.

    RED on main (P-21): no ``check_editor`` section (0 of 6 buttons named).
    Mutation: a body listing labels without `` — effect``; coverage read from
    the Fields tab only.
    """
    from textual.widgets import Button, Input as _Input, Label as _Label, Select as _Select

    from s19_app.tui import screens_directionb as sdb
    from s19_app.tui.window_help import WINDOW_HELP_SECTIONS

    assert "check_editor" in WINDOW_HELP_SECTIONS, "a check_editor help section exists"

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            app.action_show_screen("check_editor")
            await settle(pilot)
            screen = app.query_one("#screen_check_editor")
            controls, keys = set(), set()
            for tab in CHECK_TABS:
                app.query_one(f"#{tab}").press()
                await settle(pilot)
                for widget in screen.query("*"):
                    if not widget.display or widget.region.width == 0:
                        continue
                    if isinstance(widget, Button):
                        controls.add(_strip_glyph(str(widget.label)))
                    elif isinstance(widget, (_Input, _Select)):
                        row = [
                            str(lab.render()).strip()
                            for lab in screen.query(_Label)
                            if lab.display and lab.region.y == widget.region.y and lab.region.right <= widget.region.x
                        ]
                        controls.add(row[-1] if row else getattr(widget, "placeholder", ""))
                    for binding in getattr(type(widget), "BINDINGS", []):
                        key = binding.key if hasattr(binding, "key") else binding[0]
                        keys.add({"question_mark": "?"}.get(key, key))
            return controls, keys

    controls, keys = asyncio.run(_drive())
    keys &= {"space", "enter", "?"}
    keys.add("enter")
    glyphs = set(sdb.CHECK_GLYPHS)
    lines = _check_help_lines()
    assert len(controls) >= 12, sorted(controls)
    missing = sorted((controls | keys | glyphs) - set(lines))
    assert missing == [], f"labels with no `label — effect` line: {missing}"
    assert all(lines[label] for label in controls | keys | glyphs)


def test_tc_b97_33_check_glyphs_closed_and_in_the_legend(tmp_path: Path) -> None:
    """TC-B97-33 (LLR-148.7, Check arm): the glyphs painted in the ledger's mark
    column and at the head of each REPORT FIELDS line belong to
    ``CHECK_GLYPHS`` (>= 2 painted), every vocabulary glyph is named in the
    one-row ``#check_legend``, and no painted text says ``issues``.

    RED on main: no ``CHECK_GLYPHS``. Mutation: a renderer painting a glyph
    outside the vocabulary.
    """
    from s19_app.tui import screens_directionb as sdb
    from tests.b97_fixtures import DEMO_A2L, open_check_editor
    from tests.b97_probes import painted_rows

    vocabulary = getattr(sdb, "CHECK_GLYPHS", None)
    assert vocabulary, "the Check Editor's closed glyph vocabulary exists"

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            panel = await open_check_editor(app, pilot, a2l=DEMO_A2L)
            table = panel.query_one("#check_param_table")
            for row in (0, 2):
                table.move_cursor(row=row)
                await settle(pilot)
                panel.query_one("#check_param_include_button").press()
                await settle(pilot)
            panel.query_one("#check_mem_address_input").value = "0x100"
            panel.query_one("#check_mem_size_input").value = "1"
            panel.query_one("#check_mem_add_button").press()
            await settle(pilot)
            cols = table.ordered_columns
            x0 = table.cell_padding
            marks = [row[x0:x0 + cols[0].width] for row in painted_rows(app, table)[1:]]
            fields = [row[:1] for row in painted_rows(app, panel.query_one("#check_fields_lines"))[1:] if row.strip()]
            legend = panel.query_one("#check_legend")
            legend_rows = [r for r in painted_rows(app, legend) if r.strip()]
            panel_text = "\n".join(painted_rows(app, panel))
            return marks, fields, legend_rows, legend.region.height, panel_text

    marks, fields, legend_rows, legend_h, panel_text = asyncio.run(_drive())
    painted = {c for text in marks + fields for c in text if not c.isalnum() and not c.isspace()}
    assert painted <= set(vocabulary), painted - set(vocabulary)
    assert len(painted) >= 2, painted
    assert legend_h <= 2 and 1 <= len(legend_rows) <= 2
    assert all(glyph in "".join(legend_rows) for glyph in vocabulary), legend_rows
    assert "issues" not in panel_text


#: Glyphs seen painted ONE cell wide in a real Windows Terminal capture (the
#: headless compositor counts every one of them as 1 cell, so only a real
#: terminal can tell). Source: ``.dev-flow/2026-10-19-batch-97/evidence/inc-3/
#: png/impl.check-editor.png`` (Inc-3 gate fold, 2026-10-21), read at the
#: Fields lines — ``◆ 0x…`` and ``▪ 0x…`` start their addresses in the same
#: column — and the legend row; the SHA-256 is in the Inc-3 packet §4. ``☑`` is
#: deliberately absent: the first Inc-3 capture painted it two cells wide,
#: glued to the address (LED-2026-10-19-batch-97.12).
#: Inc-5 extension (design D7, PDR delta 2026-10-21 (b)): the Flow Builder
#: glyphs seen ONE cell wide in the real Windows Terminal ruler capture
#: ``evidence/pc-before-inc5-2026-10-21/png/glyph-ruler-wt*.png`` (SHA-256 in
#: its ``png/SHA256SUMS.txt``), re-confirmed on Inc-5's own captures
#: ``evidence/inc-5/png/impl.flow-builder*.png``. ``✖`` ``⚠`` ``✔`` ``☑``
#: ``⏸`` painted two cells in that capture and are absent on purpose.
WT_NARROW_GLYPHS = (
    "✓", "◆", "▪",
    "◉", "▣", "⊕", "▼", "⏚", "»", "≡", "─", "▶", "●", "◈", "○", "□", "✗",
)


def test_tc_b97_33_check_glyphs_are_narrow_in_windows_terminal() -> None:
    """TC-B97-33 (LLR-148.7 / LLR-145.6, WT width arm): every Check Editor
    glyph is one the real-terminal capture showed one cell wide, so no mark
    glues itself to the address after it.

    Why: the headless tests cannot see a double-width glyph; the operator saw
    ``☑0x00013A00`` in Windows Terminal. RED on the pre-fold tree (``☑`` in
    the vocabulary); mutation: the vocabulary back to ``☑``.
    """
    from s19_app.tui import screens_directionb as sdb

    assert set(sdb.CHECK_GLYPHS) <= set(WT_NARROW_GLYPHS), sorted(set(sdb.CHECK_GLYPHS) - set(WT_NARROW_GLYPHS))
    assert sdb.CHECK_GLYPHS.get("◆") == "parameter field"


@pytest.mark.parametrize("arm", ["no_a2l", "nothing_included", "write_dir", "write_readonly"])
def test_tc_b97_58_check_editor_region_states(tmp_path: Path, arm: str) -> None:
    """TC-B97-58 (LLR-148.9, Check arms): the parameter ledger with no A2L, the
    REPORT FIELDS card with nothing included, and a Write refused at the
    staging path (a directory, then a read-only file, P-51) each paint exactly
    one English line in their region, and no traceback.

    RED on main: no ledger empty line; a refused Write paints nothing in the
    card (the refusal only reaches the app status line).
    """
    import os

    from tests.b97_fixtures import DEMO_A2L, ES_MARKER_RE, open_check_editor, staging_block
    from tests.b97_probes import painted_rows

    blocker = None
    if arm.startswith("write_"):
        blocker = staging_block(tmp_path, "spec.chk.json", "dir" if arm == "write_dir" else "readonly")

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            panel = await open_check_editor(app, pilot, a2l=None if arm == "no_a2l" else DEMO_A2L)
            if arm == "no_a2l":
                holder = panel.query("#check_full_name_line")
                rows = painted_rows(app, holder.first()) if holder else []
                return [r.strip() for r in rows if r.strip()]
            if arm == "nothing_included":
                holder = panel.query("#check_fields_lines")
                rows = painted_rows(app, holder.first()) if holder else []
                return [r.strip() for r in rows[1:] if r.strip()]
            panel.query_one("#check_write_button").press()
            await settle(pilot, 6)
            status = panel.query_one("#check_status")
            return [r.strip() for r in painted_rows(app, status) if r.strip()]

    try:
        lines = asyncio.run(_drive())
    finally:
        if blocker is not None and blocker.is_file():
            os.chmod(blocker, 0o666)
    assert len(lines) == 1, (arm, lines)
    assert not ES_MARKER_RE.search(lines[0]), lines[0]
    assert "Traceback" not in lines[0]
    if arm.startswith("write_"):
        assert "refused" in lines[0].lower() and "MF-WRITE-CONTAINMENT" in lines[0], lines[0]


# --------------------------------------------------------------------------- #
# Inc-4 — the Patch Editor arms of LLR-148.6, 148.7, 148.9
# --------------------------------------------------------------------------- #

PATCH_TABS = ("patch_tab_inspector", "patch_tab_json", "patch_tab_checks")


def _help_lines(key: str) -> dict:
    from s19_app.tui.window_help import section_body_text

    lines = {}
    for raw in section_body_text(key).split("\n"):
        text = raw.strip()
        text = text.split(". ", 1)[1] if text[:1].isdigit() and ". " in text else text
        if " — " in text:
            label, effect = text.split(" — ", 1)
            lines[label.strip()] = effect.strip()
    return lines


def _control_label(screen, widget) -> str:
    """D20 normalisation: a button up to its first ``:``; an input or select by
    the ``Label`` on its own row to its left (``:`` stripped), else its
    placeholder."""
    from textual.widgets import Button, Label as _Label

    if isinstance(widget, Button):
        return _strip_glyph(str(widget.label)).split(":", 1)[0].strip()
    row = [
        str(lab.render()).strip()
        for lab in screen.query(_Label)
        if lab.display and lab.region.width and lab.region.y == widget.region.y
        and lab.region.right <= widget.region.x
    ]
    return (row[-1] if row else getattr(widget, "placeholder", "")).rstrip(":").strip()


def test_tc_b97_32_patch_help_names_every_label(tmp_path: Path) -> None:
    """TC-B97-32 (LLR-148.6, Patch arm, D20): the ``patch`` help body holds one
    ``label — effect`` line, effect non-empty, for every button, tab chip,
    input and select label the screen renders over its driven states
    (Inspector, JSON and Checks tabs; the save-back prompt and the
    before/after report offered), every key it binds and every glyph of
    ``PATCH_GLYPHS``. The floor is derived over ``PE_IDS_9C7BEAF`` by the type
    tuple Button · Input · Select and equals 26; the count of covered control
    WIDGETS is at least that floor; the one ``Edit JSON`` line names both tabs.

    RED on main (P-21): 6 of 19 labels named. Mutation: a body line without
    `` — effect``; coverage from one tab only; the ``TextArea`` put back in
    the tuple (derived 27 ≠ 26).
    """
    from textual.widgets import Button, Input as _Input, Select as _Select

    from s19_app.tui import screens_directionb as sdb
    from tests.b97_fixtures import PE_IDS_9C7BEAF, calib_hotfix, load_change_file, open_patch_editor

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            panel = await open_patch_editor(app, pilot)
            screen = app.query_one("#screen_patch")
            derived = {
                i for i in PE_IDS_9C7BEAF
                if isinstance(app.query_one(f"#{i}"), (Button, _Input, _Select))
            }
            await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
            seen = {}

            def harvest():
                for widget in screen.query("*"):
                    if not isinstance(widget, (Button, _Input, _Select)):
                        continue
                    if not widget.display or widget.region.width == 0:
                        continue
                    if any(not a.display for a in widget.ancestors if hasattr(a, "display")):
                        continue
                    seen[widget] = _control_label(screen, widget)

            for tab in PATCH_TABS:
                if panel.query(f"#{tab}"):
                    panel.query_one(f"#{tab}").press()
                    await settle(pilot, 3)
                harvest()
            if panel.query("#patch_tab_json"):
                panel.query_one("#patch_tab_json").press()
                await settle(pilot, 2)
            panel.query_one("#patch_doc_apply_button").press()
            await settle(pilot, 6)
            harvest()
            panel.query_one("#patch_saveback_confirm_button").press()
            await settle(pilot, 8)
            harvest()
            in_panel = {w: label for w, label in seen.items() if panel in w.ancestors}
            return derived, in_panel, set(seen.values())

    derived, in_panel, labels = asyncio.run(_drive())
    from s19_app.tui import screens_directionb as sdb

    lines = _help_lines("patch")
    keys = {"ctrl+z", "ctrl+y", "space", "enter", "?"}
    glyphs = set(getattr(sdb, "PATCH_GLYPHS", {}) or {"(no PATCH_GLYPHS)"})
    assert len(derived) == 26, sorted(derived)
    missing = sorted((labels | keys | glyphs) - set(lines))
    assert missing == [], f"labels with no `label — effect` line: {missing}"
    assert all(lines[label] for label in labels | keys | glyphs)
    covered = [w for w, label in in_panel.items() if label in lines]
    assert len(covered) >= len(derived), (len(covered), len(derived))
    assert "Inspector" in lines["Edit JSON"] and "JSON tab" in lines["Edit JSON"], lines["Edit JSON"]


def test_tc_b97_33_patch_glyphs_closed_and_in_the_legend(tmp_path: Path) -> None:
    """TC-B97-33 (LLR-148.7, Patch arm): the glyphs painted at the head of each
    ledger Kind cell and as tokens in the before→after strip belong to
    ``PATCH_GLYPHS`` (>= 2 painted: ``·`` and the unmapped ``--`` of an entry
    outside the image), every vocabulary glyph is named in the one-row
    ``#patch_legend``, and no painted text says ``issues``.

    RED on main: no ``PATCH_GLYPHS``. Mutation: the strip painting ``??`` for an
    unmapped byte (M27).
    """
    from s19_app.tui import screens_directionb as sdb
    from tests.b97_fixtures import (
        CALIB_ENTRIES,
        _bytes_entry,
        load_change_file,
        open_patch_editor,
        write_changeset,
    )
    from tests.b97_probes import painted_rows

    vocabulary = getattr(sdb, "PATCH_GLYPHS", None)
    assert vocabulary, "the Patch Editor's closed glyph vocabulary exists"
    entries = [_bytes_entry(a, r) for a, r in CALIB_ENTRIES] + [_bytes_entry(0x7FFF0, (1, 2))]
    path = write_changeset(tmp_path / "with_outside.json", entries)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            panel = await open_patch_editor(app, pilot)
            await load_change_file(app, pilot, panel, path)
            table = panel.query_one("#patch_doc_entries_table")
            x0 = table.cell_padding
            kinds = [row[x0:x0 + 1] for row in painted_rows(app, table)[1:] if row.strip()]
            table.move_cursor(row=6)
            await settle(pilot, 3)
            card = panel.query_one("#patch_before_after_card")
            strip = [row[10:] for row in painted_rows(app, card) if row[3:6] in ("was", "now")]
            tokens = {tok for row in strip for tok in row.split()}
            legend = panel.query_one("#patch_legend")
            legend_rows = [r for r in painted_rows(app, legend) if r.strip()]
            texts = []
            for tab in PATCH_TABS:
                panel.query_one(f"#{tab}").press()
                await settle(pilot, 3)
                texts.append("\n".join(painted_rows(app, panel)))
            return kinds, tokens, legend_rows, legend.region.height, "\n".join(texts)

    kinds, tokens, legend_rows, legend_h, panel_text = asyncio.run(_drive())
    hexes = {t for t in tokens if len(t) == 2 and all(c in "0123456789ABCDEF" for c in t)}
    painted = {k for k in kinds if k.strip()} | (tokens - hexes)
    assert painted <= set(vocabulary), painted - set(vocabulary)
    assert {"·", "--"} <= painted, painted
    assert legend_h <= 2 and 1 <= len(legend_rows) <= 2
    assert all(glyph in "".join(legend_rows) for glyph in vocabulary), legend_rows
    assert "issues" not in panel_text


@pytest.mark.parametrize(
    "arm", ["ledger_empty", "ledger_refused", "strip_no_image", "strip_no_entries", "json_no_document", "checks_no_run"]
)
def test_tc_b97_58_patch_editor_region_states(tmp_path: Path, arm: str) -> None:
    """TC-B97-58 (LLR-148.9, Patch arms): the ledger with no document and after
    a refused load (its finding), the before→after strip with no image and
    with no entry, the JSON view before any document and the Checks tab before
    a run each paint exactly one English line in their region, and no
    traceback.

    RED on main: the empty ledger line wraps (3 rows at 118 columns); a
    refused load paints nothing in the ledger; no JSON view exists.
    """
    from tests.b97_fixtures import ES_MARKER_RE, legacy_v1, load_change_file, open_patch_editor
    from tests.b97_probes import painted_rows

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            # With an image, its install pushes the (empty) draft document to the
            # JSON view, so the no-document arm runs before any image.
            panel = await open_patch_editor(
                app, pilot, image=arm not in ("strip_no_image", "json_no_document")
            )
            if arm == "ledger_refused":
                await load_change_file(app, pilot, panel, legacy_v1(tmp_path))
            if arm == "strip_no_image":
                panel.query_one("#patch_entry_address_input").value = "0xEB10"
                panel.query_one("#patch_entry_bytes_input").value = "01 02"
                panel.query_one("#patch_entry_add_button").press()
                await settle(pilot, 4)
            region = {
                "ledger_empty": "#patch_doc_empty_state",
                "ledger_refused": "#patch_doc_empty_state",
                "strip_no_image": "#patch_before_after_card",
                "strip_no_entries": "#patch_before_after_card",
                "json_no_document": "#patch_json_view",
                "checks_no_run": "#patch_checks_status",
            }[arm]
            tab = {"json_no_document": "patch_tab_json", "checks_no_run": "patch_tab_checks"}.get(arm)
            if tab and panel.query(f"#{tab}"):
                panel.query_one(f"#{tab}").press()
                await settle(pilot, 3)
            holder = panel.query(region)
            if not holder:
                return []
            rows = painted_rows(app, holder.first())
            if region == "#patch_before_after_card":
                rows = rows[1:]  # the border-top row carries the title
            return [r.strip() for r in rows if r.strip()]

    lines = asyncio.run(_drive())
    assert len(lines) == 1, (arm, lines)
    assert not ES_MARKER_RE.search(lines[0]), lines[0]
    assert "Traceback" not in lines[0]
    if arm == "ledger_refused":
        assert lines[0].startswith("Refused: [CHG-V1-FORMAT]") or "Refused:" in lines[0], lines[0]
    # Inc-4 gate (code-reviewer L1): the two fixed lines are compared whole, as
    # literals, so a rewritten constant fails here directly (M34).
    if arm == "ledger_empty":
        assert lines[0] == "No entries yet: Add one, paste a change-set or Load a file.", lines[0]
    if arm == "json_no_document":
        assert lines[0] == "No document yet: Load, paste or Add.", lines[0]



# --------------------------------------------------------------------------- #
# Inc-5 — the Flow Builder arms of LLR-148.5, 148.6, 148.7, 148.9
# --------------------------------------------------------------------------- #

import re as _re  # noqa: E402
import string as _string  # noqa: E402

FLOW_KINDS = ("source", "patch", "check", "crc", "write_out", "a2b", "external_step")


async def _poll(pilot, predicate, attempts: int = 60) -> bool:
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return True
    return False


def test_tc_b97_31_flow_builder_header_carries_both_chips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-31 (LLR-148.5, Builder arm): the Flow Builder header holds one
    ``OpenFolderChip`` (family ``flows``, ``📂 Open flows/``) and one
    ``WindowHelpChip``; with a project, a click and an ``enter`` on the folder
    chip each make exactly one seam call with ``resolve_chip_target``'s target.

    RED on HEAD: the header carries the help chip only (0 folder chips).
    """
    from s19_app.tui.window_help import WindowHelpChip
    from tests.b97_fixtures import flow_project

    spy = SeamSpy(monkeypatch)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=CHIP_TEST_SIZE) as pilot:
            await settle(pilot)
            project_dir = flow_project(app)
            app.action_show_screen("flow")
            await _poll(pilot, lambda: app.query_one("#flow_panel").region.height > 0)
            screen = app.query_one("#screen_flow")
            headers = list(screen.query(".db-screen-header"))
            counts = (
                sum(len(h.query(OpenFolderChip)) for h in headers),
                sum(len(h.query(WindowHelpChip)) for h in headers),
            )
            label = None
            if counts[0] == 1:
                chip = headers[0].query_one(OpenFolderChip)
                # The chip refreshes to the loaded project a tick after the
                # load: click once it is laid out and enabled.
                await _poll(pilot, lambda: chip.region.width > 0 and not chip.disabled)
                label = chip_label(chip)
                await pilot.click(f"#{chip.id}")
                await _poll(pilot, lambda: len(spy.calls) == 1)
                chip.focus()
                # Button ignores a key press during its 0.2 s click effect.
                await _poll(pilot, lambda: app.focused is chip and not chip.has_class("-active"), 120)
                await pilot.press("enter")
                await _poll(pilot, lambda: len(spy.calls) == 2)
            target = fos.resolve_chip_target(
                project_dir, family="flows", workarea=app.workarea, base_dir=tmp_path
            )
            return counts, label, target, list(spy.calls)

    counts, label, target, calls = asyncio.run(_drive())
    assert counts == (1, 1), f"one folder chip and one help chip in the header: {counts}"
    assert label == f"📂 Open {FLOWS_SUBDIR}/"
    assert [path for path, _ in calls] == [target, target]


def _flow_label(screen, widget) -> str:
    """A button label without its glyph prefix or its trailing count; an input
    or select by the ``Label`` on its own row to its left, else its
    placeholder."""
    from textual.widgets import Button, Label as _Label

    if isinstance(widget, Button):
        return _re.sub(r"\s*\(\d+\)$", "", _strip_glyph(str(widget.label)))
    row = [
        str(lab.render()).strip()
        for lab in screen.query(_Label)
        if lab.display and lab.region.width and lab.region.y == widget.region.y
        and lab.region.right <= widget.region.x
    ]
    return (row[-1] if row else getattr(widget, "placeholder", "")).rstrip(":").strip()


def test_tc_b97_32_flow_help_names_every_label(tmp_path: Path) -> None:
    """TC-B97-32 (LLR-148.6, Builder arm): the ``flow`` help body holds one
    ``label — effect`` line, effect non-empty, for every button, chip, input
    and select label the screen renders over the driven states (each of the 7
    kinds, both EXT-STEP modes, the funnel editor open), every key it binds
    (``space``, ``enter``, ``?``) and every glyph of ``FLOW_KIND_GLYPHS``,
    ``FLOW_CABLE_GLYPHS`` and the result's status glyphs; the control subset
    counts >= 21 (13 + the 8 add inputs of LLR-146.3).

    RED on HEAD (P-21): 2 of 13 labels named. Mutation: a body line without
    `` — effect``; coverage read from one kind only.
    """
    from textual.widgets import Button, Input as _Input, Select as _Select

    from s19_app.tui import flow_screens as fs
    from tests.b97_fixtures import flow_project

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            flow_project(app)
            app.action_show_screen("flow")
            panel = app.query_one("#flow_panel")
            await _poll(pilot, lambda: panel.region.height > 0)
            screen = app.query_one("#screen_flow")
            controls, keys = set(), set()

            def harvest():
                for widget in screen.query("*"):
                    if not widget.display or widget.region.width == 0:
                        continue
                    if any(not a.display for a in widget.ancestors if hasattr(a, "display")):
                        continue
                    if isinstance(widget, (Button, _Input, _Select)):
                        controls.add(_flow_label(screen, widget))
                    for binding in getattr(type(widget), "BINDINGS", []):
                        key = binding.key if hasattr(binding, "key") else binding[0]
                        keys.add({"question_mark": "?"}.get(key, key))

            panel.query_one("#flow_funnel_toggle").press()
            await _poll(pilot, lambda: panel.query_one("#flow_funnel_editor").display)
            for kind in FLOW_KINDS:
                if panel.query(f"#flow_palette_{kind}"):
                    panel.query_one(f"#flow_palette_{kind}").press()
                    await _poll(pilot, lambda: str(panel.query_one("#flow_kind").value) == kind)
                    await settle(pilot, 2)
                harvest()
            mode = panel.query_one("#flow_ext_mode", _Select)
            mode.value = "manual"
            await _poll(pilot, lambda: str(mode.value) == "manual")
            await settle(pilot, 2)
            harvest()
            return controls, keys

    controls, keys = asyncio.run(_drive())
    keys &= {"space", "enter", "?"}
    keys.add("enter")
    glyphs = set(getattr(fs, "FLOW_KIND_GLYPHS", {}) or {"(no FLOW_KIND_GLYPHS)"})
    glyphs |= set(getattr(fs, "FLOW_CABLE_GLYPHS", {}))
    glyphs |= set(fs._BLOCK_STATUS_GLYPH.values())
    lines = _help_lines("flow")
    assert len(controls) >= 21, sorted(controls)
    missing = sorted((controls | keys | glyphs) - set(lines))
    assert missing == [], f"labels with no `label — effect` line: {missing}"
    assert all(lines[label] for label in controls | keys | glyphs)


#: Characters the Builder paints as card frame and text structure, outside the
#: three vocabularies (design D7: frame ``╭ ╮ ╰ ╯ │``, ``←`` input from block
#: #n, ``…``, ``·``, plus ASCII punctuation of file names and ``#n``).
_FLOW_STRUCTURE = set("╭╮╰╯│←…·—→") | set(_string.punctuation)


def _vocabulary_glyphs(text: str) -> set:
    return {c for c in text if not c.isalnum() and not c.isspace() and c not in _FLOW_STRUCTURE}


@pytest.mark.parametrize("arm", ["patch_chain", "report_block"])
def test_tc_b97_33_flow_glyphs_closed_and_in_the_legend(tmp_path: Path, arm: str) -> None:
    """TC-B97-33 (LLR-148.7, Builder arm): the glyphs painted in the pipeline
    and the legend before a run, and at the head of each ``#flow_result``
    block line after the run, belong to ``FLOW_KIND_GLYPHS`` ∪
    ``FLOW_CABLE_GLYPHS`` ∪ the status glyphs; the three sets are pairwise
    disjoint; the one-row legend is generated from the first two (``≡``
    only when the chain carries a report block — at 220x60, where the
    10-pair legend fits); no painted text says ``issues``.

    RED on HEAD: no ``FLOW_KIND_GLYPHS``. Mutation: a card painting a glyph
    outside its vocabulary.
    """
    from s19_app.tui import flow_screens as fs
    from s19_app.tui.services.flow_model import ReportBlock
    from tests.b97_fixtures import flow_project, load_flow, patch_chain_demo, write_flow
    from tests.b97_probes import painted_rows

    kinds = getattr(fs, "FLOW_KIND_GLYPHS", None)
    cables = getattr(fs, "FLOW_CABLE_GLYPHS", None)
    assert kinds and cables, "the Builder's closed glyph vocabularies exist"
    statuses = set(fs._BLOCK_STATUS_GLYPH.values())
    size = (118, 54) if arm == "patch_chain" else (220, 60)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            project_dir = flow_project(app)
            stem = "patch_chain"
            if arm == "report_block":
                stem = "with_report"
                write_flow(project_dir, stem, patch_chain_demo() + [ReportBlock()])
            app.action_show_screen("flow")
            panel = app.query_one("#flow_panel")
            await _poll(pilot, lambda: panel.region.height > 0)
            await load_flow(app, pilot, stem)
            await settle(pilot, 2)
            pipeline = "\n".join(painted_rows(app, panel.query_one("#flow_pipeline")))
            legend = panel.query_one("#flow_legend")
            legend_rows = [r for r in painted_rows(app, legend) if r.strip()]
            panel.query_one("#flow_run").press()
            await _poll(pilot, lambda: bool(panel.query("#flow_result .flow-node-head")))
            await settle(pilot, 2)
            heads = [
                r.strip()[:1] for h in panel.query("#flow_result .flow-node-head") for r in painted_rows(app, h) if r.strip()
            ]
            text = "\n".join(painted_rows(app, panel))
            return pipeline, legend_rows, legend.region.height, heads, text

    pipeline, legend_rows, legend_h, heads, text = asyncio.run(_drive())
    union = set(kinds) | set(cables) | statuses
    assert set(kinds).isdisjoint(cables) and set(kinds).isdisjoint(statuses) and set(cables).isdisjoint(statuses)
    painted = _vocabulary_glyphs(pipeline) | _vocabulary_glyphs("".join(legend_rows)) | set(heads)
    assert painted <= union, painted - union
    assert set(heads) <= statuses and heads, heads
    assert legend_h == 1 and len(legend_rows) == 1, legend_rows
    expected = (set(kinds) - ({"≡"} if arm == "patch_chain" else set())) | set(cables)
    assert _vocabulary_glyphs(legend_rows[0]) == expected, (legend_rows, expected)
    assert "issues" not in text


def test_tc_b97_33_flow_glyphs_are_narrow_in_windows_terminal() -> None:
    """TC-B97-33 (LLR-148.7, Builder WT width arm): every glyph of the three
    Builder vocabularies is one the real-terminal capture showed one cell
    wide, so no card or result line glues a glyph to the next cell.

    Why: the headless compositor counts ``✖`` as one cell; Windows Terminal
    paints it as a two-cell emoji over the next cell. RED on HEAD: the result
    error mark is ``✖``. Mutation: ``_BLOCK_STATUS_GLYPH`` error back to ``✖``.
    """
    from s19_app.tui import flow_screens as fs

    union = set(getattr(fs, "FLOW_KIND_GLYPHS", {})) | set(getattr(fs, "FLOW_CABLE_GLYPHS", {}))
    union |= set(fs._BLOCK_STATUS_GLYPH.values())
    assert union - set(WT_NARROW_GLYPHS) == set(), sorted(union - set(WT_NARROW_GLYPHS))
    assert len(union) == 15, sorted(union)


@pytest.mark.parametrize("arm", ["pipeline_empty", "ribbon_no_session", "load_refused"])
def test_tc_b97_58_flow_builder_region_states(tmp_path: Path, arm: str) -> None:
    """TC-B97-58 (LLR-148.9, Builder arms): the pipeline with no blocks, the
    ribbon with no session and the pipeline after a refused load (a NUL ref,
    ``nul_flow``) each paint exactly one English line naming the state in
    their region — the refused load on the frame's bottom border row, the
    chain kept — and no traceback.

    RED on main: no pipeline exists, so the Builder has no empty line.
    """
    from tests.b97_fixtures import ES_MARKER_RE, flow_project, load_flow, nul_flow
    from tests.b97_probes import painted_rows

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            project_dir = flow_project(app) if arm != "ribbon_no_session" else None
            app.action_show_screen("flow")
            panel = app.query_one("#flow_panel")
            await _poll(pilot, lambda: panel.region.height > 0)
            if arm == "ribbon_no_session":
                holder = panel.query("#flow_ribbon")
                rows = painted_rows(app, holder.first()) if holder else []
                return [r.strip() for r in rows if r.strip()]
            holder = panel.query("#flow_pipeline_scroll")
            if not holder:
                return []
            scroll = holder.first()
            if arm == "pipeline_empty":
                rows = painted_rows(app, scroll, scroll.scrollable_content_region)
                return [r.strip() for r in rows if r.strip()]
            nul_flow(project_dir)
            await load_flow(app, pilot, "nul_flow")
            await _poll(pilot, lambda: "refused" in "".join(painted_rows(app, scroll)))
            return [r.strip() for r in painted_rows(app, scroll) if "refused" in r]

    lines = asyncio.run(_drive())
    assert len(lines) == 1, (arm, lines)
    assert not ES_MARKER_RE.search(lines[0]), lines[0]
    assert "Traceback" not in lines[0]
    if arm == "pipeline_empty":
        assert lines[0].startswith("No blocks yet"), lines[0]
    if arm == "ribbon_no_session":
        assert lines[0].endswith("(no active project)"), lines[0]
    if arm == "load_refused":
        assert "nul_flow" in lines[0] and "kept" in lines[0], lines[0]
