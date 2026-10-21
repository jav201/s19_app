"""The four open-folder chips on one cross-platform seam (batch-95 change 2,
HLR-139 / LLR-139.1..139.3).

One ghost chip ``📂 Open folder`` rides the header row of each of the four
windows — Patch Editor → the change-set home, Checks → the check-artifact
home, CRC Designer → the template library, Reports → the project's
``reports/`` dir — always visible, no key binding. The chips' target
resolution rides change 1's seam (``project_gather_service.scoped_home`` /
the additive resolve-only ``scoped_home_target`` — no second-guessing, no
per-file logic); every open rides the one cross-platform seam
(``folder_open_service.open_folder_in_file_manager`` — ``explorer`` /
``open`` / ``xdg-open``, argv list only), including the shipped ``o``-key
workarea opener.

Coverage map (test -> TC -> LLR):

- TC-703 / LLR-139.1 — ``test_tc703_patch_editor_chip_resolves_change_set_home_both_modes`` /
  ``test_tc703_checks_chip_resolves_check_artifact_home_both_modes`` /
  ``test_tc703_crc_designer_chip_resolves_template_library_both_modes`` /
  ``test_tc703_reports_chip_resolves_project_reports_only``: 8/8 chip × mode
  limbs press with a spied seam and the seam receives EXACTLY the contracted
  change-1 home (project ``patches/`` / ``checks/`` / ``templates/`` /
  ``reports/``; no-project COMMON ``workarea/patches/`` for Patch Editor AND
  Checks — the contract's literal ruling, folders.html §1: the no-project
  COMMON home holds change-sets and check artifacts together — and
  ``.s19tool/templates/`` for the CRC Designer); exactly one open call per
  press. ``test_tc703_chips_render_header_right_with_no_key_bindings``: the
  chip is the last (rightmost) child of each window's header row, and no
  application key binding names the chips.
- TC-704 / LLR-139.2 — ``test_tc704_missing_project_folder_dimmed_create_offer_opens``
  (parametrized over patches / checks / templates): the missing-folder chip
  stays ENABLED, renders dimmed (the ``-dimmed`` class) with the contract's
  ``folder does not exist yet`` tooltip, and its press creates exactly the
  offered folder and then opens it.
  ``test_tc704_missing_common_home_no_project_dimmed_and_recreated``: the
  no-project missing-COMMON limb — dimmed + ``no project — files are in the
  common folders``, press recreates the COMMON home and opens it.
  ``test_tc704_reports_without_project_disabled_status_reason_zero_opens``:
  the Reports chip without a project is genuinely ``disabled`` (the negative
  control 7e — an ENABLED chip there would redden the assertion), dimmed +
  tooltip, the disabling refresh names the reason on the status line, and
  pressing opens nothing.
- TC-705 / LLR-139.3 — ``test_tc705_seam_popen_argv_list_per_platform_arm``:
  each platform arm issues exactly one ``subprocess.Popen`` in argv-LIST form
  (never a bare string on POSIX) with the platform opener and the resolved
  dir.
  ``test_tc705_seam_failure_lands_on_status_line_no_escape``: a ``Popen``
  failure returns ``False``, names the failure on the status line, escapes
  nowhere.
  ``test_tc705_workarea_open_rides_the_same_seam``: the shipped ``o``-key
  workarea opener funnels through the same seam (one call, the workarea dir,
  the byte-identical ``Opened workarea: …`` status).

Harness: the ``App.run_test()`` pilot pattern of ``tests/test_project_gather.py``
(the case07 idiom) at ``size=(120, 36)`` — the batch-93 pinning rule: the
app hands the tests a 118×34 screen. The chips are pressed via
``Button.press()`` after ``action_show_screen`` gives their screen the
display (``press()`` is a no-op on a hidden screen by Textual design), and
the seam is spied by monkeypatching
``folder_open_service.open_folder_in_file_manager`` — every callsite (the
four chips and the workarea opener) reaches it through the module.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import pytest

from s19_app.tui.app import S19TuiApp
from s19_app.tui.open_folder_chip import OpenFolderChip
from s19_app.tui.screens import ReportViewerScreen
from s19_app.tui.services import folder_open_service as fos
from s19_app.tui.services.project_gather_service import (
    PROJECT_CHECKS_DIR,
    PROJECT_PATCHES_DIR,
    PROJECT_TEMPLATES_DIR,
)
from s19_app.tui.services.report_service import REPORTS_DIR_NAME
from s19_app.tui.workspace import (
    WORKAREA_DIRNAME,
    WORKAREA_PATCHES,
    WORKAREA_TEMPLATES,
)

#: The contract's literal tooltip strings (LLR-139.2) — asserted against the
#: service constants so a drifted constant reddens here, at the contract text.
_EXPECTED_TOOLTIP_NO_PROJECT = "no project — files are in the common folders"
_EXPECTED_TOOLTIP_MISSING = "folder does not exist yet"

#: The three rail-screen chips and their show-screen keys (Button.press is a
#: no-op on a hidden screen — the chip must be displayed to be pressed).
_RAIL_CHIPS: Tuple[Tuple[str, str, str], ...] = (
    ("patch", "#open_folder_patch", "screen_patch"),
    ("checks", "#open_folder_checks", "screen_checks"),
    ("templates", "#open_folder_templates", "screen_crc_designer"),
    # batch-97 Inc-3 (D9, LLR-148.5): the Check Editor header carries the
    # second ``checks`` chip under its suffixed id.
    ("checks", "#open_folder_checks_editor", "screen_check_editor"),
)


class SeamSpy:
    """A recording stand-in for ``open_folder_in_file_manager``.

    Records every call and delivers the real seam's status confirmation, so
    status-line assertions ride the same press the resolution assertions do.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: List[Tuple[Path, str]] = []
        monkeypatch.setattr(fos, "open_folder_in_file_manager", self._record)

    def _record(
        self,
        path: Path,
        *,
        set_status: Optional[Callable[[str], None]] = None,
        label: str = "folder",
    ) -> bool:
        self.calls.append((Path(path), label))
        if set_status is not None:
            set_status(f"Opened {label}: {path}")
        return True


def _press_chip(chip: OpenFolderChip) -> None:
    """Press a chip (the pilot pause afterwards pumps the Pressed message)."""
    chip.press()


async def _pilot_pause(pilot) -> None:
    for _ in range(4):
        await pilot.pause()


def _set_project(app: S19TuiApp, name: str = "proj1") -> Path:
    """Enter project mode the way the shipped tests do (before-after idiom)."""
    project_dir = app.workarea / name
    project_dir.mkdir(parents=True, exist_ok=True)
    app.current_project = name
    app.update_project_labels()  # the sanctioned project-refresh seam (chips too)
    return project_dir


# --------------------------------------------------------------------------- #
# TC-703 / LLR-139.1 — the four chips resolve to the contracted change-1 home
# --------------------------------------------------------------------------- #


def test_tc703_patch_editor_chip_resolves_change_set_home_both_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-703 (LLR-139.1): the Patch Editor chip resolves to the change-set
    home — project ``<proj>/patches/`` / no-project COMMON
    ``workarea/patches/`` — with exactly one open call per press."""
    spy = SeamSpy(monkeypatch)

    async def _drive() -> Tuple[List[Tuple[Path, str]], List[Tuple[Path, str]], Path]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            app.action_show_screen("patch")
            await _pilot_pause(pilot)
            chip = app.query_one("#open_folder_patch", OpenFolderChip)
            _press_chip(chip)
            await _pilot_pause(pilot)
            no_project_calls = list(spy.calls)
            spy.calls.clear()
            project_dir = _set_project(app)
            _press_chip(chip)
            await _pilot_pause(pilot)
            return no_project_calls, list(spy.calls), project_dir

    no_project_calls, project_calls, project_dir = asyncio.run(_drive())

    assert len(no_project_calls) == 1, "exactly one open call per press"
    assert no_project_calls[0][0] == tmp_path / WORKAREA_DIRNAME / "workarea" / WORKAREA_PATCHES, (
        "no-project Patch Editor chip must open the COMMON workarea/patches home"
    )
    assert len(project_calls) == 1, "exactly one open call per press"
    assert project_calls[0][0] == project_dir / PROJECT_PATCHES_DIR, (
        "project Patch Editor chip must open <project>/patches/"
    )


def test_tc703_checks_chip_resolves_check_artifact_home_both_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-703 (LLR-139.1): the Checks chip resolves to the check-artifact
    home — project ``<proj>/checks/`` / no-project COMMON ``workarea/patches/``
    (the contract's literal ruling: the no-project COMMON home holds
    change-sets AND check artifacts, folders.html §1)."""
    spy = SeamSpy(monkeypatch)

    async def _drive() -> Tuple[List[Tuple[Path, str]], List[Tuple[Path, str]], Path]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            app.action_show_screen("checks")
            await _pilot_pause(pilot)
            chip = app.query_one("#open_folder_checks", OpenFolderChip)
            _press_chip(chip)
            await _pilot_pause(pilot)
            no_project_calls = list(spy.calls)
            spy.calls.clear()
            project_dir = _set_project(app)
            _press_chip(chip)
            await _pilot_pause(pilot)
            return no_project_calls, list(spy.calls), project_dir

    no_project_calls, project_calls, project_dir = asyncio.run(_drive())

    assert len(no_project_calls) == 1
    assert no_project_calls[0][0] == tmp_path / WORKAREA_DIRNAME / "workarea" / WORKAREA_PATCHES, (
        "no-project Checks chip must open the COMMON workarea/patches home "
        "(the contract's literal ruling — not a checks/ COMMON home)"
    )
    assert len(project_calls) == 1
    assert project_calls[0][0] == project_dir / PROJECT_CHECKS_DIR, (
        "project Checks chip must open <project>/checks/"
    )


def test_tc703_crc_designer_chip_resolves_template_library_both_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-703 (LLR-139.1): the CRC Designer chip resolves to the template
    library — project ``<proj>/templates/`` / no-project COMMON
    ``.s19tool/templates/``."""
    spy = SeamSpy(monkeypatch)

    async def _drive() -> Tuple[List[Tuple[Path, str]], List[Tuple[Path, str]], Path]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            app.action_show_screen("crc_designer")
            await _pilot_pause(pilot)
            chip = app.query_one("#open_folder_templates", OpenFolderChip)
            _press_chip(chip)
            await _pilot_pause(pilot)
            no_project_calls = list(spy.calls)
            spy.calls.clear()
            project_dir = _set_project(app)
            _press_chip(chip)
            await _pilot_pause(pilot)
            return no_project_calls, list(spy.calls), project_dir

    no_project_calls, project_calls, project_dir = asyncio.run(_drive())

    assert len(no_project_calls) == 1
    assert no_project_calls[0][0] == tmp_path / WORKAREA_DIRNAME / WORKAREA_TEMPLATES, (
        "no-project CRC Designer chip must open the COMMON .s19tool/templates library"
    )
    assert len(project_calls) == 1
    assert project_calls[0][0] == project_dir / PROJECT_TEMPLATES_DIR, (
        "project CRC Designer chip must open <project>/templates/"
    )


def test_tc703_reports_chip_resolves_project_reports_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-703 (LLR-139.1): the Reports chip resolves to the project's
    ``reports/`` dir — project-only; the no-project limb is the disabled
    chip (0 opens, asserted with TC-704)."""
    spy = SeamSpy(monkeypatch)

    async def _drive() -> Tuple[List[Tuple[Path, str]], Path]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            project_dir = _set_project(app)
            modal = ReportViewerScreen("proj1", [])
            app.push_screen(modal)
            await _pilot_pause(pilot)
            chip = modal.query_one("#open_folder_reports", OpenFolderChip)
            _press_chip(chip)
            await _pilot_pause(pilot)
            return list(spy.calls), project_dir

    calls, project_dir = asyncio.run(_drive())

    assert len(calls) == 1, "exactly one open call per press"
    assert calls[0][0] == project_dir / REPORTS_DIR_NAME, (
        "the Reports chip must open <project>/reports/ and nothing else"
    )


def test_tc703_chips_render_header_right_with_no_key_bindings(
    tmp_path: Path,
) -> None:
    """TC-703 (LLR-139.1, placement + the no-key-binding ruling): each chip
    is the LAST (rightmost) child of its window's header row — the row is the
    first child of the screen container / modal dialog — and no application
    key binding names the chips."""
    from textual.containers import Horizontal
    from textual.widgets import Label

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            observed: dict = {}
            for _family, chip_id, screen_id in _RAIL_CHIPS:
                screen = app.query_one(f"#{screen_id}")
                row = screen.children[0]
                observed[chip_id] = (
                    isinstance(row, Horizontal),
                    row.has_class("db-screen-header"),
                    isinstance(row.children[0], Label),
                    row.children[-1].id,
                )
            modal = ReportViewerScreen("proj1", [])
            app.push_screen(modal)
            await _pilot_pause(pilot)
            dialog = modal.query_one("#report_dialog")
            row = dialog.children[0]
            observed["#open_folder_reports"] = (
                isinstance(row, Horizontal),
                row.has_class("db-screen-header"),
                isinstance(row.children[0], Label),
                row.children[-1].id,
            )
            return observed

    observed = asyncio.run(_drive())

    for chip_id in (
        "#open_folder_patch",
        "#open_folder_checks",
        "#open_folder_templates",
        "#open_folder_reports",
        "#open_folder_checks_editor",
    ):
        is_row, has_class, title_is_label, rightmost_id = observed[chip_id]
        assert is_row and has_class, f"{chip_id}: the header row must carry .db-screen-header"
        assert title_is_label, f"{chip_id}: the title label leads the header row"
        assert rightmost_id == chip_id.lstrip("#"), (
            f"{chip_id}: the chip must render header-right (last in the row)"
        )
    from textual.binding import Binding

    bound_actions = {
        binding.action if isinstance(binding, Binding) else binding[1]
        for binding in S19TuiApp.BINDINGS
    }
    assert not any("open_folder" in action for action in bound_actions), (
        "the open-folder chips carry no key binding — no app binding may name them"
    )


# --------------------------------------------------------------------------- #
# TC-704 / LLR-139.2 — missing-folder limbs and the no-project Reports limb
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "family, chip_id, subdir",
    (
        ("patch", "#open_folder_patch", PROJECT_PATCHES_DIR),
        ("checks", "#open_folder_checks", PROJECT_CHECKS_DIR),
        ("templates", "#open_folder_templates", PROJECT_TEMPLATES_DIR),
    ),
)
def test_tc704_missing_project_folder_dimmed_create_offer_opens(
    family: str,
    chip_id: str,
    subdir: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TC-704 (LLR-139.2): a missing project home keeps the chip visible but
    dimmed (``-dimmed``, NOT ``disabled`` — the create-offer is a press) with
    the contract's ``folder does not exist yet`` tooltip; the press creates
    exactly the offered folder and then opens it."""
    assert fos.TOOLTIP_MISSING_FOLDER == _EXPECTED_TOOLTIP_MISSING
    spy = SeamSpy(monkeypatch)

    async def _drive() -> Tuple[bool, bool, Optional[str], List[Tuple[Path, str]], Path]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            project_dir = _set_project(app)  # the project dir exists, the home does NOT
            app.action_show_screen(
                {"patch": "patch", "checks": "checks", "templates": "crc_designer"}[family]
            )
            await _pilot_pause(pilot)
            chip = app.query_one(chip_id, OpenFolderChip)
            state = (
                chip.disabled,
                chip.has_class("-dimmed"),
                chip.tooltip,
            )
            _press_chip(chip)
            await _pilot_pause(pilot)
            return (*state, list(spy.calls), project_dir)

    disabled, dimmed, tooltip, calls, project_dir = asyncio.run(_drive())

    assert not disabled, "the missing-folder chip must stay pressable (dimmed, not disabled)"
    assert dimmed, "the missing-folder chip must render dimmed (the -dimmed class)"
    assert tooltip == "folder does not exist yet"
    assert (project_dir / subdir).is_dir(), (
        "the create-offer must create exactly the offered folder"
    )
    assert len(calls) == 1 and calls[0][0] == project_dir / subdir, (
        "after creating, the chip opens exactly the offered folder"
    )


def test_tc704_missing_common_home_no_project_dimmed_and_recreated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-704 (LLR-139.2, the no-project limb): a missing COMMON home keeps
    the chip dimmed with ``no project — files are in the common folders``;
    the press recreates the COMMON home and opens it."""
    assert fos.TOOLTIP_NO_PROJECT == _EXPECTED_TOOLTIP_NO_PROJECT
    import shutil

    spy = SeamSpy(monkeypatch)

    async def _drive() -> Tuple[bool, Optional[str], List[Tuple[Path, str]]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            common = app.workarea / WORKAREA_PATCHES
            shutil.rmtree(common)
            app.update_project_labels()  # the project-refresh seam re-resolves the chips
            await _pilot_pause(pilot)
            app.action_show_screen("patch")
            await _pilot_pause(pilot)
            chip = app.query_one("#open_folder_patch", OpenFolderChip)
            state = (chip.disabled, chip.tooltip)
            _press_chip(chip)
            await _pilot_pause(pilot)
            return (*state, list(spy.calls))

    disabled, tooltip, calls = asyncio.run(_drive())

    assert not disabled, "the missing-COMMON limb stays pressable too"
    assert tooltip == "no project — files are in the common folders"
    assert (tmp_path / WORKAREA_DIRNAME / "workarea" / WORKAREA_PATCHES).is_dir(), (
        "the create-offer recreates the missing COMMON home"
    )
    assert len(calls) == 1 and calls[0][0] == tmp_path / WORKAREA_DIRNAME / "workarea" / WORKAREA_PATCHES


def test_tc704_reports_without_project_disabled_status_reason_zero_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-704 (LLR-139.2, the Reports no-project limb — negative control 7e):
    without a project the Reports chip is genuinely DISABLED (an enabled chip
    here would redden this assertion), dimmed with the no-project tooltip,
    the disabling refresh names the reason on the status line, and pressing
    opens nothing (0 seam calls)."""
    spy = SeamSpy(monkeypatch)

    async def _drive() -> Tuple[bool, bool, Optional[str], bool, List[Tuple[Path, str]]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            modal = ReportViewerScreen("case07", [])  # constructed with no active project
            app.push_screen(modal)
            await _pilot_pause(pilot)
            chip = modal.query_one("#open_folder_reports", OpenFolderChip)
            state = (
                chip.disabled,
                chip.has_class("-dimmed"),
                chip.tooltip,
                any("no active project" in line for line in app.log_lines),
            )
            _press_chip(chip)
            await _pilot_pause(pilot)
            return (*state, list(spy.calls))

    disabled, dimmed, tooltip, status_named_reason, calls = asyncio.run(_drive())

    assert disabled, "the no-project Reports chip must be genuinely disabled (7e)"
    assert dimmed, "the disabled chip still renders the dimmed look"
    assert tooltip == "no project — files are in the common folders"
    assert status_named_reason, "a status-line reason must say why the chip is disabled"
    assert calls == [], "the disabled chip opens nothing (0 open calls)"


# --------------------------------------------------------------------------- #
# TC-705 / LLR-139.3 — the one cross-platform open seam
# --------------------------------------------------------------------------- #


def test_tc705_seam_popen_argv_list_per_platform_arm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TC-705 (LLR-139.3): each platform arm issues exactly one Popen in
    argv-LIST form — [opener, dir] — never a bare string on POSIX."""
    popens: List[list] = []
    monkeypatch.setattr(fos.subprocess, "Popen", lambda argv: popens.append(argv))
    target = Path("/tmp/some dir")

    for platform, opener in (
        ("win32", "explorer"),
        ("darwin", "open"),
        ("linux", "xdg-open"),
    ):
        popens.clear()
        monkeypatch.setattr("sys.platform", platform)
        ok = fos.open_folder_in_file_manager(target, set_status=None)
        assert ok, f"{platform}: the seam reports success when Popen is issued"
        assert popens == [[opener, str(target)]], (
            f"{platform}: exactly one argv-list Popen with the platform opener "
            f"and the resolved dir; got {popens}"
        )
        assert isinstance(popens[0], list), "argv LIST form — never a bare string on POSIX"


def test_tc705_seam_failure_lands_on_status_line_no_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TC-705 (LLR-139.3, the error boundary): a Popen failure returns
    False, the status line names it, and nothing escapes."""

    def _boom(argv: list) -> None:
        raise OSError("no file manager")

    monkeypatch.setattr(fos.subprocess, "Popen", _boom)
    statuses: List[str] = []
    ok = fos.open_folder_in_file_manager(Path("/tmp/x"), set_status=statuses.append)
    assert ok is False
    assert len(statuses) == 1 and statuses[0].startswith("Failed to open folder:"), (
        "the failure lands on the status line, naming the cause"
    )
    assert "no file manager" in statuses[0]


def test_tc705_workarea_open_rides_the_same_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-705 (LLR-139.3, the shipped surface): the ``o``-key workarea opener
    funnels through the same seam — one call with the workarea dir, the
    label keeping its shipped status text byte-identical."""
    spy = SeamSpy(monkeypatch)

    async def _drive() -> Tuple[List[Tuple[Path, str]], str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            app.action_open_workarea()
            await _pilot_pause(pilot)
            return list(spy.calls), app.log_lines[-1]

    calls, status = asyncio.run(_drive())

    assert len(calls) == 1, "exactly one seam call per o-key press"
    assert calls[0][0] == tmp_path / WORKAREA_DIRNAME / "workarea"
    assert calls[0][1] == "workarea", "the shipped label survives the seam refactor"
    assert status.startswith("Opened workarea: "), (
        "the shipped o-key status confirmation is byte-identical"
    )
