"""The open-folder seam + chip target resolution (batch-95 change 2, HLR-139).

One ghost chip ``📂 Open folder`` rides the header row of each of the four
windows — Patch Editor, Checks, CRC Designer, Reports — opening exactly the
change-1 home of that window's artifact family (LLR-139.1). This module is
the headless half of that change:

- :func:`open_folder_in_file_manager` — THE cross-platform open seam
  (LLR-139.3): the shipped ``action_open_workarea`` idiom
  (``subprocess.Popen([opener, dir])``) generalized per platform —
  ``explorer`` on Windows, ``open`` on macOS, ``xdg-open`` on other POSIX.
  The argv LIST form is mandatory (a bare string on POSIX would shell
  through ``/bin/sh -c``); the status-line confirmation (``Opened …``) and
  the caught-failure path (``Failed to open …`` — the status line names it,
  never a traceback) are preserved. The shipped ``o``-key workarea opener
  rides this same seam, so every open in the app funnels through one helper.
- :func:`resolve_chip_target` — the chip's target, per family, riding
  change 1's resolution seam (``project_gather_service.scoped_home_target``)
  with no second-guessing and no per-file logic: Patch Editor → the
  change-set home (project ``patches/`` / COMMON ``workarea/patches/``),
  Checks → the check-artifact home (project ``checks/`` / COMMON
  ``workarea/patches/`` — the no-project COMMON home holds both change-sets
  and check artifacts, folders.html §1), CRC Designer → the template
  library (project ``templates/`` / COMMON ``.s19tool/templates/``), Reports
  → project ``reports/`` only (``None`` without a project — the Reports
  modal itself refuses there, LLR-008.1).
- :func:`create_chip_home` — the create-on-press offer (LLR-139.2): creates
  exactly the offered folder (the project limb re-runs ``scoped_home``'s
  containment check; the Reports limb mirrors ``report_service``'s
  created-on-demand idiom, LLR-007.7).

Headless by contract (mirroring ``project_gather_service``): stdlib +
sibling-service imports only, no ``textual`` symbol — the seam stays unit-
testable without a running app, and the TUI widget
(``s19_app.tui.open_folder_chip.OpenFolderChip``) is a thin shell over it.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

from ..workspace import WORKAREA_DIRNAME, WORKAREA_PATCHES, WORKAREA_TEMPLATES
from .project_gather_service import (
    PROJECT_CHECKS_DIR,
    PROJECT_PATCHES_DIR,
    PROJECT_TEMPLATES_DIR,
    scoped_home,
    scoped_home_target,
)
from .report_service import REPORTS_DIR_NAME

#: The four chip families (HLR-139) — one per window. The tokens name the
#: artifact family each chip opens, and double as the chip id suffixes
#: (``#open_folder_<family>``).
CHIP_FAMILY_PATCH = "patch"
CHIP_FAMILY_CHECKS = "checks"
CHIP_FAMILY_TEMPLATES = "templates"
CHIP_FAMILY_REPORTS = "reports"

#: Every chip family, in window order (Patch Editor · Checks · CRC Designer ·
#: Reports).
CHIP_FAMILIES: tuple[str, ...] = (
    CHIP_FAMILY_PATCH,
    CHIP_FAMILY_CHECKS,
    CHIP_FAMILY_TEMPLATES,
    CHIP_FAMILY_REPORTS,
)

#: Dimmed-chip tooltips (LLR-139.2, the contract's verbatim strings).
TOOLTIP_NO_PROJECT = "no project — files are in the common folders"
TOOLTIP_MISSING_FOLDER = "folder does not exist yet"

#: The create-offer refusal for the no-project Reports chip (its only
#: status-line reason — the chip is disabled there, so this is surfaced on
#: the refresh that disables it).
REPORTS_NO_PROJECT_REASON = (
    "📂 Open folder (Reports): no active project — load a project first."
)

#: The three families whose missing target may be created on press (the
#: contract's create-offer list; Reports joins them only WITH a project —
#: its home is project-only by definition).
_CREATABLE_FAMILIES = frozenset(
    (CHIP_FAMILY_PATCH, CHIP_FAMILY_CHECKS, CHIP_FAMILY_TEMPLATES)
)

#: The project-subdir half of the three change-1 families (Reports has
#: none — it is project-only without a subdir indirection).
_FAMILY_SUBDIR: dict[str, str] = {
    CHIP_FAMILY_PATCH: PROJECT_PATCHES_DIR,
    CHIP_FAMILY_CHECKS: PROJECT_CHECKS_DIR,
    CHIP_FAMILY_TEMPLATES: PROJECT_TEMPLATES_DIR,
}


def folder_opener_for_platform(platform: Optional[str] = None) -> str:
    """
    Summary:
        Return the platform's file-manager opener command (LLR-139.3):
        ``explorer`` on Windows, ``open`` on macOS, ``xdg-open`` on every
        other POSIX.

    Args:
        platform (Optional[str]): The ``sys.platform`` value to resolve
            for — ``None`` (the default) reads the live ``sys.platform``.

    Returns:
        str: The opener command name. Never a path, never a shell string.

    Data Flow:
        - Pure token comparison — no IO.

    Dependencies:
        Used by:
            - open_folder_in_file_manager
            - the LLR-139.3 unit TC (per-platform arm)
    """
    if platform is None:
        platform = sys.platform
    if platform.startswith("win"):
        return "explorer"
    if platform == "darwin":
        return "open"
    return "xdg-open"


def open_folder_in_file_manager(
    path: Path,
    *,
    set_status: Optional[Callable[[str], None]] = None,
    label: str = "folder",
) -> bool:
    """
    Summary:
        Open ``path`` in the platform's file manager — THE one open seam
        (LLR-139.3). Generalizes the shipped ``action_open_workarea`` idiom
        (``subprocess.Popen(["explorer", str(self.workarea)])``) per
        platform while preserving its observable behaviour: one ``Popen``
        in argv-list form with the resolved dir, the ``Opened {label}:
        …`` status-line confirmation on success, and the caught
        ``Failed to open {label}: …`` status line on any failure — never a
        traceback.

    Args:
        path (Path): The directory to open. Passed verbatim as the single
            argv element after the opener.
        set_status (Optional[Callable[[str], None]]): The status-line sink
            (the app passes ``S19TuiApp.set_status``). ``None`` silences
            the confirmation/failure lines (unit limbs).
        label (str): The noun in the status lines — ``"folder"`` for the
            chips; the shipped workarea opener passes ``"workarea"`` so
            its ``o``-key status text stays byte-identical
            (``Opened workarea: …``).

    Returns:
        bool: ``True`` when the ``Popen`` was issued; ``False`` when the
            opener raised (the failure line was already delivered to
            ``set_status``).

    Data Flow:
        - ``folder_opener_for_platform()`` → ``subprocess.Popen([opener,
          str(path)])`` (argv list only — never a bare string on POSIX).
        - Any exception from ``Popen`` is caught and named on the status
          line — 0 escapes (the error boundary is part of the seam).

    Dependencies:
        Uses:
            - folder_opener_for_platform / subprocess.Popen
        Used by:
            - s19_app.tui.open_folder_chip.OpenFolderChip (the four chips)
            - s19_app.tui.app.S19TuiApp.action_open_workarea (the o-key)
    """
    try:
        subprocess.Popen([folder_opener_for_platform(), str(path)])
    except Exception as exc:
        if set_status is not None:
            set_status(f"Failed to open {label}: {exc}")
        return False
    if set_status is not None:
        set_status(f"Opened {label}: {path}")
    return True


def _family_homes(
    family: str,
    workarea: Path,
    base_dir: Path,
) -> tuple[str, Path]:
    """
    Summary:
        Map a chip family to its change-1 ``(subdir, common_home)`` pair —
        the single place the family→home mapping lives, so the chips carry
        no per-file logic (LLR-139.1). The COMMON template library path is
        built from the same ``WORKAREA_DIRNAME`` / ``WORKAREA_TEMPLATES``
        constants :func:`workspace.ensure_template_lib` uses — the identical
        directory, observed without the mkdir (the resolution must not
        create what the dimmed chip is offering to create).

    Args:
        family (str): One of :data:`CHIP_FAMILIES`.
        workarea (Path): The app workarea (``<base>/.s19tool/workarea/``).
        base_dir (Path): The app base dir.

    Returns:
        tuple[str, Path]: ``(subdir, common_home)`` for the three
            change-1 families.

    Raises:
        ValueError: For the Reports family — it has no change-1 scoped
            home (project-only, resolved directly).

    Data Flow:
        - Pure path arithmetic — no IO.

    Dependencies:
        Used by:
            - resolve_chip_target
            - create_chip_home
    """
    if family == CHIP_FAMILY_PATCH or family == CHIP_FAMILY_CHECKS:
        return _FAMILY_SUBDIR[family], workarea / WORKAREA_PATCHES
    if family == CHIP_FAMILY_TEMPLATES:
        return (
            PROJECT_TEMPLATES_DIR,
            base_dir / WORKAREA_DIRNAME / WORKAREA_TEMPLATES,
        )
    raise ValueError(f"no change-1 scoped home for chip family: {family!r}")


def resolve_chip_target(
    project_dir: Optional[Path],
    *,
    family: str,
    workarea: Path,
    base_dir: Path,
) -> Optional[Path]:
    """
    Summary:
        Resolve a chip's open target — exactly the change-1 home for its
        window's artifact family (LLR-139.1), through
        ``project_gather_service.scoped_home_target``'s one ruling and no
        second-guessing. The Reports family resolves to the project's
        ``reports/`` dir and to ``None`` without a project (its chip is the
        disabled limb, LLR-139.2).

    Args:
        project_dir (Optional[Path]): The active project's directory, or
            ``None`` without a project.
        family (str): One of :data:`CHIP_FAMILIES`.
        workarea (Path): The app workarea.
        base_dir (Path): The app base dir.

    Returns:
        Optional[Path]: The resolved target — never created. ``None`` only
            for the Reports family without a project.

    Data Flow:
        - Reports → ``project_dir / REPORTS_DIR_NAME`` (or ``None``).
        - The three change-1 families → ``scoped_home_target(project_dir,
          subdir, common_home)`` with the :func:`_family_homes` mapping.

    Dependencies:
        Uses:
            - _family_homes / scoped_home_target / REPORTS_DIR_NAME
        Used by:
            - s19_app.tui.open_folder_chip.OpenFolderChip
            - tests/test_open_folder_chips.py (the spied-seam limbs)
    """
    if family == CHIP_FAMILY_REPORTS:
        if project_dir is None:
            return None
        return project_dir / REPORTS_DIR_NAME
    subdir, common_home = _family_homes(family, workarea, base_dir)
    return scoped_home_target(project_dir, subdir, common_home)


def create_chip_home(
    project_dir: Optional[Path],
    *,
    family: str,
    workarea: Path,
    base_dir: Path,
) -> Path:
    """
    Summary:
        The create-on-press offer (LLR-139.2): create exactly the offered
        folder and return it. The three change-1 families ride
        ``project_gather_service.scoped_home`` — the shipped save path's
        own create seam, containment check included; its no-project limb
        returns the COMMON home without creating it, so the offer mkdirs
        it here (the COMMON homes normally exist — the app creates them at
        startup — so this limb fires only for a deleted folder). Reports
        mirrors ``report_service``'s created-on-demand idiom
        (``REPORTS_DIR_NAME``, ``mkdir(parents=True, exist_ok=True)``,
        LLR-007.7) and requires a project.

    Args:
        project_dir (Optional[Path]): The active project's directory, or
            ``None`` without a project.
        family (str): One of :data:`CHIP_FAMILIES`.
        workarea (Path): The app workarea.
        base_dir (Path): The app base dir.

    Returns:
        Path: The created (now-existing) home.

    Raises:
        ValueError: Reports without a project — the target cannot exist.
        WorkareaContainmentError: A project home escapes the
            ``.s19tool/workarea/`` containment root (the shipped law, via
            ``scoped_home``). The chip surfaces it on the status line —
            never a traceback.
        OSError: The mkdir itself failed.

    Data Flow:
        - Reports → ``project_dir / REPORTS_DIR_NAME`` + mkdir.
        - Else → ``scoped_home(project_dir, subdir, common_home)``; when
          that returns a still-missing COMMON home, mkdir it.

    Dependencies:
        Uses:
            - _family_homes / scoped_home / REPORTS_DIR_NAME
        Used by:
            - s19_app.tui.open_folder_chip.OpenFolderChip (press path)
    """
    if family == CHIP_FAMILY_REPORTS:
        if project_dir is None:
            raise ValueError("the Reports folder exists only inside a project")
        home = project_dir / REPORTS_DIR_NAME
        home.mkdir(parents=True, exist_ok=True)
        return home
    subdir, common_home = _family_homes(family, workarea, base_dir)
    home = scoped_home(project_dir, subdir, common_home)
    if not home.exists():
        # scoped_home's no-project limb is create-nothing by design (the
        # COMMON homes are live libraries — creating one is this offer's
        # whole point, and it is the operator's own workspace).
        home.mkdir(parents=True, exist_ok=True)
    return home
