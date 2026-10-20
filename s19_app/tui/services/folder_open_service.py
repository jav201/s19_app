"""The open-folder seam + chip target resolution (batch-95 change 2, HLR-139;
batch-97 I-1, HLR-148).

One ghost chip ``📂 Open <folder>/`` rides the header row of each window that
owns an artifact family — Patch Editor, Checks, CRC Designer, Reports, and
(batch-97) the flow screens' ``flows`` and ``session`` families — opening
exactly that family's home (LLR-139.1, LLR-148.1/148.2). This module is the
headless half of the chip:

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
- :func:`chip_family_root` / :func:`is_openable_chip_dir` — the real-directory
  guard every press passes before the seam (LLR-148.8), and its one trust
  anchor.
- :func:`chip_label` / :func:`no_project_reason` — the label naming the
  folder the chip opens (LLR-148.10) and the per-family no-project status
  (LLR-148.3).

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

from ..workspace import (
    WORKAREA_DIRNAME,
    WORKAREA_PATCHES,
    WORKAREA_TEMPLATES,
    _path_traverses_reparse_point,
)
from .flow_persistence_service import FLOWS_SUBDIR
from .project_gather_service import (
    PROJECT_CHECKS_DIR,
    PROJECT_PATCHES_DIR,
    PROJECT_TEMPLATES_DIR,
    scoped_home,
    scoped_home_target,
)
from .report_service import REPORTS_DIR_NAME

#: The chip families (HLR-139, HLR-148). The tokens name the artifact family
#: each chip opens, and double as the chip id suffixes
#: (``#open_folder_<family>``). ``flows`` is the flow storage folder's own
#: name, imported so the chip and the flow saver cannot disagree (R15).
CHIP_FAMILY_PATCH = "patch"
CHIP_FAMILY_CHECKS = "checks"
CHIP_FAMILY_TEMPLATES = "templates"
CHIP_FAMILY_REPORTS = "reports"
CHIP_FAMILY_FLOWS = FLOWS_SUBDIR
CHIP_FAMILY_SESSION = "session"

#: Every chip family (Patch Editor · Checks · CRC Designer · Reports · Flow
#: Builder · Flow Execution).
CHIP_FAMILIES: tuple[str, ...] = (
    CHIP_FAMILY_PATCH,
    CHIP_FAMILY_CHECKS,
    CHIP_FAMILY_TEMPLATES,
    CHIP_FAMILY_REPORTS,
    CHIP_FAMILY_FLOWS,
    CHIP_FAMILY_SESSION,
)

#: Dimmed-chip tooltips (LLR-139.2, the contract's verbatim strings).
TOOLTIP_NO_PROJECT = "no project — files are in the common folders"
TOOLTIP_MISSING_FOLDER = "folder does not exist yet"
#: The ``session`` chip's tooltip when the project directory is gone: it is
#: never created, so the create-offer tooltip would promise a refused press.
TOOLTIP_PROJECT_MISSING = "project folder is missing"

#: The folder each family names in its label while it has no target
#: (LLR-148.10); with a target the label names the target's own leaf.
_FAMILY_FOLDER: dict[str, str] = {
    CHIP_FAMILY_PATCH: PROJECT_PATCHES_DIR,
    CHIP_FAMILY_CHECKS: PROJECT_CHECKS_DIR,
    CHIP_FAMILY_TEMPLATES: PROJECT_TEMPLATES_DIR,
    CHIP_FAMILY_REPORTS: REPORTS_DIR_NAME,
    CHIP_FAMILY_FLOWS: FLOWS_SUBDIR,
}

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


def chip_label(family: str, target: Optional[Path]) -> str:
    """
    Summary:
        The chip label naming the folder the chip opens (LLR-148.10):
        ``📂 Open <folder>/`` with ``<folder>`` the leaf of the resolved
        target — so the no-project Checks chip, whose target is the COMMON
        ``workarea/patches``, reads ``📂 Open patches/`` (LED-.6) — or the
        family's folder name while there is no target; ``📂 Open session``
        for the ``session`` family, whose target is the project itself.

    Args:
        family (str): One of :data:`CHIP_FAMILIES`.
        target (Optional[Path]): The resolved target, or ``None``.

    Returns:
        str: The label text.
    """
    if family == CHIP_FAMILY_SESSION:
        return "📂 Open session"
    folder = target.name if target is not None else _FAMILY_FOLDER[family]
    return f"📂 Open {folder}/"


def no_project_reason(family: str) -> str:
    """
    Summary:
        The status line of a chip with no target (LLR-148.3): it names that
        family's folder, never another family's.

    Args:
        family (str): One of :data:`CHIP_FAMILIES`.

    Returns:
        str: e.g. ``📂 Open session: no active project — load a project first.``
    """
    return f"{chip_label(family, None)}: no active project — load a project first."


#: The no-project Reports chip's status reason, kept as a name for its
#: readers; it is :func:`no_project_reason` of ``reports``.
REPORTS_NO_PROJECT_REASON = no_project_reason(CHIP_FAMILY_REPORTS)


def chip_family_root(project_dir: Optional[Path], base_dir: Path) -> Path:
    """
    Summary:
        The family root (§1.3) — the ONE producer of the trust anchor the
        real-directory guard checks against (LLR-148.8, H-C3): the active
        project directory, else the tool root ``base_dir / .s19tool``, which
        holds every COMMON home (``workarea/patches`` and ``templates``).

    Args:
        project_dir (Optional[Path]): The project dir as the app holds it
            (resolved at load), or ``None``.
        base_dir (Path): The app base dir.

    Returns:
        Path: The root a chip target must lie inside.
    """
    if project_dir is not None:
        return project_dir
    return base_dir / WORKAREA_DIRNAME


def is_openable_chip_dir(target: Path, root: Path) -> bool:
    """
    Summary:
        The real-directory guard (LLR-148.8): True only when ``target`` is a
        directory, no path element from ``target`` up to ``root`` is a
        symlink or junction, and ``target`` resolves inside the resolved
        ``root``. Any ``OSError`` / ``ValueError`` (a vanished target, a NUL
        byte) is a refusal, never a raise.

    Args:
        target (Path): The chip target, after any create-on-press.
        root (Path): The family root from :func:`chip_family_root`.

    Returns:
        bool: Whether the open seam may be called on ``target``.
    """
    try:
        if not target.is_dir():
            return False
        if _path_traverses_reparse_point(target, stop_at=root.parent):
            return False
        return target.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


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
            for the project-only families (Reports, flows, session) without
            a project.

    Data Flow:
        - Reports → ``project_dir / REPORTS_DIR_NAME`` (or ``None``).
        - flows → ``project_dir / FLOWS_SUBDIR``; session → ``project_dir``
          (the flow panels' session dir); ``None`` without a project.
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
    if family == CHIP_FAMILY_FLOWS:
        return None if project_dir is None else project_dir / FLOWS_SUBDIR
    if family == CHIP_FAMILY_SESSION:
        return project_dir
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
        ValueError: Reports or flows without a project — the target cannot
            exist; flows whose path resolves outside the project; session,
            which is the project directory and is never created.
        WorkareaContainmentError: A project home escapes the
            ``.s19tool/workarea/`` containment root (the shipped law, via
            ``scoped_home``). The chip surfaces it on the status line —
            never a traceback.
        OSError: The mkdir itself failed.

    Data Flow:
        - Reports → ``project_dir / REPORTS_DIR_NAME`` + mkdir.
        - flows → ``project_dir / FLOWS_SUBDIR`` + mkdir, only when its
          resolved form lies inside the resolved project (LLR-148.1).
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
    if family == CHIP_FAMILY_FLOWS:
        if project_dir is None:
            raise ValueError("the flows folder exists only inside a project")
        home = project_dir / FLOWS_SUBDIR
        if not home.resolve().is_relative_to(project_dir.resolve()):
            raise ValueError(f"{home} resolves outside the project")
        home.mkdir(parents=True, exist_ok=True)
        return home
    if family == CHIP_FAMILY_SESSION:
        raise ValueError("the session folder is the project and is never created")
    subdir, common_home = _family_homes(family, workarea, base_dir)
    home = scoped_home(project_dir, subdir, common_home)
    if not home.exists():
        # scoped_home's no-project limb is create-nothing by design (the
        # COMMON homes are live libraries — creating one is this offer's
        # whole point, and it is the operator's own workspace).
        home.mkdir(parents=True, exist_ok=True)
    return home
