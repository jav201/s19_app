"""The ``📂 Open <folder>/`` chip (batch-95 change 2, HLR-139 / LLR-139.1..139.3;
batch-97 I-1, HLR-148: the label names its folder, the ``flows`` / ``session``
families, ``id_suffix``, and the real-directory guard before every open).

One ghost chip rides the header row of each of the four windows — Patch
Editor → the change-set home, Checks → the check-artifact home, CRC
Designer → the template library, Reports → the project's ``reports/`` dir —
always visible, no key binding. The chip is a thin Textual shell over the
headless seam in ``s19_app.tui.services.folder_open_service``: the target
resolution, the create-on-press offer and the cross-platform open all live
there (LLR-139.1/.3); this module owns only the rendering states
(LLR-139.2):

- target present — the enabled ghost chip, no tooltip;
- target missing (patches / checks / templates) — the chip STAYS ENABLED
  but renders dimmed (the ``-dimmed`` class) with the contract's tooltip
  (``no project — files are in the common folders`` /
  ``folder does not exist yet``); pressing it creates exactly the offered
  folder and then opens it;
- no target (Reports, flows, session without a project) — the chip is
  genuinely ``disabled`` (dimmed + tooltip) and the disabling refresh names
  that family's folder on the status line (LLR-148.3); zero opens are
  possible.

Dimmed-but-enabled uses an explicit CSS class rather than ``disabled`` on
purpose: Textual's ``disabled`` swallows the press, and the missing-folder
limb's create-offer IS a press.
"""
from __future__ import annotations

from typing import List, Optional

from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Button, Label

from .services import folder_open_service
from .services.folder_open_service import (
    CHIP_FAMILIES,
    CHIP_FAMILY_SESSION,
    TOOLTIP_MISSING_FOLDER,
    TOOLTIP_NO_PROJECT,
    TOOLTIP_PROJECT_MISSING,
    chip_family_root,
    chip_label,
    create_chip_home,
    is_openable_chip_dir,
    no_project_reason,
    resolve_chip_target,
)

#: The chip's base CSS class (styles.tcss) — the compact 1-tall borderless
#: ghost idiom the shipped chip buttons use.
CHIP_CLASS = "open-folder-chip"

#: The CSS class marking the dimmed (but still pressable) missing-target
#: state, and the disabled Reports-no-project look.
DIMMED_CLASS = "-dimmed"

#: The header-row container class seating the window title left and the
#: chip at the header-right (LLR-139.1's placement).
HEADER_ROW_CLASS = "db-screen-header"


class OpenFolderChip(Button):
    """One ``📂 Open <folder>/`` chip bound to an artifact family.

    Args:
        family (str): One of :data:`folder_open_service.CHIP_FAMILIES` —
            the window's artifact family (also the chip id suffix,
            ``#open_folder_<family>``).
        id_suffix (Optional[str]): Appended as ``_<suffix>`` to the id, for
            a second chip of a family already mounted elsewhere (the Check
            Editor's ``checks`` chip, D9 / LLR-148.4).

    The chip resolves its target and label on mount and on every
    project-context refresh (``S19TuiApp.update_project_labels``), so the
    dimmed state tracks project load/save without any per-screen wiring.
    """

    def __init__(self, family: str, *, id_suffix: Optional[str] = None) -> None:
        if family not in CHIP_FAMILIES:
            raise ValueError(f"unknown open-folder chip family: {family!r}")
        chip_id = f"open_folder_{family}"
        if id_suffix is not None:
            chip_id = f"{chip_id}_{id_suffix}"
        super().__init__(
            chip_label(family, None),
            id=chip_id,
            classes=CHIP_CLASS,
        )
        #: The artifact family this chip opens (one of ``CHIP_FAMILIES``).
        self.family = family

    # ------------------------------------------------------------------ #
    # Rendering state
    # ------------------------------------------------------------------ #

    def on_mount(self) -> None:
        """Resolve the target so the initial dimmed/tooltip state renders."""
        self.refresh_target()

    def refresh_target(self) -> None:
        """Re-resolve the target and re-render the label and dimmed state.

        A ``None`` target (a project-only family without a project) is the
        genuinely disabled limb: the chip is ``disabled`` (Textual swallows
        its press — the 0-open contract) and the disabling transition names
        that family's folder on the status line. Every other missing target
        stays pressable: dimmed + tooltip, and the press is the create-offer
        (never for ``session``).
        """
        app = self.app
        project_dir = app.active_project_dir()
        target = resolve_chip_target(
            project_dir,
            family=self.family,
            workarea=app.workarea,
            base_dir=app.base_dir,
        )
        self.label = chip_label(self.family, target)
        if target is None:
            newly_disabled = not self.disabled
            self.disabled = True
            self.set_class(True, DIMMED_CLASS)
            self.tooltip = TOOLTIP_NO_PROJECT
            if newly_disabled:
                app.set_status(no_project_reason(self.family))
            return
        self.disabled = False
        missing = not target.exists()
        self.set_class(missing, DIMMED_CLASS)
        if missing and self.family == CHIP_FAMILY_SESSION:
            self.tooltip = TOOLTIP_PROJECT_MISSING
        elif missing:
            self.tooltip = (
                TOOLTIP_NO_PROJECT
                if project_dir is None
                else TOOLTIP_MISSING_FOLDER
            )
        else:
            self.tooltip = None

    # ------------------------------------------------------------------ #
    # The press — resolve (create on offer) → open on the one seam
    # ------------------------------------------------------------------ #

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle this chip's own press (the message bubbles no further)."""
        if event.button is not self:
            return
        self._open_target()

    def _open_target(self) -> None:
        """Open the resolved target through the one cross-platform seam.

        Missing target → the create-on-press offer first (LLR-139.2; never
        for ``session``, whose target is the project itself). Then the
        real-directory guard against the family root (LLR-148.8): a file, a
        junction or a path resolving outside the root is refused on the
        status line with 0 seam calls. Every failure lands on the status
        line, never a traceback. At most one open call per press rides
        ``folder_open_service.open_folder_in_file_manager``.
        """
        app = self.app
        if self.disabled:
            return  # the disabled no-target limb: 0 opens.
        project_dir = app.active_project_dir()
        target = resolve_chip_target(
            project_dir,
            family=self.family,
            workarea=app.workarea,
            base_dir=app.base_dir,
        )
        if target is None:
            # Unreachable while disabled (the guard above is the contract);
            # kept as the invariant's second wall — no traceback either way.
            app.set_status(no_project_reason(self.family))
            return
        if not target.exists() and self.family != CHIP_FAMILY_SESSION:
            try:
                target = create_chip_home(
                    project_dir,
                    family=self.family,
                    workarea=app.workarea,
                    base_dir=app.base_dir,
                )
            except Exception as exc:
                app.set_status(f"Failed to create folder: {exc}")
                return
        root = chip_family_root(project_dir, app.base_dir)
        if not is_openable_chip_dir(target, root):
            app.set_status(
                f"Refused to open {target}: not a real folder inside {root.name}/"
            )
            self.refresh_target()
            return
        try:
            folder_open_service.open_folder_in_file_manager(
                target,
                set_status=app.set_status,
            )
        except Exception as exc:
            # The seam lands its own failures on the status line; this
            # catches one that raises before reaching its guard.
            app.set_status(f"Failed to open folder: {exc}")
        self.refresh_target()


def titled_header(
    title: str,
    chip: Optional[OpenFolderChip] = None,
    *,
    title_classes: str = "db-screen-title",
    help_button: Optional[Button] = None,
) -> Horizontal:
    """Build the window header row: the title left, the chip header-right.

    Args:
        title (str): The window title (author-constant chrome, never
            file-derived — C-17).
        chip (OpenFolderChip): The window's open-folder chip. ``None``
            for the windows without one (Memory Map / Flow Builder /
            A2L Explorer / Workspace) — the title row ships without it
            (batch-95 change 3).
        title_classes (str): The title label's classes — ``modal-title``
            for the Reports modal, ``db-screen-title`` (the default)
            everywhere else.
        help_button (Optional[Button]): The per-window ``?`` usage-help
            chip (batch-95 change 3, HLR-140) — seated BETWEEN the title
            label and the chip, so the chip stays the rightmost child
            (TC-703's placement assertion is unchanged).

    Returns:
        Horizontal: The ``.db-screen-header`` row seating all parts.
    """
    children: List[Widget] = [Label(title, classes=title_classes)]
    if help_button is not None:
        children.append(help_button)
    if chip is not None:
        children.append(chip)
    return Horizontal(
        *children,
        classes=HEADER_ROW_CLASS,
    )
