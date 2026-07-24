from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, List, Mapping, Optional, Sequence, Tuple

from rich.markup import escape as escape_markup
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.message import Message
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import (
    Button,
    Input,
    Label,
    ListItem,
    ListView,
    Markdown,
    Select,
    SelectionList,
    Static,
    TextArea,
)

from .capped_text_area import CappedTextArea
from .changes.verify import STATUS_VERIFIED
from .color_policy import css_class_for_severity
from .hexview import MAX_HEX_ROWS, render_hex_view_text
from .os_clipboard_input import OsClipboardInput
from .legend import (
    BAND_DOMAIN_NOTE,
    BAND_GAP_HATCH_NOTE,
    COLOUR_SEVERITY,
    LEGEND_EXAMPLES,
    LEGEND_TABLE,
    ROLE_CAPTION,
    ROLE_LINE,
    ROLE_SUB,
    ROLE_WARNING_SAMPLE,
    build_band_key_rows,
)
from .models import LoadedFile
from .operations.crc import CrcWriteResult, inject_crcs, write_crc_image
from .operations.crc_config import (
    DUMMY_CONFIG_TEXT,
    parse_crc_config,
    read_crc_config_text,
)
from .operations.model import CrcRegionResult, OperationInput, OperationResult
from .services import operation_service
from .services.report_addendum import DeclaredRegion
from .services.report_service import (
    REPORT_CONTEXT_BYTES_DEFAULT,
    REPORT_MAX_TOTAL_BYTES,
)

if TYPE_CHECKING:
    from .operations.crc_config import CrcConfig
    from .operations.model import Operation

logger = logging.getLogger("s19tui")

#: Report-viewer render cap (LLR-008.1 / F-S-06). Chosen as 2x the
#: generator's whole-document budget rather than the 256 MB global
#: ``READ_SIZE_CAP_BYTES``: every self-generated report fits (the
#: LLR-007.6 budget is enforced at hexdump-block granularity, so explicit
#: TRUNCATED markers may push a legitimate report slightly past
#: ``REPORT_MAX_TOTAL_BYTES``), while a foreign oversized ``.md`` dropped
#: into ``reports/`` is refused long before the Markdown widget would
#: freeze the TUI rendering it. Referenced as a module global at call
#: time so tests can lower it without multi-MB fixtures.
VIEWER_SIZE_CAP_BYTES = 2 * REPORT_MAX_TOTAL_BYTES


# --- Calm Dark modal re-skin (batch-02 increment 8, LLR-015.1) --------------
# The three Load / Save / Load-Project modals adopt the Calm Dark token set
# defined in ``styles.tcss`` (`$accent-calm` + the shared dark `$bg-*` /
# `$fg-*` / `$rule` tokens). All modal styling — the dimmed `ModalScreen`
# backdrop, the dialog border / panel surface, the title, the buttons and the
# inputs — lives in ``styles.tcss`` keyed on the `.modal-dialog` /
# `.modal-title` / `.modal-buttons` / `.modal-confirm` classes (and the
# carried-over `#load_dialog` id). No per-screen ``DEFAULT_CSS`` is used: the
# Calm Dark `$bg-*` / `$fg-*` / `$rule` token variables are only in scope for
# the app-level stylesheet (`CSS_PATH = "styles.tcss"`), so the modal rules
# must live there to resolve the tokens. The three modals therefore share one
# accent and one backdrop tone (TC-033 single-accent rule).
#
# This is a VISUAL-ONLY re-skin: no behavior, no path handling, no
# ``validate_project_files`` / ``SaveProjectPayload`` / ``.s19tool/`` workarea
# logic is changed (LLR-015.2 / C-1 / A-5). No hard-coded hex color is used —
# every modal color resolves through a Calm Dark token in ``styles.tcss``.


@dataclass(frozen=True)
class SaveProjectPayload:
    """Save-dialog result: destination + the project composition to persist.

    Summary:
        Carries the parent directory and project folder name plus the optional
        per-variant / project-wide change-check composition to persist into
        ``project.json`` (HLR-017 / LLR-017.1). ``batch`` is the project-wide
        file list; ``assignments`` maps a ``variant_id`` to its per-variant file
        list. Both default empty, so a save that selects nothing re-reads
        identically to the prior active-variant-only save (LLR-017.1, F-Q-05).

    Args:
        parent_folder (str): Destination parent directory, as entered or browsed.
        project_name (str): New project folder name (sanitized downstream).
        batch (tuple[str, ...]): Project-wide change/check files as
            project-relative path strings. Empty ⇒ no project-wide files.
        assignments (Mapping[str, tuple[str, ...]]): Per-variant files keyed by
            ``variant_id`` (the workspace stem, or full filename on a stem
            collision — D-KEY); each value is project-relative path strings.
            Empty ⇒ no per-variant assignments.

    Data Flow:
        - Produced by ``SaveProjectScreen`` / a pilot and consumed by
          ``S19TuiApp._handle_save_dialog``, which threads ``batch`` /
          ``assignments`` into the manifest write + verify (LLR-017.2).
        - All values are project-relative strings; the writer's
          ``_reject_unsafe_entry`` is the sole path-safety authority (D-SEC).
    """

    parent_folder: str
    project_name: str
    batch: tuple[str, ...] = ()
    assignments: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


class LoadFileScreen(ModalScreen[Optional[Path]]):
    """Modal dialog for loading S19/HEX/MAC data files or an A2L file.

    Re-skinned to the Calm Dark theme in batch-02 increment 8 (LLR-015.1):
    the dialog carries the shared ``.modal-dialog`` class so it picks up the
    Calm Dark accent border, panel background and foreground tokens from
    ``styles.tcss``. Behavior is unchanged (LLR-015.2).
    """

    #: Route initial focus to the path Input so Ctrl+V and typing land
    #: there instead of on the Load button. Without this, Textual's default
    #: auto-focus picks the first focusable descendant of the dialog — often
    #: the primary button — and the user's paste is silently dropped.
    AUTO_FOCUS = "#load_path"

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load file (S19/HEX/MAC/A2L):", classes="modal-title"),
            OsClipboardInput(
                placeholder="C:\\path\\to\\file.s19, .hex, .mac, or .a2l",
                id="load_path",
            ),
            Container(
                Button("Load", id="load_ok", classes="modal-confirm"),
                Button("Cancel", id="load_cancel"),
                id="loadfile_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "load_cancel":
            logger.info("LoadFileScreen dismissed by cancel.")
            self.dismiss(None)
            return
        if event.button.id == "load_ok":
            value = self.query_one("#load_path", Input).value.strip()
            logger.info("LoadFileScreen load_ok pressed. has_value=%s", bool(value))
            if not value:
                return
            logger.info("LoadFileScreen dismissing with path=%s", value)
            self.dismiss(Path(value))


class ChangeSetJsonScreen(ModalScreen[Optional[str]]):
    """Full-size modal JSON editor for a paste-authored change-set (US-064b).

    Summary:
        A large editable ``TextArea`` over the current change-set JSON, opened
        from the Patch Editor's "Edit JSON" control (LLR-064b.1). It gives the
        readable multi-line editing surface the height-starved in-panel
        ``#patch_paste_text`` box cannot provide at 80x24 (batch-36 F-01): a
        modal gets the full ``.modal-dialog`` budget, so the ``TextArea``
        (``height: 1fr``, ``styles.tcss``) fills the dialog. The editor is
        SEEDED with the ``#patch_paste_text`` buffer passed at construction —
        the editable source of truth for a paste-authored document
        (``source_path is None``, the only case the app opens the popup for,
        per the LLR-064b.4 disable-guard). On **Confirm** the screen dismisses
        with the edited text; the host writes it back to ``#patch_paste_text``
        and routes it through the EXISTING ``parse_paste`` →
        ``ChangeService.load_text`` apply seam (LLR-064b.2) — no new parse/apply
        path. On **Cancel** the screen dismisses with ``None`` and the document
        is left unchanged.

        The editor is a plain ``TextArea`` — the IDENTICAL widget class to
        ``#patch_paste_text`` — so it inherits exactly the same paste mechanism
        and introduces NO new / second clipboard ingress (S-01: no uncapped
        path is added).

    Args:
        seed_text (str): The current ``#patch_paste_text`` buffer contents to
            pre-fill the editor with (the paste-authored change-set JSON).

    Returns:
        Optional[str]: The edited JSON text on Confirm, or ``None`` on
        Cancel / Escape (``ModalScreen[Optional[str]]``).

    Data Flow:
        - ``compose`` builds a ``.modal-dialog`` with a title, the seeded
          ``#changeset_json_text`` ``TextArea``, and Confirm / Cancel buttons.
        - ``on_button_pressed`` dismisses with the ``TextArea`` text (Confirm)
          or ``None`` (Cancel).

    Dependencies:
        Uses:
            - ``TextArea`` / ``Button`` / the shared ``.modal-dialog`` classes
        Used by:
            - ``S19TuiApp.on_patch_editor_panel_edit_json_requested``
            - tests/test_tui_patch_editor_v2.py

    Example:
        >>> screen = ChangeSetJsonScreen("{}")  # doctest: +SKIP
    """

    #: Route initial focus to the editor so typing / paste land there rather
    #: than on the Confirm button (mirrors :class:`LoadFileScreen`).
    AUTO_FOCUS = "#changeset_json_text"

    #: ``Escape`` cancels the modal, mirroring the Cancel button (batch-41
    #: fold: every sibling modal dismisses on Escape; this one previously
    #: exposed only the Cancel button).
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, seed_text: str) -> None:
        super().__init__()
        self._seed_text = seed_text

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Edit change-set JSON:", classes="modal-title"),
            CappedTextArea(self._seed_text, id="changeset_json_text"),
            Container(
                Button(
                    "Confirm", id="changeset_json_confirm", classes="modal-confirm"
                ),
                Button("Cancel", id="changeset_json_cancel"),
                id="changeset_json_buttons",
                classes="modal-buttons",
            ),
            id="changeset_json_dialog",
            classes="modal-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "changeset_json_cancel":
            self.dismiss(None)
            return
        if event.button.id == "changeset_json_confirm":
            self.dismiss(
                self.query_one("#changeset_json_text", TextArea).text
            )

    def action_cancel(self) -> None:
        """Dismiss with ``None`` — ``Escape`` mirrors the Cancel button."""
        self.dismiss(None)


class EntryJsonScreen(ModalScreen[Optional[str]]):
    """Modal JSON editor scoped to a SINGLE change-set entry (US-068b).

    Summary:
        A per-entry sibling of :class:`ChangeSetJsonScreen` (LLR-068b.2):
        the editable ``TextArea`` is seeded with ONE entry's canonical
        wire-form JSON (``{"type", "address", "value"|"bytes"}``) rather than
        the whole document, so the operator edits a single entry in isolation.
        This single-entry seed is what distinguishes the popup from batch-37's
        whole-set editor — it carries no document header / ``entries`` array.
        Opened from the Patch Editor's per-entry ``#patch_entry_edit_json_
        button`` (distinct from the whole-set ``#patch_edit_json_button`` and
        the field-populate ``#patch_entry_edit_button``) for the row selected
        in ``#patch_doc_entries_table``, and only for a paste-authored
        document (``source_path is None``) per the LLR-068b.4 disable-guard.

        On **Confirm** the screen dismisses with the edited text; the host
        routes it through ``ChangeService.edit_entry_json`` — which validates
        it via the EXISTING ``parse_change_document`` seam (no new parse/apply
        path) and replaces ONLY the selected entry. On **Cancel** the screen
        dismisses with ``None`` and the document is left unchanged. The editor
        is a plain ``TextArea`` (the same widget class as ``#patch_paste_text``
        / ``#changeset_json_text``), so it adds NO new clipboard ingress.

    Args:
        seed_text (str): The selected entry's canonical wire-form JSON to
            pre-fill the editor with (a single entry object).

    Returns:
        Optional[str]: The edited entry JSON on Confirm, or ``None`` on
        Cancel / Escape (``ModalScreen[Optional[str]]``).

    Data Flow:
        - ``compose`` builds a ``.modal-dialog`` with a title, the seeded
          ``#entry_json_text`` ``TextArea``, and Confirm / Cancel buttons.
        - ``on_button_pressed`` dismisses with the ``TextArea`` text (Confirm)
          or ``None`` (Cancel).

    Dependencies:
        Uses:
            - ``TextArea`` / ``Button`` / the shared ``.modal-dialog`` classes
        Used by:
            - ``S19TuiApp.on_patch_editor_panel_entry_edit_json_requested``
            - tests/test_tui_patch_editor_v2.py

    Example:
        >>> screen = EntryJsonScreen('{"type": "bytes"}')  # doctest: +SKIP
    """

    #: Route initial focus to the editor so typing / paste land there rather
    #: than on the Confirm button (mirrors :class:`ChangeSetJsonScreen`).
    AUTO_FOCUS = "#entry_json_text"

    def __init__(self, seed_text: str) -> None:
        super().__init__()
        self._seed_text = seed_text

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Edit entry JSON:", classes="modal-title"),
            CappedTextArea(self._seed_text, id="entry_json_text"),
            Container(
                Button("Confirm", id="entry_json_confirm", classes="modal-confirm"),
                Button("Cancel", id="entry_json_cancel"),
                id="entry_json_buttons",
                classes="modal-buttons",
            ),
            id="entry_json_dialog",
            classes="modal-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "entry_json_cancel":
            self.dismiss(None)
            return
        if event.button.id == "entry_json_confirm":
            self.dismiss(self.query_one("#entry_json_text", TextArea).text)


#: Static help copy for the variant-selector info modal (US-067 / LLR-067.3).
#: One paragraph per idea, joined with blank lines. Authored free of Rich /
#: console-markup metacharacters (``[`` / ``]`` / ``link=``) and rendered
#: through a ``markup=False`` ``Static`` — the text is a fixed constant with NO
#: untrusted interpolation, so it can never carry a markup or style leak
#: (C-17). The required content tokens (``picks which firmware image loads`` /
#: ``at least two firmware images`` / ``project directory``) are asserted by
#: AT-067a + TC-337, so a copy edit that drops the explanation trips the tests.
VARIANT_HELP_TEXT: str = "\n\n".join(
    (
        "The variant selector picks which firmware image loads.",
        "Each option is one firmware image found in the current project "
        "directory. Choosing an option reloads that image, so you can inspect "
        "or patch a different build without leaving the project.",
        "The selector appears only when the project directory holds at least "
        "two firmware images. With a single image there is nothing to switch "
        "between, so the control stays empty and disabled.",
    )
)


class VariantHelpScreen(ModalScreen[None]):
    """Read-only help modal explaining the variant selector (HLR-067).

    Summary:
        Static discovery help for the Patch Editor's ``#patch_variant_select``
        dropdown (LLR-067.3), opened by the always-rendered
        ``#patch_variant_info_button`` beside it. The body renders the fixed
        :data:`VARIANT_HELP_TEXT` — what the selector does (picks which
        firmware image loads) and when it appears (>=2 images in the project
        directory) — through a ``markup=False`` ``Static`` so a stray
        metacharacter could never be interpreted (C-17); the copy is a constant
        with no interpolation. Reuses the shared ``.modal-dialog`` box model
        (``height: auto`` fits the short help text at both 80x24 and 120x30 —
        pilot-measured, C-23), so no new CSS rule is added. Dismissed by Close
        (self-handled, no app-side dispatch) — the same idiom as
        :class:`LegendScreen`.

    Data Flow:
        - ``compose`` builds a ``.modal-dialog`` with a title, the
          ``#variant_help_body`` ``Static`` seeded from ``VARIANT_HELP_TEXT``,
          and a Close button.
        - ``on_button_pressed`` dismisses with ``None`` on Close.

    Dependencies:
        Uses:
            - ``Static`` / ``Button`` / the shared ``.modal-dialog`` classes
            - :data:`VARIANT_HELP_TEXT`
        Used by:
            - ``S19TuiApp.on_patch_editor_panel_variant_help_requested``
            - tests/test_tui_variants.py

    Example:
        >>> screen = VariantHelpScreen()  # doctest: +SKIP
    """

    def compose(self) -> ComposeResult:
        yield Container(
            Label("About the variant selector", classes="modal-title"),
            Static(
                VARIANT_HELP_TEXT,
                id="variant_help_body",
                markup=False,
            ),
            Container(
                Button(
                    "Close",
                    id="variant_help_close",
                    classes="modal-confirm",
                ),
                id="variant_help_buttons",
                classes="modal-buttons",
            ),
            id="variant_help_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#variant_help_close", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "variant_help_close":
            logger.info("VariantHelpScreen dismissed by close.")
            self.dismiss(None)


class SaveProjectScreen(ModalScreen[Optional[SaveProjectPayload]]):
    """Modal dialog for destination folder, project name, and per-variant assignments.

    Summary:
        Collects the save destination (parent folder + project name) and,
        when re-saving an existing multi-variant project, the per-variant
        change/check assignments plus a project-wide batch list (HLR-017 /
        LLR-017.3). The assignment rows offer ONLY project-relative ``.json``
        documents enumerated from the project dir (workarea-restricted,
        D-SCOPING); each per-variant key is sourced from the caller-supplied
        ``variant_id`` (never recomputed as ``Path.stem`` — D-KEY), and every
        selection resolves by the row's stored VALUE, never by parsing label
        text. Re-skinned to the Calm Dark theme in batch-02 increment 8
        (LLR-015.1): the dialog carries the shared ``.modal-dialog`` class.

    Args:
        default_parent (Path): Prefilled destination parent directory.
        variants (Optional[List[Tuple[str, str]]]): ``(variant_id,
            display_label)`` pairs for the existing project's variants, in
            set order (the ``_variant_display_options`` contract). ``None`` /
            empty ⇒ no assignment rows (D-NEWPROJ: a brand-new project save
            has no variant set, so it writes empty ``batch`` / ``assignments``).
        candidate_files (Optional[List[str]]): Project-relative ``.json``
            change/check document names enumerated from the project dir
            (``project.json`` excluded by the caller — D-SCOPING). ``None`` /
            empty ⇒ no assignment rows offered.

    Data Flow:
        - ``compose`` renders a ``SelectionList`` per variant (id
          ``#assign_<index>``) plus one for the project-wide batch
          (``#assign_batch``) only when both ``variants`` and
          ``candidate_files`` are non-empty.
        - ``save_ok`` reads each ``SelectionList.selected`` (a list of the
          candidate-filename VALUES) and builds ``batch`` (tuple) +
          ``assignments`` (``{variant_id: tuple}``) keyed by INDEX into
          ``self.variants`` — the writer's ``_reject_unsafe_entry`` remains
          the sole path-safety authority (D-SEC).

    Dependencies:
        Used by:
            - s19_app.tui.app.S19TuiApp.action_save_project
    """

    def __init__(
        self,
        default_parent: Path,
        variants: Optional[List[Tuple[str, str]]] = None,
        candidate_files: Optional[List[str]] = None,
    ) -> None:
        super().__init__()
        self.default_parent = default_parent
        self.variants: List[Tuple[str, str]] = list(variants or [])
        self.candidate_files: List[str] = list(candidate_files or [])

    @property
    def _assignment_rows_enabled(self) -> bool:
        """Whether the per-variant assignment section is rendered (D-NEWPROJ).

        Only a re-save of an existing multi-variant project (variants known)
        with ≥1 enumerated candidate file offers assignment rows; otherwise
        the screen collects no composition and the payload stays empty.
        """
        return bool(self.variants) and bool(self.candidate_files)

    def compose(self) -> ComposeResult:
        children: list = [
            Label("Save project folder under:", classes="modal-title"),
            Input(
                placeholder="C:\\path\\to\\parent\\folder",
                id="project_parent_path",
            ),
            Container(
                Button("Browse...", id="save_browse"),
                id="save_browse_row",
            ),
            Label("Project name (new folder name):", classes="modal-title"),
            # batch-31 AC-2 (B-03): OS-clipboard paste via the bounded
            # batch-29 funnel; the name still passes sanitize_project_name.
            # `project_parent_path` above deliberately stays a stock Input
            # (security mini-review scope condition — write-surface input).
            OsClipboardInput(
                placeholder="letters, numbers, - _", id="project_name"
            ),
        ]
        if self._assignment_rows_enabled:
            children.append(
                Label("Project-wide batch files (.json):", classes="modal-title")
            )
            children.append(
                SelectionList[str](
                    *[(name, name) for name in self.candidate_files],
                    id="assign_batch",
                    classes="assign-list",
                )
            )
            for index, (_variant_id, display) in enumerate(self.variants):
                children.append(
                    Label(
                        f"Assign files to '{display}':",
                        classes="modal-title",
                    )
                )
                children.append(
                    SelectionList[str](
                        *[(name, name) for name in self.candidate_files],
                        id=f"assign_{index}",
                        classes="assign-list",
                    )
                )
        children.append(
            Container(
                Button("Save", id="save_ok", classes="modal-confirm"),
                Button("Cancel", id="save_cancel"),
                id="saveproject_buttons",
                classes="modal-buttons",
            )
        )
        yield Container(
            *children,
            id="load_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#project_parent_path", Input).value = str(self.default_parent)

    def _collect_composition(
        self,
    ) -> Tuple[Tuple[str, ...], dict]:
        """
        Summary:
            Collect the project-wide batch selection and each per-variant
            selection into a payload composition (LLR-017.3). Returns empty
            structures when the assignment section was not rendered
            (D-NEWPROJ). Each assignment key is the caller-supplied
            ``variant_id`` resolved by row INDEX into ``self.variants`` —
            never recomputed (D-KEY). Selection values are the candidate
            filenames (project-relative strings, no pre-resolution — D-SEC);
            a variant with no selection is omitted entirely.

        Returns:
            Tuple[Tuple[str, ...], dict]: ``(batch, assignments)`` where
            ``batch`` is project-relative filename strings and ``assignments``
            maps ``variant_id`` → tuple of filename strings.

        Data Flow:
            - Short-circuit to ``((), {})`` when ``_assignment_rows_enabled``
              is false (the assignment section was not rendered, D-NEWPROJ).
            - Read the ``#assign_batch`` SelectionList's ``selected`` into the
              project-wide ``batch`` tuple.
            - For each ``(variant_id, _display)`` in ``self.variants``, read the
              row-indexed ``#assign_<index>`` SelectionList; key non-empty
              selections under ``variant_id`` (D-KEY), omit empty ones.

        Dependencies:
            Uses:
                - self.variants (variant_id source, D-KEY)
                - textual.widgets.SelectionList (queried by id)
            Used by:
                - SaveProjectScreen.on_button_pressed (Save dismiss path)
        """
        if not self._assignment_rows_enabled:
            return (), {}
        batch = tuple(self.query_one("#assign_batch", SelectionList).selected)
        assignments: dict[str, Tuple[str, ...]] = {}
        for index, (variant_id, _display) in enumerate(self.variants):
            selected = tuple(
                self.query_one(f"#assign_{index}", SelectionList).selected
            )
            if selected:
                assignments[variant_id] = selected
        return batch, assignments

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save_cancel":
            self.dismiss(None)
            return
        if event.button.id == "save_browse":
            try:
                import tkinter as tk
                from tkinter import filedialog
            except Exception as exc:
                logger.warning("Folder browse unavailable: %s", exc)
                return
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            picked = filedialog.askdirectory()
            root.destroy()
            if picked:
                self.query_one("#project_parent_path", Input).value = picked
            return
        if event.button.id == "save_ok":
            parent = self.query_one("#project_parent_path", Input).value.strip()
            name = self.query_one("#project_name", Input).value.strip()
            if not parent or not name:
                return
            batch, assignments = self._collect_composition()
            self.dismiss(
                SaveProjectPayload(
                    parent_folder=parent,
                    project_name=name,
                    batch=batch,
                    assignments=assignments,
                )
            )


class LoadProjectScreen(ModalScreen[Optional[str]]):
    """Modal dialog for selecting an existing project.

    Re-skinned to the Calm Dark theme in batch-02 increment 8 (LLR-015.1):
    the dialog carries the shared ``.modal-dialog`` class. The project list
    selection behavior is unchanged (LLR-015.2).
    """

    def __init__(self, projects: List[str]):
        super().__init__()
        self.projects = projects

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load project:", classes="modal-title"),
            ListView(
                *[ListItem(Label(name)) for name in self.projects],
                id="project_list",
            ),
            Container(
                Button("Load", id="project_ok", classes="modal-confirm"),
                Button("Cancel", id="project_cancel"),
                id="loadproject_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "project_cancel":
            self.dismiss(None)
            return
        if event.button.id == "project_ok":
            selected = self.query_one("#project_list", ListView).highlighted_child
            if selected is None:
                return
            label_widget = selected.query_one(Label)
            name = label_widget.text if hasattr(label_widget, "text") else str(label_widget)
            self.dismiss(name)


class SelectVariantScreen(ModalScreen[Optional[str]]):
    """Modal dialog for selecting the active S19/HEX variant of a project.

    Follows the ``LoadProjectScreen`` pattern (LLR-005.5): a ``ListView`` of
    display labels plus confirm/cancel buttons, dismissing with the chosen
    ``variant_id`` or ``None`` on cancel. The caller supplies pre-computed
    ``(variant_id, display_label)`` pairs — when two variants share a
    filename stem (e.g. ``fw.s19`` + ``fw.hex``) the app passes the full
    filename as the display label — and the selection resolves by list
    index, never by parsing label text back. Styling reuses the shared
    Calm Dark ``.modal-dialog`` token classes from ``styles.tcss``.
    """

    def __init__(
        self,
        project_name: str,
        options: List[Tuple[str, str]],
        active_index: int,
    ) -> None:
        super().__init__()
        self.project_name = project_name
        self.options = options
        self.active_index = active_index

    def compose(self) -> ComposeResult:
        yield Container(
            Label(
                f"Select variant (project '{self.project_name}'):",
                classes="modal-title",
            ),
            ListView(
                *[
                    ListItem(
                        Label(
                            f"{display} (active)"
                            if index == self.active_index
                            else display
                        )
                    )
                    for index, (_variant_id, display) in enumerate(self.options)
                ],
                id="variant_list",
            ),
            Container(
                Button("Activate", id="variant_ok", classes="modal-confirm"),
                Button("Cancel", id="variant_cancel"),
                id="selectvariant_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        list_view = self.query_one("#variant_list", ListView)
        if 0 <= self.active_index < len(self.options):
            list_view.index = self.active_index
        list_view.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "variant_cancel":
            logger.info("SelectVariantScreen dismissed by cancel.")
            self.dismiss(None)
            return
        if event.button.id == "variant_ok":
            list_view = self.query_one("#variant_list", ListView)
            index = list_view.index
            if index is None or not (0 <= index < len(self.options)):
                return
            variant_id = self.options[index][0]
            logger.info("SelectVariantScreen dismissing with variant_id=%s", variant_id)
            self.dismiss(variant_id)


#: N8 — map a :class:`~s19_app.tui.legend.LegendLine` role to its card CSS class
#: (``legend-card-*``, defined in ``styles.tcss`` Inc-3 — weight/dim only, never a
#: ``sev-*``/``band-*`` colour, LLR-N8-6.2). ``ROLE_WARNING_SAMPLE`` is rendered
#: separately (painted inline orange + tagged ``#legend_mac_warning_sample``).
_CARD_ROLE_CLASS: dict[str, str] = {
    ROLE_SUB: "legend-card-sub",
    ROLE_LINE: "legend-card-line",
    ROLE_CAPTION: "legend-card-caption",
}

#: The Rich style the MAC DataTable paints a WARNING row with, kept in sync with
#: ``app._SEVERITY_TO_RICH_STYLE[ValidationSeverity.WARNING]`` (``"orange3"``);
#: not imported (``app`` imports this module). AT-N8-07 couples the painted
#: segment to app's live value, so a divergence goes RED (AMD-7).
_MAC_WARNING_SAMPLE_STYLE = "orange3"


class LegendScreen(ModalScreen[None]):
    """Read-only classification-legend modal (HLR-023 / LLR-023.1; N8 cards).

    Summary:
        Renders every :data:`s19_app.tui.legend.LEGEND_TABLE` row — one
        bold sub-heading per artifact (A2L / MAC / Issues), one Label per
        classification giving ``<classification> — <meaning>`` — and
        colours each row through ``color_policy.css_class_for_severity``
        (the ``sev-*`` classes) so the in-app legend shows the same colours
        the views use. Shared single source with the report legend
        (``report_service._legend_lines``); the modal copies no literal
        text. The body scrolls so the full table fits the 80- and 120-col
        regimes (C-13). Opened by the per-view Legend buttons and dismissed
        by Close (self-handled, no app-side dispatch).

    Data Flow:
        - Reads ``LEGEND_TABLE`` + ``COLOUR_SEVERITY`` (s19_app.tui.legend)
          and ``css_class_for_severity`` (color_policy, READ-only).
        - Pushed by ``S19TuiApp.action_show_legend``, reached from the
          ``k`` binding (A2L, which has no button — C-13) and the
          ``#mac_legend_button`` / ``#issues_legend_button`` ids via
          ``on_button_pressed``; dismissed with ``None``.

    Dependencies:
        Uses:
            - s19_app.tui.legend.LEGEND_TABLE / COLOUR_SEVERITY
            - s19_app.tui.color_policy.css_class_for_severity
        Used by:
            - S19TuiApp.on_button_pressed
            - tests/test_tui_legend.py
    """

    def __init__(
        self,
        sections: Optional[Sequence[str]] = None,
        view_key: Optional[str] = None,
    ) -> None:
        """Scope the legend to a screen's section(s) and per-view example card.

        Args:
            sections (Optional[Sequence[str]]): The ``LEGEND_TABLE`` artifact
                keys to show (e.g. ``("A2L",)``). ``None`` shows every section
                (the batch-51 behaviour / N1 full-table fallback for a screen
                with no mapped section, AC-3); ``()`` shows none (an
                example-only view such as Workspace — N8 LLR-N8-1.2).
            view_key (Optional[str]): The active screen key (``workspace`` /
                ``a2l`` / ``map`` / ``mac`` / ``issues``) selecting the N8
                example card and the key type (band key for ``map``). ``None``
                preserves the exact pre-N8 render (no card).
        """
        super().__init__()
        self._sections = tuple(sections) if sections is not None else None
        self._view_key = view_key

    def _render_card(self) -> List[Static]:
        """
        Summary:
            Render the N8 per-view annotated example card — the ``LegendLine``
            rows in :data:`LEGEND_EXAMPLES` for ``self._view_key`` — as
            ``Static`` widgets (so long lines wrap, HLR-N8-6), each classed by
            its role. The ``warning_sample`` row is painted inline orange and
            tagged ``#legend_mac_warning_sample`` (AMD-7/AMD-11). Returns ``[]``
            when the view has no card (``view_key`` is ``None`` or unmapped).

        Returns:
            List[Static]: the ordered card widgets, or ``[]``.

        Data Flow:
            - Reads ``LEGEND_EXAMPLES`` (legend.py, static author data);
              markup-bearing lines carry pre-escaped literal brackets (TC-N8-11).
            - Consumed by :meth:`compose`, placed above the colour/band key.

        Dependencies:
            Uses:
                - LEGEND_EXAMPLES / ROLE_WARNING_SAMPLE / _CARD_ROLE_CLASS
                - rich.markup.escape (warning-sample content)
            Used by:
                - LegendScreen.compose
        """
        card = LEGEND_EXAMPLES.get(self._view_key) if self._view_key else None
        if not card:
            return []
        widgets: List[Static] = []
        for line in card:
            if line.role == ROLE_WARNING_SAMPLE:
                widgets.append(
                    Static(
                        f"[{_MAC_WARNING_SAMPLE_STYLE}]"
                        f"{escape_markup(line.text)}[/]",
                        id="legend_mac_warning_sample",
                        classes="legend-card-line",
                    )
                )
            else:
                widgets.append(
                    Static(
                        line.text,
                        classes=_CARD_ROLE_CLASS.get(line.role, "legend-card-line"),
                    )
                )
        return widgets

    def _render_key(self) -> List[Widget]:
        """
        Summary:
            Render the colour/band key below the card. For ``view_key == "map"``
            this is the entropy band key derived from ``ENTROPY_BANDS`` via
            ``build_band_key_rows`` (``band-*`` classes — an entropy domain,
            LLR-N8-3.2), rendered ``markup=False`` since each range reads
            ``[lo,hi)`` (a literal bracket). For every other view it is the
            ``LEGEND_TABLE`` severity key filtered by ``self._sections`` and
            painted through ``css_class_for_severity`` — the pre-N8 rows, now
            ``Static`` so long meanings wrap instead of truncating (HLR-N8-6).

        Returns:
            List[Widget]: artifact-header + classification/band rows; possibly
            empty (an example-only view passed ``sections=()``).

        Data Flow:
            - Reads ``LEGEND_TABLE`` + ``COLOUR_SEVERITY`` and, for the map,
              ``build_band_key_rows``; colours via ``css_class_for_severity``.
            - Consumed by :meth:`compose`, placed below the example card.

        Dependencies:
            Uses:
                - LEGEND_TABLE / COLOUR_SEVERITY / css_class_for_severity
                - build_band_key_rows / BAND_GAP_HATCH_NOTE / BAND_DOMAIN_NOTE
            Used by:
                - LegendScreen.compose
        """
        if self._view_key == "map":
            rows: List[Widget] = [
                Label("Entropy bands", classes="legend-artifact")
            ]
            for band in build_band_key_rows():
                rows.append(
                    Static(
                        f"{band.glyph}  {band.label}  {band.range_text} — "
                        f"{band.meaning}",
                        markup=False,
                        classes=f"legend-row {band.css_class}".strip(),
                    )
                )
            rows.append(
                Static(BAND_GAP_HATCH_NOTE, markup=False, classes="legend-row")
            )
            rows.append(Static(BAND_DOMAIN_NOTE, classes="legend-card-caption"))
            return rows
        rows = []
        for artifact, table in LEGEND_TABLE.items():
            if self._sections is not None and artifact not in self._sections:
                continue
            rows.append(Label(artifact, classes="legend-artifact"))
            for classification, (colour, meaning) in table.items():
                severity = COLOUR_SEVERITY.get(colour)
                sev_class = (
                    css_class_for_severity(severity)
                    if severity is not None
                    else ""
                )
                classes = f"legend-row {sev_class}".strip()
                rows.append(Static(f"{classification} — {meaning}", classes=classes))
        return rows

    def compose(self) -> ComposeResult:
        body = self._render_card() + self._render_key()
        yield Container(
            Label("Classification legend", classes="modal-title"),
            ScrollableContainer(*body, id="legend_body"),
            Container(
                Button("Close", id="legend_close", classes="modal-confirm"),
                id="legend_buttons",
                classes="modal-buttons",
            ),
            id="legend_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#legend_close", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "legend_close":
            logger.info("LegendScreen dismissed by close.")
            self.dismiss(None)


def _parse_declared_regions(text: str) -> Tuple[Tuple[DeclaredRegion, ...], int]:
    """
    Summary:
        Parse the report dialog's declared-region input (LLR-024.3): one
        ``name,start,end`` per line, where ``start``/``end`` accept ``0x`` hex
        or decimal. Blank lines and malformed/invalid lines are skipped (the
        ``DeclaredRegion`` constructor validates + scrubs each name) — a bad
        line never aborts the parse. Malformed (wrong field count) and invalid
        (failed ``int``/``DeclaredRegion`` parse) lines are counted so the
        caller can surface a skip count (LLR-029.1); blank/whitespace-only
        lines are intentional spacing and are NOT counted.

    Args:
        text (str): The raw multi-line region input.

    Returns:
        Tuple[Tuple[DeclaredRegion, ...], int]: A pair of
            ``(regions, skipped_count)`` — the successfully parsed regions in
            order, and the number of non-blank lines skipped as malformed or
            invalid (blank lines excluded from the count).

    Dependencies:
        Uses:
            - DeclaredRegion
        Used by:
            - ReportViewerScreen.on_button_pressed
    """
    regions: List[DeclaredRegion] = []
    skipped = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) != 3:
            logger.info("ReportViewerScreen skipped malformed region line: %r", line)
            skipped += 1
            continue
        name, start_text, end_text = parts
        try:
            regions.append(DeclaredRegion(name, int(start_text, 0), int(end_text, 0)))
        except ValueError:
            logger.info("ReportViewerScreen skipped invalid region line: %r", line)
            skipped += 1
    return tuple(regions), skipped


class ReportViewerScreen(ModalScreen[None]):
    """Read-only report viewer + generation trigger modal (LLR-008.1/008.5).

    Summary:
        Lists the active project's reports newest-first (the caller passes
        the ``list_project_reports`` result, LLR-008.3) and renders the
        selected one through ``textual.widgets.Markdown`` constructed with
        ``open_links=False`` — render-only per F-S-06: no link navigation,
        no file inclusion, no URL opening, and NO ``Markdown.LinkClicked``
        handler is registered here or in the app. Files larger than
        :data:`VIEWER_SIZE_CAP_BYTES` are refused with a neutral message
        instead of being rendered. The bottom row collects ``context_bytes``
        (prefilled with the LLR-007.2 default) and posts
        :class:`ReportViewerScreen.GenerateRequested` to the app — the
        screen itself assembles nothing (LLR-008.5).

    Args:
        project_name (str): The active project's display name.
        reports (List[Path]): Report paths newest-first (LLR-008.3 order
            is the CALLER's contract; this screen preserves it verbatim).
        declared_regions (Tuple[DeclaredRegion, ...]): Regions carried over
            from the loaded project's manifest (LLR-028.3); seeded into the
            ``#report_declared_regions`` TextArea by ``compose`` (LLR-028.4)
            so the operator does not retype them. Defaults to ``()`` — the
            2-arg constructions stay valid (no seed text).
        filter_names (Tuple[str, ...]): The scanned ``filters/*.json`` bare
            names for the ``#report_filter_select`` dropdown (batch-35
            US-056, LLR-056.2). Option labels are markup-escaped at
            construction (C-15 probe: textual 8.2.8 parses raw labels as
            markup).
        filter_select_value (Optional[str]): Reopen-seed for the dropdown
            (F-05(i)) — the sticky selection's bare name when it lives in
            the project's ``filters/`` dir, else ``None`` (blank).
        filter_path_text (str): Reopen-seed for the free-path input — the
            sticky selection's path string when it was a typed path, else
            ``""``.

    Returns:
        None: ``ModalScreen[None]`` — always dismisses with ``None``.

    Data Flow:
        - Selection resolves by list index into ``self.reports`` (never by
          parsing label text back).
        - ``Generate new report`` parses the context input as a plain
          decimal int; an unparsable value is ignored (the LoadFileScreen
          empty-input pattern) while DOMAIN errors (F-S-05) surface later
          via the app's ``ReportOptions`` status line.

    Dependencies:
        Uses:
            - VIEWER_SIZE_CAP_BYTES / REPORT_CONTEXT_BYTES_DEFAULT
        Used by:
            - s19_app.tui.app.S19TuiApp.action_view_reports

    Example:
        >>> screen = ReportViewerScreen("proj", [])  # doctest: +SKIP
    """

    EMPTY_TEXT = "No reports in this project yet - use 'Generate new report' below."
    TOO_LARGE_TEXT = (
        "This report file is larger than the viewer cap and was not "
        "rendered. It remains available on disk."
    )
    UNREADABLE_TEXT = "This report file could not be read."

    class GenerateRequested(Message):
        """Operator asked for a new report with the given context size.

        Summary:
            Posted (then the screen dismisses) when the Generate button is
            pressed with a parsable integer in the context input; bubbles
            to ``S19TuiApp`` which owns the generation flow (LLR-008.5).

        Args:
            context_bytes (int): The collected hexdump context size —
                domain validation is deferred to ``ReportOptions``
                (F-S-05: out-of-domain is an explicit ERROR, never a
                silent clamp).

        Dependencies:
            Used by:
                - s19_app.tui.app.S19TuiApp.on_report_viewer_screen_generate_requested
        """

        def __init__(
            self,
            context_bytes: int,
            declared_regions: Tuple[DeclaredRegion, ...] = (),
        ) -> None:
            super().__init__()
            self.context_bytes = context_bytes
            self.declared_regions = declared_regions

    class FilterSelected(Message):
        """Operator picked a report filter on the dropdown (US-056).

        Summary:
            Posted straight to the app's queue when the
            ``#report_filter_select`` value changes; carries the picked
            filter's BARE FILENAME (the dropdown option value), or ``None``
            when the blank option was chosen (= full report, LLR-056.2).
            Path resolution and the sticky-state update are the APP's job
            (LLR-056.3) — the screen holds no config (batch-32 precedent).

        Args:
            name (Optional[str]): The picked ``filters/*.json`` bare name,
                or ``None`` for the blank (no-filter) selection.

        Dependencies:
            Used by:
                - s19_app.tui.app.S19TuiApp.on_report_viewer_screen_filter_selected
        """

        def __init__(self, name: Optional[str]) -> None:
            super().__init__()
            self.name = name

    class FilterPathTyped(Message):
        """Operator submitted a free filter path (US-056, LLR-056.4).

        Summary:
            Posted straight to the app's queue when Enter is pressed in
            ``#report_filter_path`` with non-blank text; carries the RAW
            typed string — resolution (``resolve_input_path``), the
            symlink/non-file refusal, and the sticky-state update are the
            APP's job (LLR-056.4).

        Args:
            raw (str): The typed path text, stripped, non-empty.

        Dependencies:
            Used by:
                - s19_app.tui.app.S19TuiApp.on_report_viewer_screen_filter_path_typed
        """

        def __init__(self, raw: str) -> None:
            super().__init__()
            self.raw = raw

    def __init__(
        self,
        project_name: str,
        reports: List[Path],
        declared_regions: Tuple[DeclaredRegion, ...] = (),
        filter_names: Tuple[str, ...] = (),
        filter_select_value: Optional[str] = None,
        filter_path_text: str = "",
    ) -> None:
        super().__init__()
        self.project_name = project_name
        self.reports = reports
        self.declared_regions = declared_regions
        #: Report-filter selector inputs (batch-35 US-056, LLR-056.2): the
        #: scanned ``filters/*.json`` bare names (dropdown options), plus the
        #: reopen-seeding state derived from the app's sticky
        #: ``_report_filter_path`` (F-05(i)) — a dropdown-file selection
        #: seeds the Select value, a free-path selection seeds the path
        #: input text. Defaults keep every existing 2/3-arg construction
        #: valid (no options, blank seed).
        self.filter_names = filter_names
        self.filter_select_value = filter_select_value
        self.filter_path_text = filter_path_text
        self.selected_path: Optional[Path] = None

    def compose(self) -> ComposeResult:
        if self.reports:
            listing: ListView | Static = ListView(
                *[ListItem(Label(path.name)) for path in self.reports],
                id="report_list",
            )
        else:
            listing = Static(self.EMPTY_TEXT, id="report_empty_state", markup=False)
        yield Container(
            Label(
                f"Reports (project '{self.project_name}'):",
                classes="modal-title",
            ),
            listing,
            ScrollableContainer(
                Markdown("", open_links=False, id="report_markdown"),
                id="report_markdown_scroll",
            ),
            Label("Declared regions (name,start,end per line):"),
            CappedTextArea(
                "\n".join(
                    f"{region.name},{region.start},{region.end}"
                    for region in self.declared_regions
                ),
                id="report_declared_regions",
            ),
            Horizontal(
                Label("Filter:", id="report_filter_label"),
                Select(
                    # C-15 probe (2026-07-10, textual 8.2.8): raw str option
                    # labels are PARSED AS MARKUP — an unescaped hostile
                    # filename renders styled/corrupted. Escape at option
                    # construction so the literal name renders (LLR-056.2
                    # F-05(ii)); the VALUE stays the raw bare name.
                    [
                        (escape_markup(name), name)
                        for name in self.filter_names
                    ],
                    id="report_filter_select",
                    allow_blank=True,
                    value=(
                        self.filter_select_value
                        if self.filter_select_value in self.filter_names
                        else Select.NULL
                    ),
                ),
                OsClipboardInput(
                    value=self.filter_path_text,
                    placeholder="filter path (blank = full report)",
                    id="report_filter_path",
                ),
                id="report_filter_row",
            ),
            Container(
                Label("Context bytes:"),
                Input(
                    value=str(REPORT_CONTEXT_BYTES_DEFAULT),
                    id="report_context_bytes",
                ),
                Button(
                    "Generate new report",
                    id="report_generate",
                    classes="modal-confirm",
                ),
                Button("Close", id="report_close"),
                id="reportviewer_buttons",
                classes="modal-buttons",
            ),
            id="report_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        if self.reports:
            self.query_one("#report_list", ListView).focus()

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        index = event.list_view.index
        if index is None or not (0 <= index < len(self.reports)):
            return
        await self._render_report(self.reports[index])

    async def _render_report(self, path: Path) -> None:
        """
        Summary:
            Render one report into the Markdown widget, refusing files
            over the viewer cap with a neutral message (F-S-06) — never
            rendering past the cap.

        Args:
            path (Path): The selected report file.

        Returns:
            None

        Data Flow:
            - Probe the on-disk size FIRST; over the (call-time module
              global) ``VIEWER_SIZE_CAP_BYTES`` → the too-large message
              replaces the render and ``selected_path`` stays ``None``
              for that file.
            - Decode errors never crash the modal: ``errors="replace"``
              plus an unreadable-message fallback on ``OSError``.

        Dependencies:
            Uses:
                - VIEWER_SIZE_CAP_BYTES
            Used by:
                - on_list_view_selected
        """
        markdown = self.query_one("#report_markdown", Markdown)
        try:
            size_bytes = path.stat().st_size
        except OSError:
            self.selected_path = None
            await markdown.update(self.UNREADABLE_TEXT)
            return
        if size_bytes > VIEWER_SIZE_CAP_BYTES:
            logger.info(
                "Report viewer refused oversized file (%d bytes): %s",
                size_bytes,
                path.name,
            )
            self.selected_path = None
            await markdown.update(self.TOO_LARGE_TEXT)
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            self.selected_path = None
            await markdown.update(self.UNREADABLE_TEXT)
            return
        self.selected_path = path
        await markdown.update(text)

    def on_select_changed(self, event: Select.Changed) -> None:
        """
        Summary:
            Forward a report-filter dropdown change to the app as a
            :class:`FilterSelected` message (LLR-056.2) — blank maps to
            ``None`` via the ``Select.NULL`` runtime sentinel (C-15:
            ``Select.BLANK`` resolves to an unrelated inherited bool on
            the installed textual and never matches; batch-23 precedent).

        Args:
            event (Select.Changed): The dropdown change event.

        Returns:
            None

        Data Flow:
            - ``#report_filter_select`` only; posted straight to the app's
              queue (the ``GenerateRequested`` idiom) so the message
              survives any screen dismissal ordering.

        Dependencies:
            Used by:
                - Textual select-change dispatch
        """
        if event.select.id != "report_filter_select":
            return
        event.stop()
        if event.value is Select.NULL:
            self.app.post_message(self.FilterSelected(None))
            return
        self.app.post_message(self.FilterSelected(str(event.value)))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """
        Summary:
            Forward a submitted free filter path to the app as a
            :class:`FilterPathTyped` message (LLR-056.4). An empty submit
            is ignored (the LoadFileScreen empty-input pattern).

        Args:
            event (Input.Submitted): The Enter-key submission event.

        Returns:
            None

        Data Flow:
            - ``#report_filter_path`` only (``#report_context_bytes`` keeps
              its Generate-button-only flow); stripped, non-empty text is
              posted raw — resolution and refusal are the app's job.

        Dependencies:
            Used by:
                - Textual input-submit dispatch
        """
        if event.input.id != "report_filter_path":
            return
        event.stop()
        raw = event.value.strip()
        if not raw:
            return
        self.app.post_message(self.FilterPathTyped(raw))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "report_close":
            logger.info("ReportViewerScreen dismissed by close.")
            self.dismiss(None)
            return
        if event.button.id == "report_generate":
            raw = self.query_one("#report_context_bytes", Input).value.strip()
            try:
                context_bytes = int(raw)
            except ValueError:
                logger.info("ReportViewerScreen ignored non-integer context: %r", raw)
                return
            logger.info(
                "ReportViewerScreen requesting generation. context_bytes=%d",
                context_bytes,
            )
            regions, skipped = _parse_declared_regions(
                self.query_one("#report_declared_regions", TextArea).text
            )
            if skipped >= 1:
                # Count-only (LLR-029.3 / carry C-P3b): never interpolate the
                # offending line text — it renders pre-scrub in the toast.
                self.notify(f"{skipped} region line(s) skipped")
            # Posted straight to the app's queue (not bubbled) so the
            # immediately following dismiss can never drop it.
            self.app.post_message(
                self.GenerateRequested(context_bytes, regions)
            )
            self.dismiss(None)


@dataclass(frozen=True)
class ConfirmWriteResult:
    """Outcome of :class:`ConfirmWriteScreen` (US-019, Option C).

    Carries the confirm/cancel decision AND the selected S19 record width, so the
    width chosen on the modal reaches ``OperationsScreen._on_confirm_write`` — the
    consumer runs after the modal is dismissed and cannot read the modal's own
    state, so the width must ride the dismiss result.

    Attributes:
        confirmed (bool): ``True`` only when ``Confirm`` was pressed.
        bytes_per_line (int): The chosen data-record width, 16 or 32 (default 32).
    """

    confirmed: bool
    bytes_per_line: int = 32


class ConfirmWriteScreen(ModalScreen[Optional[ConfirmWriteResult]]):
    """Two-stage write confirmation modal for the CRC inject path (I5b).

    Summary:
        A Confirm / Cancel modal shown before the CRC write emits a modified S19
        into the work area (stage 2 of the two-stage confirmation — stage 1 is the
        ``Write CRC`` button, enabled only after a real check). It also hosts a
        record-width selector (US-019) the operator can cycle over ``(32, 16)``.
        It dismisses with a :class:`ConfirmWriteResult` carrying ``confirmed``
        (``True`` only on ``Confirm``) AND the selected ``bytes_per_line``; any
        other dismissal yields ``None`` so the caller performs NO write. Styling
        reuses the shared Calm Dark ``.modal-dialog`` token classes.

    Args:
        None: the message text is a fixed class constant; the width selector
            defaults to 32 (the prior fixed behaviour).

    Returns:
        Optional[ConfirmWriteResult]: the decision + chosen width on Confirm /
        Cancel; ``None`` on an Escape/click-outside dismissal.

    Data Flow:
        - Pushed by :meth:`OperationsScreen._on_write_pressed` with a callback;
          the callback dispatches the write worker only when ``confirmed`` is
          ``True``, threading ``bytes_per_line`` into the writer.

    Dependencies:
        Used by:
            - s19_app.tui.screens.OperationsScreen._on_write_pressed
            - tests/test_tui_crc_surface.py (TC-124, TC-125, US-019 AT/TC)

    Example:
        >>> screen = ConfirmWriteScreen()  # doctest: +SKIP
    """

    CONFIRM_TEXT = (
        "Write the computed CRC(s) into a new modified S19 under the work area?"
    )
    #: Operator-cyclable S19 record widths (US-019); the default (first) is 32,
    #: preserving the prior fixed contract. Mirrors the Patch Editor's
    #: ``SAVEBACK_WIDTHS`` (screens_directionb.py).
    CRC_WIDTHS = (32, 16)

    def __init__(self) -> None:
        super().__init__()
        #: The currently-selected save width; cycled by ``#confirm_write_width``
        #: and carried on the ``ConfirmWriteResult`` (US-019 / LLR-019.1).
        self._crc_saveback_width = self.CRC_WIDTHS[0]

    def compose(self) -> ComposeResult:
        yield Container(
            Label(self.CONFIRM_TEXT, classes="modal-title"),
            Container(
                Button(
                    f"Width: {self._crc_saveback_width} bytes/line",
                    id="confirm_write_width",
                ),
                Button("Confirm", id="confirm_write_ok", classes="modal-confirm"),
                Button("Cancel", id="confirm_write_cancel"),
                id="confirm_write_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm_write_width":
            # Selector state only — cycle the record width and relabel; no
            # dismiss (the Patch Editor #patch_saveback_width_button idiom).
            index = self.CRC_WIDTHS.index(self._crc_saveback_width)
            self._crc_saveback_width = self.CRC_WIDTHS[
                (index + 1) % len(self.CRC_WIDTHS)
            ]
            event.button.label = f"Width: {self._crc_saveback_width} bytes/line"
            return
        if event.button.id == "confirm_write_ok":
            logger.info(
                "ConfirmWriteScreen confirmed (width=%d).",
                self._crc_saveback_width,
            )
            self.dismiss(ConfirmWriteResult(True, self._crc_saveback_width))
            return
        if event.button.id == "confirm_write_cancel":
            logger.info("ConfirmWriteScreen cancelled.")
            self.dismiss(ConfirmWriteResult(False, self._crc_saveback_width))


class OperationsScreen(ModalScreen[None]):
    """Operations modal: select a registered operation, execute, view result.

    Summary:
        Lists the registered operations (batch-08 HLR-004 / LLR-004.1) in a
        ``ListView`` following the ``SelectVariantScreen`` pattern: the
        caller supplies pre-computed ``(operation_id, title)`` pairs in
        registry order and the selection resolves by list index, never by
        parsing label text back. Pressing ``Execute`` resolves the selected
        id through the ``operation_service.operation_resolver`` seam
        (LLR-004.2) inside a narrow ``except KeyError`` and runs the resolved
        operation's ``.execute`` OUTSIDE that catch (M-3 / LLR-005.2 — the
        catch covers only the registry miss, not execution) synchronously
        on the UI thread (LLR-004.4 — placeholders do no I/O and no parsing),
        then presents the ``OperationResult``'s ``status`` and ``notes`` in
        ``#operation_result_status`` plus a hex render of
        ``result.output.mem_map`` in ``#operation_result_hex`` produced with
        the LLR-004.3 pinned ``render_hex_view_text`` argument tuple.
        Styling reuses the shared Calm Dark ``.modal-dialog`` token classes.

    Args:
        options (List[Tuple[str, str]]): Pre-computed ``(operation_id,
            title)`` pairs in registry order (the LLR-004.1 caller-supplies-
            options contract — enumeration happens in the app via
            ``list_operation_ids``, not here).
        loaded (LoadedFile): The currently loaded image snapshot the
            selected operation executes against (the app guards against
            pushing this screen with no file loaded).

    Returns:
        None: ``ModalScreen[None]`` — always dismisses with ``None``.

    Data Flow:
        - Execute resolves the row index into ``self.options`` →
          ``operation_service.operation_resolver(operation_id)`` (in a narrow
          ``try``) → resolved op ``.execute(OperationInput.from_loaded(self.loaded), now_fn=None)``
          (out of the ``try``) → status/notes text into
          ``#operation_result_status`` and the pinned hex render into
          ``#operation_result_hex``.
        - A registry ``KeyError`` (LLR-002.3) surfaces as an app status-line
          error, never a crash (LLR-004.2 acceptance criterion); a KeyError
          raised inside ``.execute`` is NOT caught here (M-3, LLR-005.2).

    Dependencies:
        Uses:
            - operation_service.operation_resolver (the LLR-003.1 seam)
              / Operation.execute
            - render_hex_view_text / MAX_HEX_ROWS
        Used by:
            - s19_app.tui.app.S19TuiApp.action_operations_view

    Example:
        >>> screen = OperationsScreen([("crc", "CRC")], loaded)  # doctest: +SKIP
    """

    #: Registry id of the CRC operation — the only operation that takes a
    #: ``CrcConfig`` and renders per-region rows, so it is the only one whose
    #: editable config TextArea is shown (LLR-004.2). Other operations keep
    #: the synchronous, config-less behavior unchanged.
    CRC_OPERATION_ID: str = "crc"

    #: Status text for a CRC run with no usable config (F-L1): a parse error
    #: or empty editor must NOT read like a passed check.
    NO_CONFIG_TEXT = "CRC config error - no check was run:"

    #: Status prefix for the write path when the re-read image drifts from the
    #: injected one (F-L1): a mismatch must NOT read like a clean write.
    VERIFY_MISMATCH_TEXT = "VERIFY MISMATCH - the written image did not verify:"

    #: Status prefix when no file was written (containment / emit / write
    #: fault, F-L1): a failure must NOT read like a clean write.
    WRITE_FAILED_TEXT = "WRITE FAILED - no file was written:"

    def __init__(self, options: List[Tuple[str, str]], loaded: LoadedFile) -> None:
        super().__init__()
        self.options = options
        self.loaded = loaded
        #: Monotonic dispatch token (F1). Every Execute press bumps it; the CRC
        #: worker captures the value at dispatch and ``_present_result`` only
        #: lands a result whose token still matches. A thread worker cannot be
        #: interrupted mid-run, so this is the safety net that guarantees a
        #: stale (superseded or error-branch-bypassed) worker can never
        #: overwrite the current surface — cancellation alone cannot, since the
        #: running thread still reaches ``call_from_thread``.
        self._crc_dispatch_token = 0
        #: Independent dispatch token for the CRC WRITE path (I5b), mirroring
        #: ``_crc_dispatch_token``. Bumped on every write dispatch AND on the
        #: decline / config-error write paths so a stale write worker (one a
        #: later decline or re-check superseded) cannot repaint the surface
        #: after it lands via ``call_from_thread``.
        self._crc_write_token = 0
        #: The last check result's per-region payload, captured by
        #: :meth:`_present_result`. Non-``None`` only after a real check ran
        #: (config-supplied, no parse error); gates the ``Write CRC`` button.
        self._last_crc_regions: Optional[List[CrcRegionResult]] = None

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Operations:", classes="modal-title"),
            ListView(
                *[
                    ListItem(Label(f"{operation_id} - {title}"))
                    for operation_id, title in self.options
                ],
                id="operations_list",
            ),
            Label("CRC config (editable JSON):", id="operation_config_label"),
            Input(
                placeholder="config file path (.json)",
                id="operation_config_path",
            ),
            Button("Load config", id="operation_config_load"),
            CappedTextArea(DUMMY_CONFIG_TEXT, id="operation_config"),
            Static("", id="operation_result_status", markup=False),
            ScrollableContainer(
                Static("", id="operation_result_hex"),
                id="operation_result_hex_scroll",
            ),
            Container(
                Button("Execute", id="operations_execute", classes="modal-confirm"),
                Button("Write CRC", id="operations_write", disabled=True),
                Button("Close", id="operations_close"),
                id="operations_buttons",
                classes="modal-buttons",
            ),
            id="operations_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        list_view = self.query_one("#operations_list", ListView)
        if self.options:
            list_view.index = 0
        self._sync_config_visibility()
        list_view.focus()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        """
        Summary:
            Show the editable CRC config surface only while the CRC row is
            highlighted (LLR-004.2): non-CRC operations take no config, so
            their config editor is hidden to keep their behavior unchanged.

        Args:
            event (ListView.Highlighted): The highlight-change event from the
                operations list.

        Returns:
            None

        Data Flow:
            - Re-derive visibility from the current highlighted index via
              :meth:`_sync_config_visibility`.

        Dependencies:
            Used by:
                - the Textual message pump (highlight changes)
        """
        if event.list_view.id == "operations_list":
            self._sync_config_visibility()

    def _selected_operation_id(self) -> Optional[str]:
        """
        Summary:
            Resolve the highlighted operations-list row index into its
            ``operation_id`` (no label-text parsing), or ``None`` when there
            is no valid selection.

        Args:
            None

        Returns:
            Optional[str]: The highlighted operation id, or ``None``.

        Data Flow:
            - ``ListView.index`` → ``self.options[index][0]``.

        Dependencies:
            Used by:
                - _sync_config_visibility / _execute_selected
        """
        index = self.query_one("#operations_list", ListView).index
        if index is None or not (0 <= index < len(self.options)):
            return None
        return self.options[index][0]

    def _sync_config_visibility(self) -> None:
        """
        Summary:
            Display the CRC config label + editor iff the CRC operation is
            highlighted; hide them for every other operation (LLR-004.2).

        Args:
            None

        Returns:
            None

        Data Flow:
            - ``_selected_operation_id() == CRC_OPERATION_ID`` toggles the
              ``display`` style of ``#operation_config_label``,
              ``#operation_config_path``, ``#operation_config_load`` and
              ``#operation_config`` (the config-load controls share the CRC
              row's visibility, LLR-013.1).

        Dependencies:
            Used by:
                - on_mount / on_list_view_highlighted
        """
        is_crc = self._selected_operation_id() == self.CRC_OPERATION_ID
        self.query_one("#operation_config_label", Label).display = is_crc
        self.query_one("#operation_config_path", Input).display = is_crc
        self.query_one("#operation_config_load", Button).display = is_crc
        self.query_one("#operation_config", TextArea).display = is_crc
        # The Write CRC button is meaningful only for the CRC op, and only
        # after a real check landed regions. Hide it entirely off the CRC row;
        # on the CRC row it stays disabled until a check enables it.
        write_button = self.query_one("#operations_write", Button)
        write_button.display = is_crc
        if not is_crc:
            write_button.disabled = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "operations_close":
            logger.info("OperationsScreen dismissed by close.")
            self.dismiss(None)
            return
        if event.button.id == "operations_execute":
            self._execute_selected()
            return
        if event.button.id == "operation_config_load":
            self._load_config_from_path()
            return
        if event.button.id == "operations_write":
            self._on_write_pressed()

    def _load_config_from_path(self) -> None:
        """
        Summary:
            Load the CRC config file named in ``#operation_config_path`` into
            the editable ``#operation_config`` ``TextArea`` as RAW TEXT
            (LLR-013.2 / LLR-013.3). On success the editor is the single source
            of truth: the load NEVER parses, validates, or runs the CRC check —
            the run still parses the editor text on Execute. On any fault
            (empty / unresolvable / over-cap / unreadable) the collected error
            is surfaced on ``#operation_result_status`` and the editor is left
            unchanged (collect-don't-abort).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Read ``#operation_config_path`` ``.value``; an empty path surfaces
              a message and returns without touching the editor.
            - Resolve + size-cap + read via
              ``crc_config.read_crc_config_text(path, self.app.base_dir)``.
            - On ``(None, [error])`` surface the error on
              ``#operation_result_status`` and leave the editor unchanged.
            - On ``(raw_text, [])`` replace ``#operation_config`` ``.text`` with
              the raw text and run no check.

        Dependencies:
            Uses:
                - crc_config.read_crc_config_text (resolve + size-cap + read)
            Used by:
                - on_button_pressed (Load config button)
        """
        path_text = self.query_one("#operation_config_path", Input).value.strip()
        status = self.query_one("#operation_result_status", Static)
        if not path_text:
            status.update("CRC config load: enter a config file path first.")
            return

        raw_text, errors = read_crc_config_text(path_text, self.app.base_dir)
        if errors:
            logger.info("OperationsScreen CRC config load error: %s", errors)
            status.update("\n".join(["CRC config load error:", *errors]))
            return

        assert raw_text is not None  # no errors ⇒ raw text present
        self.query_one("#operation_config", TextArea).text = raw_text
        status.update(f"Loaded CRC config from {path_text}")

    def _execute_selected(self) -> None:
        """
        Summary:
            Execute the highlighted operation through the ``run_operation``
            service seam and present the result (LLR-004.2 / LLR-004.3) —
            synchronously, on the UI thread (LLR-004.4).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Resolve the ``ListView`` index into ``self.options`` (no
              label-text parsing); bail silently on no selection.
            - Resolve the id through ``operation_service.operation_resolver``
              inside a narrow ``try``/``except KeyError`` (a registry miss
              becomes a status line); call the resolved operation's
              ``.execute(OperationInput.from_loaded(self.loaded), now_fn=None)`` OUTSIDE that ``try`` so
              an execute-internal ``KeyError`` is NOT masked (M-3, LLR-005.2).
            - ``status`` + ``notes`` → ``#operation_result_status``; the
              LLR-004.3 PINNED render call
              ``render_hex_view_text(result.output.mem_map,
              focus_address=None, row_bases=None, highlight=None,
              mac_highlight_addresses=None, max_rows=MAX_HEX_ROWS)`` →
              ``#operation_result_hex``.
            - A registry ``KeyError`` becomes an app status-line message
              (LLR-004.2 acceptance criterion), never a crash.

        Dependencies:
            Uses:
                - operation_service.operation_resolver / Operation.execute
                - render_hex_view_text / MAX_HEX_ROWS
            Used by:
                - on_button_pressed (Execute button)
        """
        operation_id = self._selected_operation_id()
        if operation_id is None:
            return
        logger.info("OperationsScreen executing operation: %s", operation_id)
        # M-3 (LLR-005.2): the KeyError catch guards ONLY the registry
        # resolution (operation_resolver raises KeyError on a miss). Execute
        # runs OUTSIDE the try so a KeyError from inside the operation's own
        # logic propagates rather than being misreported as "unknown operation".
        try:
            operation = operation_service.operation_resolver(operation_id)
        except KeyError as exc:
            logger.warning("OperationsScreen unknown operation id: %s", exc)
            self.app.set_status(f"Operations error: unknown operation {operation_id}")
            return
        op_input = OperationInput.from_loaded(self.loaded)
        if operation_id == self.CRC_OPERATION_ID:
            config, issues = parse_crc_config(
                self.query_one("#operation_config", TextArea).text
            )
            if issues:
                # F-L1: a config/parse error must NOT look like a passed
                # check — surface the error, render no per-region rows and no
                # hex, and run no computation (LLR-004.2 config-error path).
                #
                # F1: bump the dispatch token and cancel the in-flight CRC
                # worker group BEFORE painting the error. The token bump is the
                # safety net (a still-running thread worker reaches
                # ``call_from_thread`` even after cancel, but its captured token
                # is now stale so ``_present_result`` drops it); cancel_group
                # releases the worker slot promptly. Without this, a prior valid
                # run could complete after the error paint and overwrite it with
                # a stale "status: ok" + MATCH surface.
                self._crc_dispatch_token += 1
                self._crc_write_token += 1
                self.workers.cancel_group(self, "crc_operation")
                self.workers.cancel_group(self, "crc_write")
                self._last_crc_regions = None
                self.query_one("#operations_write", Button).disabled = True
                logger.info("OperationsScreen CRC config error: %s", issues)
                self.query_one("#operation_result_status", Static).update(
                    "\n".join([self.NO_CONFIG_TEXT, *issues])
                )
                self.query_one("#operation_result_hex", Static).update("")
                return
            # R-6 (LLR-002.3): the real CRC execute runs on a Textual
            # thread-worker, not synchronously on the UI thread. Bump the
            # dispatch token so this run's result is the only one that can land
            # (F1: supersedes any prior in-flight worker).
            self._crc_dispatch_token += 1
            self._run_crc_worker(operation, op_input, config, self._crc_dispatch_token)
            return
        # Non-CRC operations stay on the synchronous, config-less path
        # (placeholders do no I/O and no parsing, LLR-004.4).
        result = operation.execute(op_input, now_fn=None)
        self._present_result(result)

    @work(thread=True, exclusive=True, group="crc_operation")
    def _run_crc_worker(
        self,
        operation: "Operation",
        op_input: OperationInput,
        config: Optional["CrcConfig"],
        token: int,
    ) -> None:
        """
        Summary:
            Off-thread CRC execute worker (R-6 / LLR-002.3): run the resolved
            operation's ``execute`` with the parsed ``CrcConfig`` on a Textual
            thread-worker — never on the UI thread — and marshal the
            :class:`OperationResult` back to the UI thread via
            ``call_from_thread`` so the per-region rows render on the main
            thread (the ``app.py:1599`` ``execute_scope`` precedent).

        Args:
            operation (Operation): The resolved CRC ``Operation`` (annotated
                under ``TYPE_CHECKING`` only — the ABC is never imported at
                runtime into this UI module; only its ``execute`` is called).
            op_input (OperationInput): The neutral input built from
                ``self.loaded``.
            config (Optional[CrcConfig]): The parsed ``CrcConfig`` (validated
                non-error in the caller).
            token (int): The dispatch token captured at Execute (F1).
                :meth:`_present_result` lands this result only if the token
                still matches ``self._crc_dispatch_token`` — a superseded or
                error-branch-bypassed run carries a stale token and is dropped.

        Returns:
            None

        Data Flow:
            - ``operation.execute(op_input, now_fn=None, config=config)`` runs
              on the worker thread; the result is handed to
              :meth:`_present_result` on the UI thread via
              ``call_from_thread`` together with ``token`` so a stale run is
              dropped. A worker-side crash surfaces as one status line, never
              an unhandled worker exception.

        Dependencies:
            Uses:
                - call_from_thread / _present_result
            Used by:
                - _execute_selected (CRC path)
        """
        try:
            result = operation.execute(op_input, now_fn=None, config=config)
        except Exception as exc:  # noqa: BLE001 - surfaced, never swallowed
            logger.exception("CRC operation worker failed: %s", exc)
            self.app.call_from_thread(
                self.app.set_status,
                f"CRC operation failed: {type(exc).__name__}: {exc}",
            )
            return
        self.app.call_from_thread(self._present_result, result, token)

    def _present_result(
        self, result: OperationResult, token: Optional[int] = None
    ) -> None:
        """
        Summary:
            Render an :class:`OperationResult` into the result surface: the
            status + notes into ``#operation_result_status`` (followed by one
            per-region row per ``crc_regions`` entry when present, LLR-002.4),
            and the LLR-004.3 pinned hex render of ``result.output.mem_map``
            into ``#operation_result_hex``. Runs on the UI thread.

        Args:
            result (OperationResult): The result to present (from the CRC
                worker or the synchronous non-CRC path).
            token (Optional[int]): The CRC worker's captured dispatch token
                (F1). When supplied, the result is dropped unless it still
                matches ``self._crc_dispatch_token`` — this is what makes a
                stale worker (one the config-error branch bypassed-cancel, or a
                superseded earlier run) unable to overwrite the current surface,
                since a thread worker cannot be interrupted once running. The
                synchronous non-CRC path passes ``None`` (always present — it
                runs inline on the UI thread and can never be stale).

        Returns:
            None

        Data Flow:
            - Token-stale CRC results are dropped before any widget write.
            - ``status`` + ``notes`` (+ per-region rows from
              :meth:`_crc_region_lines`) → ``#operation_result_status``; the
              pinned ``render_hex_view_text`` tuple → ``#operation_result_hex``.

        Dependencies:
            Uses:
                - _crc_region_lines / render_hex_view_text / MAX_HEX_ROWS
            Used by:
                - _execute_selected (non-CRC) / _run_crc_worker (CRC)
        """
        if token is not None and token != self._crc_dispatch_token:
            # F1: a superseded / bypassed-cancel CRC worker landed late. Drop
            # it so it cannot overwrite the current (error or newer) surface.
            logger.info(
                "OperationsScreen dropping stale CRC result (token %s != %s)",
                token,
                self._crc_dispatch_token,
            )
            return
        status_lines = [f"status: {result.status}"]
        status_lines.extend(result.notes)
        status_lines.extend(self._crc_region_lines(result.crc_regions))
        self.query_one("#operation_result_status", Static).update(
            "\n".join(status_lines)
        )
        rendered = render_hex_view_text(
            result.output.mem_map,
            focus_address=None,
            row_bases=None,
            highlight=None,
            mac_highlight_addresses=None,
            max_rows=MAX_HEX_ROWS,
        )
        self.query_one("#operation_result_hex", Static).update(rendered)
        # Enable the Write CRC button ONLY after a real check landed regions
        # (config supplied, no parse error). A non-CRC op or no-config run
        # carries ``crc_regions is None`` and leaves the button disabled, so
        # the write path is unreachable without a prior check (F-L1 / two-stage
        # confirmation stage 1).
        if result.crc_regions is not None:
            self._last_crc_regions = result.crc_regions
            self.query_one("#operations_write", Button).disabled = False
        else:
            self._last_crc_regions = None
            self.query_one("#operations_write", Button).disabled = True

    @staticmethod
    def _crc_region_lines(
        crc_regions: Optional[List[CrcRegionResult]],
    ) -> List[str]:
        """
        Summary:
            Build one human-readable row per CRC region (LLR-002.4): output
            address, computed CRC, stored value, and a clear match/mismatch
            verdict. Returns an empty list when there is no CRC payload (a
            non-CRC op, or a config-error run handled upstream), so the
            result surface only shows verdict rows for an actual check
            (F-L1: no payload never reads as "matched").

        Args:
            crc_regions (Optional[List[CrcRegionResult]]): The per-region
                check results in config order, or ``None``.

        Returns:
            List[str]: One verdict row per region, or ``[]`` when
            ``crc_regions`` is ``None``.

        Data Flow:
            - Map each :class:`CrcRegionResult` tri-state ``matched`` (True /
              False / None) to ``MATCH`` / ``MISMATCH`` / ``no stored value``.

        Dependencies:
            Used by:
                - _present_result
        """
        if crc_regions is None:
            return []
        lines: List[str] = []
        for region in crc_regions:
            if region.matched is True:
                verdict = "MATCH"
            elif region.matched is False:
                verdict = "MISMATCH"
            else:
                verdict = "no stored value"
            stored = (
                f"0x{region.stored_value:08X}"
                if region.stored_value is not None
                else "(absent)"
            )
            lines.append(
                f"region @ 0x{region.output_address:08X}: "
                f"computed 0x{region.computed_crc:08X}, "
                f"stored {stored} -> {verdict}"
            )
        return lines

    def _on_write_pressed(self) -> None:
        """
        Summary:
            Begin the two-stage CRC write (I5b): push :class:`ConfirmWriteScreen`
            with a callback. The button is only enabled after a real check ran
            (stage 1), so reaching here implies a prior check; the modal is
            stage 2. The callback performs the write ONLY on an explicit
            ``True`` confirmation — ``False`` / ``None`` make no
            :func:`write_crc_image` call and leave the surface unchanged.

        Args:
            None

        Returns:
            None

        Data Flow:
            - ``push_screen(ConfirmWriteScreen(), self._on_confirm_write)`` (the
              app's ``push_screen(Screen, callback)`` idiom, never
              ``push_screen_wait``); the callback re-parses the config and
              dispatches the write worker on confirm.

        Dependencies:
            Uses:
                - ConfirmWriteScreen / _on_confirm_write
            Used by:
                - on_button_pressed (Write CRC button)
        """
        logger.info("OperationsScreen Write CRC pressed - confirming.")
        self.app.push_screen(ConfirmWriteScreen(), self._on_confirm_write)

    def _on_confirm_write(self, result: Optional["ConfirmWriteResult"]) -> None:
        """
        Summary:
            Handle the :class:`ConfirmWriteScreen` outcome (I5b stage 2). On a
            declined / dismissed modal (``False`` / ``None``) NOTHING is written
            and the surface is unchanged. On ``True`` the config ``TextArea`` is
            RE-PARSED (honoring any edits made between check and write); a parse
            error surfaces the config error and writes nothing (F-L1), while a
            clean parse dispatches the off-thread write worker under a fresh
            write token.

        Args:
            result (Optional[ConfirmWriteResult]): The modal result — its
                ``confirmed`` flag (``True`` confirm, else cancel) and the
                selected ``bytes_per_line`` (16/32) threaded into the writer;
                ``None`` on an Escape/click-outside dismissal.

        Returns:
            None

        Data Flow:
            - ``confirmed is not True`` → no write, return.
            - Else :func:`parse_crc_config` on the editor text; issues →
              bump tokens, cancel groups, paint the config error, disable Write,
              no write. Clean parse → bump :attr:`_crc_write_token` and dispatch
              :meth:`_run_crc_write_worker`.

        Dependencies:
            Uses:
                - parse_crc_config / _run_crc_write_worker / OperationInput
            Used by:
                - _on_write_pressed (modal callback)
        """
        if result is None or not result.confirmed:
            logger.info("OperationsScreen write declined - no file written.")
            return
        config, issues = parse_crc_config(
            self.query_one("#operation_config", TextArea).text
        )
        if issues or config is None:
            # F-L1: an edit between check and write that broke the config must
            # not silently write a stale CRC — surface the error and write
            # nothing, mirroring the check-path config-error branch.
            self._crc_dispatch_token += 1
            self._crc_write_token += 1
            self.workers.cancel_group(self, "crc_operation")
            self.workers.cancel_group(self, "crc_write")
            self._last_crc_regions = None
            self.query_one("#operations_write", Button).disabled = True
            logger.info("OperationsScreen write config error: %s", issues)
            self.query_one("#operation_result_status", Static).update(
                "\n".join([self.NO_CONFIG_TEXT, *issues])
            )
            self.query_one("#operation_result_hex", Static).update("")
            return
        op_input = OperationInput.from_loaded(self.loaded)
        self._crc_write_token += 1
        self._run_crc_write_worker(
            op_input, config, self._crc_write_token, result.bytes_per_line
        )

    @work(thread=True, exclusive=True, group="crc_write")
    def _run_crc_write_worker(
        self,
        op_input: OperationInput,
        config: "CrcConfig",
        token: int,
        bytes_per_line: int = 32,
    ) -> None:
        """
        Summary:
            Off-thread CRC write worker (I5b): run :func:`write_crc_image`
            against the work area on a Textual thread-worker — never the UI
            thread — and marshal the :class:`CrcWriteResult` back to the UI
            thread via ``call_from_thread`` so the write outcome renders on the
            main thread (the ``_run_crc_worker`` precedent).

        Args:
            op_input (OperationInput): The neutral input built from
                ``self.loaded``; only ``mem_map`` / ``ranges`` are read.
            config (CrcConfig): The parsed config re-validated at confirm time.
            token (int): The write dispatch token captured at confirm.
                :meth:`_present_write_result` lands this result only if the
                token still matches ``self._crc_write_token`` — a superseded
                run (a later decline / config error) carries a stale token and
                is dropped.

        Returns:
            None

        Data Flow:
            - ``write_crc_image(op_input, config, workarea_base=self.app.base_dir)``
              runs on the worker thread; the :class:`CrcWriteResult` is handed
              to :meth:`_present_write_result` on the UI thread via
              ``call_from_thread`` with ``token``. A worker-side crash surfaces
              as one status line, never an unhandled worker exception.

        Dependencies:
            Uses:
                - write_crc_image / call_from_thread / _present_write_result
            Used by:
                - _on_confirm_write (confirmed write path)
        """
        try:
            result = write_crc_image(
                op_input,
                config,
                workarea_base=self.app.base_dir,
                bytes_per_line=bytes_per_line,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced, never swallowed
            logger.exception("CRC write worker failed: %s", exc)
            self.app.call_from_thread(
                self.app.set_status,
                f"CRC write failed: {type(exc).__name__}: {exc}",
            )
            return
        self.app.call_from_thread(self._present_write_result, result, token)

    def _present_write_result(
        self, result: CrcWriteResult, token: int
    ) -> None:
        """
        Summary:
            Render a :class:`CrcWriteResult` into the result surface (I5b),
            distinguishing the three outcomes so none of them reads as a clean
            pass (F-L1): a clean ``verified`` write shows the emitted path +
            verdict and the written regions; a ``mismatch`` prepends a clear
            ``VERIFY MISMATCH`` line; a no-file write (``written_path is None``
            or findings present) prepends ``WRITE FAILED`` and the finding.
            Runs on the UI thread; a stale-token result is dropped first.

        Args:
            result (CrcWriteResult): The headless write outcome.
            token (int): The worker's captured write token; the result is
                dropped unless it still matches ``self._crc_write_token`` so a
                superseded write worker cannot repaint the surface.

        Returns:
            None

        Data Flow:
            - Token-stale results are dropped before any widget write.
            - Build the status prefix from the outcome (failed / mismatch /
              verified), append a path note and the written per-region rows,
              and render the injected ``mem_map`` hex via the pinned
              ``render_hex_view_text`` tuple.

        Dependencies:
            Uses:
                - _crc_region_lines / render_hex_view_text / MAX_HEX_ROWS
            Used by:
                - _run_crc_write_worker (via call_from_thread)
        """
        if token != self._crc_write_token:
            logger.info(
                "OperationsScreen dropping stale CRC write result "
                "(token %s != %s)",
                token,
                self._crc_write_token,
            )
            return

        status_lines: List[str] = ["status: ok"]
        write_failed = result.written_path is None or bool(result.findings)
        if write_failed:
            status_lines = [self.WRITE_FAILED_TEXT, *result.findings]
        elif result.verify_status != STATUS_VERIFIED:
            status_lines = [
                self.VERIFY_MISMATCH_TEXT,
                f"wrote {result.written_path} but it did not verify "
                f"(verify status: {result.verify_status})",
            ]
        else:
            status_lines.append(f"wrote {result.written_path} (verified)")
        # F1: on a WRITE FAILED the pre-write CHECK verdict (MATCH/MISMATCH) is
        # the last meaningful per-region state. On a written result the per-region
        # `matched`/`stored_value` are the now-STALE pre-write check values
        # (`inject_crcs` only flips `written=True`), so rendering them as
        # MATCH/MISMATCH would print a stale "MISMATCH" beside a "(verified)"
        # write — instead describe what was WRITTEN.
        if write_failed:
            status_lines.extend(self._crc_region_lines(result.crc_regions))
        else:
            # batch-32 (LLR-GRP-001.12): the write width comes from the
            # result field — legacy rows keep rendering "(4 LE bytes)".
            status_lines.extend(
                f"region @ 0x{region.output_address:08X}: wrote "
                f"0x{region.computed_crc:08X} ({region.output_bytes} LE bytes)"
                for region in result.crc_regions
            )
        self.query_one("#operation_result_status", Static).update(
            "\n".join(status_lines)
        )

        if result.written_path is None:
            # No file written: leave the prior check's hex render in place
            # rather than rendering a misleading "written" image.
            return
        # Render the injected image (the bytes actually written) so the hex
        # surface reflects the write outcome, not the pre-inject check image.
        op_input = OperationInput.from_loaded(self.loaded)
        injected_mem, _ranges, _written = inject_crcs(op_input, result.crc_regions)
        rendered = render_hex_view_text(
            injected_mem,
            focus_address=None,
            row_bases=None,
            highlight=None,
            mac_highlight_addresses=None,
            max_rows=MAX_HEX_ROWS,
        )
        self.query_one("#operation_result_hex", Static).update(rendered)
