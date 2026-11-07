from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, List, Literal, Mapping, Optional, Sequence, Tuple

from rich.cells import cell_len
from rich.markup import escape as escape_markup
from rich.table import Table
from rich.text import Text
from textual import events, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, VerticalScroll
from textual.content import Content
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
    OptionList,
    Select,
    SelectionList,
    Static,
    TextArea,
)

from markdown_it import MarkdownIt

from .capped_text_area import CappedTextArea
from .a2l_parameter_picker import (
    A2LParameterPicker,
    _clip_to_cells,
    parse_parameter_list,
)
from .changes.verify import STATUS_VERIFIED
from .color_policy import css_class_for_severity
from ..render.hexview import MAX_HEX_ROWS, render_hex_view_text
from ..utils import safe_text
from .insight_style import DGRAY, GREEN, RED, YELLOW
from .open_folder_chip import OpenFolderChip, titled_header
from .window_help import WindowHelpChip, open_window_help
from .os_clipboard_input import OsClipboardInput, _CLIPBOARD_CAP_CHARS
from .workspace import (
    ExternalImportRefusal,
    import_external_ref,
    sanitize_project_name,
)
from .legend import (
    BAND_GAP_FIELDS,
    COLOUR_SEVERITY,
    LEGEND_EXAMPLES,
    LEGEND_TABLE,
    MAP_KEYS_LINE,
    MAP_REGION_ROW_FIELD_KEY,
    MAP_REGION_ROW_SAMPLE,
    ROLE_CAPTION,
    ROLE_LINE,
    ROLE_SUB,
    ROLE_WARNING_SAMPLE,
    build_band_key_rows,
    build_map_anatomy_samples,
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
from .services.flow_model import (
    BLOCK_A2B,
    BLOCK_CHECK,
    BLOCK_CRC,
    BLOCK_EXTERNAL_STEP,
    BLOCK_PATCH,
    BLOCK_REPORT,
    BLOCK_SOURCE,
    BLOCK_WRITE_OUT,
    CHECK_GATING_ADVISORY,
    CHECK_GATING_BLOCK_OWN,
    EXTERNAL_MODE_MANUAL,
    EXTERNAL_MODE_TERMINAL,
    A2BBlock,
    A2B_INPUT_FLOW,
    CheckBlock,
    CrcBlock,
    ExternalStepBlock,
    Flow,
    FlowBlock,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
    parse_a2b_binding,
)
from .services.entropy_service import ENTROPY_WINDOW_BYTES
from .flow_screens import BrowseRequested
from .services.report_addendum import DeclaredRegion
from .services.report_service import (
    REPORT_CONTEXT_BYTES_DEFAULT,
    REPORT_MAX_TOTAL_BYTES,
)

if TYPE_CHECKING:
    from .operations.crc_config import CrcConfig
    from .services import project_gather_service
    from .services.variant_execution_service import LoadAnnouncement, LoadProblem
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


def _hardened_markdown_parser() -> MarkdownIt:
    """Build the report viewer's Markdown parser with its risky extensions OFF.

    Summary:
        ``textual.widgets.Markdown`` defaults to ``MarkdownIt("gfm-like")``, which
        enables **linkify** and **raw HTML**. A report embeds file-derived text
        (block summaries echoing a change-doc name, finding messages, filenames),
        so under the default parser a bare ``http://…`` in a hostile filename
        becomes a live link and ``~~x~~`` strikes a ledger row through — a
        deception primitive in a document meant to be an audit record.

        This factory keeps tables (the reports are table-heavy) but turns
        ``linkify`` and ``html`` off, so no live link or raw-HTML node can be
        produced from document text no matter what reaches the renderer. It is
        the ENFORCING half of the batch-60 markup contract (§6.5 AMD-13); the
        composer's ``markdown_safety.md_safe`` is the best-effort half that
        travels with the ``.md`` file once it leaves the app.

        It hardens project reports too — and since batch-62 their generator
        escapes file-derived text as well, so both halves are now present for
        both report kinds. The two cannot drift silently: this half is pinned by
        ``tests/test_flow_report_ui.py`` (``linkify is False``) and the composer
        half by the payload set's re-derivation from the live parsers.

    Returns:
        MarkdownIt: A ``gfm-like`` parser with ``linkify`` and ``html`` disabled.

    Dependencies:
        Used by:
            - ReportViewerScreen.compose (the ``#report_markdown`` widget)
    """
    # Options are passed at construction: `.configure({"options": …})` REPLACES
    # the whole options mapping and would drop defaults such as ``maxNesting``.
    return MarkdownIt("gfm-like", {"linkify": False, "html": False})


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
        parent_folder (str): The work area (the dialog sets it; LLR-175.2a).
        project_name (str): New project folder name (sanitized downstream).
        batch (tuple[str, ...]): Project-wide change/check files as
            project-relative path strings. Empty ⇒ no project-wide files.
        assignments (Mapping[str, tuple[str, ...]]): Per-variant files keyed by
            ``variant_id`` (the workspace stem, or full filename on a stem
            collision — D-KEY); each value is project-relative path strings.
            Empty ⇒ no per-variant assignments.
        plan (Optional[project_gather_service.SavePlan]): The plan the Save
            dialog painted and confirmed; ``None`` for a payload built without
            the dialog (LLR-175.4l). Not part of equality.

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
    plan: Optional[project_gather_service.SavePlan] = field(default=None, compare=False)


WhereKind = Literal["info", "refusal"]
WhereLine = tuple[str, WhereKind]


@dataclass(frozen=True)
class SavePreview:
    """The app → dialog value for one typed name (HLR-175).

    Summary:
        Built only by the app (``_save_dialog_preview`` and the confirm
        step); the dialog paints it and never builds one (SC-1, SC-2).
        Frozen and equal by value, so the dialog holds the very object the
        app returned and can compare it against a fresh one.

    Args:
        where (tuple[WhereLine, ...]): The ``#save_where`` lines, in order.
            Each ``(text, kind)`` pair paints one plain line; ``kind`` is
            ``"info"`` for the target line or ``"refusal"`` for a reason.
        rows (tuple[str, ...]): The ``#save_summary`` lines, in order, one
            line each, already composed by the app.
        plan (Optional[project_gather_service.SavePlan]): The plan these rows
            paint; ``None`` when nothing is planned (empty name, name
            refusal).
        refused (bool): ``True`` → Save keeps the dialog open (LLR-175.3f).

    Data Flow:
        - Produced by ``S19TuiApp._save_dialog_preview`` and the confirm
          step; consumed by ``SaveProjectScreen._paint`` (the only reader).
    """

    where: tuple[WhereLine, ...]
    rows: tuple[str, ...]
    plan: Optional[project_gather_service.SavePlan]
    refused: bool


LoadKind = Literal["project", "workarea", "recent", "path"]


@dataclass(frozen=True)
class LoadChoice:
    """A Load-dialog choice: the kind plus its on-disk value or typed text.

    Summary:
        The single dismiss value of the Load dialog (``LoadDialog``). ``value``
        is always ``str``: the on-disk project name, the on-disk work-area
        file name, the recorded recent-path text, or the typed path text.
        There is no runtime check on ``kind``; the dialog and the app router
        trust the producer. Frozen, equal by value, hashable and immutable, so
        a ``LoadChoice`` can key a set or dict and the row object built by the
        app is the very object the dialog dismisses (never one rebuilt from a
        painted label).

    Args:
        kind: One of ``project``, ``workarea``, ``recent`` or ``path``.
        value: The on-disk name / recorded path / typed text (verbatim).

    Dependencies:
        Used by:
            - ``LoadDialog`` (the row choices and the typed-path choice)
            - ``S19TuiApp`` (``rows`` / ``verdict`` / ``preview`` producers and
              the load router)
    """

    kind: LoadKind
    value: str


LoadRow = tuple[str, str, Optional[LoadChoice]]
PreviewLine = tuple[str, bool]


#: ``(reason, step)`` token pair painted in ``#load_reason`` when a load
#: request has nothing selected (an empty path field, or no highlighted /
#: enabled row).
LOAD_NOTHING_SELECTED = ("nothing selected", "pick a row or type a path")
#: Prefix painted before a marked preview line (U+25CF U+0020).
LOAD_MARK = "● "


class LoadDialog(ModalScreen[Optional[LoadChoice]]):
    """Modal Load dialog: pick a project / work-area / recent row or type a path.

    Summary:
        The single Load entry point that replaces the retired Load-file and
        Load-project screens. In ``mode="path"`` it opens with the path field
        focused and dismisses with a ``LoadChoice("path", typed_text)``; in
        ``mode="list"`` it opens with the row list focused and dismisses with
        the ``LoadChoice`` object the highlighted row holds. The caller (the
        app) supplies three callables: ``rows`` builds the section heading /
        label rows (labels already scrubbed and clipped), ``verdict`` answers
        ``None`` to allow a load or a ``(reason, step)`` pair that keeps the
        dialog open, and ``preview`` returns the ``(text, marked)`` lines
        shown beside the list. The dialog paints nothing from disk except
        through those callables, so it needs no filesystem or workspace import.

        Markup safety: the list is an ``OptionList(markup=False)`` fed plain
        ``str`` prompts, and the preview body is a ``markup=False`` ``Static``
        updated with a ``rich.text.Text``, so no label or path is ever parsed
        as console markup.

    Args:
        mode: ``"path"`` to focus the path field first, ``"list"`` to focus
            the row list first. Also the initial load source.
        highlight: Project name to highlight on open (list mode), or ``None``.
        rows: Called once on mount; returns the section heading / label rows.
        verdict: Called once per load request with the chosen ``LoadChoice``;
            ``None`` allows the load, a ``(reason, step)`` pair is painted in
            ``#load_reason`` and the dialog stays open.
        preview: Called for every list highlight; returns the lines to paint.

    Returns:
        Optional[LoadChoice]: the choice on Load, or ``None`` on Cancel /
        Escape (``ModalScreen[Optional[LoadChoice]]``).

    Data Flow:
        - ``on_mount`` fills ``_rows``, populates and disables ``#load_list``
          rows whose choice is ``None``, sets the initial highlight and focus,
          then applies the stacked / side-by-side pane layout.
        - ``on_key`` intercepts ``escape``, ``enter`` (list / preview) and
          printable keys redirected from the list into ``#load_path``.
        - ``action_load`` resolves the source (row or typed text), runs
          ``verdict``, and either paints ``#load_reason`` or dismisses.

    Dependencies:
        Uses:
            - ``OptionList`` / ``OsClipboardInput`` / ``Container`` /
              ``Horizontal`` / ``VerticalScroll`` / ``Label`` / ``Static`` /
              ``Button`` / ``Binding``
            - :class:`LoadChoice`, :data:`LOAD_NOTHING_SELECTED`,
              :data:`LOAD_MARK`
        Used by:
            - ``S19TuiApp`` (pushed and routed via the Load choice handler)

    Example:
        >>> dialog = LoadDialog(  # doctest: +SKIP
        ...     mode="list",
        ...     highlight=None,
        ...     rows=lambda: [],
        ...     verdict=lambda c: None,
        ...     preview=lambda c: [],
        ... )
    """

    BINDINGS = [
        Binding("escape", "cancel", show=False),
        Binding("alt+l", "load", show=False, priority=True),
    ]

    def __init__(
        self,
        *,
        mode: Literal["path", "list"],
        highlight: Optional[str],
        rows: Callable[[], list[LoadRow]],
        verdict: Callable[[LoadChoice], Optional[tuple[str, str]]],
        preview: Callable[[LoadChoice], list[PreviewLine]],
    ) -> None:
        super().__init__()
        self._mode = mode
        self._highlight = highlight
        self._rows_fn = rows
        self._verdict = verdict
        self._preview_fn = preview
        self._rows: list[LoadRow] = []
        self._source = mode
        self._dismissed = False

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load", classes="modal-title"),
            Horizontal(
                Container(
                    OsClipboardInput(
                        placeholder=r"C:\path\to\file.s19, .hex, .mac, .a2l, or a project folder",
                        id="load_path",
                        restrict=r"[^\x00-\x1f\x7f]*",
                        max_length=4096,
                    ),
                    OptionList(id="load_list", markup=False),
                    id="load_left",
                ),
                VerticalScroll(
                    Static("", markup=False),
                    id="load_preview",
                ),
                id="load_panes",
            ),
            Static("", id="load_reason", markup=False),
            Container(
                Button("Load (alt+l)", id="load_ok", classes="modal-confirm"),
                Button("Cancel (esc)", id="load_cancel"),
                id="load_buttons",
                classes="modal-buttons",
            ),
            id="load_box",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        """Fill the row list, set the initial highlight and focus, lay the panes.

        Data Flow:
            - ``_rows_fn`` is called exactly once here (never in ``__init__``).
            - Row order is kept exactly as given: no sort, no filter.
            - Rows whose choice is ``None`` (headings and empty / problem
              token lines) are disabled, so they cannot be highlighted by key
              or click and cannot be loaded.
        """
        self._rows = list(self._rows_fn())
        lst = self.query_one("#load_list", OptionList)
        lst.add_options([label for _s, label, _c in self._rows])
        for i, row in enumerate(self._rows):
            if row[2] is None:
                lst.disable_option_at_index(i)
        lst.highlighted = self._initial_index()
        if self._mode == "list":
            self.query_one("#load_list").focus()
        else:
            self.query_one("#load_path").focus()
        self._apply_stack(self.app.size.width)

    def _initial_index(self) -> Optional[int]:
        """
        Summary:
            Return the row to highlight on open. The same rule holds in both
            modes, so a ``mode="path"`` dialog still has a row ready when
            the engineer tabs to the list.

        Returns:
            Optional[int]: The ``#load_list`` index, or ``None`` when no row
            holds a choice.

        Data Flow:
            First match of: a project row whose value equals ``_highlight``;
            else the first project row; else the first row with a choice;
            else ``None``.

        Dependencies:
            Uses:
                - ``self._rows`` / ``self._highlight``
            Used by:
                - ``LoadDialog.on_mount``
        """
        for i, (_s, _label, choice) in enumerate(self._rows):
            if (
                choice is not None
                and choice.kind == "project"
                and choice.value == self._highlight
            ):
                return i
        for i, (_s, _label, choice) in enumerate(self._rows):
            if choice is not None and choice.kind == "project":
                return i
        for i, (_s, _label, choice) in enumerate(self._rows):
            if choice is not None:
                return i
        return None

    def on_key(self, event: events.Key) -> None:
        """
        Summary:
            Intercept keys before the non-priority bindings see them.
            ``escape`` is tested before ``enter`` (A9b-06), so an Escape
            queued ahead of an Enter cancels and the Enter finds the dialog
            already dismissed.

        Args:
            event (events.Key): The key event that reached the dialog.

        Data Flow:
            - ``escape`` cancels from any focus, at the same hop as ``enter``.
            - ``enter`` on ``#load_list`` or ``#load_preview`` loads (this
              stops ``OptionList``'s own ``enter`` → ``OptionSelected``).
            - A printable key with ``#load_list`` focused is redirected into
              ``#load_path``: the field text grows, ``_source`` becomes
              ``"path"`` at once, and the preview clears.
            - All other keys (``up`` / ``down`` / ``home`` / ``end`` /
              ``pageup`` / ``pagedown`` / ``tab``) keep their bindings.

        Dependencies:
            Uses:
                - ``action_cancel`` / ``action_load`` / ``_schedule_preview``
            Used by:
                - Textual key dispatch (every key the dialog receives)
        """
        f = self.focused
        if f is None:
            return
        if event.key == "escape":
            event.stop()
            event.prevent_default()
            self.action_cancel()
            return
        if event.key == "enter" and f.id in ("load_list", "load_preview"):
            event.stop()
            event.prevent_default()
            self.action_load()
            return
        if f.id == "load_list" and event.is_printable:
            event.stop()
            event.prevent_default()
            inp = self.query_one("#load_path", Input)
            inp.value = inp.value + event.character
            inp.cursor_position = len(inp.value)
            self._source = "path"
            self._schedule_preview(None)
            inp.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Route an ``enter`` in ``#load_path`` to ``action_load``."""
        if event.input.id == "load_path":
            event.stop()
            self.action_load()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Route ``#load_ok`` / ``#load_cancel`` to load / cancel."""
        event.stop()
        if event.button.id == "load_ok":
            self.action_load()
        elif event.button.id == "load_cancel":
            self.action_cancel()

    def action_load(self) -> None:
        """
        Summary:
            Resolve the source, run ``verdict``, then dismiss or paint a
            reason. The last-focused source decides the choice (S-f), not
            the widget that holds focus now; a second request after the
            dismiss returns at once (A9b-02).

        Data Flow:
            - The source decides the choice: the highlighted row's ``LoadChoice``
              object when ``_source == "list"``, else ``LoadChoice("path",
              field value)`` with the text verbatim.
            - ``None`` choice (empty field, or no / disabled highlighted row)
              paints ``LOAD_NOTHING_SELECTED`` and returns.
            - A non-``None`` ``verdict`` pair is painted and the dialog stays
              open with the field untouched; only ``None`` dismisses.

        Dependencies:
            Uses:
                - ``_row_choice`` / ``_path_choice`` / ``_verdict`` /
                  ``_say`` / ``_close``
            Used by:
                - ``on_key`` / ``on_input_submitted`` / ``on_button_pressed``
                  / the ``alt+l`` binding
        """
        if self._dismissed:
            return
        choice = self._row_choice() if self._source == "list" else self._path_choice()
        if choice is None:
            self._say(*LOAD_NOTHING_SELECTED)
            return
        pair = self._verdict(choice)
        if pair is not None:
            self._say(*pair)
            return
        self._close(choice)

    def action_cancel(self) -> None:
        """Dismiss with ``None`` — ``escape`` and ``#load_cancel`` mirror here."""
        self._close(None)

    def _row_choice(self) -> Optional[LoadChoice]:
        """Return the highlighted row's choice object, or ``None``."""
        i = self.query_one("#load_list", OptionList).highlighted
        if i is None:
            return None
        return self._rows[i][2]

    def _path_choice(self) -> Optional[LoadChoice]:
        """Return ``LoadChoice("path", field)`` with the text verbatim, or ``None``."""
        t = self.query_one("#load_path", Input).value
        if t.strip() == "":
            return None
        return LoadChoice("path", t)

    def _say(self, reason: str, step: str) -> None:
        """Paint ``reason — step`` into ``#load_reason`` (the only writer)."""
        self.query_one("#load_reason", Static).update(f"{reason} — {step}")

    def _close(self, result: Optional[LoadChoice]) -> None:
        """
        Summary:
            Dismiss once; a second queued close / load request returns at
            once, so two Enters (or Escape then Enter) give one dismiss
            (A9b-02, R2-6).

        Args:
            result (Optional[LoadChoice]): The choice to hand the caller, or
                ``None`` for Cancel / Escape.

        Data Flow:
            - ``_dismissed`` is set before ``dismiss`` runs.

        Dependencies:
            Uses:
                - ``ModalScreen.dismiss``
            Used by:
                - ``action_load`` / ``action_cancel``
        """
        if self._dismissed:
            return
        self._dismissed = True
        self.dismiss(result)

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        """
        Summary:
            Track the last-focused source widget (``#load_list`` vs
            ``#load_path``). Focus on the preview or a button keeps the
            source, so ``#load_ok`` loads what the engineer last chose (S-f).

        Args:
            event (events.DescendantFocus): The focus event of a child widget.

        Data Flow:
            - Focus on the preview or a button changes nothing.
            - A source change updates ``_source`` and asks for the new source's
              preview (the row's choice for the list, none for the path field).

        Dependencies:
            Uses:
                - ``_row_choice`` / ``_schedule_preview``
            Used by:
                - Textual focus dispatch
        """
        if event.widget.id in ("load_list", "load_path"):
            src = "list" if event.widget.id == "load_list" else "path"
            if src != self._source:
                self._source = src
                self._schedule_preview(self._row_choice() if src == "list" else None)

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        """Refresh the preview on every list highlight, while the list is source."""
        if self._source == "list":
            self._schedule_preview(self._row_choice())

    def _schedule_preview(self, choice: Optional[LoadChoice]) -> None:
        """Clear the preview body, then paint ``preview(choice)`` when non-``None``.

        Data Flow:
            - The body is cleared first so no ``●`` of the previous target
              stays visible. ``None`` leaves it empty (the path-field-source
              case). ``preview`` returns the lines synchronously.
        """
        self.query_one("#load_preview Static", Static).update("")
        if choice is None:
            return
        self.show_preview(self._preview_fn(choice))

    def show_preview(self, lines: list[PreviewLine]) -> None:
        """Paint the preview lines, prefixing ``● `` only where ``marked``.

        Args:
            lines: ``(text, marked)`` pairs; the dialog paints the ``● `` mark
                exactly where ``marked`` is ``True`` and never parses the text
                as markup (a ``rich.text.Text`` into a ``markup=False``
                ``Static``).
        """
        body = "\n".join(
            (LOAD_MARK + text) if marked else text for text, marked in lines
        )
        self.query_one("#load_preview Static", Static).update(Text(body))

    def on_resize(self, event: events.Resize) -> None:
        """Re-apply the stacked / side-by-side pane layout on terminal resize."""
        self._apply_stack(event.size.width)

    def _apply_stack(self, width: int) -> None:
        """Set the ``stacked`` class on ``#load_panes`` below 100 columns."""
        self.query_one("#load_panes").set_class(width < 100, "stacked")


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
    #: than on the Confirm button (mirrors the Load dialog).
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


class BulkParameterAddScreen(ModalScreen[Optional[dict]]):
    """Bulk-add modal for A2L parameter names (US-102-04, R-B102-BULK-001..007).

    Summary:
        The popup the Check Editor's ``Add list`` control opens (the picker
        emits ``BulkAddRequested`` and stays presentational — E3 ruling 5).
        A multiline :class:`CappedTextArea` (the SAME capped, OS-clipboard
        paste surface the other five paste sites use — no new ingress, S-01)
        takes the pasted list; ``Include matches`` parses it with
        :func:`parse_parameter_list` and includes exact source matches
        through :meth:`A2LParameterPicker.include_names`. The modal STAYS
        OPEN after an include so the operator can correct a mixed list
        without losing the summary (batch-102 Inc-4 decision); only
        ``Close`` or ``esc`` dismisses.

        The summary is the modal's single feedback region
        (F-B102-BULK-2): ``Included <n> · already included <n> · not found
        <n>``, with `` — first missing: <name>`` when names were missed, or
        exactly ``No listed parameters found.`` when nothing matched.
        Every file-derived surface — the pasted buffer, the missing name —
        reaches the screen as a literal ``Text`` through ``safe_text``
        (R-B102-BULK-006): the summary never parses markup and the missing
        name is scrubbed and clipped to the dialog's available width
        (E3 ruling 2). When the buffer sits at the 64 KiB paste cap it must
        have been truncated on ingress, so the summary carries a second
        line: ``Input truncated at 65536 chars.`` (E3 ruling 8).

        Dismiss contract (E3 ruling 6): ``esc`` and ``Close`` WITHOUT an
        include in this session dismiss ``None`` — no re-apply, no host
        refresh; ``Close`` AFTER a successful include dismisses with the
        last summary dict, so the host repaints its preview/count. The
        modal never logs the pasted content — only counts reach the log
        (E3 ruling 10), and closing never reloads the spec or rebuilds
        the ledger (E3 ruling 9 — the host's dismiss tail only refreshes
        the preview).

    Args:
        picker (A2LParameterPicker): The host's embedded picker; the modal
            applies the list through its ``include_names`` seam.

    Returns:
        Optional[dict]: The last include summary after a session that
            included at least one name, else ``None``
            (``ModalScreen[Optional[dict]]``).

    Data Flow:
        - ``compose`` builds a ``.modal-dialog`` with the title, the exact
          contract instruction, ``#bulk_param_text`` (``CappedTextArea``),
          ``#bulk_param_summary`` and the Include / Close button row.
        - ``on_button_pressed``: Include → ``_apply_list`` (parse →
          ``include_names`` → paint the summary); Close → dismiss.
        - ``action_cancel`` (``esc``) → dismiss with ``None``.

    Dependencies:
        Uses:
            - ``CappedTextArea`` / ``Button`` / the shared
              ``.modal-dialog`` classes; ``parse_parameter_list`` /
              ``A2LParameterPicker.include_names``; ``safe_text`` /
              ``_clip_to_cells`` for the missing-name detail.
        Used by:
            - ``CheckEditorPanel._open_parameter_bulk_add``
              (``screens_directionb.py``; Patch Editor at Inc 5).

    Example:
        >>> screen = BulkParameterAddScreen(picker)  # doctest: +SKIP
    """

    #: The contract instruction (R-B102-BULK-001): painted verbatim, as a
    #: literal ``Text`` — never through a markup path.
    _INSTRUCTION = "Separate names with new lines, commas, semicolons or spaces."

    #: The 64 KiB paste-cap notice (E3 ruling 8): painted when the buffer
    #: length sits AT the cap — a longer buffer is impossible through a
    #: single capped paste, so ``len(text) >= cap`` means ingress truncated.
    _TRUNCATED_NOTICE = f"Input truncated at {_CLIPBOARD_CAP_CHARS} chars."

    #: Route initial focus to the multiline area so a paste lands there
    #: rather than on a button; ``enter`` never confirms accidentally
    #: (tui-design posture: only the Include action applies).
    AUTO_FOCUS = "#bulk_param_text"

    #: ``Escape`` cancels the modal, mirroring the Close button (E3 ruling
    #: 6: cancel dismisses ``None``, without re-applying or refreshing).
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, picker: A2LParameterPicker) -> None:
        super().__init__()
        self._picker = picker
        #: Whether an include landed new picks in THIS session; drives the
        #: dismiss value (E3 ruling 6).
        self._changed = False
        #: The last apply's summary; dismissed when ``_changed``.
        self._last_summary: Optional[dict] = None

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Add A2L parameters", classes="modal-title"),
            Label(Text(self._INSTRUCTION), id="bulk_param_instruction"),
            CappedTextArea("", id="bulk_param_text"),
            Static("", id="bulk_param_summary", markup=False),
            Container(
                Button(
                    "Include matches",
                    id="bulk_param_include_button",
                    classes="modal-confirm",
                ),
                Button("Close", id="bulk_param_close_button"),
                id="bulk_param_buttons",
                classes="modal-buttons",
            ),
            id="bulk_param_dialog",
            classes="modal-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "bulk_param_include_button":
            self._apply_list()
            return
        if event.button.id == "bulk_param_close_button":
            # E3 ruling 6: a change-flagged close carries the summary; a
            # no-change close dismisses ``None`` so the host repaints
            # nothing.
            self.dismiss(self._last_summary if self._changed else None)

    def action_cancel(self) -> None:
        """Dismiss with ``None`` — ``Escape`` mirrors the Close button."""
        self.dismiss(None)

    # ------------------------------------------------------------------
    # Apply + summary
    # ------------------------------------------------------------------

    def _apply_list(self) -> None:
        """Parse the buffer, include the matches, paint the summary.

        R-B102-BULK-002 (split on every separator via
        :func:`parse_parameter_list`), R-B102-BULK-004 (the fixed-order
        summary), R-B102-BULK-005 (the exact no-match line), E3 ruling 8
        (the 64 KiB truncation notice). Neither the buffer nor any name is
        logged — counts only (E3 ruling 10).
        """
        text = self.query_one("#bulk_param_text", TextArea).text
        names = parse_parameter_list(text)
        summary = self._picker.include_names(names)
        if summary["included"]:
            self._changed = True
            self._last_summary = summary
        self._paint_summary(summary, truncated=len(text) >= _CLIPBOARD_CAP_CHARS)

    def _paint_summary(self, summary: Mapping, *, truncated: bool) -> None:
        """Paint the modal's single feedback region (F-B102-BULK-2).

        The counts line keeps the contract's fixed order; the missing-name
        detail is safe_text-scrubbed and clipped to the dialog width (E3
        ruling 2); the truncation notice, when the buffer sat at the paste
        cap, rides a second dim line so the contract line stays intact.
        """
        text = self._summary_text(summary)
        if truncated:
            text.append("\n")
            text.append(self._TRUNCATED_NOTICE, style=DGRAY)
        self.query_one("#bulk_param_summary", Static).update(text)

    def _summary_text(self, summary: Mapping) -> Text:
        """Build the counts line as literal text — never markup."""
        if summary.get("parsed_unique", 0) == 0:
            return Text("No listed parameters found.", style=DGRAY)
        line = Text(
            f"Included {summary['included']} · already included "
            f"{summary['already_included']} · not found {summary['not_found']}",
            style=DGRAY,
        )
        if summary["not_found"]:
            line.append(" — first missing: ")
            name = safe_text(str(summary["first_missing"] or "")).plain
            budget = max(8, self._line_width_budget() - cell_len(line.plain))
            line.append(safe_text(_clip_to_cells(name, budget)))
        return line

    def _line_width_budget(self) -> int:
        """The summary line's cell budget: the dialog's content width.

        Before the first layout pass (or when the dialog cannot be found)
        the 118-column interior is assumed, so a pre-mount paint errs long
        rather than clipping an honest name.
        """
        try:
            width = self.query_one("#bulk_param_dialog", Container).content_region.width
        except Exception:  # pragma: no cover - defensive seam
            width = 0
        return width if width > 0 else 76


#: Debounce window for the save-plan recompute: one run 150 ms after the
#: last keystroke (LLR-175.5a).
SAVE_RECOMPUTE_S = 0.150


class SaveProjectScreen(ModalScreen[Optional[SaveProjectPayload]]):
    """Modal Save-project dialog: name, target line, summary, and assignments.

    Summary:
        The single Save entry point (HLR-175). It paints the plan the app
        computes for the typed name — the target folder and its kind in
        ``#save_where`` and the plan's rows in ``#save_summary`` — and asks
        the app again on every Save request (``alt+s``, ``enter`` in the
        field, or ``#save_ok``) before dismissing with the painted plan. The
        dialog decides nothing about the save: the plan, the refusals and
        every painted string come from the app through the ``preview`` /
        ``confirm`` callables (LLR-175.6). The per-variant assignment rows
        (HLR-017 / LLR-017.3) keep their ids, order and meaning (ruling Q4).

    Args:
        preview (Callable[[str], SavePreview]): Called once after the first
            refresh and once per debounce window with the field text
            verbatim; returns the plan to paint.
        confirm (Callable[[str, Optional[SavePlan]], Optional[SavePreview]]):
            Called on every Save request with the text verbatim and the
            painted plan (or ``None``); ``None`` → dismiss, a preview → paint
            it and stay open.
        initial_name (Optional[str]): The open project's on-disk name,
            prefilled and selected (LLR-175.3h).
        variants (Optional[List[Tuple[str, str]]]): ``(variant_id,
            display_label)`` pairs for the existing project's variants, in
            set order (the ``_variant_display_options`` contract). ``None`` /
            empty ⇒ no assignment rows.
        candidate_files (Optional[List[str]]): Project-relative ``.json``
            change/check document names enumerated from the project dir.

    Returns:
        Optional[SaveProjectPayload]: the payload on Save, ``None`` on Cancel
        (``ModalScreen[Optional[SaveProjectPayload]]``).

    Data Flow:
        - ``on_mount`` schedules ``_first_preview`` after the first refresh;
          the first ``preview`` call runs there (LLR-175.5b).
        - Each keystroke resets the 150 ms debounce timer
          (``SAVE_RECOMPUTE_S``); ``_recompute`` calls ``preview`` and
          ``_paint`` paints the result.
        - ``action_save`` calls ``confirm``; ``None`` dismisses with the
          painted plan, a preview repaints and keeps the dialog open.
        - ``action_cancel`` / ``escape`` dismiss with ``None``.

    Dependencies:
        Uses:
            - ``Container`` / ``Label`` / ``Static`` / ``VerticalScroll`` /
              ``SelectionList`` / ``Button`` / ``Binding`` /
              ``OsClipboardInput``
            - :class:`SavePreview`, :class:`SaveProjectPayload`,
              :data:`SAVE_RECOMPUTE_S`
        Used by:
            - ``S19TuiApp.action_save_project``
    """

    AUTO_FOCUS = "#project_name"

    BINDINGS = [
        Binding("escape", "cancel", show=False),
        Binding("alt+s", "save", show=False, priority=True),
    ]

    def __init__(
        self,
        *,
        preview: Callable[[str], SavePreview],
        confirm: Callable[
            [str, Optional[project_gather_service.SavePlan]], Optional[SavePreview]
        ],
        initial_name: Optional[str] = None,
        variants: Optional[List[Tuple[str, str]]] = None,
        candidate_files: Optional[List[str]] = None,
    ) -> None:
        super().__init__()
        self._preview_fn = preview
        self._confirm_fn = confirm
        self._initial_name = initial_name
        self.variants: List[Tuple[str, str]] = list(variants or [])
        self.candidate_files: List[str] = list(candidate_files or [])
        self._plan: Optional[project_gather_service.SavePlan] = None
        self._live = False
        self._trailing = None
        self._shown = False
        self._dismissed = False

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
            Label("Project name", classes="modal-title"),
            OsClipboardInput(
                value=self._initial_name or "",
                placeholder="letters, digits, - and _",
                id="project_name",
            ),
            Static("", id="save_where", markup=False),
            VerticalScroll(id="save_summary"),
        ]
        if self._assignment_rows_enabled:
            children.append(
                Label(
                    "Project-wide batch files (.json):",
                    classes="modal-title",
                    markup=False,
                )
            )
            children.append(
                SelectionList[str](
                    *[(Text(name), name) for name in self.candidate_files],
                    id="assign_batch",
                    classes="assign-list",
                )
            )
            for index, (_variant_id, display) in enumerate(self.variants):
                children.append(
                    Label(
                        f"Assign files to '{display}':",
                        classes="modal-title",
                        markup=False,
                    )
                )
                children.append(
                    SelectionList[str](
                        *[(Text(name), name) for name in self.candidate_files],
                        id=f"assign_{index}",
                        classes="assign-list",
                    )
                )
        children.append(
            Container(
                Button("Save (alt+s)", id="save_ok", classes="modal-confirm"),
                Button("Cancel (esc)", id="save_cancel"),
                id="saveproject_buttons",
                classes="modal-buttons",
            )
        )
        yield Container(
            *children,
            id="save_box",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        self.call_after_refresh(self._first_preview)

    def _first_preview(self) -> None:
        """Run the first preview once the first frame has laid out the dialog."""
        if self._dismissed:
            return
        self._live = True
        self._recompute()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Reset the 150 ms debounce; one recompute runs after the last change."""
        if event.input.id != "project_name" or not self._live or self._dismissed:
            return
        self._stop_trailing()
        self._trailing = self.set_timer(SAVE_RECOMPUTE_S, self._recompute)

    def _recompute(self) -> None:
        """Run ``preview`` with the field text verbatim and paint the result."""
        if self._dismissed:
            return
        self._stop_trailing()
        self._paint(self._preview_fn(self.query_one("#project_name", Input).value))

    def _stop_trailing(self) -> None:
        """Stop the pending recompute timer, if one is running."""
        if self._trailing is not None:
            self._trailing.stop()
            self._trailing = None

    def _paint(self, p: SavePreview) -> None:
        """Paint ``#save_where`` and the summary rows; the only ``_plan`` writer.

        Data Flow:
            - ``_plan`` is set to the preview's plan; ``_shown`` is cleared
              and re-set by ``_mark_shown`` after the next refresh (S11-04).
            - ``#save_where`` is one ``markup=False`` ``Static`` painted with
              the where lines joined by newlines; the ``refusal`` class is
              set when ``refused`` is true or any line has the ``refusal``
              kind.
            - The summary rows are one ``markup=False`` ``Static`` each, in
              order, updated in place with only the difference mounted or
              removed.
        """
        self._plan = p.plan
        self._shown = False
        self.call_after_refresh(self._mark_shown)
        where = self.query_one("#save_where", Static)
        where.update(Text("\n".join(text for text, _kind in p.where)))
        where.set_class(
            p.refused or any(kind == "refusal" for _text, kind in p.where),
            "refusal",
        )
        box = self.query_one("#save_summary", VerticalScroll)
        have = list(box.query(Static))
        for w, row in zip(have, p.rows):
            w.update(Text(row))
        if len(p.rows) > len(have):
            box.mount_all(
                [Static(Text(row), markup=False) for row in p.rows[len(have):]]
            )
        for w in have[len(p.rows):]:
            w.remove()

    def _mark_shown(self) -> None:
        """Mark the painted preview shown once the next refresh lands."""
        if not self._dismissed:
            self._shown = True

    @property
    def plan(self) -> Optional[project_gather_service.SavePlan]:
        """The plan of the last painted preview, read-only (LLR-175.4k)."""
        return self._plan

    def action_save(self) -> None:
        """Run ``confirm`` on the typed name; dismiss or repaint and stay open."""
        if self._dismissed:
            return
        name = self.query_one("#project_name", Input).value
        painted = self._plan if self._shown else None
        again = self._confirm_fn(name, painted)
        if again is not None:
            self._stop_trailing()
            self._paint(again)
            return
        if painted is None:
            logger.warning("Save dialog: confirm accepted no painted plan; repainting")
            self._recompute()
            return
        batch, assignments = self._collect_composition()
        self._close(
            SaveProjectPayload(
                parent_folder=str(painted.target.parent),
                project_name=name,
                batch=batch,
                assignments=assignments,
                plan=painted,
            )
        )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "project_name":
            event.stop()
            self.action_save()

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
                - SaveProjectScreen.action_save
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
        event.stop()
        if event.button.id == "save_ok":
            self.action_save()
        elif event.button.id == "save_cancel":
            self.action_cancel()

    def action_cancel(self) -> None:
        """Dismiss with ``None`` — ``escape`` and ``#save_cancel`` mirror here."""
        self._close(None)

    def _close(self, result: Optional[SaveProjectPayload]) -> None:
        """Dismiss once; a second queued close / save returns at once.

        Args:
            result (Optional[SaveProjectPayload]): The payload to hand the
                caller, or ``None`` for Cancel / Escape.

        Data Flow:
            - ``_dismissed`` is set before ``dismiss`` runs; the pending
              recompute timer is stopped so it cannot fire after the dismiss.
        """
        if self._dismissed:
            return
        self._dismissed = True
        self._stop_trailing()
        self.dismiss(result)


class SaveFlowScreen(ModalScreen[Optional[str]]):
    """Modal to name and save the current Flow Builder pipeline (batch-53 FB-P1).

    Summary:
        A unified Save / Save-As dialog (D1): one ``OsClipboardInput`` prefilled
        with the current flow name, a sanitiser hint, and a live
        ``(overwrites existing)`` notice shown when the sanitised name already
        maps to a saved ``flows/<name>.json``. Save dismisses with the RAW typed
        name (the app runs ``save_flow_json`` → ``sanitize_project_name`` as the
        write-side containment authority); Cancel dismisses with ``None``.
        Mirrors :class:`SaveProjectScreen` (LLR-003.2).

    Args:
        default_name (str): The current flow name to prefill (editing = Save-As).
        existing (List[str]): Saved flow stems (``list_saved_flows``) — the
            overwrite notice fires when the sanitised input is one of these.
    """

    def __init__(self, default_name: str, existing: Optional[List[str]] = None) -> None:
        super().__init__()
        self.default_name = default_name
        self.existing: List[str] = list(existing or [])

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Save flow as:", classes="modal-title"),
            OsClipboardInput(placeholder="letters, numbers, - _", id="flow_save_name"),
            Label(
                "Name is sanitised (letters, numbers, - _); "
                "identity is the filename.",
                classes="modal-hint",
                markup=False,
            ),
            Label("", id="flow_overwrite_notice", classes="sev-warning", markup=False),
            Container(
                Button("Save", id="flow_save_ok", classes="modal-confirm"),
                Button("Cancel", id="flow_save_cancel"),
                id="flowsave_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#flow_save_name", Input).value = self.default_name
        self._refresh_overwrite_notice(self.default_name)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "flow_save_name":
            self._refresh_overwrite_notice(event.value)

    def _refresh_overwrite_notice(self, raw: str) -> None:
        """Show ``(overwrites existing)`` when the sanitised name already exists."""
        clean = sanitize_project_name(raw)
        notice = self.query_one("#flow_overwrite_notice", Label)
        notice.update("(overwrites existing)" if clean in self.existing else "")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "flow_save_cancel":
            self.dismiss(None)
            return
        if event.button.id == "flow_save_ok":
            raw = self.query_one("#flow_save_name", Input).value.strip()
            if not raw:
                return
            self.dismiss(raw)


class LoadFlowScreen(ModalScreen[Optional[str]]):
    """Modal to pick a saved flow to load, or Import an external ``flow.json``.

    Summary:
        Lists ``flows/*.json`` stems in a ``ListView`` with Import…/Load/Cancel.
        Import opens a tkinter filedialog and COPIES the picked file into
        ``flows/`` via ``import_flow_file`` (never loaded in place — the copy is
        containment- and size-guarded); the new stem is appended to the list. A
        containment/size rejection (or any raise) shows an inline status line,
        never a crash. Load dismisses with the highlighted stem; Cancel with
        ``None`` (LLR-003.3/.4). Mirrors the Load dialog.

    Args:
        flows (List[str]): The saved flow stems to list.
        project_dir (Path): The active project dir — the Import copy destination
            (``project_dir/flows``).
    """

    def __init__(self, flows: List[str], project_dir: Path) -> None:
        super().__init__()
        self.flows: List[str] = list(flows)
        self.project_dir = project_dir

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load flow:", classes="modal-title"),
            ListView(
                *[
                    ListItem(Label(stem, markup=False), name=stem)
                    for stem in self.flows
                ],
                id="flow_list",
            ),
            Label("", id="flow_import_status", classes="sev-warning", markup=False),
            Container(
                Button("Import…", id="flow_import"),
                Button("Load", id="flow_load_ok", classes="modal-confirm"),
                Button("Cancel", id="flow_load_cancel"),
                id="loadflow_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "flow_load_cancel":
            self.dismiss(None)
            return
        if event.button.id == "flow_import":
            self._import_external()
            return
        if event.button.id == "flow_load_ok":
            selected = self.query_one("#flow_list", ListView).highlighted_child
            if selected is None or selected.name is None:
                return
            # Identity travels on the ListItem's ``name`` (set to the stem), not
            # parsed back out of the Label renderable (which is unreliable).
            self.dismiss(selected.name)

    def _import_external(self) -> None:
        """Filedialog → containment-guarded COPY into ``flows/`` → refresh list.

        A rejection or any raise is surfaced inline (``#flow_import_status``),
        never a crash — the copy guard is the authority (LLR-003.4).
        """
        status = self.query_one("#flow_import_status", Label)
        try:
            import tkinter as tk
            from tkinter import filedialog
        except Exception as exc:  # pragma: no cover - headless
            logger.warning("Flow import browse unavailable: %s", exc)
            status.update("import unavailable in this environment")
            return
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        picked = filedialog.askopenfilename(
            filetypes=[("Flow JSON", "*.json"), ("All files", "*.*")]
        )
        root.destroy()
        if not picked:
            return
        from .services.flow_persistence_service import import_flow_file
        from .workspace import WorkareaContainmentError

        try:
            imported = import_flow_file(Path(picked), self.project_dir)
        except (WorkareaContainmentError, OSError) as exc:
            status.update(f"import refused: {type(exc).__name__}")
            return
        stem = imported.stem
        if stem not in self.flows:
            self.flows.append(stem)
            self.query_one("#flow_list", ListView).append(
                ListItem(Label(stem, markup=False), name=stem)
            )
        status.update(f"imported flows/{imported.name}")


# ---------------------------------------------------------------------------
# batch-102 Inc 7 (US-102-07) — the flow file-ref chooser (R-B102-FILE-002..007)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileRefCandidate:
    """One Browse candidate (E3 ruling 1).

    Args:
        label (str): The display line (scrubbed by the chooser at render).
        ref (str): The wire value written into the host field on a direct
            pick (project files, or a loaded artifact already inside the
            project — its project-relative posix path).
        origin (str): ``project`` / ``temp`` / ``loaded``.
        source (Optional[Path]): The absolute file a temp/loaded pick must
            import through :func:`s19_app.tui.workspace.import_external_ref`
            before the field receives ``external/<name>``; ``None`` for a
            direct pick.
    """

    label: str
    ref: str
    origin: str
    source: Optional[Path] = None


@dataclass(frozen=True)
class FileRefChoice:
    """The chooser's dismiss value: the wire ref + the origin it came from."""

    ref: str
    origin: str  # "project" | "temp" | "loaded" | "external"


class FileRefChooserScreen(ModalScreen[Optional[FileRefChoice]]):
    """Modal to pick the file behind one flow ref field (batch-102 Inc 7).

    Summary:
        Opened by the app when a flow host posts ``BrowseRequested``
        (E3 ruling 2 — the app coordinates the modal, never the host).
        Lists the three candidate sections — ``Project``, ``Temp /
        workarea`` and ``Loaded artifacts`` — plus an external-path input
        with an Import action (R-B102-FILE-002).  Picking a candidate
        dismisses with its wire value and NEVER adds or edits a block
        (R-B102-FILE-003); a temp or loaded pick whose file is not already
        inside the active project is first imported into
        ``<project>/external/`` through the hardened
        :func:`import_external_ref`, so every produced value is runnable
        by ``run_flow`` (E3 ruling 1).  Every refusal is painted in the
        modal with its exact pinned line, names at most the file NAME
        (never a path — E3 ruling 8), and leaves the host field untouched
        (R-B102-FILE-005/006).  Every file-derived string renders through
        ``safe_text``/``Content`` — literal text, zero markup spans
        (R-B102-FILE-007).

    Args:
        candidates (Sequence[FileRefCandidate]): The app-built candidate
            list (project/temp/loaded).
        project_root (Optional[Path]): The active project dir — the only
            import destination; ``None`` refuses every import with the
            pinned no-project line.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    #: The section headers, in stack order (R-B102-FILE-002: 3/3 visible).
    _SECTION_TITLES: Tuple[Tuple[str, str], ...] = (
        ("project", "Project"),
        ("temp", "Temp / workarea"),
        ("loaded", "Loaded artifacts"),
    )

    def __init__(
        self,
        candidates: Sequence[FileRefCandidate],
        project_root: Optional[Path],
    ) -> None:
        super().__init__()
        self._candidates = list(candidates)
        self._project_root = project_root
        self._pick_map: Mapping[str, FileRefCandidate] = {}

    def compose(self) -> ComposeResult:
        with Container(id="file_ref_dialog", classes="modal-dialog"):
            yield Static(
                "CHOOSE INPUT FILE", classes="modal-title", markup=False
            )
            pick_index = 0
            for origin, title in self._SECTION_TITLES:
                yield Static(
                    title, classes="file-ref-section", markup=False
                )
                items = [c for c in self._candidates if c.origin == origin]
                if not items:
                    yield Static(
                        "(none)", classes="file-ref-none", markup=False
                    )
                    continue
                for candidate in items:
                    button_id = f"file_ref_pick_{pick_index}"
                    pick_index += 1
                    self._pick_map[button_id] = candidate
                    yield Button(
                        Content(safe_text(candidate.label).plain),
                        id=button_id,
                        classes="file-ref-item",
                    )
            with Horizontal(classes="file-ref-external"):
                yield Label(
                    "External path", classes="flow-field-label", markup=False
                )
                yield OsClipboardInput(
                    placeholder="absolute path to a file outside the project",
                    id="flow_external_path_input",
                    classes="file-ref-path",
                    compact=True,
                )
                yield Button("Import", id="flow_external_import")
            yield Static(
                "", id="file_ref_status", classes="sev-warning", markup=False
            )
            with Horizontal(classes="modal-buttons"):
                yield Button("Cancel", id="file_ref_cancel")

    def on_mount(self) -> None:
        self.query_one("#file_ref_status", Static).display = False
        self.query_one("#flow_external_path_input", Input).focus()

    # -- picking ----------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "file_ref_cancel":
            self.dismiss(None)
            return
        if button_id == "flow_external_import":
            raw = self.query_one("#flow_external_path_input", Input).value.strip()
            if not raw:
                self._paint_status(
                    "External path is empty — type a path or pick a candidate."
                )
                return
            choice = self._import_source(Path(raw))
            if choice is not None:
                self.dismiss(choice)
            return
        if button_id is not None and button_id.startswith("file_ref_pick_"):
            candidate = self._pick_map.get(button_id)
            if candidate is not None:
                self._pick_candidate(candidate)

    def _pick_candidate(self, candidate: FileRefCandidate) -> None:
        """Dismiss with the candidate's wire value (R-B102-FILE-003).

        A project candidate (or a loaded one already inside the project)
        dismisses directly; a temp/loaded pick imports first (E3 ruling 1)
        so the field receives an ``external/<name>`` value the flow can
        actually run.  Nothing here mutates a block or the host field.
        """
        if candidate.source is None:
            self.dismiss(
                FileRefChoice(ref=candidate.ref, origin=candidate.origin)
            )
            return
        choice = self._import_source(candidate.source)
        if choice is not None:
            self.dismiss(choice)

    def _import_source(self, source: Path) -> Optional[FileRefChoice]:
        """The hardened import; ``None`` (refusal painted) on any refusal.

        The refusal messages are operator-facing and path-free (E3 ruling
        8); nothing is copied on a refusal (R-B102-FILE-005/006).
        """
        try:
            imported = import_external_ref(source, self._project_root)
        except ExternalImportRefusal as refusal:
            self._paint_status(str(refusal))
            return None
        if imported is None:  # defensive: the refusal class covers this
            self._paint_status(
                "Load or create a project before importing an external file."
            )
            return None
        _landed, ref = imported
        return FileRefChoice(ref=ref, origin="external")

    def _paint_status(self, message: str) -> None:
        status = self.query_one("#file_ref_status", Static)
        status.update(safe_text(message))  # SINK: file-derived refusal text
        status.display = True

    def action_cancel(self) -> None:
        self.dismiss(None)


#: kind → path-bearing wire fields (the NUL pre-check set, the add form's
#: S4-1 idiom): a candidate holding a NUL refuses before the loader runs.
_EDIT_PATH_FIELDS: Mapping[str, Tuple[str, ...]] = {
    BLOCK_SOURCE: ("image_ref",),
    BLOCK_PATCH: ("change_doc_ref",),
    BLOCK_CHECK: ("check_doc_ref",),
    BLOCK_CRC: ("config_ref",),
    BLOCK_WRITE_OUT: ("output_name",),
    BLOCK_A2B: ("image_a", "image_b"),
    BLOCK_EXTERNAL_STEP: ("log_ref", "output_path"),
}


class FlowBlockEditScreen(ModalScreen[Optional[FlowBlock]]):
    """Modal to edit ONE existing flow block in place (batch-102 Inc 6).

    Summary:
        Opened by the app when the Flow Builder posts ``EditRequested``
        (R-B102-FB-001). The dialog fixes the block kind — the title names
        ``EDIT BLOCK #<n> — <kind>`` — and shows exactly the add-row's
        field vocabulary for that kind, prefilled with the block's current
        values (TC-B102-FB-01's 8/8 kinds). Save builds the candidate by
        MERGING the modal fields over the ORIGINAL wire dict (E3 ruling 2:
        ``file_type`` / ``a2l_ref`` / ``fmt`` and any future unexposed
        field survive — the candidate is never rebuilt from scratch),
        substitutes it at the picked index in the CURRENT wire envelope and
        re-validates the whole envelope through the hardened
        ``dict_to_flow`` loader — the same fail-closed gate Paste uses
        (finding F-B102-FB-2: a failed edit must never corrupt the chain).
        On findings the ORIGINAL block stays, the refusal is painted in the
        modal (R-B102-FB-003) listing every finding, and the modal stays
        open; on success it dismisses with the replacement block and the
        app applies it through the panel's public ``replace_block``.

        A2B bindings round-trip canonically (E3 ruling 6): shown as ``#n``
        (1-based, the operator grammar) and saved through
        :func:`parse_a2b_binding` as the wire form ``{"source", "ref"}``
        (0-based) — never the display form.

        batch-102 Inc 7: the READ file-ref rows carry a Browse chip that
        posts the module-level ``BrowseRequested`` (E3 ruling 2 — the app
        coordinates :class:`FileRefChooserScreen` and writes the pick back
        through the public :meth:`apply_browsed_ref`; the block changes
        only on a validated Save).

        Without a containment base (E3 ruling 4) Save refuses IN the modal
        — a hostile ref is never stored to fail later. Every file-derived
        string (title, prefilled fields, refusal) renders literal:
        ``safe_text`` + ``markup=False`` (R-B102-FB-006), and nothing
        content-bearing is logged (E3 ruling 10).

    Args:
        index (int): The block's 0-based position in the chain (title is 1-based).
        block (FlowBlock): The block being edited (frozen — never mutated).
        wire_blocks (List[dict]): The chain's current ``flow_to_dict``
            projection (the envelope the candidate is validated against).
        project_dir (Optional[Path]): The resolved containment base; ``None``
            when no project is active (Save then refuses in-modal).

    Data Flow:
        - Compose → per-kind prefilled fields (markup-safe).
        - Save → candidate wire (merge over the original) → substituted
          envelope → ``dict_to_flow`` → dismiss(replacement) | paint refusal.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(
        self,
        index: int,
        block: FlowBlock,
        wire_blocks: List[dict],
        project_dir: Optional[Path],
    ) -> None:
        super().__init__()
        self._index = index
        self._block = block
        #: A snapshot — the caller's chain can change while the modal is up;
        #: Save re-checks the index before substituting.
        self._wire_blocks = [dict(w) for w in wire_blocks]
        self._project_dir = project_dir
        if isinstance(block, A2BBlock):
            self._first_field = "#flow_edit_ref_a"
        elif isinstance(block, ExternalStepBlock):
            self._first_field = "#flow_edit_ext_mode"
        elif isinstance(block, ReportBlock):
            self._first_field = "#flow_edit_save"
        else:
            self._first_field = "#flow_edit_ref"

    # -- composition ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Container(id="block_edit_dialog", classes="modal-dialog"):
            yield Static(
                safe_text(
                    f"EDIT BLOCK #{self._index + 1} — {self._block.kind.upper()}"
                ),
                classes="modal-title",
                markup=False,
            )
            block = self._block
            if isinstance(block, SourceBlock):
                yield from self._ref_row(
                    "image file", block.image_ref, "flow_edit_ref",
                    "e.g. prg.s19", browse=True,
                )
            elif isinstance(block, PatchBlock):
                yield from self._ref_row(
                    "change doc", block.change_doc_ref, "flow_edit_ref",
                    "e.g. calib_hotfix.json", browse=True,
                )
            elif isinstance(block, CheckBlock):
                yield from self._ref_row(
                    "check doc", block.check_doc_ref, "flow_edit_ref",
                    "e.g. baseline.chk.json", browse=True,
                )
                with Horizontal(classes="flow-edit-line"):
                    yield Label("gating", classes="flow-field-label", markup=False)
                    yield Select(
                        (
                            (CHECK_GATING_ADVISORY, CHECK_GATING_ADVISORY),
                            (CHECK_GATING_BLOCK_OWN, CHECK_GATING_BLOCK_OWN),
                        ),
                        value=block.gating,
                        allow_blank=False,
                        id="flow_edit_gating",
                        compact=True,
                    )
            elif isinstance(block, CrcBlock):
                yield from self._ref_row(
                    "CRC template", block.config_ref, "flow_edit_ref",
                    "e.g. crc.json", browse=True,
                )
            elif isinstance(block, WriteOutBlock):
                yield from self._ref_row(
                    "output file", block.output_name, "flow_edit_ref",
                    "e.g. fw_app_patched.s19", browse=True,
                )
            elif isinstance(block, A2BBlock):
                # Bindings display as the operator grammar (#n 1-based); the
                # wire form is rebuilt from parse_a2b_binding on Save.
                yield from self._ref_row(
                    "image A", _binding_field_text(block.image_a),
                    "flow_edit_ref_a", "file or #n", browse=True,
                )
                yield from self._ref_row(
                    "image B", _binding_field_text(block.image_b),
                    "flow_edit_ref_b", "file or #n", browse=True,
                )
            elif isinstance(block, ExternalStepBlock):
                with Horizontal(classes="flow-edit-line"):
                    yield Label("mode", classes="flow-field-label", markup=False)
                    yield Select(
                        (
                            ("Terminal", EXTERNAL_MODE_TERMINAL),
                            ("Manual", EXTERNAL_MODE_MANUAL),
                        ),
                        value=block.mode,
                        allow_blank=False,
                        id="flow_edit_ext_mode",
                        compact=True,
                    )
                noun = "command" if block.mode == EXTERNAL_MODE_TERMINAL else "instruction"
                yield from self._ref_row(
                    noun, block.instruction, "flow_edit_ext_instruction",
                    "the exact command run outside the app",
                )
                yield from self._ref_row(
                    "log", block.log_ref, "flow_edit_ext_log", "log file (required)"
                )
                yield from self._ref_row(
                    "output file", block.output_path, "flow_edit_ext_output",
                    "the file the step leaves, absolute path preferred",
                )
            else:
                # ReportBlock (and any future ref-less kind): field-less by
                # design — Save round-trips the original wire unchanged.
                yield Label(
                    "This block carries no editable fields.",
                    classes="modal-hint",
                    markup=False,
                )
            yield Static("", id="block_edit_refusal", markup=False, classes="sev-warning")
            with Horizontal(id="flow_edit_buttons", classes="modal-buttons"):
                yield Button("Save", id="flow_edit_save", classes="modal-confirm")
                yield Button("Cancel", id="flow_edit_cancel")

    def _ref_row(
        self, label: str, value: str, input_id: str, placeholder: str,
        *, browse: bool = False,
    ) -> ComposeResult:
        """One label + prefilled input row (the add-row vocabulary).

        The prefill rides through ``safe_text`` (R-B102-FB-006): the block's
        stored value is literal text — control bytes are scrubbed before it
        enters the field, markup characters stay inert.  ``browse=True``
        (the READ file-ref rows only, E3 ruling 6) adds the Browse chip that
        posts :class:`BrowseRequested` for the app to coordinate
        (batch-102 Inc 7, E3 ruling 2).
        """
        with Horizontal(classes="flow-edit-line"):
            yield Label(label, classes="flow-field-label", markup=False)
            yield OsClipboardInput(
                value=safe_text(value).plain,
                placeholder=placeholder,
                id=input_id,
                compact=True,
            )
            if browse:
                browse_id = (
                    "flow_edit_browse"
                    if input_id == "flow_edit_ref"
                    else f"{input_id}_browse"
                )
                yield Button(
                    "Browse", id=browse_id, classes="flow-browse"
                )

    def _browse_ref(self, input_id: str) -> None:
        """Post :class:`BrowseRequested` for one of the modal's ref fields.

        The modal never pushes the chooser itself (E3 ruling 2): the app
        pushes ``FileRefChooserScreen`` and writes the choice back through
        the public :meth:`apply_browsed_ref`.
        """
        self.post_message(BrowseRequested(f"#{input_id}"))

    def apply_browsed_ref(self, input_id: str, ref: str) -> None:
        """Write a browsed ref into one of the modal's fields
        (R-B102-FILE-003): the field updates, the block changes only on a
        validated Save.  A stale or foreign selector is a silent no-op.
        """
        try:
            widget = self.query_one(input_id, Input)
        except Exception:  # noqa: BLE001 - a stale host selector refuses silently
            return
        widget.value = safe_text(ref).plain

    def _kind_title(self) -> str:
        """The title's kind word — the add-row look-up table, else the raw kind."""
        titles = {
            BLOCK_SOURCE: "LOAD",
            BLOCK_PATCH: "PATCH",
            BLOCK_CHECK: "CHECK",
            BLOCK_CRC: "CRC",
            BLOCK_WRITE_OUT: "WRITE-OUT",
            BLOCK_A2B: "A2B-DIFF",
            BLOCK_EXTERNAL_STEP: "EXT-STEP",
            BLOCK_REPORT: "REPORT",
        }
        return titles.get(self._block.kind, self._block.kind.upper())

    def on_mount(self) -> None:
        self.query_one("#block_edit_refusal", Static).display = False
        first_field = self._first_field
        self.query_one(first_field).focus()

    # -- save / cancel -------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "flow_edit_browse":
            self._browse_ref("flow_edit_ref")
            return
        if (
            button_id is not None
            and button_id.startswith("flow_edit_")
            and button_id.endswith("_browse")
        ):
            self._browse_ref(button_id[: -len("_browse")])
            return
        if button_id == "flow_edit_save":
            self._save()
        elif button_id == "flow_edit_cancel":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _save(self) -> None:
        """Validate the merged candidate against the chain; dismiss or refuse.

        R-B102-FB-002 / R-B102-FB-003 / E3 rulings 2/4/6/7: without a base
        the refusal is painted here (nothing hostile is kept); the candidate
        merges over the original wire (unexposed fields survive); the
        substituted envelope re-runs the hardened loader — any finding keeps
        the original block and paints EVERY finding in the modal.
        """
        if self._project_dir is None:
            self._paint_refusal(
                "Edit refused: load a project first (the edit is checked "
                "against the session directory)."
            )
            return
        candidate, refusal = self._candidate_wire()
        if refusal is not None:
            self._paint_refusal(refusal)
            return
        if not 0 <= self._index < len(self._wire_blocks):
            self._paint_refusal(
                f"Edit refused: the chain no longer holds block "
                f"#{self._index + 1}."
            )
            return
        envelope_blocks = [
            *self._wire_blocks[: self._index],
            candidate,
            *self._wire_blocks[self._index + 1 :],
        ]
        from .services import flow_persistence_service as fps

        envelope = {
            "schema_version": 1,
            "name": "block-edit",
            "blocks": envelope_blocks,
        }
        parsed, findings = fps.dict_to_flow(envelope, self._project_dir)
        if parsed is None or findings:
            messages = [
                safe_text(finding.message).plain for finding in findings
            ] or ["invalid block"]
            self._paint_refusal("Edit refused: " + "; ".join(messages))
            return
        self.dismiss(parsed.blocks[self._index])

    def _field_text(self, input_id: str) -> str:
        """One modal input's value, stripped — the Add form's grammar."""
        return self.query_one(input_id, Input).value.strip()

    def _candidate_wire(self) -> Tuple[Optional[dict], Optional[str]]:
        """The candidate wire dict: the ORIGINAL merged with the modal fields.

        E3 ruling 2 — never rebuilt from scratch: the canonical
        ``flow_to_dict`` projection of the edited block is copied and only
        the exposed fields are overwritten, so ``file_type`` / ``a2l_ref`` /
        ``fmt`` and any future unexposed field round-trip untouched. A2B
        bindings save the canonical wire form via ``parse_a2b_binding``;
        a NUL in a path-bearing field refuses with the loader's code (the
        add form's S4-1 idiom) before the loader ever runs.
        """
        from .services import flow_persistence_service as fps

        original = fps.flow_to_dict(
            Flow(name="block-edit", blocks=[self._block])
        )["blocks"][0]
        candidate = dict(original)
        block = self._block
        text = self._field_text
        if isinstance(block, SourceBlock):
            candidate["image_ref"] = text("#flow_edit_ref")
        elif isinstance(block, PatchBlock):
            candidate["change_doc_ref"] = text("#flow_edit_ref")
        elif isinstance(block, CheckBlock):
            candidate["check_doc_ref"] = text("#flow_edit_ref")
            candidate["gating"] = str(
                self.query_one("#flow_edit_gating", Select).value
            )
        elif isinstance(block, CrcBlock):
            candidate["config_ref"] = text("#flow_edit_ref")
        elif isinstance(block, WriteOutBlock):
            candidate["output_name"] = text("#flow_edit_ref")
        elif isinstance(block, A2BBlock):
            for field, input_id in (
                ("image_a", "#flow_edit_ref_a"),
                ("image_b", "#flow_edit_ref_b"),
            ):
                binding = parse_a2b_binding(text(input_id))
                if binding is None:
                    return None, (
                        f"Edit refused: {field} must be a file name or #<n> "
                        "(a flow output)."
                    )
                candidate[field] = {"source": binding.source, "ref": binding.ref}
        elif isinstance(block, ExternalStepBlock):
            candidate["mode"] = str(
                self.query_one("#flow_edit_ext_mode", Select).value
            )
            candidate["instruction"] = text("#flow_edit_ext_instruction")
            candidate["log_ref"] = text("#flow_edit_ext_log")
            candidate["output_path"] = text("#flow_edit_ext_output")
        for field in _EDIT_PATH_FIELDS.get(block.kind, ()):
            value = candidate.get(field)
            if isinstance(value, dict):
                value = value.get("ref", "")
            if isinstance(value, str) and "\x00" in value:
                return None, (
                    f"Edit refused: [{fps.FLOW_UNSAFE_REF}] "
                    f"{self._kind_title()} {field} holds a NUL character "
                    "- not a path"
                )
        return candidate, None

    def _paint_refusal(self, message: str) -> None:
        """Paint the in-modal refusal (markup-safe; empty hides the region)."""
        refusal = self.query_one("#block_edit_refusal", Static)
        if message:
            refusal.update(safe_text(message))
            refusal.display = True
        else:
            refusal.update("")
            refusal.display = False


def _binding_field_text(binding) -> str:
    """The operator display form of one A2B binding: ``#n`` 1-based for a
    flow output, the file ref verbatim otherwise (never the ``.out`` stub
    form — the modal field must re-parse through ``parse_a2b_binding``)."""
    if binding.source == A2B_INPUT_FLOW:
        return f"#{int(binding.ref) + 1}"
    return binding.ref


class ConfirmDiscardScreen(ModalScreen[bool]):
    """Confirm-discard modal shown before a Load replaces UNSAVED flow edits.

    Summary:
        The dirty-guard (OQ-3 / LLR-003.6 / AMD-8): when Load is confirmed over a
        dirty flow (``●``), this modal asks the operator to confirm discarding the
        current edits. Discard dismisses ``True`` (the app proceeds with
        ``set_blocks``); Cancel dismisses ``False`` (the current blocks are kept —
        no data loss). Mirrors the project modals' box model.

    Args:
        target (str): The stem of the flow about to be loaded (shown, markup-safe).
    """

    def __init__(self, target: str) -> None:
        super().__init__()
        self.target = target

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Discard unsaved flow edits?", classes="modal-title"),
            Label(
                f"Loading '{self.target}' replaces the current unsaved flow.",
                classes="modal-hint",
                markup=False,
            ),
            Container(
                Button("Discard", id="flow_discard_ok", classes="modal-confirm"),
                Button("Cancel", id="flow_discard_cancel"),
                id="flowdiscard_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "flow_discard_ok":
            self.dismiss(True)
        elif event.button.id == "flow_discard_cancel":
            self.dismiss(False)


class ConfirmQuestionScreen(ModalScreen[bool]):
    """One-question confirm modal shown before unsaved work is replaced.

    Summary:
        A generic yes/no question shown before an image-replacing route
        discards unsaved work (HLR-174, LLR-174.2). ``Replace`` dismisses
        ``True`` (the app continues with the load); ``Cancel`` dismisses
        ``False`` (nothing changes). The title, body and the two button
        labels arrive as already-painted plain ``str`` parameters — the
        screen neither scrubs nor rewrites them and owns no painted
        literal of its own, so Inc 12 can reuse it for the quit question.
        The box reuses the shared ``.modal-dialog`` token classes.

    Args:
        title (str): The question title (already painted, markup-safe).
        body (str): The question body (already painted, markup-safe).
        yes_label (str): The ``#confirm_yes`` button label (already painted).
        no_label (str): The ``#confirm_no`` button label (already painted).

    Dependencies:
        Used by:
            - S19TuiApp._confirm_then_load (the load question); Inc 12
              builds the quit question from it.
    """

    AUTO_FOCUS = "#confirm_no"
    #: The button painted with the primary ``modal-confirm`` style.
    PRIMARY_BUTTON = "confirm_yes"
    BINDINGS = [
        Binding("y", "answer(True)", show=False),
        Binding("n", "answer(False)", show=False),
        Binding("escape", "answer(False)", show=False),
    ]

    def __init__(
        self,
        title: str,
        body: str,
        yes_label: str,
        no_label: str,
    ) -> None:
        super().__init__()
        self._question_title = title
        self._question_body = body
        self._yes_label = yes_label
        self._no_label = no_label
        self._dismissed = False

    def compose(self) -> ComposeResult:
        yield Container(
            Label(
                self._question_title,
                id="confirm_title",
                classes="modal-title",
                markup=False,
            ),
            Static(self._question_body, id="confirm_body", markup=False),
            Container(
                Button(
                    Text(self._yes_label),
                    id="confirm_yes",
                    classes="modal-confirm" if self.PRIMARY_BUTTON == "confirm_yes" else "",
                ),
                Button(
                    Text(self._no_label),
                    id="confirm_no",
                    classes="modal-confirm" if self.PRIMARY_BUTTON == "confirm_no" else "",
                ),
                id="confirm_buttons",
                classes="modal-buttons",
            ),
            id="confirm_box",
            classes="modal-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "confirm_yes":
            self._close(True)
        elif event.button.id == "confirm_no":
            self._close(False)

    def action_answer(self, value: bool) -> None:
        self._close(value)

    def _close(self, result: bool) -> None:
        if self._dismissed:
            return
        self._dismissed = True
        self.dismiss(result)


class SelectVariantScreen(ModalScreen[Optional[str]]):
    """Modal dialog for selecting the active S19/HEX variant of a project.

    Follows the Load dialog pattern (LLR-005.5): a ``ListView`` of
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


#: The value the Load-result panel dismisses with when the operator asks for
#: the variant selector (``v`` or ``#result_variant``, LLR-178.3).
LOAD_RESULT_SELECT_VARIANT = "select_variant"

#: The Load-result panel's label column (P-E verdict B): a value that wraps
#: hangs under its value column, never under the label.
_RESULT_KEY_WIDTH = 10
#: The problem mark column (``"  ! "``): a problem that wraps hangs under
#: its label, never under the mark.
_RESULT_MARK_WIDTH = 4


class LoadResultScreen(ModalScreen[Optional[str]]):
    """The Load-result panel (HLR-178 / LLR-178.3, P-E verdict B).

    Summary:
        Opened after a project load from the Load project dialog: which
        variant opened and why, how many the project holds, the other
        variants, the MAC and A2L that loaded, and every problem in a
        scrolling list with no truncation. Every name read from disk
        renders through ``safe_text``. The focus starts on the list
        (``#result_body``: up, down, PgUp, PgDn, Home, End scroll it);
        ``tab`` moves to ``#result_ok`` ("Close (esc)"); ``escape``
        dismisses from anywhere and ``enter`` only on ``#result_ok``; ``v``
        (or ``#result_variant``) dismisses with
        :data:`LOAD_RESULT_SELECT_VARIANT` so the app opens its variant
        selector. ``#result_variant`` is reached by its key, not by
        ``tab``, so ``tab`` from the list lands on Close. Severity colours
        follow the prototype (``insight_style``): the fallback reason, the
        ``derived_from`` "patched" line, the problem heading and each
        problem's mark and label in the warning colour, the recorded reason
        in the OK colour, a variant that is not readable marked in the error
        colour (Inc 7), labels and details dim; every colour is a ``Text``
        style, never markup.

    Args:
        announcement (LoadAnnouncement): The composed announcement
            (``compose_load_announcement``).

    Data Flow:
        - ``compose`` builds the summary grid (label column, value column),
          the problem heading and one ``Static`` row per problem (mark
          column, text column) inside ``#result_body``.
        - ``on_mount`` focuses ``#result_body``.
        - The bindings and ``on_button_pressed`` dismiss with ``None`` or
          :data:`LOAD_RESULT_SELECT_VARIANT`.

    Dependencies:
        Uses:
            - ``safe_text`` / the shared ``.modal-dialog`` classes
        Used by:
            - ``S19TuiApp._route_load_project``
    """

    BINDINGS = [
        Binding("escape", "close_result", "Close", show=False),
        Binding("v", "select_variant", "Select variant", show=False),
    ]

    def __init__(self, announcement: "LoadAnnouncement") -> None:
        super().__init__()
        self.announcement = announcement

    def compose(self) -> ComposeResult:
        announcement = self.announcement
        # F2: the count covers the problems the last row counts.
        count = announcement.problem_count
        title = f"Project {announcement.project} opened" + (
            f" with {count} problem{'' if count == 1 else 's'}" if count else ""
        )
        heading = (
            Text("Problems found (the rest loaded)", style=f"bold {YELLOW}")
            if count
            else Text("No problems found.", style=GREEN)
        )
        variant_button = Button(
            "Select variant (v)", id="result_variant"
        )
        variant_button.can_focus = False
        yield Container(
            Label(safe_text(title), classes="modal-title"),
            VerticalScroll(
                Static(self._summary(), id="result_summary"),
                Label(heading, classes="result-heading"),
                *[
                    Static(self._problem_row(problem), classes="result-problem")
                    for problem in announcement.problems
                ],
                id="result_body",
            ),
            Container(
                variant_button,
                Button("Close (esc)", id="result_ok", classes="modal-confirm"),
                id="result_buttons",
                classes="modal-buttons",
            ),
            id="load_result_dialog",
            classes="modal-dialog",
        )

    def _summary(self) -> Table:
        announcement = self.announcement
        grid = Table.grid()
        grid.add_column(width=_RESULT_KEY_WIDTH, no_wrap=True, style=DGRAY)
        grid.add_column()
        grid.add_row("Opened", safe_text(announcement.opened or "(no image)", "bold"))
        grid.add_row(
            "",
            Text(
                announcement.reason_text,
                style=GREEN if announcement.latest else YELLOW,
            ),
        )
        if announcement.relation:
            # LLR-178.1 / UX-26: the derived_from line (P-E verdict B).
            grid.add_row("", safe_text(announcement.relation, YELLOW))
        grid.add_row("Variants", Text(f"{announcement.count} in the project"))
        for index, name in enumerate(announcement.others):
            value = safe_text(name)
            if name in announcement.unreadable:
                # P-E verdict B: a variant the load could not read is marked
                # in the error colour beside its name.
                value.append("   not readable", style=RED)
            grid.add_row("Others" if index == 0 else "", value)
        for key, name in (("MAC", announcement.mac), ("A2L", announcement.a2l)):
            grid.add_row(key, safe_text(name) if name else Text("(none)", style=DGRAY))
        return grid

    @staticmethod
    def _problem_row(problem: "LoadProblem") -> Table:
        text = Text()
        text.append_text(safe_text(f"{problem.label}: ", YELLOW))
        text.append_text(safe_text(problem.file))
        text.append_text(safe_text(f"  {problem.detail}", DGRAY))
        grid = Table.grid()
        grid.add_column(width=_RESULT_MARK_WIDTH, no_wrap=True)
        grid.add_column()
        grid.add_row(Text("  ! ", style=YELLOW), text)
        return grid

    def on_mount(self) -> None:
        self.query_one("#result_body", VerticalScroll).focus()

    def action_close_result(self) -> None:
        self.dismiss(None)

    def action_select_variant(self) -> None:
        self.dismiss(LOAD_RESULT_SELECT_VARIANT)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "result_ok":
            self.dismiss(None)
        elif event.button.id == "result_variant":
            self.dismiss(LOAD_RESULT_SELECT_VARIANT)


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

#: batch-72 LLR-072-6.1 — the width at or above which the Legend renders its two
#: panes side by side. The SAME breakpoint the base screen uses for
#: ``width-narrow`` (``app.py::_apply_width_regime``, ``narrow = width < 120``);
#: the modal cannot reuse that class, because it is applied to
#: ``#workspace_shell`` / ``#workspace_body`` on the BASE screen and a pushed
#: ``ModalScreen`` is a descendant of neither — and textual 8.2.8 has no CSS
#: media queries.
_LEGEND_NARROW_WIDTH: int = 120


class LegendScreen(ModalScreen[None]):
    """Read-only classification-legend modal (HLR-023 / LLR-023.1; N8 cards).

    Summary:
        Per-view legend modal. The non-map views render their N8 annotated
        example card + the ``LEGEND_TABLE`` severity key (one bold sub-heading
        per artifact — A2L / MAC / Issues — one row per classification
        ``<classification> — <meaning>``, coloured through
        ``color_policy.css_class_for_severity`` so the in-app legend shows the
        same colours the views use). The MAP view renders its spec sheet
        instead (batch-93 HLR-132 — four grouped bordered boxes,
        :meth:`_render_map_sheet`). The body scrolls so the full content fits
        the 80- and 120-col regimes (C-13). Opened by the per-view Legend
        buttons / the ``k`` binding and dismissed by Close, by Esc
        (:meth:`action_close_legend` — HLR-132 / LLR-132.2) or the app-side
        pop; the ``LegendScreen(sections, view_key)`` constructor signature is
        unchanged since batch-51 (LLR-132.3).

    Data Flow:
        - Reads ``LEGEND_EXAMPLES`` / ``LEGEND_TABLE`` + ``COLOUR_SEVERITY``
          (s19_app.tui.legend) and, for the map sheet, the HLR-132 authored
          data + ``build_band_key_rows`` (live); colours via
          ``css_class_for_severity``.
        - Pushed by ``S19TuiApp.action_show_legend``, reached from the
          ``k`` binding (A2L, which has no button — C-13) and the
          ``#mac_legend_button`` / ``#issues_legend_button`` ids via
          ``on_button_pressed``; dismissed with ``None``.

    Dependencies:
        Uses:
            - s19_app.tui.legend (LEGEND_EXAMPLES / LEGEND_TABLE / COLOUR_SEVERITY
              / the HLR-132 sheet data / build_band_key_rows)
            - s19_app.tui.color_policy.css_class_for_severity
        Used by:
            - S19TuiApp.on_button_pressed
            - tests/test_tui_legend.py
    """

    BINDINGS = [
        Binding("escape", "close_legend", "Close", show=False),
    ]

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
                example card, or — for ``map`` — the batch-93 HLR-132 spec
                sheet. ``None`` preserves the exact pre-N8 render (no card).
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
            Render the colour key below the card: the ``LEGEND_TABLE`` severity
            key filtered by ``self._sections`` and painted through
            ``css_class_for_severity`` — the pre-N8 rows, now ``Static`` so
            long meanings wrap instead of truncating (HLR-N8-6). The map view
            never reaches this path: its ``k``-legend is the spec sheet
            (batch-93 HLR-132), rendered entirely by
            :meth:`_render_map_sheet` — band facts included, so this helper
            stays severity-only.

        Returns:
            List[Widget]: artifact-header + classification rows; possibly
            empty (an example-only view passed ``sections=()``).

        Data Flow:
            - Reads ``LEGEND_TABLE`` + ``COLOUR_SEVERITY``; colours via
              ``css_class_for_severity``.
            - Consumed by :meth:`compose`, placed below the example card.

        Dependencies:
            Uses:
                - LEGEND_TABLE / COLOUR_SEVERITY / css_class_for_severity
            Used by:
                - LegendScreen.compose
        """
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

    def _render_map_sheet(self) -> List[Widget]:
        """
        Summary:
            Render the map view's spec sheet (batch-93 HLR-132 / LLR-132.1) —
            the operator ruling of 2026-08-06 (legend A): four grouped,
            bordered boxes in ONE full-width scrolling column:

            1. **Entropy bands** — the band key DERIVED AT RENDER TIME from
               ``build_band_key_rows()`` (LLR-132.4's live-source law — never
               a hand-copied label list, so the sheet cannot drift from the
               band domain), each row column-aligned under the live-derived
               label/range widths, painted with its ``band-*`` class, plus the
               ``╱`` gap pseudo-row (:data:`BAND_GAP_FIELDS`) through the same
               alignment — and the box title carrying the live entropy window
               size from ``ENTROPY_WINDOW_BYTES``.
            2. **Map anatomy** — one rendered sample line per map surface →
               one dim meaning line each (band bar, ruler, glance chips, stats
               line), the samples' band glyphs derived live from
               ``band_style``.
            3. **Region row** — one shipped-fixed-width sample row
               (:data:`MAP_REGION_ROW_SAMPLE`, LLR-127.1's format) + its one-
               line field key.
            4. **Keys** — one line (:data:`MAP_KEYS_LINE`).

            Every line renders ``markup=False`` — the ``[lo,hi)`` ranges carry
            literal brackets (TC-N8-11's precedent) and no line needs markup.

        Returns:
            List[Widget]: the four ``.legend-sheet-box`` containers, in box
            order, each carrying its border title + line Statics.

        Data Flow:
            - Reads ``build_band_key_rows`` (live), ``BAND_GAP_FIELDS``,
              ``build_map_anatomy_samples``, ``MAP_REGION_ROW_SAMPLE``,
              ``MAP_REGION_ROW_FIELD_KEY``, ``MAP_KEYS_LINE`` and
              ``ENTROPY_WINDOW_BYTES`` — all READ-only (legend.py data +
              entropy_service).
            - Consumed by :meth:`compose`, which gives the sheet its own
              full-width single-pane dialog branch.

        Dependencies:
            Uses:
                - build_band_key_rows / BAND_GAP_FIELDS
                - build_map_anatomy_samples / MAP_REGION_ROW_SAMPLE
                - MAP_REGION_ROW_FIELD_KEY / MAP_KEYS_LINE
                - ENTROPY_WINDOW_BYTES
            Used by:
                - LegendScreen.compose (map ``view_key`` branch)
                - tests/test_legend_map_sheet.py
        """
        band_rows = build_band_key_rows()
        gap_glyph, gap_label, gap_range, gap_meaning = BAND_GAP_FIELDS
        # Column alignment DERIVED from the live rows (never hard-coded
        # widths): label/range columns wide enough for the longest live value
        # plus the gap pseudo-row, separated by two blanks.
        label_w = max([len(row.label) for row in band_rows] + [len(gap_label)]) + 2
        range_w = (
            max([len(row.range_text) for row in band_rows] + [len(gap_range)]) + 2
        )

        def _box(title: str, lines: List[Widget]) -> Container:
            box = Container(*lines, classes="legend-sheet-box")
            box.border_title = title
            return box

        def _line(text: str, classes: str = "legend-sheet-line") -> Static:
            return Static(text, markup=False, classes=classes)

        band_lines: List[Widget] = [
            _line(
                f"{row.glyph}  {row.label:<{label_w}}"
                f"{row.range_text:<{range_w}}{row.meaning}",
                classes=f"legend-row {row.css_class}".strip(),
            )
            for row in band_rows
        ]
        band_lines.append(
            _line(
                f"{gap_glyph}  {gap_label:<{label_w}}"
                f"{gap_range:<{range_w}}{gap_meaning}",
                classes="legend-row",
            )
        )
        anatomy_lines: List[Widget] = []
        for sample, meaning in build_map_anatomy_samples():
            anatomy_lines.append(_line(sample))
            anatomy_lines.append(
                _line(meaning, classes="legend-sheet-line legend-sheet-meaning")
            )
        region_lines = [
            _line(MAP_REGION_ROW_SAMPLE),
            _line(
                MAP_REGION_ROW_FIELD_KEY,
                classes="legend-sheet-line legend-sheet-meaning",
            ),
        ]
        keys_lines = [_line(MAP_KEYS_LINE)]
        return [
            _box(
                f"Entropy bands — {ENTROPY_WINDOW_BYTES} B windows, bits/byte",
                band_lines,
            ),
            _box("Map anatomy", anatomy_lines),
            _box("Region row", region_lines),
            _box("Map keys", keys_lines),  # batch-94: the box documents the MAP's keys; the title says so (operator feedback 2026-10-13)
        ]

    def compose(self) -> ComposeResult:
        """
        Summary:
            Two layouts from one constructor (the ``LegendScreen(sections,
            view_key)`` API survives unchanged — LLR-132.3). The MAP view
            renders its spec sheet (batch-93 HLR-132): a SINGLE full-width
            scrolling column of four bordered boxes — the sheet must not split
            across the two-pane split (its boxes span the dialog width, and
            the contract's no-wrap limb at the 80x24 floor needs every column
            the dialog can give: ``#legend_dialog.legend-sheet`` in
            ``styles.tcss`` carries the measured budget). Every OTHER view
            keeps the batch-72 two-pane body (example card left, colour key
            right — LLR-072-5.1).

        Returns:
            ComposeResult: the single ``#legend_dialog`` container; the map
            branch's ``#legend_body`` is the sheet's own scroll pane, the
            other views' is the two-pane wrapper (both preserve the
            ``#legend_body`` id the 9 descendant query sites select through).

        Data Flow:
            - Map: ``_render_map_sheet()`` widgets are re-parented into the
              sheet pane, never reconstructed.
            - Other views: ``_render_card()`` / ``_render_key()`` are called
              unchanged; their widgets are re-parented into the two panes,
              never reconstructed (LLR-072-7.1).

        Dependencies:
            Uses:
                - LegendScreen._render_map_sheet (map branch)
                - LegendScreen._render_card / LegendScreen._render_key
            Used by:
                - S19TuiApp.action_show_legend (screen push)
        """
        if self._view_key == "map":
            yield Container(
                Label("Classification legend", classes="modal-title"),
                ScrollableContainer(
                    *self._render_map_sheet(), id="legend_body"
                ),
                Container(
                    Button("Close", id="legend_close", classes="modal-confirm"),
                    id="legend_buttons",
                    classes="modal-buttons",
                ),
                id="legend_dialog",
                classes="modal-dialog legend-sheet",
            )
            return
        yield Container(
            Label("Classification legend", classes="modal-title"),
            Horizontal(
                ScrollableContainer(*self._render_card(), id="legend_card_pane"),
                ScrollableContainer(*self._render_key(), id="legend_key_pane"),
                id="legend_body",
            ),
            Container(
                Button("Close", id="legend_close", classes="modal-confirm"),
                id="legend_buttons",
                classes="modal-buttons",
            ),
            id="legend_dialog",
            classes="modal-dialog",
        )

    def _apply_width_regime(self, width: int) -> None:
        """
        Summary:
            Put the two-pane body in the regime ``width`` calls for: side by
            side above the breakpoint, stacked key-above-card below it
            (batch-72 LLR-072-6.1). The map spec-sheet branch has NO two-pane
            body — a single full-width column — so the regime hook is a no-op
            there (``#legend_card_pane`` / ``#legend_key_pane`` do not exist).

        Args:
            width (int): The terminal width in columns — the caller passes
                ``self.app.size.width``, NOT ``self.size.width``, which is 2
                smaller under ``Screen { padding: 1 }`` and would flip a
                120-column terminal into the narrow regime.

        Data Flow:
            - Toggles ``legend-narrow`` on ``#legend_dialog``, which is what the
              prefixed CSS rules key on.
            - Reorders the panes inside ``#legend_body`` with ``move_child``:
              textual 8.2.8 has no CSS ordering property, so document order IS
              the stacking order. Idempotent — the move is skipped when the
              wanted pane is already first, so every resize can call this.

        Dependencies:
            Used by:
                - LegendScreen.on_mount
                - LegendScreen.on_resize
        """
        if self._view_key == "map":
            return
        narrow = width < _LEGEND_NARROW_WIDTH
        self.query_one("#legend_dialog").set_class(narrow, "legend-narrow")
        body = self.query_one("#legend_body")
        card = self.query_one("#legend_card_pane")
        key = self.query_one("#legend_key_pane")
        first, second = (key, card) if narrow else (card, key)
        if body.children and body.children[0] is not first:
            body.move_child(first, before=second)

    def on_mount(self) -> None:
        self._apply_width_regime(self.app.size.width)
        self.query_one("#legend_close", Button).focus()

    def on_resize(self, event: events.Resize) -> None:
        """Re-apply the width regime when the terminal is resized."""
        self._apply_width_regime(self.app.size.width)

    def action_close_legend(self) -> None:
        """Dismiss the modal on ``Esc`` (HLR-132 / LLR-132.2) — the map spec
        sheet's contract-pinned close key; the binding is screen-level, so it
        serves every view's legend without an app-wide escape law (the app's
        ``on_key`` escape handling is gated on the six find/goto Inputs and is
        untouched by this)."""
        logger.info("LegendScreen dismissed by Esc.")
        self.dismiss(None)

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
          decimal int; an unparsable value is ignored (the Load dialog
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

    #: batch-95 change 3 (HLR-140) — while the Reports window (this modal)
    #: is focused, `?` opens ITS usage-help section instead of the app-wide
    #: stock HelpPanel; the binding is `show=False` and lives on the modal,
    #: so the global `question_mark` binding is untouched and still opens
    #: the panel everywhere else.
    BINDINGS = [
        Binding("question_mark", "show_window_usage_help", "Window help", show=False),
        Binding("escape", "close_reports", "Close", show=False),
    ]

    def action_show_window_usage_help(self) -> None:
        open_window_help(self.app, "reports")

    def action_close_reports(self) -> None:
        logger.info("ReportViewerScreen dismissed by Esc.")
        self.dismiss(None)

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
            titled_header(
                f"Reports (project '{self.project_name}'):",
                OpenFolderChip("reports"),
                title_classes="modal-title",
                help_button=WindowHelpChip("reports"),
            ),
            listing,
            ScrollableContainer(
                Markdown(
                    "",
                    open_links=False,
                    parser_factory=_hardened_markdown_parser,
                    id="report_markdown",
                ),
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
                OsClipboardInput(
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
            is ignored (the Load dialog empty-input pattern).

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
            OsClipboardInput(
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
