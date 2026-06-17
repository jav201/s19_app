from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Tuple

from textual import work
from textual.app import ComposeResult
from textual.containers import Container, ScrollableContainer
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Input,
    Label,
    ListItem,
    ListView,
    Markdown,
    Static,
    TextArea,
)

from .hexview import MAX_HEX_ROWS, render_hex_view_text
from .models import LoadedFile
from .operations.crc_config import DUMMY_CONFIG_TEXT, parse_crc_config
from .operations.model import CrcRegionResult, OperationInput, OperationResult
from .services import operation_service
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
    """Parent directory (as entered or browsed) and project folder name for save."""

    parent_folder: str
    project_name: str


class LoadFileScreen(ModalScreen[Optional[Path]]):
    """Modal dialog for loading S19/HEX/MAC data files or an A2L file.

    Re-skinned to the Calm Dark theme in batch-02 increment 8 (LLR-015.1):
    the dialog carries the shared ``.modal-dialog`` class so it picks up the
    Calm Dark accent border, panel background and foreground tokens from
    ``styles.tcss``. Behavior is unchanged (LLR-015.2).
    """

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load file (S19/HEX/MAC/A2L):", classes="modal-title"),
            Input(
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


class SaveProjectScreen(ModalScreen[Optional[SaveProjectPayload]]):
    """Modal dialog for destination folder, optional browse, and project name.

    Re-skinned to the Calm Dark theme in batch-02 increment 8 (LLR-015.1):
    the dialog carries the shared ``.modal-dialog`` class. Behavior — the
    browse fallback, ``SaveProjectPayload`` construction and the
    ``.s19tool/`` workarea destination — is unchanged (LLR-015.2 / A-5).
    """

    def __init__(self, default_parent: Path) -> None:
        super().__init__()
        self.default_parent = default_parent

    def compose(self) -> ComposeResult:
        yield Container(
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
            Input(placeholder="letters, numbers, - _", id="project_name"),
            Container(
                Button("Save", id="save_ok", classes="modal-confirm"),
                Button("Cancel", id="save_cancel"),
                id="saveproject_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#project_parent_path", Input).value = str(self.default_parent)

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
            self.dismiss(SaveProjectPayload(parent_folder=parent, project_name=name))


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

        def __init__(self, context_bytes: int) -> None:
            super().__init__()
            self.context_bytes = context_bytes

    def __init__(self, project_name: str, reports: List[Path]) -> None:
        super().__init__()
        self.project_name = project_name
        self.reports = reports
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
            # Posted straight to the app's queue (not bubbled) so the
            # immediately following dismiss can never drop it.
            self.app.post_message(self.GenerateRequested(context_bytes))
            self.dismiss(None)


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
            TextArea(DUMMY_CONFIG_TEXT, id="operation_config"),
            Static("", id="operation_result_status", markup=False),
            ScrollableContainer(
                Static("", id="operation_result_hex"),
                id="operation_result_hex_scroll",
            ),
            Container(
                Button("Execute", id="operations_execute", classes="modal-confirm"),
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
              ``display`` style of ``#operation_config_label`` and
              ``#operation_config``.

        Dependencies:
            Used by:
                - on_mount / on_list_view_highlighted
        """
        is_crc = self._selected_operation_id() == self.CRC_OPERATION_ID
        self.query_one("#operation_config_label", Label).display = is_crc
        self.query_one("#operation_config", TextArea).display = is_crc

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "operations_close":
            logger.info("OperationsScreen dismissed by close.")
            self.dismiss(None)
            return
        if event.button.id == "operations_execute":
            self._execute_selected()

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
                self.workers.cancel_group(self, "crc_operation")
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
