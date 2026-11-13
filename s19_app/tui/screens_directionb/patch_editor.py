"""s19_app.tui.screens_directionb.patch_editor — PatchEditorPanel (moved verbatim from s19_app/tui/screens_directionb.py at 4f721985)."""
from __future__ import annotations

from typing import List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union
from rich.cells import cell_len
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    Input,
    Label,
    Select,
    Static,
    TextArea,
)
from ..a2l import MAX_A2L_DECODE_BYTES
from ..a2l_parameter_picker import A2LParameterPicker, clip_tail
from ..screens import BulkParameterAddScreen
from ..changes.io import DUMMY_CHANGESET_TEXT
from ..insight_style import (
    CYAN,
    DGRAY,
    GREEN,
    LABEL,
    PURPLE,
    RED,
    VALUE,
    YELLOW,
    cap_gauge_style,
    label_value,
    microbar,
)
from ..json_highlight import JsonHighlightTextArea
from ..os_clipboard_input import _CLIPBOARD_READ_CAP_CHARS
from ..os_clipboard_input import OsClipboardInput
from ...utils import safe_text
from . import deps
from .shared import (
    _clip_to_cells,
    CARD_UNMAPPED_TOKEN,
    STRIP_ROW_BYTES,
    before_after_card_text,
    cap_json_lines,
    CheckLayout,
    check_layout,
    TabChip,
)


class _Unset:
    """Sentinel type for "argument not supplied" (batch-48 LLR-080.2).

    ``None`` cannot serve: it is a MEANINGFUL value for ``mem_map`` — "no
    image is loaded" (LLR-080.4) — and conflating it with "not supplied" is
    the bug. ``refresh_entries`` has FIVE call sites and one of them (the
    panel's own ``on_mount`` self-call) has no ``mem_map`` to give; an
    unconditional retain would let that call NULL a map a real load had
    already supplied. Sentinel ⇒ preserve; explicit ``None`` ⇒ clear.
    """


_UNSET = _Unset()

#: The before/after strip's neutral states (batch-48 LLR-080.4; batch-97
#: D5 (h), LLR-148.9). Author-fixed literals, each at most 38 cells (the
#: card's content width at 118 columns) — nothing file-derived reaches the
#: card (LLR-080.7).
CARD_NO_ENTRIES = "No entry yet: Add one or Load a file."


class BeforeAfterCard(Static):
    """The inspector's before→after hex strip (batch-48 LLR-080.1; batch-97 D5).

    Summary:
        A read-only card at the top of the Patch Editor's Inspector pane
        (batch-97 moved it there from the JSON window, D5). Selecting a ledger
        row shows the image bytes at that entry's span beside the bytes the
        entry would write, as the stacked pe_A grid of
        :func:`before_after_card_text` — live, BEFORE any apply. It applies
        nothing (LLR-080.5). Its ``border-top`` row carries the title
        ``BEFORE → AFTER``, so the title costs no row. Height is the content's
        (no cap): the strip itself caps its rows (``STRIP_ROW_CAP``).

    Note (Textual internal-name shadowing):
        The only members added are the public ``show_entry`` / ``show_state``
        methods and ``on_mount`` — no Widget private name is introduced
        (TC-080.1).
    """

    DEFAULT_CSS = """
    BeforeAfterCard {
        height: auto;
        padding: 0 1;
        border-top: solid $panel;
    }
    """

    def on_mount(self) -> None:
        self.border_title = "BEFORE → AFTER"

    def show_entry(
        self,
        address: Optional[int],
        before: Optional[Sequence[Optional[int]]],
        after: Sequence[int],
        per_row: int = 8,
        lead: Sequence[Optional[int]] = (),
        trail: Sequence[Optional[int]] = (),
    ) -> None:
        """Update the card to preview one entry (LLR-080.3/.4, D5)."""
        self.update(
            before_after_card_text(address, before, after, per_row, lead=lead, trail=trail)
        )

    def show_state(self, line: str) -> None:
        """Paint one of the card's author-fixed state lines (LLR-148.9)."""
        self.update(Text(line, style=DGRAY))


class PatchEditorPanel(ScrollableContainer):
    """Consolidated Patch Editor rail screen — the single v2 change flow.

    Summary:
        Lays out the Direction B Patch Editor as **one** change-flow section
        operating on v2 ``s19app-changeset`` JSON documents (LLR-003.1,
        batch-07 increment E3a): an entries ``DataTable`` (kind / address /
        value-or-bytes / status / linkage), address + string-value + bytes
        ``Input`` fields wired to add / edit / remove for **both** entry
        kinds, and one control row — Load / Validate / Apply / Save /
        Run checks — over a change-file path ``Input``. The batch-03
        parameter section, the ``.cdfx`` file row, and the batch-04
        selective-export control no longer exist (HLR-003 statement 2).

        Two further surfaces ride the panel:

        - **Declaration faults** (LLR-002.8) — a persistent fault listing
          plus a count line, re-rendered from the service's issue store
          after every action and cleared only by a clean re-validate or a
          clean re-load; never a transient status-line-only message.
        - **Save-back prompt** (LLR-002.7 UI half) — an inline row, hidden
          until an apply writes ≥1 entry on an S19 image, carrying an
          editable filename ``Input`` pre-filled with the
          ``<variant_id>-patched.s19`` suggestion and confirm / decline
          buttons that post a :class:`SaveBackDecision` message.
        - **Check results** (LLR-004.5) — one ``Static`` row per check
          entry coloured by its ``sev-*`` class, plus an aggregate-count
          status line.

        The panel stays **presentational**: a control press does not call
        the ``changes`` package directly — it posts an
        :class:`ActionRequested` (or :class:`SaveBackDecision`) message that
        ``app.py`` handles by calling ``services.change_service``; the
        screen then receives display rows back via the ``refresh_*``
        methods. No JSON / model logic lives in this widget (constraint
        C-7).

    Args:
        None

    Returns:
        None

    Data Flow:
        - Every control posts ``ActionRequested``; ``app.py`` routes it to
          ``ChangeService`` and calls :meth:`refresh_entries` /
          :meth:`refresh_issues` (and :meth:`refresh_check_results` after a
          check run) with the shaped results.
        - The save-back confirm / decline controls post
          ``SaveBackDecision`` — deliberately **not** an ``ActionRequested``
          action, so the routed action set stays exactly the LLR-003.2
          eight plus the single E6 extension (``execute_scope`` — nine
          total, F-A-15). The scope-cycling button is selector state only
          and posts no message.

    Dependencies:
        Used by:
            - ``S19TuiApp._compose_screen_patch`` / ``S19TuiApp`` action
              wiring

    Example:
        >>> panel = PatchEditorPanel()
        >>> panel.id
        'patch_editor_panel'
    """

    #: The ledger's empty-state line (LLR-148.9): one English line, short
    #: enough for the 118-column ledger (65 cells), so it never wraps.
    EMPTY_STATE_TEXT = "No entries yet: Add one, paste a change-set or Load a file."

    #: The JSON view's state before any document reaches it (D4 (4), LLR-148.9).
    JSON_VIEW_EMPTY_TEXT = "No document yet: Load, paste or Add."

    #: The Checks tab's state line before any run (LLR-148.9).
    CHECKS_NO_RUN_TEXT = "No check run yet: press Run checks."

    #: The inspector's four tabs: (chip id, label, pane id, border title).
    #: The A2L tab (batch-102 Inc 5, US-102-05) embeds the shared parameter
    #: picker in pick mode beside the Check Editor's pick-mode one.
    _TABS = (
        ("patch_tab_inspector", "Inspector", "patch_pane_inspector", "INSPECTOR"),
        ("patch_tab_json", "JSON", "patch_win_json", "JSON"),
        ("patch_tab_checks", "Checks", "patch_win_checks", "CHECKS"),
        ("patch_tab_a2l", "A2L", "patch_win_a2l", "A2L"),
    )


    _ENTRIES_COLUMNS = ("Kind", "Address", "Value / bytes", "Status", "Linkage")

    #: Check-glyph → render style (batch-48 LLR-077.3). The glyph is FOLDED
    #: into the ``Kind`` cell as its own leading span, so this map lives at the
    #: render boundary while ``ChangeService`` owns the token → glyph half —
    #: the panel imports nothing from the service layer (C-7 purity).
    #:
    #: The two halves are keyed on the same 4 characters in two modules, so
    #: ``test_tui_patch_glyphs.py::test_tc077_3_glyph_map`` asserts they stay
    #: TOTAL over each other. Without that guard a glyph renamed on the service
    #: side would fall through to the ``·`` style and mis-colour silently.
    _GLYPH_STYLE = {
        "✓": GREEN,
        "✗": RED,
        "◐": YELLOW,
        "·": DGRAY,
    }

    #: Cell budget for the CHECKS pass/fail strip's bar (LLR-078.1).
    #:
    #: ⚠ RESOLVED at Inc-5 (the Inc-4 F1 note is superseded; its history is in
    #: the increment record). The strip is an INTENTIONAL TWO-LINE widget:
    #: counts on line 1, bar on line 2. The C-29 measurement chain that forces
    #: it, RE-MEASURED at Inc-5 against the real container:
    #:
    #:   120x30  window w=22 → body interior w=18 → STRIP CONTENT w=14
    #:    80x24  window w=68 → body interior w=66 → STRIP CONTENT w=62
    #:
    #: **14 is the budget at 120x30 — the batch's primary regime.** Two figures
    #: above it were each one container too generous: 22-23 is the WINDOW width
    #: (``test_tui_patch_layout.py:56-58``, which Inc-4 sized 8 cells against),
    #: and 16 is the BODY's content width. Each level costs borders + padding.
    #:
    #: The one-line layout does not fit at ANY separator width: the counts
    #: alone are 15 chars at the old spacing, and even the tightest form
    #: (``✓123 ✗456 ◐789`` = 14 exactly) leaves 0 cells for a bar. Worse, the
    #: old one-line form did not merely overflow — it wrapped MID-TOKEN once a
    #: count reached 2 digits, orphaning ``◐`` from its number and making the
    #: number read as a label on the bar:
    #:
    #:   agg 12/34/56 → line0 '✓ 12  ✗ 34  ◐ '   line1 '56  █░░░░░░░  '
    #:
    #: That is a WRONG-ANSWER defect on a verdict surface, reachable by any
    #: change-set with >= 10 entries — not an overflow nuisance. Making the two
    #: lines intentional costs nothing at 120x30 (h=2 is what already painted)
    #: and one scrolled row at 80x24, and it removes the mid-token wrap.
    #:
    #: REJECTED: responsive width (needs geometry in the builder — a
    #: first-layout-0 hazard, and it breaks the ``__new__`` unit tests) ·
    #: dropping the bar (fits, but guts HLR-078's proportional bar — an
    #: acceptance relaxation, not an implementation choice).
    _CHECK_STRIP_BAR_CELLS = 8

    #: The history strip's key-hint line (LLR-081.2). The two bindings are the
    #: batch-40 S2 ``ctrl+z`` / ``ctrl+y`` pair; this batch adds NO App-level
    #: ``Binding(show=True)``, so the hint is panel-local text and C-28's
    #: shared-chrome census does not fire (LLR-081.4).
    _HISTORY_HINT = "ctrl+z / ctrl+y"
    #: The history strip's DISABLED line. Shown whenever the Undo/Redo buttons
    #: are disabled — today the batch-38 A-01 file-backed guard, but the panel
    #: is a view and is told the STATE, not the reason, so this text names
    #: neither. It carries no key hints: the same guard gates the bindings, so
    #: the keys are inert and a hint for them would be a wrong answer.
    _HISTORY_OFF = "history off"

    #: The history strip's TWO-LINE shape — position on line 1, key hints on
    #: line 2 — is intentional, and the C-29 budget it is measured against is
    #: the SCRIPT window's, NOT the CHECKS window's. MEASURED at Inc-6 with the
    #: strip mounted (`region` / `content_region` off the live tree):
    #:
    #:   120x30  #patch_history_controls content w=38 → STRIP CONTENT w=38
    #:    80x24  #patch_history_controls content w=64 → STRIP CONTENT w=64
    #:
    #: **38 is the budget — do NOT inherit ``_CHECK_STRIP_BAR_CELLS``'s 14.**
    #: That 14 is the CHECKS window's content width at 120x30, and at that
    #: regime the patch layout is a 3-column split in which the SCRIPT window is
    #: nearly three times wider (44 vs 22). Inheriting a figure measured on a
    #: sibling container is precisely the C-29 error, and the record was sitting
    #: right there in `_CHECK_STRIP_BAR_CELLS` inviting it.
    #:
    #: Line 1's worst case is bounded WITHOUT a width assumption: ``back`` and
    #: ``forward`` are snapshot counts that `_push_history` evicts at
    #: `_HISTORY_MAX` (20) and `undo`/`redo` conserve, so ``back + forward <=
    #: 20`` and every count is at most 2 digits. The widest reachable line 1 is
    #: ``↶ 20 back  ↷ 0 fwd  20/20`` = 25 cells; line 2 is 15. Both clear 38
    #: with room, so the two lines are a READING-ORDER choice (position, then
    #: how to move it), not a wrap workaround like the CHECKS strip's.
    _HISTORY_STRIP_BUDGET_COLS = 38

    #: The shared 64 KiB paste cap, in CHARS (LLR-079.4). Aliased from the
    #: single source (``os_clipboard_input.py:72``) rather than re-spelled, so
    #: the gauge's denominator and the truncation it predicts cannot drift.
    _PASTE_CAP_CHARS = _CLIPBOARD_READ_CAP_CHARS
    #: Percent-of-cap cutoffs for the gauge's escalation (:func:`cap_gauge_style`).
    #: ``100`` is lower-inclusive, so AT the cap — the first point at which the
    #: next pasted character is silently dropped — already reads bold.
    _PASTE_GAUGE_WARN_PCT = 75.0
    _PASTE_GAUGE_BAD_PCT = 100.0

    #: The E6 execution scopes in selector cycle order (LLR-006.6) and their
    #: button labels. The scope tokens are the service vocabulary
    #: (``variant_execution_service.EXECUTION_SCOPES``) spelled locally so
    #: this view widget imports nothing from the service layer.
    EXECUTE_SCOPES = ("active", "all", "assignments")
    _SCOPE_LABELS = {
        "active": "active variant",
        "all": "all variants",
        "assignments": "per assignment",
    }

    #: The ledger window's border title (LLR-075.1). CONSTANT author string —
    #: never file-derived (C-17). batch-97: the inspector's title follows the
    #: active tab (``_TABS``); the JSON and CHECKS panes have no border.
    _WINDOW_BORDER_TITLES = {
        "patch_win_script": "PATCH SCRIPT",
    }

    #: The JSON tab's subtitle on the inspector border (LLR-075.1) — the
    #: change-set schema token, spelled locally (C-7).
    _JSON_SCHEMA_SUBTITLE = "v2 schema"

    #: The CHECKS pane's subtitle before any check run (LLR-075.1).
    _NO_RUN_SUBTITLE = "no run yet"

    #: The save-back S19 record widths in selector cycle order (US-015 /
    #: LLR-015.3). 32 is the default (the populated-S0 / 32-byte mode); 16 is
    #: the legacy empty-S0 / 16-byte mode. Spelled locally so this view widget
    #: imports nothing from the engine or service layer.
    SAVEBACK_WIDTHS = (32, 16)

    #: The DOCUMENT tally's bar width (pe_A, design §3).
    _TALLY_BAR_CELLS = 12

    # Layout rules for the v2 widget ids live in styles.tcss, in the one
    # scoped section ``/* batch-97 patch_editor */`` (D23).


    class ActionRequested(Message):
        """A Patch Editor control was triggered — ``app.py`` should act.

        Summary:
            Posted by the entry add / edit / remove controls and the
            document control row. The widget carries **no**
            ``changes``-package logic; this message hands the action and
            the current input-field values to ``app.py``, which calls
            ``ChangeService`` and feeds the shaped rows back via the
            panel's ``refresh_*`` methods. The routable action set is
            exactly the LLR-003.2 v2 eight at E3a (extended by
            ``execute_scope`` at E6).

        Args:
            action (str): One of ``"add_entry"`` / ``"edit_entry"`` /
                ``"remove_entry"`` / ``"load_doc"`` / ``"validate_doc"`` /
                ``"apply_doc"`` / ``"save_doc"`` / ``"run_checks"``.
            address_text (str): The entry-address input's current text.
            value_text (str): The string-value input's current text.
            bytes_text (str): The hex-bytes input's current text.
            path_text (str): The change-file path input's current text —
                used by the ``"load_doc"`` action.
            scope_text (str): The execution scope the selector currently
                shows (one of ``EXECUTE_SCOPES``) — used by the E6
                ``"execute_scope"`` action; empty default keeps the E3a
                constructions unchanged.
            paste_text (str): The paste ``TextArea``'s current text — used
                by the batch-13 ``"parse_paste"`` action (LLR-014.2); empty
                default keeps the prior constructions unchanged.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_action_requested``
        """

        def __init__(
            self,
            action: str,
            address_text: str = "",
            value_text: str = "",
            bytes_text: str = "",
            path_text: str = "",
            scope_text: str = "",
            paste_text: str = "",
        ) -> None:
            super().__init__()
            self.action = action
            self.address_text = address_text
            self.value_text = value_text
            self.bytes_text = bytes_text
            self.path_text = path_text
            self.scope_text = scope_text
            self.paste_text = paste_text

    class SaveBackDecision(Message):
        """The operator answered the post-apply save prompt (LLR-002.7).

        Summary:
            Posted by the save-back confirm / decline buttons. Deliberately
            a separate message class — not an ``ActionRequested`` action —
            so the LLR-003.2 routed action set stays exactly eight at E3a.

        Args:
            filename (Optional[str]): The (possibly edited) target filename
                when the operator confirmed; ``None`` when declined — the
                app persists nothing and ``ChangeSummary.saved_path`` stays
                ``None``.
            bytes_per_line (int): The data-bytes-per-S19-record width the
                operator selected (``{16, 32}``, default 32) — carried only on
                a confirm so ``app.py`` can thread it (and the matching S0
                policy) into ``ChangeService.save_patched`` (US-015 / LLR-015.3).

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_save_back_decision``
        """

        def __init__(
            self, filename: Optional[str], bytes_per_line: int = 32
        ) -> None:
            super().__init__()
            self.filename = filename
            self.bytes_per_line = bytes_per_line

    class BeforeAfterReportRequested(Message):
        """The operator activated the persistent before/after control (US-061).

        Summary:
            Posted by the ``#patch_before_after_button`` in the persistent
            report row revealed after a successful save-back (LLR-061.1).
            Carries no payload — it is a pure trigger: ``app.py`` routes it to
            the single existing ``action_before_after_report`` writer
            (LLR-061.2), so the control adds no new report-writing code and the
            ``b`` accelerator stays bound to the same handler.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_before_after_report_requested``
        """

    class EditJsonRequested(Message):
        """The operator activated the "Edit JSON" control (US-064b).

        Summary:
            Posted by ``#patch_edit_json_button`` to open the full-size JSON
            popup (``ChangeSetJsonScreen``) over the current paste buffer
            (LLR-064b.1). Carries the ``#patch_paste_text`` contents so the app
            can seed the popup without a second query. The button is DISABLED
            whenever a file-backed document is loaded (LLR-064b.4 A-01
            data-loss guard), so this message is only posted for a
            paste-authored / empty document; the app re-checks the guard
            predicate defensively before pushing the popup.

        Args:
            paste_text (str): The current ``#patch_paste_text`` buffer — the
                paste-authored change-set JSON to seed the popup editor with.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_edit_json_requested``
        """

        def __init__(self, paste_text: str = "") -> None:
            super().__init__()
            self.paste_text = paste_text

    class ChangeFileSelected(Message):
        """The operator picked a change file from the patches dropdown (US-026).

        Summary:
            Posted when ``#patch_doc_file_select`` fires ``Select.Changed`` with
            a concrete filename (not the blank sentinel). Carries the listed
            value only (``checks/<n>``, ``patches/<n>`` or ``library/<n>`` in a
            project; the bare name without one) — the panel owns no
            ``changes``-package logic and no path resolution; ``app.py``
            resolves the value against its homes through the pick guard
            (``_resolve_listed_file``) and routes it through the existing
            ``ChangeService.load`` path. Blank / cleared selections
            post nothing (a blank is not a load request).

        Args:
            filename (str): The chosen change-file's bare component
                (``match.name``), e.g. ``"changes.json"``.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_change_file_selected``
        """

        def __init__(self, filename: str) -> None:
            super().__init__()
            self.filename = filename

    class UndoRequested(Message):
        """The operator activated the change-set Undo control (US-068a).

        Summary:
            Posted by ``#patch_undo_button`` — routed to
            ``ChangeService.undo()`` (LLR-068a.2/.3). Carries no payload: it is
            a pure trigger, so ``app.py`` restores the prior change-set and
            re-renders the entries table. The button is DISABLED whenever a
            file-backed document is loaded (LLR-068a.4 A-01 data-loss guard),
            so this message is only posted for a paste-authored / empty
            document.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_undo_requested``
        """

    class RedoRequested(Message):
        """The operator activated the change-set Redo control (US-068a).

        Summary:
            Posted by ``#patch_redo_button`` — routed to
            ``ChangeService.redo()`` (LLR-068a.2/.3). Carries no payload: it is
            a pure trigger, so ``app.py`` re-applies the undone change-set and
            re-renders the entries table. DISABLED for a file-backed document
            (LLR-068a.4 A-01 guard), mirroring :class:`UndoRequested`.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_redo_requested``
        """

    class EntryEditJsonRequested(Message):
        """The operator activated the per-entry Edit-JSON control (US-068b).

        Summary:
            Posted by ``#patch_entry_edit_json_button`` — the per-entry JSON
            control (LLR-068b.1), DISTINCT from the whole-set
            ``#patch_edit_json_button`` and the field-populate
            ``#patch_entry_edit_button``. Carries the SELECTED row index of
            ``#patch_doc_entries_table`` so ``app.py`` seeds ``EntryJsonScreen``
            with that one entry's JSON and routes Confirm through the validated
            per-entry apply (``ChangeService.edit_entry_json``). The button is
            DISABLED whenever a file-backed document is loaded (LLR-068b.4 A-01
            data-loss guard), so this message is only posted for a
            paste-authored / empty document; with no rows the panel posts
            nothing (no selection is a no-op).

        Args:
            index (int): The zero-based index of the selected entry row.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_entry_edit_json_requested``
        """

        def __init__(self, index: int) -> None:
            super().__init__()
            self.index = index

    def __init__(self) -> None:
        super().__init__(id="patch_editor_panel")
        #: The A2L parameter picker (batch-102 Inc 5, US-102-05): the shared
        #: selector in pick mode with include and bulk controls, namespaced
        #: ``patch_param_*`` so it mounts beside the Check Editor's
        #: ``check_param_*`` picker without duplicate ids (R-B102-PE-002).
        #: The panel stays the host: it injects the A2L tab's width derivation
        #: as ``layout_provider`` (a one-way call — the provider reads cached
        #: scalars, never picker entry points), hosts the shared bulk modal
        #: without document writes, and transfers the highlighted row into the
        #: entry form on ``Use parameter`` (R-B102-PE-003).
        self._a2l_picker = A2LParameterPicker(
            id_prefix="patch_param",
            mode="pick",
            show_include_button=True,
            show_bulk_button=True,
            layout_provider=self._a2l_widths,
        )
        #: The last derived A2L-tab widths; ``None`` until the tab is measured.
        self._a2l_layout: Optional[CheckLayout] = None
        #: The last ``Use parameter`` outcome line painted on
        #: ``#patch_param_use_status`` (the single status surface, E3
        #: ruling 7); empty until the first use.
        self._a2l_use_status: str = ""
        #: The execution scope the selector currently shows (LLR-006.6) —
        #: cycled by ``#patch_execute_scope_button``; carried on the
        #: ``execute_scope`` ``ActionRequested``.
        self._execute_scope: str = self.EXECUTE_SCOPES[0]
        #: The save-back S19 record width the selector currently shows
        #: (US-015 / LLR-015.3) — cycled by ``#patch_saveback_width_button``;
        #: carried on the ``SaveBackDecision``. Defaults to 32.
        self._saveback_width: int = self.SAVEBACK_WIDTHS[0]
        #: The dirty flag (batch-94, LLR-005.1). Set while unsaved edits exist
        #: in EITHER editor region (the entries or the paste buffer); cleared
        #: by a successful save or load. Readers in this module: the Load guard,
        #: the ledger's border subtitle and the JSON stamp (batch-97 D4).
        #: Outside this module it is read only through ``is_dirty``
        #: (LLR-174.1c), by three readers: the app's load guard,
        #: ``_handle_save_dialog`` and the change-file dropdown guard
        #: (LLR-174.2t).
        #: Writer census (C-15.1, five sites): w1 ``request_action`` (entry
        #: edit) · w2 ``on_text_area_changed`` (paste typing) · w3
        #: ``mark_saved`` · w4 ``mark_loaded`` · w5 ``mark_pasted`` (Parse
        #: pasted, batch-97 Inc-4).
        self._dirty: bool = False
        #: The loaded image's sparse memory map, RETAINED from
        #: ``refresh_entries``' parameter for the before/after strip
        #: (batch-48 LLR-080.2). ``None`` is MEANINGFUL — "no image loaded" —
        #: which is why that parameter's default is a sentinel. The panel never
        #: fetches this itself (C-7): it arrives as data, or not at all.
        self._mem_map: Optional[Mapping[int, int]] = None
        #: The rows last rendered into the entries table, retained so the strip
        #: resolves the highlighted row POSITIONALLY (LLR-080.3).
        self._entry_rows: List[object] = []
        #: batch-97 D4 (1): (entry count, ``HH:MM:SS``, uncapped json text) of
        #: the document the JSON view last painted; ``None`` until the first
        #: document push (the fresh-start state).
        self._json_shown: Optional[Tuple[int, str, str]] = None
        #: batch-97 D21: the last derived widths; ``None`` until measured.
        self._layout: Optional[PatchLayout] = None
        #: batch-97 LLR-144.7: the document identity the ribbon paints.
        self._identity: Tuple[Optional[str], str] = (None, "change")

    def set_change_files(self, names: Sequence[str]) -> None:
        """Populate the change-file dropdown with the patches-folder files.

        Summary:
            Replace the ``#patch_doc_file_select`` options with one blank-prompt
            entry per change-file name (LLR-030.2), so the operator can pick a
            file instead of typing its path. Called by ``app.py`` on patch-screen
            activation and after each save (LLR-030.3 / R2). This is the ONLY
            populator of the dropdown; a panel never handed a scan keeps its
            empty (blank-prompt) option set — the bare-construction invariant
            (W2). An empty ``names`` clears every option, leaving the blank
            state (``allow_blank=True``), so an empty patches folder renders a
            valid placeholder dropdown without crashing (AT-030b / W1).

        Args:
            names (Sequence[str]): The change list's listed values
                (``*.json``): ``checks/<n>``, ``patches/<n>`` and
                ``library/<n>`` with a project open, the bare names of
                ``workarea/patches/`` without one, already ordered by the
                caller. The option value equals the
                name, so the ``Select.Changed`` handler forwards it verbatim.

        Returns:
            None

        Data Flow:
            - Map each name to a ``(safe_text(name), name)`` option pair and
              hand them to the ``Select`` via ``set_options``; an empty list
              clears the options, and Textual falls back to the blank prompt.
              The VALUE stays the bare ``str`` — the ``Select.Changed`` handler
              forwards it verbatim and never renders it.

        Dependencies:
            Uses:
                - ``safe_text``
                - ``textual.widgets.Select.set_options``
            Used by:
                - ``S19TuiApp._prefill_patch_change_files``

        Example:
            >>> panel.set_change_files(["changes.json", "changes-1.json"])
        """
        # C-17 (Inc-1b — the THIRD site of the class the Inc-1 security review
        # measured): the option LABEL is a FILENAME read off disk
        # (`S19TuiApp._scan_patch_change_files()` reads the filenames over
        # `workarea/patches/`), so anyone who can drop a file into the work
        # area names it. `Select._watch_value` hands the label to
        # `SelectCurrent.update(prompt)` (`_select.py:615`) -> a markup-enabled
        # `Static` -> `Content.from_markup` (`visual.py:103`). Measured at
        # `textual==8.2.8`: `[red]PWNED[/red]` -> plain 'PWNED' +
        # Span(0,5,'red'); `[/nope]` and `[link=…]` -> `MarkupError` out of
        # `set_change_files`. `update` takes a `RenderableType`, so a literal
        # `Text` label is passed through unparsed — same fix shape as
        # `set_variants` below.
        options = [(safe_text(str(name)), name) for name in names]
        self.query_one("#patch_doc_file_select", Select).set_options(options)

    def compose(self) -> ComposeResult:
        """Lay out the Patch Editor as a ledger + inspector (HLR-144, pe_A).

        Summary:
            The batch-97 composition (design §3, Patch Editor tree): an
            identity ribbon; the full-height PATCH SCRIPT ledger (``3fr``)
            beside the inspector (``2fr``) whose Inspector / JSON / Checks /
            A2L tab chips switch one ``ContentSwitcher``; then the file row,
            the document controls and the glyph legend, one terminal row
            each. Every shipped id is kept (LLR-144.1) and each
            ``patch_win_*`` / ``patch_saveback_row`` /
            ``patch_before_after_row`` / ``patch_checks_results`` id keeps
            its ``Container`` type. Geometry lives in ``styles.tcss`` (one
            scoped section, D23); Python sizes only the ledger columns and
            the strip's bytes per row (D21).

        Returns:
            ComposeResult: The widget tree.
        """
        yield Static(
            "", id="patch_identity_ribbon", classes="nowrap-ribbon", markup=False
        )
        with Horizontal(id="patch_main"):
            with Container(id="patch_win_script") as script:
                script.border_title = self._WINDOW_BORDER_TITLES["patch_win_script"]
                with VerticalScroll(id="patch_win_script_body") as script_body:
                    script_body.can_focus = False
                    with Container(id="patch_pane_entries"):
                        yield DataTable(
                            id="patch_doc_entries_table",
                            zebra_stripes=True,
                            cursor_type="row",
                            classes="nowrap-ledger",
                        )
                        yield Static(
                            self.EMPTY_STATE_TEXT,
                            id="patch_doc_empty_state",
                            markup=False,
                        )
            with Vertical(id="patch_inspector") as inspector:
                inspector.border_title = self._TABS[0][3]
                with Horizontal(id="patch_tabs"):
                    for chip_id, label, _pane, _title in self._TABS:
                        yield TabChip(
                            label,
                            id=chip_id,
                            classes="tab-chip chip-selected"
                            if chip_id == "patch_tab_inspector"
                            else "tab-chip",
                        )
                with ContentSwitcher(
                    initial="patch_pane_inspector", id="patch_tab_switcher"
                ):
                    with VerticalScroll(id="patch_pane_inspector") as pane:
                        pane.can_focus = False
                        yield BeforeAfterCard(id="patch_before_after_card")
                        with Vertical(id="patch_doc_entry_inputs"):
                            for label, input_id, placeholder in (
                                ("Address", "patch_entry_address_input", "0x100"),
                                ("String", "patch_entry_value_input", "text (document encoding)"),
                                ("Bytes", "patch_entry_bytes_input", "hex bytes, e.g. DE AD BE EF"),
                            ):
                                with Horizontal(classes="pe-row"):
                                    yield Label(label, classes="pe-label")
                                    # batch-31 AC-2 (B-03): OsClipboardInput so
                                    # Ctrl+V pastes through the bounded funnel.
                                    yield OsClipboardInput(
                                        placeholder=placeholder,
                                        id=input_id,
                                        compact=True,
                                    )
                        with Horizontal(
                            id="patch_doc_entry_buttons",
                            classes="patch-docked-row patch-chip-entry",
                        ):
                            yield Button("Add", id="patch_entry_add_button", classes="patch-chip")
                            yield Button("Edit", id="patch_entry_edit_button", classes="patch-chip")
                            yield Button(
                                "Remove", id="patch_entry_remove_button", classes="patch-chip"
                            )
                            # US-068b: the per-entry JSON editor for the
                            # SELECTED row — disabled for a file-backed document.
                            yield Button(
                                "Edit JSON",
                                id="patch_entry_edit_json_button",
                                classes="patch-chip",
                            )
                        yield Static("", id="patch_doc_tally", markup=False)
                    with Container(id="patch_win_json"):
                        yield Static(
                            "LOADED DOCUMENT · read-only",
                            id="patch_json_heading",
                            classes="nowrap-heading",
                            markup=False,
                        )
                        yield Static(
                            "", id="patch_json_stamp", classes="nowrap-heading", markup=False
                        )
                        # D3: literal by construction (no markup parser, C-17),
                        # focusable and scrolled by the arrow keys (LLR-144.10).
                        yield TextArea(
                            self.JSON_VIEW_EMPTY_TEXT,
                            id="patch_json_view",
                            read_only=True,
                            soft_wrap=False,
                        )
                        with VerticalScroll(id="patch_win_json_body") as json_body:
                            json_body.can_focus = False
                            with Container(id="patch_paste_row"):
                                with Horizontal(id="patch_paste_head"):
                                    yield Static(
                                        "PASTE BUFFER · example",
                                        id="patch_paste_heading",
                                        classes="nowrap-heading",
                                        markup=False,
                                    )
                                    # batch-48 (LLR-079.4): the paste-cap gauge
                                    # — integers + author-fixed labels only.
                                    yield Static(
                                        "",
                                        id="patch_paste_gauge",
                                        markup=False,
                                        classes="patch-field-label",
                                    )
                                # batch-48 (LLR-079.1): capped, JSON-coloured,
                                # no markup path (C-17 / LLR-079.3).
                                yield JsonHighlightTextArea(
                                    DUMMY_CHANGESET_TEXT, id="patch_paste_text"
                                )
                        spacer = Container(id="patch_win_json_dock_spacer")
                        spacer.display = False
                        yield spacer
                        with Horizontal(
                            id="patch_paste_controls",
                            classes="patch-docked-row patch-chip-apply",
                        ):
                            yield Button(
                                "Parse pasted",
                                id="patch_paste_parse_button",
                                classes="patch-chip",
                            )
                            # US-064b: the full-size JSON popup over the paste
                            # buffer; disabled for a file-backed document.
                            yield Button(
                                "Edit JSON", id="patch_edit_json_button", classes="patch-chip"
                            )
                        # batch-48 (LLR-081.2): the history strip beside the
                        # Undo/Redo row it describes; derived integers and
                        # author-fixed key hints only (C-17).
                        yield Static(
                            "",
                            id="patch_history_strip",
                            markup=False,
                            classes="patch-docked-row",
                        )
                        with Horizontal(
                            id="patch_history_controls",
                            classes="patch-docked-row patch-chip-entry",
                        ):
                            yield Button("Undo", id="patch_undo_button", classes="patch-chip")
                            yield Button("Redo", id="patch_redo_button", classes="patch-chip")
                        with Container(id="patch_execute_row", classes="patch-docked-group"):
                            yield Label("Execute over variants", classes="patch-field-label")
                            with Horizontal(
                                id="patch_execute_buttons", classes="patch-chip-apply"
                            ):
                                yield Button(
                                    f"Scope: {self._SCOPE_LABELS[self._execute_scope]}",
                                    id="patch_execute_scope_button",
                                    classes="patch-chip",
                                )
                                yield Button(
                                    "Execute scope",
                                    id="patch_execute_run_button",
                                    classes="patch-chip",
                                )
                            # LLR-075.3: the execution scope as a readable line;
                            # every update() passes a literal Text (C-17).
                            yield Static(
                                "",
                                id="patch_scope_line",
                                markup=False,
                                classes="patch-stat-line",
                            )
                        # The save-back prompt (LLR-002.7), hidden until an
                        # apply writes >= 1 entry; its label shares its input's
                        # row (design §3).
                        with Container(
                            id="patch_saveback_row", classes="hidden patch-docked-group"
                        ):
                            with Horizontal(classes="pe-row"):
                                yield Label("Save patched image as:", classes="pe-label")
                                yield OsClipboardInput(
                                    id="patch_saveback_name_input", compact=True
                                )
                            with Horizontal(
                                id="patch_saveback_buttons", classes="patch-chip-apply"
                            ):
                                yield Button(
                                    f"Width: {self._saveback_width} bytes/line",
                                    id="patch_saveback_width_button",
                                    classes="patch-chip",
                                )
                                yield Button(
                                    "Write file",
                                    id="patch_saveback_confirm_button",
                                    classes="patch-chip",
                                )
                                yield Button(
                                    "Don't save",
                                    id="patch_saveback_decline_button",
                                    classes="patch-chip",
                                )
                        # US-061: the persistent before/after-report control.
                        with Container(
                            id="patch_before_after_row", classes="hidden patch-docked-group"
                        ):
                            yield Label(
                                "Before/after report available:",
                                classes="patch-field-label",
                            )
                            with Horizontal(
                                id="patch_before_after_buttons", classes="patch-chip-apply"
                            ):
                                yield Button(
                                    "Write before/after report",
                                    id="patch_before_after_button",
                                    classes="patch-chip",
                                )
                    with Container(id="patch_win_checks"):
                        with VerticalScroll(id="patch_win_checks_body"):
                            yield Label(
                                "", id="patch_doc_issue_count", classes="patch-field-label"
                            )
                            yield Static(
                                "", id="patch_doc_issues", markup=False, classes="hidden"
                            )
                            # batch-33 (LLR-051.6, C-17): the untruncated
                            # run-block reason — markup never interpreted.
                            yield Label(
                                self.CHECKS_NO_RUN_TEXT,
                                id="patch_checks_status",
                                classes="patch-field-label",
                                markup=False,
                            )
                            # batch-48 (LLR-078.1): the pass/fail strip —
                            # integer counts and closed glyphs only (C-17).
                            yield Static(
                                "",
                                id="patch_checks_strip",
                                markup=False,
                                classes="patch-field-label",
                            )
                            yield Container(id="patch_checks_results")
                        section = Label(
                            "Checks",
                            id="patch_checks_section_label",
                            classes="patch-section-title",
                        )
                        section.display = False
                        yield section
                        with Container(
                            id="patch_checks_controls",
                            classes="patch-docked-group patch-chip-checks",
                        ):
                            yield Button(
                                "Run checks",
                                id="patch_checks_run_button",
                                classes="patch-chip",
                            )
                            # batch-35 (US-052): the clarity help, kept verbatim
                            # (AT-032a / AT-052a pin it); it wraps under Run
                            # checks in the pane's spare rows.
                            yield Label(
                                "Checks: runs the loaded change document's checks "
                                "against the loaded image. Needs kind 'check' (a "
                                "change-set cannot be checked). Uncheckable rows "
                                "name their reason (declaration fault, "
                                "partial/outside range, or no image); healthy "
                                "entries are still checked.",
                                id="patch_checks_help",
                                classes="patch-field-label",
                            )
                    # batch-102 Inc 5 (US-102-05): the A2L tab hosts the shared
                    # picker in pick mode; ``Use parameter`` transfers the
                    # highlighted row into the entry form without touching the
                    # document (R-B102-PE-003).
                    with Container(id="patch_win_a2l"):
                        yield self._a2l_picker
                        with Horizontal(
                            id="patch_param_use_row",
                            classes="patch-docked-row patch-chip-entry",
                        ):
                            yield Button(
                                "Use parameter",
                                id="patch_param_use_button",
                                classes="patch-chip",
                            )
                        use_status = Static(
                            "",
                            id="patch_param_use_status",
                            classes="patch-field-label",
                            markup=False,
                        )
                        use_status.styles.height = 3
                        use_status.styles.text_wrap = "wrap"
                        use_status.display = False
                        yield use_status
        with Horizontal(id="patch_doc_file_row", classes="patch-docked-row"):
            yield Label("File", classes="pe-label")
            with Horizontal(id="patch_doc_file_line1"):
                yield Select(
                    [],
                    id="patch_doc_file_select",
                    prompt="Change files in patches/",
                    allow_blank=True,
                    compact=True,
                )
                yield OsClipboardInput(
                    placeholder=(
                        "or type a path to the same change-set JSON "
                        "(alternative to the patches/ dropdown)"
                    ),
                    id="patch_doc_path_input",
                    compact=True,
                )
                yield Button("Load", id="patch_doc_load_button", classes="patch-chip")
            with Horizontal(id="patch_doc_file_line2"):
                yield Button(
                    "Refresh", id="patch_doc_refresh_button", classes="patch-chip"
                )
                # batch-35 (US-057): the section label stays mounted (census),
                # its words carried by the ledger's border title.
                label = Label(
                    "Patch script",
                    id="patch_script_section_label",
                    classes="patch-section-title",
                )
                label.display = False
                yield label
        with Horizontal(
            id="patch_doc_controls", classes="patch-docked-row patch-chip-apply"
        ):
            yield Button("Validate", id="patch_doc_validate_button", classes="patch-chip")
            yield Button(
                "Apply loaded changes", id="patch_doc_apply_button", classes="patch-chip"
            )
            # LLR-144.11: Save is the ONE filled element besides the ledger.
            yield Button(
                "Save", id="patch_doc_save_button", classes="patch-chip fill-accent"
            )
        yield Static(
            "   ".join(f"{glyph} {meaning}" for glyph, meaning in PATCH_GLYPHS.items()),
            id="patch_legend",
            classes="glyph-legend nowrap-legend",
            markup=False,
        )

    def _set_window_subtitle(self, window_id: str, subtitle: str) -> None:
        """Set one patch window's live border subtitle (LLR-075.1).

        Summary:
            Write ``subtitle`` onto the ``#patch_win_*`` container's
            ``border_subtitle``. Tolerates a not-yet-mounted tree so the
            ``refresh_*`` renderers stay callable from ``on_mount`` and from
            ``app.py`` alike.

        Args:
            window_id (str): The window container id — one of
                ``_WINDOW_BORDER_TITLES``' keys.
            subtitle (str): The author-composed live state token. NEVER
                file-derived (C-17): every caller passes a count or a fixed
                token, never a document string.

        Returns:
            None

        Data Flow:
            - Query the window container; assign ``border_subtitle``.

        Dependencies:
            Used by:
                - ``PatchEditorPanel.refresh_entries`` (SCRIPT entry count)
                - ``PatchEditorPanel.refresh_check_results`` (CHECKS run state)

        Example:
            >>> panel._set_window_subtitle("patch_win_script", "3 entries")
        """
        windows = self.query(f"#{window_id}")
        if windows:
            windows.first(Container).border_subtitle = subtitle
        self._refresh_inspector_subtitle()

    def _refresh_inspector_subtitle(self) -> None:
        """The inspector's border subtitle follows the tab (LLR-075.1): the
        JSON tab shows the schema token, the Checks tab its run state."""
        switchers = self.query("#patch_tab_switcher")
        if not switchers:
            return
        current = switchers.first(ContentSwitcher).current
        subtitle = ""
        if current == "patch_win_json":
            subtitle = self._JSON_SCHEMA_SUBTITLE
        elif current == "patch_win_checks":
            subtitle = self.query_one("#patch_win_checks", Container).border_subtitle or ""
        self.query_one("#patch_inspector").border_subtitle = subtitle

    def _refresh_scope_line(self) -> None:
        """Render the execution-scope line (LLR-075.3, batch-94 form).

        Summary:
            Compose ``Scope <label>`` as a Rich ``Text`` and write it to
            ``#patch_scope_line``. The scope label comes from the panel's
            OWN local vocabulary (``_SCOPE_LABELS``), so this view widget
            still imports nothing from the service layer (C-7). Batch-94
            (HLR-006): the ``Variant <id> ·`` half of the former
            variant/scope line retired with the variant selector — the line
            names the scope only, and carries NO file-derived text.

        Returns:
            None

        Data Flow:
            - ``self._execute_scope`` (cycled by the scope button) →
              ``label_value`` pair → ``Static.update``.

        Dependencies:
            Uses:
                - ``insight_style.label_value``
            Used by:
                - ``PatchEditorPanel.on_button_pressed`` (the scope cycle)
                - ``PatchEditorPanel.on_mount``

        Example:
            >>> panel._refresh_scope_line()
        """
        lines = self.query("#patch_scope_line")
        if not lines:
            return
        lines.first(Static).update(
            label_value("Scope", self._SCOPE_LABELS[self._execute_scope])
        )

    # ------------------------------------------------------------------
    # A2L tab (batch-102 Inc 5, US-102-05 — the shared picker in pick mode)
    # ------------------------------------------------------------------

    def set_a2l_parameters(
        self, rows: Sequence[dict], signature: object = None
    ) -> None:
        """Populate the A2L picker (R-B102-PE-001, R-B102-PE-005).

        Delegates rows, the app's safe ``_a2l_enriched_key`` signature and its
        current parsed A2L data to the embedded picker: it mounts at most one
        200-row page and preserves the filter, page, highlight and picks while
        the signature is unchanged, in which case this shim returns without
        touching the layout. On a real (re)population the cached ``Fmt · Unit``
        width may change, so the derived widths are invalidated and re-derived
        on the next layout pass. A headless panel or an app without parsed A2L
        data supplies ``None``.
        """
        a2l_data = (
            getattr(self.app, "current_a2l_data", None) if self.is_mounted else None
        )
        if not self._a2l_picker.set_parameters(rows, signature, a2l_data=a2l_data):
            return
        self._a2l_layout = None
        self.call_after_refresh(self._apply_a2l_layout)

    def set_image_mem_map(self, mem_map: Optional[Mapping[int, int]]) -> None:
        """Replace the retained image map (batch-102 Inc 5, E3 ruling 4).

        The app pushes ``None`` here when the primary image is unloaded, so
        a later ``Use parameter`` seeds Bytes from no map and paints the
        ``image bytes unavailable`` line instead of the unloaded image's
        stale bytes. Tolerates a not-yet-mounted tree (headless unit path).
        """
        self._mem_map = mem_map

    def _a2l_widths(self) -> "CheckLayout":
        """The A2L tab's current layout, or the pre-measure reading of the
        118-column regime before the tab is first measured (E3 ruling 1:
        never the picker's built-in 118-column default — this derivation
        follows the Patch inspector's real width)."""
        if self._a2l_layout is not None:
            return self._a2l_layout
        return check_layout(39, 41, self._a2l_fmt_longest())

    def _a2l_fmt_longest(self) -> int:
        """The cached longest ``Fmt · Unit`` cell (recomputed per population)."""
        return self._a2l_picker.fmt_longest

    def _apply_a2l_layout(self) -> None:
        """Re-derive the A2L tab widths and repaint the picker's ledger.

        Reads the measured content width of ``#patch_param_table`` (the
        picker's ledger fills the A2L pane inside the inspector — never the
        terminal width). A hidden tab measures 0 and repaints nothing; the
        cache is kept, so showing the tab re-derives nothing it already
        knows. An unchanged layout repaints nothing. Otherwise it sets each
        column's width and rewrites the Parameter and ``Fmt · Unit`` cells
        with ``update_cell`` (the public repaint path, D21/PC-8); it never
        adds a column. At no more than 12 panel rows the ledger keeps its
        header and one data row, the picker sizes to its content, and the panel
        grows to 13 rows so the full Use status wraps on its own row. Taller
        panels keep the flexible table and panel height. The ledger rows belong
        to the picker.
        """
        table = self.query_one("#patch_param_table", DataTable)
        if table.content_region.width == 0:
            return
        compact = self.region.height <= 13
        table.styles.height = 2 if compact else "1fr"
        table.show_header = True
        self._a2l_picker.styles.height = "auto"
        self.styles.height = 13 if compact else "1fr"
        layout = check_layout(
            table.content_region.width,
            self.query_one("#patch_inspector").content_region.width,
            self._a2l_fmt_longest(),
        )
        if layout == self._a2l_layout:
            return
        self._a2l_layout = layout
        columns = table.ordered_columns
        for column, width in zip(columns, (1, layout.param, 10, layout.fmt)):
            column.width = width
            column.auto_width = False
        columns[3].label = Text(layout.fmt_label)
        keys = [column.key for column in columns]
        if not self._a2l_picker.visible_params:
            # D21 (5): with no rows the pass is ``clear()`` (rows only).
            table.clear()
        for index, name in enumerate(self._a2l_picker.visible_params):
            cells = self._a2l_picker.row_cells(name, layout)
            table.update_cell(name, keys[1], cells[1], update_width=(index == 0))
            table.update_cell(name, keys[3], cells[3])
        self._a2l_picker.refresh_full_name()

    def _on_a2l_parameter_picker_bulk_add_requested(
        self, event: A2LParameterPicker.BulkAddRequested
    ) -> None:
        """The picker's bulk-add control was activated: push the shared bulk
        modal for this panel's picker. The host owns the screen stack; bulk
        inclusion never creates a Patch document action."""
        event.stop()
        self._open_parameter_bulk_add()

    def _open_parameter_bulk_add(self) -> None:
        """Push :class:`BulkParameterAddScreen` bound to the Patch picker."""
        self.app.push_screen(
            BulkParameterAddScreen(self._a2l_picker), self._on_bulk_add_closed
        )

    def _on_bulk_add_closed(self, summary: Optional[dict]) -> None:
        """Bulk modal dismissed without rebuilding the ledger or changing the
        document, dirty flag, undo/redo history or current selection. The
        shared picker retains successful includes and the modal owns its
        summary; cancellation and escape are inert."""

    def _use_highlighted_parameter(self) -> None:
        """Transfer the highlighted A2L row into the entry form
        (R-B102-PE-003, R-B102-PE-004; E3 rulings 4/5/6/9).

        Reads the picker's ``highlighted_parameter``: with no usable row (or
        a non-integer address, E3 ruling 9) it paints ``No parameter
        highlighted.`` and touches nothing else. It writes a valid Address as
        ``0x%08X``. A missing declared size then clears Bytes and paints
        ``Parameter has no length — Bytes not prefilled.`` before any image
        lookup. Otherwise the Bytes input receives the panel-retained current
        image bytes for the parameter size — every byte of
        ``[address, address + size)`` must be mapped, and the size must not
        exceed ``MAX_A2L_DECODE_BYTES`` (E3 ruling 5: no giant range is
        iterated, no silent truncation); on either miss Bytes is left empty
        and ``Parameter address loaded; image bytes unavailable.`` paints.
        No document action is posted and the dirty/undo/redo state is unchanged
        — the document changes only through Add / Edit. Every painted line is
        an author-fixed string through ``safe_text`` (E3 ruling 7); no
        parameter name, image byte or path is logged (E3 ruling 10).
        """
        parameter = self._a2l_picker.highlighted_parameter
        address = parameter.get("address") if parameter else None
        if parameter is None or not isinstance(address, int) or address < 0:
            self._paint_a2l_use_status("No parameter highlighted.")
            return
        self.query_one("#patch_entry_address_input", Input).value = (
            f"0x{address:08X}"
        )
        size = parameter.get("size")
        if size is None:
            self.query_one("#patch_entry_bytes_input", Input).value = ""
            self._paint_a2l_use_status(
                "Parameter has no length — Bytes not prefilled."
            )
            return
        bytes_text = ""
        status = ""
        if size > MAX_A2L_DECODE_BYTES:
            status = (
                f"Parameter size {size} bytes over the "
                f"{MAX_A2L_DECODE_BYTES}-byte decode cap — Bytes not prefilled."
            )
        else:
            mem_map = self._mem_map
            data: Optional[List[int]] = []
            if mem_map is not None:
                for offset in range(size):
                    byte = mem_map.get(address + offset)
                    if byte is None:
                        # Partial map: any missing byte means unavailable —
                        # zero-fill is prohibited (E3 ruling 6).
                        data = None
                        break
                    data.append(int(byte))
            if mem_map is None or data is None:
                status = "Parameter address loaded; image bytes unavailable."
            else:
                bytes_text = " ".join(f"{byte:02X}" for byte in data)
        self.query_one("#patch_entry_bytes_input", Input).value = bytes_text
        if status:
            self._paint_a2l_use_status(status)
        else:
            self._clear_a2l_use_status()

    def _paint_a2l_use_status(self, line: str) -> None:
        """Paint one author-fixed outcome line on the A2L tab's single status
        surface ``#patch_param_use_status`` (E3 ruling 7), tolerating a
        not-yet-mounted tree."""
        self._a2l_use_status = line
        holders = self.query("#patch_param_use_status")
        if not holders:
            return
        holder = holders.first(Static)
        holder.update(safe_text(line))
        holder.display = True

    def _clear_a2l_use_status(self) -> None:
        """Hide the use-status surface (a fully successful use paints no line)."""
        self._a2l_use_status = ""
        holders = self.query("#patch_param_use_status")
        if holders:
            holders.first(Static).display = False

    def _on_a2l_parameter_picker_view_changed(
        self, event: A2LParameterPicker.ViewChanged
    ) -> None:
        """The A2L ledger re-rendered (populate, filter, page turn):
        re-assert the host's use-status surface and re-derive the tab widths
        (the measured table width exists only while the tab is shown). The
        document rows and the entry inputs are never touched here
        (R-B102-PE-005, R-B102-PE-006)."""
        self._apply_a2l_layout()
        if self._a2l_use_status:
            self._paint_a2l_use_status(self._a2l_use_status)

    # ------------------------------------------------------------------
    # Width derivation (D21: mount, resize, show)
    # ------------------------------------------------------------------

    def _widths(self) -> "PatchLayout":
        """The current layout, or the 118-column reading before the first measure."""
        return self._layout or patch_layout(65, 41, self._status_longest(), 110)

    def _status_longest(self) -> int:
        return max((cell_len(str(row.status_text)) for row in self._entry_rows), default=0)

    def _ledger_cells(self, row: object, layout: "PatchLayout") -> tuple:
        """The five cells of one ledger row, every one a literal ``Text`` (C-17)."""
        return (
            self._kind_cell(row),
            safe_text(str(row.address_text), CYAN),
            safe_text(_clip_to_cells(safe_text(str(row.value_text)).plain, layout.value), VALUE),
            safe_text(_clip_to_cells(safe_text(str(row.status_text)).plain, layout.status)),
            safe_text(_clip_to_cells(safe_text(str(row.linkage_text)).plain, layout.linkage)),
        )

    def _apply_layout(self) -> None:
        """Re-derive the widths and repaint every width-dependent text (D21).

        Reads the measured content widths of ``#patch_win_script`` (the
        ledger's frame, which the table fills), ``#patch_inspector`` and the
        ribbon — never the terminal width. An unchanged layout repaints
        nothing. Otherwise it sets each column's width and rewrites the
        Value / Status / Linkage cells with ``update_cell`` (the first call
        ``update_width=True``, the PC-8 path), re-renders the strip at its new
        bytes per row and repaints the ribbon. It never adds a column.
        """
        ledger = self.query_one("#patch_win_script")
        inspector = self.query_one("#patch_inspector")
        ribbon = self.query_one("#patch_identity_ribbon")
        if ledger.content_region.width == 0 or inspector.content_region.width == 0:
            return
        layout = patch_layout(
            ledger.content_region.width,
            inspector.content_region.width,
            self._status_longest(),
            ribbon.content_region.width,
        )
        if layout == self._layout:
            return
        self._layout = layout
        table = self.query_one("#patch_doc_entries_table", DataTable)
        columns = table.ordered_columns
        widths = (layout.kind, layout.address, layout.value, layout.status, layout.linkage)
        for column, width in zip(columns, widths):
            column.width = width
            column.auto_width = False
        keys = [column.key for column in columns]
        if not self._entry_rows:
            # D21 (5): with no rows the pass is ``clear()`` (rows only).
            table.clear()
        for index, row in enumerate(self._entry_rows):
            cells = self._ledger_cells(row, layout)
            for column in (2, 3, 4):
                table.update_cell(
                    str(index), keys[column], cells[column],
                    update_width=(index == 0 and column == 2),
                )
        self._render_before_after_card()
        self._refresh_ribbon()
        # batch-102 Inc 5: the A2L tab's ledger follows the same D21 pass.
        self._apply_a2l_layout()

    def on_resize(self, event: events.Resize) -> None:
        self.call_after_refresh(self._apply_layout)

    def on_show(self, event: events.Show) -> None:
        self.call_after_refresh(self._apply_layout)

    def on_mount(self) -> None:
        """Add the five ledger columns once and paint every initial state."""
        layout = self._widths()
        table = self.query_one("#patch_doc_entries_table", DataTable)
        for label, width in zip(
            self._ENTRIES_COLUMNS,
            (layout.kind, layout.address, layout.value, layout.status, layout.linkage),
        ):
            table.add_column(label, width=width)
        self.refresh_entries([])
        # LLR-075.3: the scope line never mounts blank.
        self._refresh_scope_line()
        # LLR-079.4: the buffer mounts NON-empty (`DUMMY_CHANGESET_TEXT`).
        self._refresh_paste_gauge()
        self._set_window_subtitle("patch_win_checks", self._NO_RUN_SUBTITLE)
        self._refresh_json_stamp()
        self.call_after_refresh(self._apply_layout)

    # ------------------------------------------------------------------
    # Tabs, ribbon, tally and the JSON view (batch-97 HLR-144)
    # ------------------------------------------------------------------

    def _show_tab(self, chip_id: str) -> None:
        """Switch the inspector to ``chip_id``'s pane; its title follows the tab."""
        for tab_id, _label, pane, title in self._TABS:
            selected = tab_id == chip_id
            self.query_one(f"#{tab_id}").set_class(selected, "chip-selected")
            if selected:
                self.query_one("#patch_tab_switcher", ContentSwitcher).current = pane
                self.query_one("#patch_inspector").border_title = title
                if pane == "patch_win_a2l":
                    # The A2L ledger measures only while its tab is shown
                    # (batch-102 Inc 5, E3 ruling 1).
                    self.call_after_refresh(self._apply_a2l_layout)
        self._refresh_inspector_subtitle()

    def _refresh_ribbon(self) -> None:
        """Paint the identity ribbon: file name (tail kept) · kind (LLR-144.7).

        The name is file-derived, so it goes through ``safe_text`` and is
        appended literally; a name wider than the ribbon keeps its tail behind
        one ``…`` (LLR-149.4, file names). A document with no file reads
        ``draft``.
        """
        name, kind = self._identity
        ribbon = self.query_one("#patch_identity_ribbon", Static)
        width = self._widths().ribbon
        tail = Text(f" · {kind or 'no kind'}", style=DGRAY)
        if name is None:
            text = Text("draft", style=VALUE)
        else:
            room = max(8, width - cell_len(tail.plain))
            text = safe_text(clip_tail(safe_text(name).plain, room), VALUE)
        text.append_text(tail)
        ribbon.update(text)

    def _tally_text(self) -> Text:
        """The DOCUMENT tally at the Inspector pane's foot (design §3, PC-6).

        Counts only, from the rows' closed status vocabulary: ``DOCUMENT``, a
        12-cell bar (one ``▓`` per entry in its status colour while the
        entries fit, else proportional), ``N entries · I inside · P partial``
        and ``O outside · F faults`` (`` · U no image`` when non-zero) — four
        explicit lines, never a wrapped one. Empty: ``DOCUMENT`` + ``0 entries``.
        """
        rows = self._entry_rows
        text = Text("DOCUMENT", style=DGRAY)
        text.append("\n")
        if not rows:
            text.append("0 entries", style=f"bold {VALUE}")
            return text
        counts = {"inside": 0, "partial": 0, "outside": 0, "unvalidated-no-image": 0}
        faults = 0
        colours = []
        style_of = {"inside": GREEN, "partial": YELLOW, "outside": RED}
        for row in rows:
            status = str(row.status_text)
            base = status.split(" / ", 1)[0]
            if base in counts:
                counts[base] += 1
            if "fault" in status:
                faults += 1
            colours.append(RED if "fault" in status else style_of.get(base, DGRAY))
        cells = self._TALLY_BAR_CELLS
        if len(rows) <= cells:
            for colour in colours:
                text.append("▓", style=colour)
            text.append("░" * (cells - len(rows)), style=DGRAY)
        else:
            painted = 0
            for key in ("inside", "partial", "outside"):
                share = round(cells * counts[key] / len(rows))
                text.append("▓" * share, style=style_of[key])
                painted += share
            text.append("░" * max(0, cells - painted), style=DGRAY)
        text.append("\n")
        n = len(rows)
        text.append(f"{n} {'entry' if n == 1 else 'entries'}", style=f"bold {VALUE}")
        text.append(" · ", style=DGRAY)
        text.append(f"{counts['inside']} inside", style=GREEN if counts["inside"] else DGRAY)
        text.append(" · ", style=DGRAY)
        text.append(f"{counts['partial']} partial", style=YELLOW if counts["partial"] else DGRAY)
        text.append("\n")
        text.append(f"{counts['outside']} outside", style=RED if counts["outside"] else DGRAY)
        text.append(" · ", style=DGRAY)
        text.append(f"{faults} faults", style=RED if faults else DGRAY)
        if counts["unvalidated-no-image"]:
            text.append(" · ", style=DGRAY)
            text.append(f"{counts['unvalidated-no-image']} no image", style=DGRAY)
        return text

    def _refresh_json_stamp(self) -> None:
        """Recompose the stamp from the retained count and time + the dirty flag (D4)."""
        stamps = self.query("#patch_json_stamp")
        if not stamps:
            return
        shown = self._json_shown
        stamps.first(Static).update(
            Text(
                json_stamp_text(
                    None if shown is None else shown[0],
                    None if shown is None else shown[1],
                    self._dirty,
                ),
                style=DGRAY,
            )
        )

    def _show_document(self, document: "PatchDocumentView") -> None:
        """The D1 document path: identity always, the view only on a new payload.

        D4 (2), the equal-payload rule: a document whose serialised text equals
        the one shown leaves the view (text, cursor, scroll), the retained time
        and the stamp untouched; the ribbon is repainted either way (a Save can
        name a draft). A new payload reloads the view with the capped text,
        takes the time from :func:`_json_clock` and recomposes the stamp.
        """
        self._identity = (document.name, document.kind)
        self._refresh_ribbon()
        shown = self._json_shown
        if shown is not None and shown[2] == document.json_text:
            return
        self._json_shown = (document.entry_count, deps._json_clock(), document.json_text)
        self.query_one("#patch_json_view", TextArea).load_text(
            cap_json_lines(document.json_text.rstrip("\n"))
        )
        self._refresh_json_stamp()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        """Keep the paste-cap gauge in step with the buffer (LLR-079.4).

        Summary:
            Re-render the gauge whenever the paste buffer's content changes —
            which is every ingress at once (bracketed paste, ``ctrl+v``,
            typing, and the app's programmatic ``load_text``), because
            ``TextArea.Changed`` is posted by the document edit itself rather
            than by any one caller. A per-call-site refresh would be the
            batch-38 Inc-4 F1 stale-panel shape: an omitted site leaves a
            wrong number on screen.

        Args:
            event (TextArea.Changed): The originating widget's change message.

        Returns:
            None.

        Raises:
            None.

        Data Flow:
            - Filter to ``#patch_paste_text`` → :meth:`_refresh_paste_gauge`.
            - The id filter matters: ``Changed`` bubbles, so an unfiltered
              handler would repaint the gauge from an unrelated ``TextArea``.

        Dependencies:
            Uses:
                - :meth:`_refresh_paste_gauge`
            Used by:
                - Textual message dispatch (the ``#patch_paste_text`` buffer)
        """
        if event.text_area.id == "patch_paste_text":
            # w2 (LLR-005.1 writer census): an edit in the JSON text region
            # sets the dirty flag — the Load guard treats the buffer as
            # unsaved work even when the entries table is clean.
            self._dirty = True
            self._refresh_dirty_indicator()
            self._refresh_paste_gauge()

    def _refresh_paste_gauge(self) -> None:
        """Render the gauge from the buffer's CURRENT length (LLR-079.4).

        Summary:
            Read ``#patch_paste_text``'s length and hand it to
            :meth:`_paste_gauge_text`. The length is read from the widget
            here — not passed in — so no caller can supply a count that
            disagrees with what is on screen.

        Args:
            None.

        Returns:
            None.

        Raises:
            None — both ids are composed by this panel.

        Data Flow:
            - ``len(TextArea.text)`` → :meth:`_paste_gauge_text` →
              ``#patch_paste_gauge``.

        Dependencies:
            Uses:
                - :meth:`_paste_gauge_text`
            Used by:
                - :meth:`on_mount`, :meth:`on_text_area_changed`,
                  :meth:`clear_paste_buffer`

        The same pass names the buffer in ``#patch_paste_heading``:
        ``example`` while it equals ``DUMMY_CHANGESET_TEXT``, else
        ``editable``.
        """
        buffer = self.query_one("#patch_paste_text", TextArea)
        self.query_one("#patch_paste_gauge", Static).update(
            self._paste_gauge_text(len(buffer.text))
        )
        # batch-97 Inc-4 gate (ux Obs 5): the heading says when the buffer
        # still holds the shipped example rather than the operator's text.
        self.query_one("#patch_paste_heading", Static).update(
            "PASTE BUFFER · example"
            if buffer.text == DUMMY_CHANGESET_TEXT
            else "PASTE BUFFER · editable"
        )

    def request_action(self, action: str) -> None:
        """Post an :class:`ActionRequested` message for ``action``.

        Summary:
            Read the entry and path input fields and post an
            ``ActionRequested`` message so ``app.py`` can call
            ``ChangeService``. The widget itself performs no
            ``changes``-package work — it only forwards the request.
            Batch-94 (LLR-005.1): the entries-table edit actions also SET
            the dirty flag (writer w1) — an Add / Edit / Remove is unsaved
            work until the next successful save or load.

        Args:
            action (str): One of the eight LLR-003.2 v2 actions —
                ``"add_entry"`` / ``"edit_entry"`` / ``"remove_entry"`` /
                ``"load_doc"`` / ``"validate_doc"`` / ``"apply_doc"`` /
                ``"save_doc"`` / ``"run_checks"`` — or the E6 extension
                ``"execute_scope"`` (LLR-006.6).

        Dependencies:
            Uses:
                - ``ActionRequested``
            Used by:
                - the panel's entry and document controls
        """
        if action in ("add_entry", "edit_entry", "remove_entry"):
            # w1 (LLR-005.1 writer census): entries-table edit → dirty.
            self._dirty = True
            self._refresh_dirty_indicator()
        self.post_message(
            self.ActionRequested(
                action=action,
                address_text=self.query_one(
                    "#patch_entry_address_input", Input
                ).value,
                value_text=self.query_one(
                    "#patch_entry_value_input", Input
                ).value,
                bytes_text=self.query_one(
                    "#patch_entry_bytes_input", Input
                ).value,
                path_text=self.query_one(
                    "#patch_doc_path_input", Input
                ).value,
                scope_text=self._execute_scope,
            )
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Translate any Patch Editor button press into a message.

        Summary:
            Map the pressed button id to one of the v2 actions and forward
            it via :meth:`request_action`; the "Parse pasted" button posts
            its own :class:`ActionRequested` carrying the paste ``TextArea``
            body (``parse_paste``, LLR-014.2), and the save-back confirm /
            decline buttons post a :class:`SaveBackDecision` instead. Stops
            the event so it does not also reach the app-level
            ``on_button_pressed``.

        Args:
            event (Button.Pressed): The Textual button-press event.

        Dependencies:
            Uses:
                - ``request_action`` / ``SaveBackDecision``
            Used by:
                - Textual button-press dispatch
        """
        button_id = event.button.id or ""
        if any(button_id == tab[0] for tab in self._TABS):
            event.stop()
            self._show_tab(button_id)
            return
        if button_id == "patch_param_use_button":
            # batch-102 Inc 5 (R-B102-PE-003): transfer the highlighted A2L
            # row into the entry form — the document is not touched.
            event.stop()
            self._use_highlighted_parameter()
            return
        if button_id == "patch_saveback_width_button":
            # Selector state only — cycle the save-back record width and
            # relabel; no message is posted, so this adds no routed action
            # (the same idiom as #patch_execute_scope_button). The chosen
            # width rides the next SaveBackDecision (US-015 / LLR-015.3).
            event.stop()
            index = self.SAVEBACK_WIDTHS.index(self._saveback_width)
            self._saveback_width = self.SAVEBACK_WIDTHS[
                (index + 1) % len(self.SAVEBACK_WIDTHS)
            ]
            event.button.label = (
                f"Width: {self._saveback_width} bytes/line"
            )
            return
        if button_id == "patch_saveback_confirm_button":
            event.stop()
            self.post_message(
                self.SaveBackDecision(
                    self.query_one("#patch_saveback_name_input", Input).value,
                    bytes_per_line=self._saveback_width,
                )
            )
            return
        if button_id == "patch_saveback_decline_button":
            event.stop()
            self.post_message(self.SaveBackDecision(None))
            return
        if button_id == "patch_before_after_button":
            # US-061 / LLR-061.2: the persistent control is a second trigger
            # onto the ONE report writer — post a payload-free request; the app
            # routes it to action_before_after_report (no duplicated code).
            event.stop()
            self.post_message(self.BeforeAfterReportRequested())
            return
        if button_id == "patch_paste_parse_button":
            # The paste action carries the TextArea body (not an Input), so
            # it posts its own ActionRequested with ``paste_text`` rather
            # than going through request_action (LLR-014.2).
            event.stop()
            self.post_message(
                self.ActionRequested(
                    action="parse_paste",
                    paste_text=self.query_one(
                        "#patch_paste_text", TextArea
                    ).text,
                )
            )
            return
        if button_id == "patch_edit_json_button":
            # US-064b / LLR-064b.1: open the full-size JSON popup over the paste
            # buffer. Carries the current buffer as the seed; the app pushes
            # ``ChangeSetJsonScreen`` and applies the edit through the existing
            # ``parse_paste`` → ``load_text`` seam. Disabled for a file-backed
            # document (LLR-064b.4), so a press here is paste-authored only.
            event.stop()
            self.post_message(
                self.EditJsonRequested(
                    paste_text=self.query_one(
                        "#patch_paste_text", TextArea
                    ).text
                )
            )
            return
        if button_id == "patch_undo_button":
            # US-068a / LLR-068a.3: pure trigger — the app calls
            # ``ChangeService.undo()`` and re-renders. Disabled for a
            # file-backed document (LLR-068a.4), so a press is history-safe.
            event.stop()
            self.post_message(self.UndoRequested())
            return
        if button_id == "patch_redo_button":
            event.stop()
            self.post_message(self.RedoRequested())
            return
        if button_id == "patch_entry_edit_json_button":
            # US-068b / LLR-068b.1: open the per-entry JSON popup for the
            # SELECTED entries-table row. Carry the selected row index; the app
            # seeds ``EntryJsonScreen`` with that one entry's JSON and routes
            # Confirm through the validated per-entry apply. With no rows there
            # is no selection → no-op. Disabled for a file-backed document
            # (LLR-068b.4), so a press here is paste-authored only.
            event.stop()
            table = self.query_one("#patch_doc_entries_table", DataTable)
            if table.row_count == 0:
                return
            self.post_message(self.EntryEditJsonRequested(table.cursor_row))
            return
        if button_id == "patch_execute_scope_button":
            # Selector state only — cycle the scope and relabel; no message
            # is posted, so this adds no routed action.
            event.stop()
            index = self.EXECUTE_SCOPES.index(self._execute_scope)
            self._execute_scope = self.EXECUTE_SCOPES[
                (index + 1) % len(self.EXECUTE_SCOPES)
            ]
            event.button.label = (
                f"Scope: {self._SCOPE_LABELS[self._execute_scope]}"
            )
            # LLR-075.3: the line and the button label are two views of the
            # SAME `_execute_scope` — cycle them together or the line lies.
            self._refresh_scope_line()
            return
        if button_id == "patch_doc_load_button":
            # batch-94 (HLR-005 / LLR-005.2): the dirty guard. With unsaved
            # edits in either editor region, Load does NOT load — it asks.
            # Post :class:`DirtyLoadRequested`; ``app.py`` pushes the
            # :class:`LoadGuardScreen` modal and only proceeds with THIS path
            # when the operator accepts the loss. A clean document loads
            # directly (the popup-always shape is the negative control).
            event.stop()
            path_text = self.query_one("#patch_doc_path_input", Input).value
            if self._dirty:
                self.post_message(self.DirtyLoadRequested(path_text=path_text))
            else:
                self.request_action("load_doc")
            return
        actions = {
            "patch_entry_add_button": "add_entry",
            "patch_entry_edit_button": "edit_entry",
            "patch_entry_remove_button": "remove_entry",
            "patch_doc_refresh_button": "refresh_doc",
            "patch_doc_validate_button": "validate_doc",
            "patch_doc_apply_button": "apply_doc",
            "patch_doc_save_button": "save_doc",
            "patch_checks_run_button": "run_checks",
            "patch_execute_run_button": "execute_scope",
        }
        action = actions.get(button_id)
        if action is not None:
            event.stop()
            self.request_action(action)

    def mark_saved(self) -> None:
        """Clear the dirty flag after a successful save (LLR-005.1, writer w3).

        Called by ``app.py`` when the change service reports a clean
        ``save_doc`` — the flag must not survive its own save (the
        save-then-check arm of TC-B94-10 is the negative control).
        """
        self._dirty = False
        self._refresh_dirty_indicator()

    def mark_loaded(self) -> None:
        """Clear the dirty flag after a successful load (LLR-005.1, writer w4).

        Called by ``app.py`` when a document load / paste parse succeeds —
        the freshly-loaded document has no unsaved edits, in BOTH editor
        regions (the entries table re-renders from the loaded document and
        the buffer is reseeded, so one clear covers the two regions).
        """
        self._dirty = False
        self._refresh_dirty_indicator()

    def clear_paste_buffer(self) -> None:
        """Empty ``#patch_paste_text`` without marking the panel dirty.

        Called by ``app.py``'s project-session reset (batch-100 LED .55(b)):
        the outgoing document's buffer is discarded, not edited. The clear
        runs with ``TextArea.Changed`` prevented, so writer w2 never sees it
        and no dirty flag is set behind the caller's back — a deferred
        ``mark_loaded`` raced that message and lost (hotfix 3b). The gauge
        and heading are repainted here because the prevented message is
        what normally repaints them.
        """
        buffer = self.query_one("#patch_paste_text", TextArea)
        with buffer.prevent(TextArea.Changed):
            buffer.text = ""
        self._refresh_paste_gauge()

    def mark_pasted(self) -> None:
        """Set the dirty flag after a successful paste parse (batch-97 Inc-4 gate).

        Called by ``app.py`` when Parse pasted replaces the document. The
        parsed document is a draft no file holds, so it is unsaved work: the
        JSON stamp reads ``unsaved changes`` beside the ribbon's ``draft`` and
        a Load asks first (ux-reviewer H1, LLR-144.6 amended; was
        ``mark_loaded``, batch-94 w4).
        """
        self._dirty = True
        self._refresh_dirty_indicator()

    @property
    def is_dirty(self) -> bool:
        """Whether either editor region holds unsaved edits (LLR-174.1c).

        The one reader of ``_dirty`` outside this module: the app's load
        guard, ``_handle_save_dialog`` and the change-file dropdown guard
        (LLR-174.2t) read it here, never the private attribute. No setter:
        only the five writers change the flag.
        """
        return self._dirty

    def _refresh_dirty_indicator(self) -> None:
        """Repaint the SCRIPT window's dirty marker (LLR-005.1 reader).

        The marker rides the SCRIPT window's border subtitle after the entry
        count: ``N entries ●`` when unsaved edits exist, ``N entries`` when
        clean. The count half is rewritten by :meth:`refresh_entries`; this
        method repaints only the marker half so the two readers (the Load
        guard and this chrome) can never disagree.
        """
        subtitle = self.query_one("#patch_win_script", Container).border_subtitle
        if subtitle is None:
            subtitle = ""
        base = subtitle.split(" ●", 1)[0]
        self.query_one("#patch_win_script", Container).border_subtitle = (
            f"{base} ●" if self._dirty else base
        )
        # batch-97 D4: the dirty trigger of the JSON stamp — the four dirty
        # writers all end here, so the stamp follows the flag at once.
        self._refresh_json_stamp()

    class DirtyLoadRequested(Message):
        """Load was activated while unsaved edits exist (HLR-005).

        Summary:
            Posted by ``#patch_doc_load_button`` in place of the plain
            ``load_doc`` action when the dirty flag is set. Carries the path
            input's current text so ``app.py`` can present the guard popup
            and, on accept, run EXACTLY the load the operator asked for —
            the path beside the Load control (annotation 6).

        Args:
            path_text (str): The change-file path input's current text.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_dirty_load_requested``
        """

        def __init__(self, path_text: str) -> None:
            super().__init__()
            self.path_text = path_text

    def on_select_changed(self, event: Select.Changed) -> None:
        """Forward a change-file dropdown pick to ``app.py`` (US-026).

        Summary:
            When ``#patch_doc_file_select`` changes to a concrete filename,
            post a :class:`ChangeFileSelected` carrying the listed value so
            the app resolves it against its homes through the pick guard
            (``_resolve_listed_file``) and loads it via the existing
            ``ChangeService.load`` path. A blank selection (``Select.NULL`` —
            the ``NoSelection`` placeholder emitted when ``set_change_files``
            repopulates or clears the option set) is NOT a request, so
            nothing is posted. Batch-94 (HLR-006): the variant dropdown
            retired with the variant group — this handler owns the one
            remaining select.

        Args:
            event (Select.Changed): The Textual select-change event; its
                ``select.id`` and ``value`` identify the widget and choice.

        Returns:
            None

        Data Flow:
            - Ignore events from other selects and the blank sentinel, else
              post ``ChangeFileSelected(str(value))``.

        Dependencies:
            Uses:
                - ``ChangeFileSelected``
            Used by:
                - Textual select-change dispatch
        """
        if event.select.id != "patch_doc_file_select":
            return
        if event.value is Select.NULL:
            return
        event.stop()
        self.post_message(self.ChangeFileSelected(str(event.value)))

    def _kind_cell(self, row: object) -> Text:
        """Build the ``Kind`` cell — the check glyph FOLDED in as a leading span.

        Summary:
            Render column 0 as ``"<glyph> <kind>"`` in one ``Text``: the glyph
            leads in its own verdict-coloured span, the kind text follows in
            the cell's PURPLE role style (LLR-077.3/077.4).

            **No sixth column is added** — this is the house idiom, not an
            invention: the A2L table folds its in-image glyph into the name
            cell (``S19TuiApp._build_a2l_table_cells``) and the MAC table folds
            its status glyph into the Tag cell "as its own span"
            (``S19TuiApp._populate_mac_datatable``), both
            keeping the column count unchanged. A leading COLUMN would instead
            shift ``Coordinate(row, 1)`` / ``(row, 2)`` under every existing
            index-reader (``tests/test_tui_patch_editor_v2.py:2578``,
            ``:3208-3209``, whose docstring pins the order as contract) and
            force a width relaxation at 80x24 that the fold makes unnecessary.

            The glyph is also NOT redundant with the ``Status`` column:
            ``status_text`` is the CONTAINMENT verdict (``MemoryStatus``), the
            glyph is the CHECK-RUN verdict — different semantics, different
            lifetimes. Folding into ``Kind`` puts visual distance between them.

        Args:
            row (object): One ``ChangeEntryRow``; ``check_glyph`` is read
                duck-typed (defaulting to ``·``) so this view widget keeps
                importing nothing from the service layer (C-7).

        Returns:
            Text: The cell — ``.style`` is the PURPLE role style (so the role
            assertion still reads the cell), ``.plain`` starts with the glyph,
            and ``.spans`` carries exactly the glyph's own style span.

        Data Flow:
            - Look the glyph's style up in ``_GLYPH_STYLE``; an unknown glyph
              falls back to the muted ``DGRAY``.
            - ``append`` the glyph, then ``append`` the kind text.

        Dependencies:
            Uses:
                - ``_GLYPH_STYLE`` ; ``insight_style.PURPLE`` / ``DGRAY``
            Used by:
                - ``refresh_entries``

        Note (C-17):
            ``kind_text`` is file-derived. ``Text.append`` takes its argument
            LITERALLY — it never markup-parses — so appending it is the same
            guarantee ``safe_text`` gives the other four cells. The cell is
            still a ``Text``, so ``default_cell_formatter`` never sees a
            ``str`` to hand to ``Text.from_markup`` (LLR-075.6). The glyph
            itself is one of four author-owned constants (LLR-077.6).
        """
        glyph = str(getattr(row, "check_glyph", "·"))
        cell = Text(style=PURPLE)
        cell.append(f"{glyph} ", style=self._GLYPH_STYLE.get(glyph, DGRAY))
        cell.append(str(row.kind_text))
        return cell

    def refresh_entries(
        self,
        rows: Sequence[object],
        mem_map: Union[Mapping[int, int], None, _Unset] = _UNSET,
        document: Union["PatchDocumentView", _Unset] = _UNSET,
    ) -> None:
        """Repopulate the ledger, the strip, the tally and the JSON view.

        Summary:
            Replace every ledger row with the supplied ``ChangeEntryRow`` list;
            with no rows show the one empty-state line instead (LLR-148.9).
            Every cell is a literal ``Text`` (``_kind_cell`` / ``safe_text``),
            never a bare ``str`` — Textual's ``default_cell_formatter`` would
            markup-parse one (LLR-075.6 / C-17). Value, Status and Linkage are
            clipped to their derived widths with one ``…`` (LLR-149.4). Also
            refresh the ledger's ``N entries`` subtitle (+ the dirty marker),
            the DOCUMENT tally and the before→after strip.

            batch-97 I-2/I-3 (D1): ``document`` carries the serialised
            document and its identity; the app builds it at all four sites,
            so the rows, the ribbon and the JSON view cannot disagree.

        Args:
            rows (Sequence[object]): ``ChangeService.rows`` output (duck-typed,
                C-7).
            mem_map (Union[Mapping[int, int], None, _Unset]): The image's map,
                RETAINED for the strip: omitted ⇒ preserve; ``None`` ⇒ clear
                ("no image loaded"); a mapping ⇒ replace (TC-080.2a). The
                sentinel is load-bearing: ``on_mount``'s self-call has no map.
            document (Union[PatchDocumentView, _Unset]): omitted ⇒ preserve
                the shown document (the self-call); a view ⇒ the D4 document
                path (:meth:`_show_document`).
        """
        if not isinstance(mem_map, _Unset):
            self._mem_map = mem_map
        self._entry_rows = list(rows)
        table = self.query_one("#patch_doc_entries_table", DataTable)
        empty_state = self.query_one("#patch_doc_empty_state", Static)
        layout = self._widths()
        table.clear()
        for index, row in enumerate(rows):
            table.add_row(*self._ledger_cells(row, layout), key=str(index))
        count = len(rows)
        # LLR-005.1 (batch-94): the entry-count subtitle doubles as the dirty
        # indicator — the marker is part of the SAME string.
        self._set_window_subtitle(
            "patch_win_script",
            f"{count} {'entry' if count == 1 else 'entries'}"
            + (" ●" if self._dirty else ""),
        )
        if rows:
            table.remove_class("hidden")
            empty_state.add_class("hidden")
        else:
            table.add_class("hidden")
            empty_state.remove_class("hidden")
            empty_state.update(self.EMPTY_STATE_TEXT)
        self.query_one("#patch_doc_tally", Static).update(self._tally_text())
        self._render_before_after_card()
        if not isinstance(document, _Unset):
            self._show_document(document)
        # The Status column is sized to the longest status (D21 input): only a
        # change of that width needs a layout pass (resize / show run their own).
        if self._layout is not None and self._layout.status != max(
            7, min(self._status_longest(), 20)
        ):
            self.call_after_refresh(self._apply_layout)

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted
    ) -> None:
        """Drive the before/after card as the entries cursor moves (LLR-080.3).

        Summary:
            The entries table is ``cursor_type="row"``, so the highlighted row
            index IS the document-order entry index — the card previews THAT
            entry. Highlight (not ``RowSelected``) is the right event: it fires
            on cursor movement, giving the analyst a live read-out without
            requiring a commit keystroke — the ``A2LDetailCard`` precedent
            (batch-47 LLR-069.2).

        Args:
            event (DataTable.RowHighlighted): Event payload carrying
                ``data_table`` and ``cursor_row``.

        Returns:
            None

        Data Flow:
            - Ignore every table but ``#patch_doc_entries_table``.
            - Hand ``event.cursor_row`` to :meth:`_render_before_after_card`.
            - The event is NOT stopped: ``S19TuiApp.on_data_table_row_highlighted``
              also listens (for the A2L card) and filters by table id, so
              letting it bubble costs nothing and stopping it would couple this
              panel to that handler's business.

        Dependencies:
            Uses:
                - :meth:`_render_before_after_card`
            Used by:
                - Textual event dispatch for ``DataTable.RowHighlighted``
        """
        table = getattr(event, "data_table", None)
        if getattr(table, "id", None) != "patch_doc_entries_table":
            return
        self._render_before_after_card(event.cursor_row)

    def _render_before_after_card(self, index: Optional[int] = None) -> None:
        """Render the before→after strip for one entry index (LLR-080.3, D5).

        Summary:
            Resolve the selected entry POSITIONALLY, read the image bytes of its
            span and of the context around it (the aligned row start up to the
            address, and the span end to the end of its last row) out of the
            retained ``mem_map``, and hand them to the card at the layout's
            bytes per row. No entries → the no-entries state; no selection →
            the no-selection state; no image → the no-image state.

        Note (the join is POSITIONAL — never address-matched):
            ``ChangeEntry`` carries no id; the contract is document order and
            ``cursor_type="row"`` makes the cursor row that same index; two
            entries sharing a start address stay distinct (TC-080.3).

        Note (read-only — LLR-080.5; ints only — LLR-080.7):
            ``mem_map`` is read with ``.get``; only ``row.address`` and
            ``row.encoded_bytes`` are read off the row.
        """
        cards = self.query("#patch_before_after_card")
        if not cards:
            return
        card = cards.first(BeforeAfterCard)
        if not self._entry_rows:
            card.show_state(CARD_NO_ENTRIES)
            return
        if index is None:
            index = self.query_one(
                "#patch_doc_entries_table", DataTable
            ).cursor_row
        if not 0 <= index < len(self._entry_rows):
            card.show_entry(None, None, ())
            return
        # Direct attribute access: these fields are REQUIRED for the strip,
        # and a default would silently paint an empty preview.
        row = self._entry_rows[index]
        address = int(row.address)
        after = tuple(row.encoded_bytes)
        if self._mem_map is None:
            card.show_entry(address, None, after)
            return
        per_row = self._widths().strip_bytes
        row_start = address - address % per_row
        span_end = address + len(after)
        rows = -(-(span_end - row_start) // per_row)
        mem = self._mem_map
        card.show_entry(
            address,
            [mem.get(a) for a in range(address, span_end)],
            after,
            per_row,
            lead=[mem.get(a) for a in range(row_start, address)],
            trail=[mem.get(a) for a in range(span_end, row_start + rows * per_row)],
        )

    def refresh_issues(self, lines: Sequence[str]) -> None:
        """Render the persistent declaration-fault area (LLR-002.8).

        Non-empty → the count label ``Declaration faults: N`` and the listing
        (a literal ``Text`` through ``safe_text`` — the lines echo file-derived
        values, LLR-144.7); empty → both cleared. With no entries, the first
        finding is also the ledger's one state line (LLR-148.9: a refused load
        shows its finding where the entries would be).
        """
        count_label = self.query_one("#patch_doc_issue_count", Label)
        listing = self.query_one("#patch_doc_issues", Static)
        empty_state = self.query_one("#patch_doc_empty_state", Static)
        if lines:
            count_label.update(f"Declaration faults: {len(lines)}")
            listing.update(safe_text("\n".join(str(line) for line in lines)))
            listing.remove_class("hidden")
            if not self._entry_rows:
                empty_state.update(safe_text(f"Refused: {lines[0]}"))
        else:
            count_label.update("")
            listing.update("")
            listing.add_class("hidden")
            if not self._entry_rows:
                empty_state.update(self.EMPTY_STATE_TEXT)

    def show_save_prompt(self, suggestion: str) -> None:
        """Show the post-apply save-back prompt (LLR-002.7 UI half).

        Summary:
            Un-hide the save-back row and pre-fill the filename ``Input``
            with the editable ``<variant_id>-patched.s19`` suggestion.

        Args:
            suggestion (str): The pre-filled target filename suggestion.

        Dependencies:
            Used by:
                - ``S19TuiApp`` apply-action handling
        """
        self.query_one("#patch_saveback_name_input", Input).value = suggestion
        # Reset the width selector to its 32-byte default each time the prompt
        # appears, so a per-apply width choice never leaks into the next apply.
        self._saveback_width = self.SAVEBACK_WIDTHS[0]
        self.query_one("#patch_saveback_width_button", Button).label = (
            f"Width: {self._saveback_width} bytes/line"
        )
        self.query_one("#patch_saveback_row", Container).remove_class("hidden")

    def hide_save_prompt(self) -> None:
        """Hide the save-back prompt after a confirm / decline.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_save_back_decision``
        """
        self.query_one("#patch_saveback_row", Container).add_class("hidden")

    def show_before_after_prompt(self) -> None:
        """Reveal the persistent before/after-report control (US-061).

        Summary:
            Un-hide the ``#patch_before_after_row`` so the report control is
            discoverable and actionable after a successful save-back —
            persistent widget state, NOT a transient ``notify`` (LLR-061.1).
            Mirrors :meth:`show_save_prompt`'s ``.hidden``-reveal idiom.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_save_back_decision``
        """
        self.query_one("#patch_before_after_row", Container).remove_class(
            "hidden"
        )

    def hide_before_after_prompt(self) -> None:
        """Re-hide the persistent before/after-report control (US-061).

        Summary:
            Add the ``.hidden`` class back to ``#patch_before_after_row`` when
            the editing context clears (a new document load resets
            ``ChangeService.last_summary`` to ``None``, so a stale "report
            ready" offer must not persist — LLR-061.1 clear-on-context).

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_action_requested``
                  (load_doc / parse_paste / refresh_doc arms)
        """
        self.query_one("#patch_before_after_row", Container).add_class("hidden")

    def set_edit_json_enabled(self, enabled: bool) -> None:
        """Toggle the "Edit JSON" control's enabled state (US-064b, A-01 guard).

        Summary:
            Enable or disable ``#patch_edit_json_button`` so the JSON popup
            opens ONLY for a paste-authored / empty document — the LLR-064b.4
            data-loss guard. The app calls this after every action with
            ``enabled = document.source_path is None``: a file-backed document
            (``source_path is not None``) disables the control so its stale
            ``DUMMY_CHANGESET_TEXT`` buffer can never be Confirmed to
            ``load_text``-REPLACE the loaded document.

        Args:
            enabled (bool): ``True`` to enable the control (paste-authored /
                empty document); ``False`` to disable it (file-backed).

        Dependencies:
            Used by:
                - ``S19TuiApp`` Patch Editor action / change-file handlers
        """
        self.query_one("#patch_edit_json_button", Button).disabled = not enabled

    def _history_strip_text(
        self, enabled: bool, depths: Optional[Mapping[str, int]]
    ) -> Text:
        """Build the history strip's renderable (LLR-081.2).

        Summary:
            Compose the analyst's position in the undo/redo history — steps
            available backward and forward, the depth against the bound, and
            the keys that move it — as TWO deliberate lines:

                ``↶ 1 back  ↷ 1 fwd  2/20``
                ``ctrl+z / ctrl+y``

            When the controls are DISABLED the strip renders a single muted
            ``history off`` line and NO key hints, because the keys are inert:
            ``ctrl+z``/``ctrl+y`` route through the same ``_patch_history_
            action_allowed`` A-01 guard that disables the buttons. Printing a
            hint for a key that does nothing is a wrong answer, not chrome.

        Args:
            enabled (bool): The Undo/Redo controls' enabled state, so the strip
                and the buttons cannot disagree about whether a step exists
                (LLR-081.3). The panel is told the STATE, never the reason: it
                is a view, and "file-backed" is the caller's A-01 rationale.
            depths (Optional[Mapping[str, int]]): ``ChangeService.
                history_depths()`` — ``back`` / ``forward`` / ``bound``.
                Duck-typed so this view widget imports nothing from the service
                layer (C-7). ``None`` or a missing key reads 0, which renders
                the honest empty state.

        Returns:
            rich.text.Text: The strip's renderable. Never a ``str`` — and never
            any file-derived text: derived integers and an author-fixed
            vocabulary only (C-17).

        Data Flow:
            - Disabled → the muted ``history off`` line, nothing else.
            - Else → glyph + count per direction, ``back+forward`` against
              ``bound``, then the key-hint line.
            - Counts are rendered VALUE when non-zero and DGRAY at zero, so
              "no step that way" reads as absent rather than as a number. No
              new hue: the strip is chrome, not a verdict (GREEN/YELLOW/RED
              stay reserved for verdicts inside this panel — Inc-2b).

        Dependencies:
            Uses:
                - ``_HISTORY_HINT`` / ``_HISTORY_OFF`` ; ``insight_style``
                  ``LABEL`` / ``VALUE`` / ``DGRAY``
            Used by:
                - :meth:`set_undo_redo_enabled`

        Example:
            >>> panel = PatchEditorPanel.__new__(PatchEditorPanel)
            >>> panel._history_strip_text(
            ...     True, {"back": 1, "forward": 1, "bound": 20}
            ... ).plain
            '↶ 1 back  ↷ 1 fwd  2/20\\nctrl+z / ctrl+y'
        """
        if not enabled:
            return Text(self._HISTORY_OFF, style=DGRAY)

        counts = depths or {}
        back = int(counts.get("back", 0))
        forward = int(counts.get("forward", 0))
        bound = int(counts.get("bound", 0))

        text = Text()
        for index, (glyph, count, noun) in enumerate(
            (("↶", back, "back"), ("↷", forward, "fwd"))
        ):
            if index:
                text.append("  ", style=LABEL)
            text.append(f"{glyph} ", style=LABEL)
            text.append(str(count), style=VALUE if count else DGRAY)
            text.append(f" {noun}", style=LABEL)
        # Depth against the bound. `back + forward` is the number of snapshots
        # the history holds, which `_push_history`'s eviction caps at `bound`
        # and `undo`/`redo` conserve — so this total saturates rather than
        # growing (LLR-081.1's derivation; AT-081b's 21st-op arm).
        text.append("  ", style=LABEL)
        text.append(f"{back + forward}/{bound}", style=LABEL)
        text.append("\n", style=LABEL)
        text.append(self._HISTORY_HINT, style=DGRAY)
        return text

    def set_undo_redo_enabled(
        self, enabled: bool, depths: Optional[Mapping[str, int]] = None
    ) -> None:
        """Toggle the Undo/Redo controls + render the history strip (US-068a / LLR-081.2).

        Summary:
            Enable or disable ``#patch_undo_button`` and ``#patch_redo_button``
            together so change-set undo/redo is available ONLY for a
            paste-authored / empty document — the LLR-068a.4 data-loss guard.
            The app calls this after every action with
            ``enabled = document.source_path is None``: a file-backed document
            (``source_path is not None``) disables both controls so a
            file-backed change document can never be silently mutated or
            replaced through the history path (batch-37 ``set_edit_json_enabled``
            precedent).

            **batch-48 (LLR-081.2/.3): this is ALSO the history strip's seam**,
            deliberately — the strip answers "is a step back available?", which
            is the same question the enable state answers. Rendering both from
            ONE call means the strip and the buttons cannot disagree; a
            separate ``refresh_history`` would be a second seam that a future
            call site could forget, which is exactly the batch-38 Inc-4 F1
            stale-panel defect.

        Args:
            enabled (bool): ``True`` to enable both controls (paste-authored /
                empty document); ``False`` to disable them (file-backed).
            depths (Optional[Mapping[str, int]]): ``ChangeService.
                history_depths()`` — threaded in as a PARAMETER so the panel
                keeps importing nothing from the service layer and never
                reaches the running app (C-7 / the ``MemoryMapPanel.
                render_ranges(…, mem_map=…)`` precedent). Defaulted, so no
                existing caller breaks; ``None`` renders the empty state.

        Dependencies:
            Uses:
                - :meth:`_history_strip_text`
            Used by:
                - ``S19TuiApp`` Patch Editor action / change-file / history
                  handlers (all THREE push the depths — LLR-081.3)
        """
        self.query_one("#patch_undo_button", Button).disabled = not enabled
        self.query_one("#patch_redo_button", Button).disabled = not enabled
        self.query_one("#patch_history_strip", Static).update(
            self._history_strip_text(enabled, depths)
        )

    def set_entry_edit_json_enabled(self, enabled: bool) -> None:
        """Toggle the per-entry Edit-JSON control's enabled state (US-068b).

        Summary:
            Enable or disable ``#patch_entry_edit_json_button`` so the
            per-entry JSON popup opens ONLY for a paste-authored / empty
            document — the LLR-068b.4 A-01 data-loss guard. The app calls this
            after every action with ``enabled = document.source_path is None``:
            a file-backed document (``source_path is not None``) disables the
            control so a per-entry edit can never silently mutate the loaded
            document (batch-37 ``set_edit_json_enabled`` precedent).

        Args:
            enabled (bool): ``True`` to enable the control (paste-authored /
                empty document); ``False`` to disable it (file-backed).

        Dependencies:
            Used by:
                - ``S19TuiApp`` Patch Editor action / change-file / history
                  handlers
        """
        self.query_one(
            "#patch_entry_edit_json_button", Button
        ).disabled = not enabled

    def _paste_gauge_text(self, used_chars: int) -> Text:
        """Build the paste-cap gauge's renderable (LLR-079.4).

        Summary:
            Render ``<used>K / 64.0K`` against the shared 64 KiB paste cap,
            styled by :func:`cap_gauge_style` so the read-out ESCALATES as the
            buffer fills.

            **Units are CHARS, not bytes, and that is deliberate.** The cap
            (``_CLIPBOARD_READ_CAP_CHARS``, ``os_clipboard_input.py:72``)
            truncates on ``text[:CAP]`` — a **character** slice — so a
            byte-denominated gauge would disagree with the truncation it
            exists to predict, by up to 4x on non-ASCII input. ``human_bytes``
            is therefore NOT used here despite being the house size helper: it
            is a *byte* humanizer, and rendering a char count through it would
            print a confident, wrong unit. ``K`` = 1024 chars.

            **Hue (operator ruling, 2026-07-16):** the gauge escalates as a
            WARNING (§6.5 Amendment F's semantics, app-wide, unnarrowed) but
            must NOT reuse GREEN/YELLOW/RED, because inside
            ``#patch_editor_panel`` those three are VERDICT hues
            (``_GLYPH_STYLE``, the pass/fail strip). ``threshold_style``
            returns exactly those three and is therefore NOT usable here;
            :func:`cap_gauge_style` escalates within the MAGENTA family
            instead (quiet grey → magenta → bold magenta), whose hue is the
            MEASURED optimum against the full app-wide claimant census
            (``test_tc079_5*``): no hue on the circle separates further from
            every claimed hue than MAGENTA does.
            ⚠ The earlier ">= 43 deg from every claimant" wording here was
            FALSE and is retracted (Inc-5b). It was not merely wrong — it was
            UNSATISFIABLE: against the complete census the best any hue
            achieves is 40.77 deg, so no colour could have satisfied it. It
            "passed" only because the census omitted the hues that would have
            failed it. The binding assertion is now optimality plus an
            ANCHORED floor (24 deg — beating the 23.5 deg pair the app already
            ships and reads fine), which is self-calibrating and cannot go
            unsatisfiable. See REQUIREMENTS.md §6.5 Amendment F-1.

        Args:
            used_chars (int): The buffer's current ``len(text)``. Read from
                the widget by :meth:`_refresh_paste_gauge`; never a
                caller-supplied count.

        Returns:
            rich.text.Text: The gauge line. Never a ``str`` — and never any
            file-derived text: an integer and author-fixed labels only
            (C-17 / LLR-079.3). The pasted buffer reaches this method as a
            ``len``, so no payload character can reach the render path even
            in principle.

        Raises:
            None. Integer arithmetic and a constant divisor.

        Data Flow:
            - ``used_chars`` → percent of ``_PASTE_CAP_CHARS`` →
              :func:`cap_gauge_style` → :func:`label_value`.
            - No clamp on the percentage: ``cap_gauge_style``'s top band is
              lower-inclusive, so at-cap and over-cap both read bold.

        Dependencies:
            Uses:
                - ``_PASTE_CAP_CHARS`` / ``_PASTE_GAUGE_WARN_PCT`` /
                  ``_PASTE_GAUGE_BAD_PCT`` ; ``insight_style.cap_gauge_style``
                  / ``LABEL``
            Used by:
                - :meth:`_refresh_paste_gauge`

        Example:
            >>> panel = PatchEditorPanel.__new__(PatchEditorPanel)
            >>> panel._paste_gauge_text(32768).plain
            '32.0K / 64.0K'
        """
        cap = self._PASTE_CAP_CHARS
        pct = (used_chars / cap) * 100.0
        text = Text()
        # The USED figure escalates; the denominator is a constant, so it stays
        # muted. `label_value` would have styled these the other way round.
        text.append(
            f"{used_chars / 1024:.1f}K",
            style=cap_gauge_style(
                pct, self._PASTE_GAUGE_WARN_PCT, self._PASTE_GAUGE_BAD_PCT
            ),
        )
        text.append(f" / {cap / 1024:.1f}K", style=LABEL)
        return text

    def _check_strip_text(self, aggregates: Optional[Mapping[str, int]]) -> Text:
        """Build the CHECKS pass/fail strip's renderable (LLR-078.1).

        Summary:
            Compose ``✓P ✗F ◐U`` from the three aggregate counts, each glyph
            carrying its ``_GLYPH_STYLE`` verdict colour, followed on a SECOND
            LINE by a proportional bar of the PASS rate.

            **The line break is intentional, not overflow** — see
            ``_CHECK_STRIP_BAR_CELLS`` for the C-29 measurement that forces it.
            In one sentence: the strip's real content budget at 120x30 is 14
            cells, the tightest one-line counts consume all 14 at 3 digits, and
            the previous one-line form wrapped MID-TOKEN at 2 digits — reading
            a count as a bar label. Two deliberate lines cost h=2, which is
            exactly what the wrapped form already painted.

        Args:
            aggregates (Optional[Mapping[str, int]]): The three counts —
                duck-typed so this view widget imports nothing from the
                service layer (C-7). ``None`` or a missing key reads ``0``;
                A3 guarantees the real seam always carries all three.

        Returns:
            rich.text.Text: The strip line. Never a ``str`` — and never any
            file-derived text: integers and a closed glyph vocabulary only
            (C-17 / LLR-078.5).

        Data Flow:
            - Read the three counts; append a styled glyph + count per
              verdict; append ``microbar(passed / total)``.
            - ``total == 0`` short-circuits ``frac`` to ``0.0`` — there is no
              division, so a 0-entry run cannot raise (LLR-078.4).
            - The bar is UNFLOORED (the helper's default). ``floor=True`` is
              reserved for bars meaning "this row exists" (batch-47
              LLR-042.7); this bar means "this fraction passed". MEASURED: the
              floor is gated on ``clamped > 0.0`` (``insight_style.py:214``),
              so it does NOT affect a 0-pass run — both settings render an
              empty bar there. What it changes is a small-but-nonzero rate: 1
              passed of 20 is ``round(0.05 * 8) == 0`` cells unfloored and 1
              floored.
            - ⚠ **The reason is REDUNDANCY, not asymmetry** (Inc-5, correcting
              this docstring's own third-time-repeated claim). The tempting
              justification — "overstating passes is the harm, and the floor
              only overstates" — is FALSE, and falsifying it needs no new
              measurement: ``round()`` overstates passes at the TOP end too,
              floored or not. **19 of 20 → ``round(0.95 * 8) == 8`` — a FULL
              bar, pixel-identical to 20 of 20.** A bar that paints "all
              passed" over a real failure is the same harm, at the end where
              the floor is not even involved; there is no asymmetry to appeal
              to. The honest reason ``floor=False`` is right is that the
              AUTHORITATIVE counts sit on the line above, so +-1 cell of
              rounding either way costs nothing — the bar is a shape cue, not
              the datum. The default is therefore the correct default because
              it is the default, and nothing here needs an override.

        Dependencies:
            Uses:
                - ``_GLYPH_STYLE`` / ``_CHECK_STRIP_BAR_CELLS`` ;
                  ``insight_style.microbar`` / ``GREEN`` / ``VALUE``
            Used by:
                - :meth:`refresh_check_results`

        Example:
            >>> panel = PatchEditorPanel.__new__(PatchEditorPanel)
            >>> panel._check_strip_text(
            ...     {"passed": 2, "failed": 1, "uncheckable": 1}
            ... ).plain
            '✓2 ✗1 ◐1\\n████░░░░'
        """
        counts = aggregates or {}
        passed = int(counts.get("passed", 0))
        failed = int(counts.get("failed", 0))
        uncheckable = int(counts.get("uncheckable", 0))
        total = passed + failed + uncheckable

        text = Text()
        for index, (glyph, count) in enumerate(
            (("✓", passed), ("✗", failed), ("◐", uncheckable))
        ):
            if index:
                text.append(" ", style=VALUE)
            text.append(glyph, style=self._GLYPH_STYLE[glyph])
            text.append(str(count), style=VALUE)
        # Line 2 — see `_CHECK_STRIP_BAR_CELLS`: the bar cannot share line 1 at
        # the measured 14-cell budget, so it gets its own line rather than
        # wrapping into one mid-token.
        text.append("\n", style=VALUE)
        frac = passed / total if total else 0.0
        text.append_text(
            microbar(frac, self._CHECK_STRIP_BAR_CELLS, style=GREEN)
        )
        return text

    def refresh_check_results(
        self,
        rows: Sequence[object],
        status_line: str,
        aggregates: Optional[Mapping[str, int]] = None,
    ) -> None:
        """Render the check-run display (LLR-004.5) + the pass/fail strip (LLR-078.1).

        Summary:
            Replace the check-results area with one ``Static`` per result
            row, each carrying its ``sev-*`` class (the
            ``css_class_for_severity`` colour the service shaped), set the
            aggregate-count status line, and render the pass/fail strip.

        Args:
            rows (Sequence[object]): The ``ChangeService.check_rows``
                output — each exposes ``text`` and ``css_class``. Typed as
                ``object`` so this view widget imports nothing from the
                service layer.
            status_line (str): The three-aggregate-count line (``Checks: P
                passed, F failed, U uncheckable``) or the pending-seam
                message.
            aggregates (Optional[Mapping[str, int]]): The three counts for
                the strip — ``ChangeService.check_aggregates()``, threaded in
                as a PARAMETER so the panel keeps importing nothing from the
                service layer and never reaches the running app (C-7 /
                LLR-078.2; the ``MemoryMapPanel.render_ranges(…, mem_map=…)``
                precedent). Defaulted, so no existing caller breaks; ``None``
                renders the all-zero cleared strip.

        Data Flow:
            - Update the status label, render the strip, remove prior result
              children, mount one classed ``Static`` per row.
            - Set the CHECKS window's run-state border subtitle (LLR-075.1):
              the row count when a run is shown (a non-empty status line),
              else the no-run token.
            - The strip CLEARS by riding ``last_check_result``'s existing
              ``undo``/``redo`` reset (``change_service.py:538`` / ``:570``):
              the history call site passes the accessor's all-zero mapping,
              so the strip and ``check_rows()`` always read one state
              (LLR-078.3). An omitted history site would leave a stale count
              — the batch-38 Inc-4 F1 defect.

        Dependencies:
            Used by:
                - ``S19TuiApp`` run-checks action handling (post-run site)
                - ``S19TuiApp._refresh_patch_history_view`` (cleared state)
        """
        # batch-97 LLR-148.9: a cleared run (the undo/redo reset passes "")
        # shows the Checks tab's one no-run line, never a blank region.
        self.query_one("#patch_checks_status", Label).update(
            status_line or self.CHECKS_NO_RUN_TEXT
        )
        self.query_one("#patch_checks_strip", Static).update(
            self._check_strip_text(aggregates)
        )
        container = self.query_one("#patch_checks_results", Container)
        container.remove_children()
        for row in rows:
            container.mount(Static(row.text, classes=row.css_class, markup=False))
        # LLR-075.1: derived from whether a run is shown (the status line is
        # non-empty), never from the row count — an empty 0-entry run shows
        # "0 checked" while a non-current run shows "no run yet". The subtitle
        # stays an author-composed token (C-17).
        self._set_window_subtitle(
            "patch_win_checks",
            f"{len(rows)} checked" if status_line else self._NO_RUN_SUBTITLE,
        )


#: batch-97 (LLR-148.7, D7): the Patch Editor's closed glyph vocabulary —
#: glyph -> its one meaning. The four check-run verdicts lead each ledger
#: row's Kind cell (``_GLYPH_STYLE``); ``--`` is the strip's unmapped byte
#: (``CARD_UNMAPPED_TOKEN``). ``#patch_legend`` is generated from it.
PATCH_GLYPHS: Mapping[str, str] = {
    "✓": "check passed",
    "✗": "check failed",
    "◐": "uncheckable",
    "·": "not checked",
    CARD_UNMAPPED_TOKEN: "byte not in the image",
}


def json_stamp_text(n: Optional[int], hhmmss: Optional[str], dirty: bool) -> str:
    """The JSON view's stamp (LLR-144.6, D4).

    Example:
        >>> json_stamp_text(6, "10:20:30", False)
        '6 entries · 10:20:30 · saved'
        >>> json_stamp_text(None, None, True)
        'no document yet · unsaved changes'
    """
    if n is None:
        return "no document yet" + (" · unsaved changes" if dirty else "")
    noun = "entry" if n == 1 else "entries"
    return f"{n} {noun} · {hhmmss} · {'unsaved changes' if dirty else 'saved'}"


class PatchLayout(NamedTuple):
    """The Patch Editor widths Python derives (D21); CSS sizes everything else."""

    kind: int
    address: int
    value: int
    status: int
    linkage: int
    strip_bytes: int
    ribbon: int


def patch_layout(
    ledger_w: int, inspector_w: int, status_longest: int = 0, ribbon_w: int = 110
) -> PatchLayout:
    """Derive the Patch Editor's painted widths from its measured content widths.

    Summary:
        D21 / D5 (f). ``ledger_w`` is the PATCH SCRIPT frame's content width
        (the table fills it; its 1-cell vertical scrollbar gutter is always
        reserved and every column pays 2 cells of padding). Kind (glyph +
        ``string``) is 8, Address 10 (``0x`` + 8 digits, never clipped),
        Linkage 7 (its header) and Status the longest status text, between 7
        and 20; Value / bytes takes the rest (never below 12).
        ``inspector_w`` is ``#patch_inspector``'s content width: the strip's
        bytes per row is the largest of :data:`STRIP_ROW_BYTES` whose line
        (``3·k + 8``) fits the card (``inspector_w − 3``: the pane's scrollbar
        gutter and the card's padding). ``ribbon_w`` is the identity ribbon's
        content width (the file name keeps its tail inside it).

    Example:
        >>> tuple(patch_layout(65, 41, 6))
        (8, 10, 22, 7, 7, 8, 110)
        >>> patch_layout(115, 75, 6).strip_bytes
        16
    """
    status = max(7, min(status_longest, 20))
    usable = ledger_w - 1 - 2 * 5
    value = max(12, usable - 8 - 10 - 7 - status)
    fitting = [k for k in STRIP_ROW_BYTES if 3 * k + 8 <= inspector_w - 3]
    strip = max(fitting) if fitting else STRIP_ROW_BYTES[0]
    return PatchLayout(8, 10, value, status, 7, strip, max(8, ribbon_w))
