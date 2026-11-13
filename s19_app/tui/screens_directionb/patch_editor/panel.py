"""s19_app.tui.screens_directionb.patch_editor.panel - the thin PatchEditorPanel (class-level statements and lifecycle methods moved verbatim from patch_editor.py at 2dbd7d5a)."""
from __future__ import annotations

from typing import List, Mapping, Optional, Sequence, Tuple
from textual import events
from textual.containers import Container, ScrollableContainer
from textual.message import Message
from textual.widgets import ContentSwitcher, DataTable, Select, Static
from ...a2l_parameter_picker import A2LParameterPicker
from ...insight_style import DGRAY, GREEN, RED, YELLOW, label_value
from ...os_clipboard_input import _CLIPBOARD_READ_CAP_CHARS
from ....utils import safe_text
from ..shared import CheckLayout
from .shared import PatchLayout
from .layout import LayoutMixin
from .a2l_picker import A2lPickerMixin
from .document import DocumentMixin
from .entries import EntriesMixin
from .actions import ActionsMixin
from .checks import ChecksMixin


class PatchEditorPanel(
    LayoutMixin,
    A2lPickerMixin,
    DocumentMixin,
    EntriesMixin,
    ActionsMixin,
    ChecksMixin,
    ScrollableContainer,
):
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

    def set_image_mem_map(self, mem_map: Optional[Mapping[int, int]]) -> None:
        """Replace the retained image map (batch-102 Inc 5, E3 ruling 4).

        The app pushes ``None`` here when the primary image is unloaded, so
        a later ``Use parameter`` seeds Bytes from no map and paints the
        ``image bytes unavailable`` line instead of the unloaded image's
        stale bytes. Tolerates a not-yet-mounted tree (headless unit path).
        """
        self._mem_map = mem_map

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
