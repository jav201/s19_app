"""
Change service — the v2 (`s19app-changeset`) Patch Editor orchestration layer.

This module is the batch-07 E3a evolution of ``services/cdfx_service.py``
(LLR-003.4): it owns one in-memory v2 :class:`~s19_app.tui.changes.model.
ChangeDocument` and sequences every ``changes``-package call the consolidated
Patch Editor needs — entry add / edit / remove for **both** entry kinds
(``"string"`` / ``"bytes"``), v2 JSON load / save (``read_change_document`` /
``write_change_document``), validation (collision rule + image containment),
apply (``apply_change_document``) with the LLR-002.7 save-back flow
(``save_patched_image``), and the LLR-004.5 run-checks surface through the
``check_runner`` seam — filled by the real E4 engine
(``changes.check.run_check_document``) since increment E4, still injectable
for tests.

It also hosts the LLR-004.4 **headless project entry point**,
:func:`run_checks_for_project` — service-level per the LLR's wording: paths
in, one :class:`CheckRunResult` out, reusing the load-service parse path
(``build_loaded_s19`` / ``build_loaded_hex``) plus the MAC / A2L parsers for
the informative linkage sources. No TUI interaction anywhere on that path.

The retired parameter-by-name methods and the selective-``.cdfx`` export of
``CdfxService`` deliberately do not exist here (HLR-003 statement 2); the
``cdfx_service.py`` file itself was deleted at increment E3b.

This module imports stdlib + the parse layer (``core`` / ``hexfile`` /
``mac`` / ``a2l_parse``) + the ``changes`` package + sibling services +
``validation.model`` + ``color_policy`` only — **no Textual import**
(service-layer contract; the screen and ``app.py`` stay presentational,
constraint C-7; verified by the subprocess-isolated probe in
``tests/test_checks_engine.py``, F-Q-07).
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ...core import S19File
from ...hexfile import IntelHexFile
from ...validation.model import ValidationIssue, ValidationSeverity
from ..a2l_parse import parse_a2l_file
from ..changes import (
    CHG_COLLISION,
    ChangeDocument,
    ChangeEntry,
    ChangeSummary,
    DEFAULT_CHANGE_FILE_NAME,
    FORMAT_ID,
    FORMAT_VERSION,
    apply_change_document,
    classify_containment,
    collision_issues,
    read_change_document,
    save_patched_image,
    serialize_change_document,
    verify_written_image,
    write_change_document,
)
from ..changes.check import run_check_document
from ..changes.io import parse_change_document
from ..changes.model import CHECK_AGGREGATE_KEYS, CheckRunResult
from ..color_policy import css_class_for_severity
from ..mac import parse_mac_file
from .a2l_service import enrich_tags_and_render
from .load_service import build_loaded_hex, build_loaded_s19

#: The two v2 entry kinds (LLR-001.2 wire field ``type``).
ENTRY_KIND_STRING = "string"
ENTRY_KIND_BYTES = "bytes"

#: Check-result token → severity for the LLR-004.5 row colouring. ``pass``
#: maps to OK (``sev-ok`` — the Phase-3 colour-policy decision), ``fail`` to
#: ERROR (``sev-error``), ``uncheckable`` to WARNING (``sev-warning``).
_CHECK_RESULT_SEVERITY: Dict[str, ValidationSeverity] = {
    "pass": ValidationSeverity.OK,
    "fail": ValidationSeverity.ERROR,
    "uncheckable": ValidationSeverity.WARNING,
}

#: The batch-48 check-glyph vocabulary (LLR-077.3) — a CLOSED 4-token set.
#: Author-controlled constants; no file-derived text ever reaches a glyph
#: (LLR-077.6). The render styles live at the render boundary
#: (``screens_directionb._GLYPH_STYLE``); ``test_tui_patch_glyphs.py``
#: asserts the two maps stay total over each other.
GLYPH_PASS = "✓"
GLYPH_FAIL = "✗"
GLYPH_UNCHECKABLE = "◐"
#: No check result is current for the live document AND the live image —
#: the honest degradation of LLR-077.2's provenance stamp, and the state of
#: every row before any run.
GLYPH_NO_RESULT = "·"

#: Check-result token → glyph. An UNRECOGNISED token maps to
#: :data:`GLYPH_UNCHECKABLE`, mirroring ``_CHECK_RESULT_SEVERITY``'s
#: WARNING default rather than inventing a second policy (LLR-077.3).
_CHECK_RESULT_GLYPH: Dict[str, str] = {
    "pass": GLYPH_PASS,
    "fail": GLYPH_FAIL,
    "uncheckable": GLYPH_UNCHECKABLE,
}

#: How many byte tokens an entries-table value cell shows before eliding.
_ROW_BYTES_PREVIEW = 8

#: Maximum depth of the change-set undo history (US-068a / LLR-068a.1). Each
#: document-mutating operation pushes ONE deep-copy snapshot; the stack evicts
#: its oldest entry past this bound so a long editing session cannot grow the
#: history without limit (risk R-B). Value assumed (Phase-3 flag): 20 change-
#: set-level (not keystroke-level) snapshots is ample for interactive editing.
_HISTORY_MAX = 20

#: The keys of :meth:`ChangeService.history_depths` in canonical order — the
#: history strip's data contract (LLR-081.1). ``back`` / ``forward`` are the
#: number of steps ``undo`` / ``redo`` can actually take from here; ``bound`` is
#: :data:`_HISTORY_MAX`, published so the strip can show the depth AGAINST the
#: limit without importing the constant.
HISTORY_DEPTH_KEYS: tuple[str, ...] = ("back", "forward", "bound")


def parse_address(address_text: str) -> int:
    """
    Summary:
        Map a Patch Editor address input field to a non-negative integer
        memory address — the permissive **TUI-input grammar** of LLR-001.2
        (the strict ``0x``-string wire grammar lives in ``changes/io.py``).

    Args:
        address_text (str): The raw text of the address ``Input``. Accepts a
            ``0x``-prefixed hexadecimal literal or a plain decimal literal —
            ``int(text, 0)`` honours the prefix.

    Returns:
        int: The parsed non-negative integer memory address.

    Raises:
        ValueError: When ``address_text`` is blank, is not a valid integer
            literal, or is negative — the app reports it as a status message
            rather than crashing.

    Data Flow:
        - Strip the field, parse with base-0 so ``0x`` is honoured, reject a
          negative result before it reaches the entry model.

    Dependencies:
        Used by:
            - ChangeService.add_entry / edit_entry / remove_entry

    Example:
        >>> parse_address("0x100")
        256
        >>> parse_address("512")
        512
    """
    stripped = address_text.strip()
    if not stripped:
        raise ValueError("memory address must not be empty")
    address = int(stripped, 0)
    if address < 0:
        raise ValueError(f"memory address must be non-negative, got {address}")
    return address


def parse_new_bytes(bytes_text: str) -> list[int]:
    """
    Summary:
        Map a Patch Editor bytes input field to an ordered list of integer
        byte values — the permissive **TUI-input grammar** of LLR-001.2
        (commas, decimals and ``0x`` prefixes accepted interactively; the
        canonical writer normalises to the strict wire form on save).

    Args:
        bytes_text (str): The raw text of the bytes ``Input`` — a run of byte
            tokens separated by whitespace and/or commas. Each token is a
            ``0x``-prefixed hex literal or a plain decimal literal; a bare
            two-digit hex string (for example ``DE AD BE EF``) is also
            accepted so the engineer can paste a hex-dump fragment directly.

    Returns:
        list[int]: The parsed byte values in input order. Range checking
        (0-255) and the empty-run rejection are left to
        ``ChangeEntry.__post_init__`` so there is one authoritative
        byte-range rule.

    Raises:
        ValueError: When ``bytes_text`` holds a token that is neither a valid
            integer literal nor a bare hex byte string.

    Data Flow:
        - Split on commas and whitespace, drop empty tokens.
        - Parse each token base-0; a token that fails base-0 but is a pure
          hex string is retried as base-16 (the bare-hex-dump convenience).

    Dependencies:
        Used by:
            - ChangeService.add_entry / edit_entry

    Example:
        >>> parse_new_bytes("0x01 0xAB 0xFF")
        [1, 171, 255]
        >>> parse_new_bytes("DE AD BE EF")
        [222, 173, 190, 239]
    """
    tokens = [tok for tok in bytes_text.replace(",", " ").split() if tok]
    values: list[int] = []
    for token in tokens:
        try:
            values.append(int(token, 0))
        except ValueError:
            try:
                values.append(int(token, 16))
            except ValueError:
                raise ValueError(
                    f"invalid byte token {token!r} - use hex (0x1F or 1F) "
                    "or decimal"
                ) from None
    return values


@dataclass(slots=True)
class ChangeActionResult:
    """
    Summary:
        The outcome of a change-service action — a short status message plus
        the ``ValidationIssue`` list the app surfaces on the status path
        (the ``CdfxActionResult`` pattern, evolved for the v2 flow).

    Args:
        message (str): A short human-readable summary of the action for the
            status line (kept brief — the log line view trims to 50 chars).
        issues (list[ValidationIssue]): Every finding the underlying
            ``changes``-package call produced or that the action surfaced.
            May be empty.
        ok (bool): ``True`` when the action completed without an
            ERROR-severity finding and without an outright refusal.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Returned by the :class:`ChangeService` action methods.
        - ``app.py`` reads ``message`` for ``set_status`` and ``issues`` to
          render the finding list.

    Dependencies:
        Used by:
            - ChangeService.load / validate / save / save_patched /
              run_checks
            - app.py status wiring (``_report_change_result``)
    """

    message: str
    issues: list[ValidationIssue]
    ok: bool


@dataclass(slots=True)
class ChangeEntryRow:
    """
    Summary:
        One display row of the Patch Editor entries table — the rendered
        view of a single v2 :class:`ChangeEntry` (LLR-003.1 columns: kind,
        address, value-or-bytes, status, linkage).

    Args:
        kind_text (str): The entry kind — ``"string"`` or ``"bytes"``.
        address_text (str): The start address as ``0x``-prefixed uppercase
            hex.
        value_text (str): The declared string value (string entry) or the
            elided hex byte preview (bytes entry).
        status_text (str): The containment status token, suffixed with
            `` / fault`` when an ERROR-severity declaration fault names the
            entry's address (the LLR-002.8 per-entry status arm).
        linkage_text (str): The informative linkage classification from the
            last apply summary, or ``"-"`` before any apply.
        check_glyph (str): The last check run's verdict for THIS entry
            (batch-48 LLR-077.1) — one token of the closed vocabulary
            :data:`GLYPH_PASS` / :data:`GLYPH_FAIL` / :data:`GLYPH_UNCHECKABLE`
            / :data:`GLYPH_NO_RESULT`. Defaults to :data:`GLYPH_NO_RESULT`, so
            the field is additive and breaks no caller. Rendered as the
            LEADING SPAN of the ``Kind`` cell — not as a sixth column
            (LLR-077.4).
        address (int): The entry's RAW start address (batch-48 LLR-080.3) —
            the before/after card's span origin. Carried as the ``int`` beside
            the ``0x``-formatted ``address_text`` because the card must index
            ``mem_map`` (an ``int``-keyed sparse dict), and re-parsing the
            display string would re-derive a datum the entry already holds.
            Defaults to ``0``, so the field is additive and breaks no caller.
        encoded_bytes (Tuple[int, ...]): The entry's resolved target byte run
            (batch-48 LLR-080.3) — the card's "after" bytes, and the span
            LENGTH that bounds its "before" read (``addressed_range`` uses the
            ENCODED length, LLR-001.5). Carried raw for the same reason as
            ``address``: ``value_text`` is an ELIDED preview
            (``.. (N bytes)``), so it is lossy and cannot reconstruct the run.
            Defaults to ``()``.

    Note (batch-48 D-5 — why these ride the ROW and ``mem_map`` does not):
        ``address``/``encoded_bytes`` are per-ENTRY data that ``rows()``
        already holds while building each row, so a defaulted field reaches
        every ``refresh_entries`` call site free — the ``check_glyph``
        precedent (LLR-077.5). ``mem_map`` is per-IMAGE and is needed at
        row-SELECTION time, not refresh time, so it cannot ride here and is
        threaded as a panel parameter instead (LLR-080.2). That asymmetry is
        deliberate; do not "helpfully" move either one to match the other.

    Returns:
        None: Dataclass container.

    Dependencies:
        Used by:
            - ChangeService.rows
            - PatchEditorPanel.refresh_entries (the screen widget)
            - PatchEditorPanel._render_before_after_card (the card, via the
              retained row list — batch-48 LLR-080.3)
    """

    kind_text: str
    address_text: str
    value_text: str
    status_text: str
    linkage_text: str
    check_glyph: str = GLYPH_NO_RESULT
    address: int = 0
    encoded_bytes: Tuple[int, ...] = ()


@dataclass(slots=True)
class CheckResultRow:
    """
    Summary:
        One display row of the Patch Editor check-results area — the
        LLR-004.5 per-entry rendering of a check run, coloured through
        ``css_class_for_severity``.

    Args:
        text (str): The rendered row — address range, expected / actual
            bytes, and the result token.
        css_class (str): The ``sev-*`` class for the row's result —
            ``sev-ok`` (pass), ``sev-error`` (fail), ``sev-warning``
            (uncheckable).

    Returns:
        None: Dataclass container.

    Dependencies:
        Used by:
            - ChangeService.check_rows
            - PatchEditorPanel.refresh_check_results (the screen widget)
    """

    text: str
    css_class: str


@dataclass(slots=True)
class CheckDisplayRow:
    """
    Summary:
        One grouped display row of the dedicated CHECKS screen (batch-49,
        LLR-084.2) — the address / expected / actual / result line plus the
        entry's ``address_start`` (for the hex peek), the ``sev-*`` class for
        the row's ``result``, and the entry's ``linkage_symbol`` carried
        apart from ``text``. Distinct from the flat :class:`CheckResultRow`
        the Patch Editor renders: this exposes the per-entry ADDRESS (for the
        peek) and the grouping ``result`` token, and keeps the file-derived
        ``linkage_symbol`` in its own field so the widget renders it in a
        dedicated markup-safe cell (C-17), never interpolated into ``text``.

    Args:
        result (str): The entry's result token — ``"pass"`` / ``"fail"`` /
            ``"uncheckable"`` — the grouping key for the CHECKS screen.
        address (Optional[int]): The entry's ``address_start``, carried for
            the CHECKS hex peek (LLR-084.5).
        text (str): The rendered row — author-domain address range +
            expected / actual hex + result token, with the file-derived
            ``reason`` appended only when present (uncheckable rows).
        css_class (str): The ``sev-*`` class for the result — ``sev-error``
            (fail) / ``sev-warning`` (uncheckable) / ``sev-ok`` (pass), via
            ``css_class_for_severity``.
        linkage_symbol (Optional[str]): The entry's matching MAC/A2L symbol
            name (file-derived), rendered in its OWN cell; ``None`` when the
            entry is standalone. Optional so the four core fields keep the
            LLR-084.2 positional contract.

    Returns:
        None: Dataclass container.

    Dependencies:
        Used by:
            - ChangeService.check_display_rows
            - tui.checks_view.GroupedChecksPanel.render_groups (via app.py)
    """

    result: str
    address: Optional[int]
    text: str
    css_class: str
    linkage_symbol: Optional[str] = None


class ChangeService:
    """
    Summary:
        Stateful orchestration of the consolidated Patch Editor — owns one
        v2 :class:`ChangeDocument` and sequences the ``changes``-package
        calls the screen needs (LLR-003.4): both-kind entry mutation, v2
        load / validate / apply / save, the LLR-002.7 save-back, and the
        E4-seamed run-checks surface.

    The service is the only object that touches the ``changes`` package on
    the Patch Editor path: the screen widget and ``app.py`` call these
    methods and render the results, holding no JSON / model logic themselves
    (constraint C-7). One service instance lives per app; its document is the
    single source of truth for the entries table and the declaration-fault
    rendering (LLR-002.8).

    Args:
        None: Construct with an empty ``kind="change"`` document
        (``utf-8`` / ``text`` defaults) and no check runner.

    Data Flow:
        - ``add_entry`` / ``edit_entry`` / ``remove_entry`` mutate the
          document's entry list (both kinds, keyed by address).
        - ``load`` replaces the document via ``read_change_document``;
          ``save`` writes it via ``write_change_document``.
        - ``validate`` refreshes the collision findings and stamps image
          containment; ``apply`` runs the E2 engine and records the summary;
          ``save_patched`` persists the patched image and stamps
          ``ChangeSummary.saved_path``.
        - ``run_checks`` delegates to the ``check_runner`` seam — the real
          E4 engine by default, injectable for tests.
        - ``rows`` / ``issue_lines`` / ``check_rows`` shape display data for
          the screen.

    Dependencies:
        Uses:
            - changes.read_change_document / write_change_document
            - changes.collision_issues / classify_containment
            - changes.apply_change_document / save_patched_image
            - css_class_for_severity (check-row colouring)
        Used by:
            - PatchEditorPanel and S19TuiApp (the Patch Editor screen)
    """

    def __init__(self) -> None:
        #: The owned v2 document backing the Patch Editor entries table.
        self.document: ChangeDocument = self._empty_document()
        #: The summary of the most recent apply run (``None`` before any
        #: apply); its ``saved_path`` is stamped by :meth:`save_patched`.
        self.last_summary: Optional[ChangeSummary] = None
        #: The check-engine seam (LLR-004.5): a callable
        #: ``(document, mem_map, ranges, mac_records, a2l_tags) -> result``
        #: returning the LLR-004.3 ``CheckRunResult`` shape — ``entries``
        #: records with ``address_start`` / ``address_end`` /
        #: ``expected_bytes`` / ``actual_bytes`` / ``result``, plus an
        #: ``aggregates`` mapping with ``passed`` / ``failed`` /
        #: ``uncheckable`` keys. Defaults to the real E4 engine
        #: (``changes.check.run_check_document``); kept injectable so tests
        #: can substitute a stub.
        self.check_runner: Callable[..., object] = run_check_document
        #: The result object of the most recent check run (``None`` before
        #: any run or when the seam is unfilled).
        self.last_check_result: Optional[object] = None
        #: The image-load generation this service currently believes is
        #: loaded (batch-48 LLR-077.2, the BL-4 arm). A monotonic token
        #: OWNED BY ``app.py`` and pushed here via :meth:`set_image_generation`
        #: on every image install; ``0`` means "no image has been loaded".
        #: Object identity (``id(mem_map)``) is deliberately NOT used — CPython
        #: reuses ``id()`` values after GC, so a freed map and a freshly-loaded
        #: one can collide into a false "same image" match, which is precisely
        #: the bug this token exists to prevent.
        self.image_generation: int = 0
        #: The two-part provenance stamp of :attr:`last_check_result` —
        #: ``(document_signature, image_generation)`` describing the INPUTS the
        #: run was executed over (LLR-077.2 ★). ``rows`` emits result glyphs
        #: only while BOTH parts still equal the live values; on any mismatch
        #: every glyph degrades to :data:`GLYPH_NO_RESULT`.
        #:
        #: Both parts are load-bearing, and neither alone suffices:
        #:
        #: - ``last_check_result`` survives ``add_entry`` / ``remove_entry`` /
        #:   ``load`` / ``load_text`` (it is reset ONLY by ``undo`` / ``redo``),
        #:   so a mutated document would otherwise be index-aligned onto a
        #:   stale result. A COUNT is insufficient — an in-place per-entry JSON
        #:   edit preserves the count — hence a CONTENT signature.
        #: - ``run_checks`` reads each entry's ``actual_bytes`` from the IMAGE,
        #:   and this service is constructed once at ``app.py`` init and never
        #:   rebuilt on file load. Without the generation arm: check image A
        #:   (all pass) → load image B → the document is untouched → a
        #:   document-only signature still MATCHES → the glyphs render,
        #:   describing image A. Reachable via the most routine action in the
        #:   app, with no error path.
        #:
        #: ``mac_records`` / ``a2l_tags`` are also ``check_runner`` inputs but
        #: drive ``CheckRunEntry.linkage``, NOT ``.result``; the glyph renders
        #: ``.result`` only, so they are deliberately NOT covered.
        self._last_check_stamp: Optional[Tuple[object, int]] = None
        #: The change-set undo history (US-068a / LLR-068a.1): a bounded stack
        #: of DEEP-COPY :class:`ChangeDocument` snapshots, each captured
        #: immediately before a document-mutating operation. :meth:`undo` pops
        #: from here; :meth:`_push_history` bounds it at :data:`_HISTORY_MAX`.
        self._undo_stack: List[ChangeDocument] = []
        #: The change-set redo stack — documents popped by :meth:`undo`,
        #: replayable by :meth:`redo`; cleared by :meth:`_push_history` on any
        #: fresh mutation (a new edit invalidates the redo future).
        self._redo_stack: List[ChangeDocument] = []

    @staticmethod
    def _empty_document() -> ChangeDocument:
        """
        Summary:
            Build the empty default document a fresh service owns — a valid
            v2 ``change`` envelope with ``utf-8`` text values and no entries.

        Returns:
            ChangeDocument: The empty ``kind="change"`` document.

        Dependencies:
            Used by:
                - ChangeService.__init__
        """
        return ChangeDocument(
            format=FORMAT_ID,
            version=FORMAT_VERSION,
            kind="change",
            encoding="utf-8",
            value_mode="text",
        )

    @property
    def issues(self) -> list[ValidationIssue]:
        """
        Summary:
            The document's current declaration faults — read-time findings
            plus the latest collision recomputation (LLR-002.8 carrier).

        Returns:
            list[ValidationIssue]: ``self.document.issues`` — the single
            issue store; persistent until a clean re-validate or a re-load.
        """
        return self.document.issues

    def is_empty(self) -> bool:
        """
        Summary:
            Report whether the document has no entries — the entries table's
            empty-state condition.

        Returns:
            bool: ``True`` when the entry list is empty.

        Dependencies:
            Used by:
                - PatchEditorPanel.refresh_entries
        """
        return not self.document.entries

    # ------------------------------------------------------------------
    # Change-set history — bounded deep-copy undo/redo (US-068a, LLR-068a.1/.2)
    # ------------------------------------------------------------------

    def _push_history(self) -> None:
        """
        Summary:
            Capture a deep-copy snapshot of the current document onto the undo
            stack immediately before a mutation, evicting the oldest snapshot
            past :data:`_HISTORY_MAX` and clearing the redo stack (a fresh
            mutation invalidates any redo future) — LLR-068a.1.

        Data Flow:
            - ``copy.deepcopy(self.document)`` → append to ``_undo_stack``;
              trim the head past the bound; empty ``_redo_stack``.

        Dependencies:
            Uses:
                - copy.deepcopy
            Used by:
                - add_entry / edit_entry / remove_entry / load / load_text
        """
        self._undo_stack.append(copy.deepcopy(self.document))
        if len(self._undo_stack) > _HISTORY_MAX:
            del self._undo_stack[0]
        self._redo_stack.clear()

    def undo(self) -> ChangeDocument:
        """
        Summary:
            Restore the immediately-prior change-set (LLR-068a.2): replace the
            live document with the top undo snapshot, pushing the current
            document onto the redo stack. An empty undo stack is a no-op that
            returns the unchanged document.

        Returns:
            ChangeDocument: The now-current document (the restored prior
            change-set, or the unchanged document when the undo stack is empty).

        Data Flow:
            - Empty stack → return ``self.document`` unchanged.
            - Else → push the live document onto ``_redo_stack``, pop the top
              undo snapshot as the new live document, and reset
              ``last_summary`` / ``last_check_result`` (a restored change-set
              has no matching apply or check run, so a stale check result must
              not survive the history move).

        Dependencies:
            Used by:
                - app.py ``on_patch_editor_panel_undo_requested``
        """
        if not self._undo_stack:
            return self.document
        self._redo_stack.append(self.document)
        self.document = self._undo_stack.pop()
        self.last_summary = None
        self.last_check_result = None
        return self.document

    def redo(self) -> ChangeDocument:
        """
        Summary:
            Re-apply the most-recently-undone change-set (LLR-068a.2): replace
            the live document with the top redo snapshot, pushing the current
            document onto the undo stack. An empty redo stack is a no-op that
            returns the unchanged document.

        Returns:
            ChangeDocument: The now-current document (the re-applied change-set,
            or the unchanged document when the redo stack is empty).

        Data Flow:
            - Empty stack → return ``self.document`` unchanged.
            - Else → push the live document onto ``_undo_stack``, pop the top
              redo snapshot as the new live document, and reset
              ``last_summary`` / ``last_check_result`` (a re-applied change-set
              has no matching apply or check run, so a stale check result must
              not survive the history move).

        Dependencies:
            Used by:
                - app.py ``on_patch_editor_panel_redo_requested``
        """
        if not self._redo_stack:
            return self.document
        self._undo_stack.append(self.document)
        self.document = self._redo_stack.pop()
        self.last_summary = None
        self.last_check_result = None
        return self.document

    def history_depths(self) -> dict[str, int]:
        """
        Summary:
            Return how many history steps are available backward and forward
            from the live document, plus the history bound — the history
            strip's data source (LLR-081.1).

        Returns:
            dict[str, int]: Every key of :data:`HISTORY_DEPTH_KEYS` in
            canonical order — ``back`` (steps :meth:`undo` can take),
            ``forward`` (steps :meth:`redo` can take), and ``bound``
            (:data:`_HISTORY_MAX`). Never partial.

        Data Flow:
            - ``back`` is ``len(self._undo_stack)``; ``forward`` is
              ``len(self._redo_stack)``; ``bound`` is the module constant.

        Dependencies:
            Uses:
                - self._undo_stack ; self._redo_stack ; _HISTORY_MAX
            Used by:
                - app.py, threaded into
                  ``PatchEditorPanel.set_undo_redo_enabled`` at all THREE
                  call sites (LLR-081.3)
                - tests/test_tui_patch_history_strip.py

        Example:
            >>> service = ChangeService()
            >>> service.history_depths()
            {'back': 0, 'forward': 0, 'bound': 20}
        """
        # DERIVED, never stored. No history cursor exists and this method does
        # NOT introduce one: a cursor would be a second source of truth that
        # `undo`/`redo`/`_push_history` would each have to remember to move,
        # and the one that forgot would silently misreport where the analyst
        # is in their own edit history.
        #
        # Why these two lengths are the step counts EXACTLY — the derivation is
        # the same predicate the moves themselves use, not a parallel model:
        #
        #   * `undo` no-ops iff `not self._undo_stack` (:533) and otherwise pops
        #     exactly one snapshot (:536). So the number of undo steps
        #     available IS `len(self._undo_stack)`. `redo` is the mirror
        #     (:565/:568).
        #   * `_push_history` appends the PRE-mutation document (:504), so
        #     after N mutations the stack holds N snapshots and N steps back
        #     exist — there is no "current position" snapshot on either stack
        #     to discount. This is where an off-by-one would live if the stacks
        #     held the live document too; they do not (it is `self.document`).
        #   * `bound` is honoured without arithmetic here: `_push_history`
        #     evicts at `> _HISTORY_MAX` (:505-506), so `back` saturates at 20
        #     rather than growing. `undo`/`redo` only MOVE snapshots between
        #     the two stacks (:535-536 / :567-568), which conserves
        #     `back + forward` — so the total cannot exceed the bound either,
        #     and `redo`'s unbounded-looking `append` (:567) cannot breach it.
        return {
            "back": len(self._undo_stack),
            "forward": len(self._redo_stack),
            "bound": _HISTORY_MAX,
        }

    # ------------------------------------------------------------------
    # Entry mutation — both kinds (LLR-003.4)
    # ------------------------------------------------------------------

    def _build_entry(
        self, address: int, value_text: str, bytes_text: str
    ) -> ChangeEntry:
        """
        Summary:
            Construct one v2 entry from the screen's value / bytes input
            fields — a non-blank bytes field wins (a ``"bytes"`` entry), a
            non-blank value field otherwise (a ``"string"`` entry encoded
            with the document's declared encoding).

        Args:
            address (int): The parsed entry start address.
            value_text (str): The string-value input text.
            bytes_text (str): The hex-bytes input text.

        Returns:
            ChangeEntry: The constructed entry.

        Raises:
            ValueError: When both fields are blank, a byte token is
                unparseable, the byte run is empty / out of range, or the
                string value does not encode under the document encoding.

        Data Flow:
            - Bytes field non-blank → ``parse_new_bytes`` →
              ``ChangeEntry("bytes", ...)``.
            - Else value field non-blank → encode with
              ``document.encoding`` → ``ChangeEntry("string", ...)``.

        Dependencies:
            Uses:
                - parse_new_bytes
            Used by:
                - add_entry / edit_entry
        """
        if bytes_text.strip():
            return ChangeEntry(
                ENTRY_KIND_BYTES, address, tuple(parse_new_bytes(bytes_text))
            )
        if value_text:
            try:
                encoded = value_text.encode(self.document.encoding)
            except (UnicodeEncodeError, LookupError) as exc:
                raise ValueError(
                    f"string value does not encode under "
                    f"{self.document.encoding!r}: {exc}"
                ) from None
            return ChangeEntry(
                ENTRY_KIND_STRING, address, tuple(encoded), value=value_text
            )
        raise ValueError("enter a string value or a run of new bytes")

    def _entry_index(self, address: int) -> int:
        """
        Summary:
            Find the index of the entry declared at ``address``.

        Args:
            address (int): The entry start address to look up.

        Returns:
            int: The index of the first entry with that address.

        Raises:
            KeyError: When no entry declares that address.

        Dependencies:
            Used by:
                - add_entry / edit_entry / remove_entry
        """
        for index, entry in enumerate(self.document.entries):
            if entry.address == address:
                return index
        raise KeyError(f"no change entry at address 0x{address:X}")

    def add_entry(
        self, address_text: str, value_text: str, bytes_text: str
    ) -> ChangeEntry:
        """
        Summary:
            Append one entry of either kind from the screen's address /
            value / bytes input fields (LLR-003.4 add, both kinds).

        Args:
            address_text (str): The address field (``parse_address``
                grammar).
            value_text (str): The string-value field — used when the bytes
                field is blank.
            bytes_text (str): The hex-bytes field — non-blank wins and makes
                a ``"bytes"`` entry.

        Returns:
            ChangeEntry: The appended entry.

        Raises:
            ValueError: When the address or content fields are invalid, or
                an entry already declares that address (use Edit).

        Data Flow:
            - Parse the address; refuse a duplicate address (the v2 file
              format keeps duplicates as collisions, but the interactive add
              treats one as an operator mistake); build and append.

        Dependencies:
            Uses:
                - parse_address / _build_entry / _entry_index
            Used by:
                - app.py ``add_entry`` action routing
        """
        address = parse_address(address_text)
        try:
            self._entry_index(address)
        except KeyError:
            entry = self._build_entry(address, value_text, bytes_text)
            # US-068a / LLR-068a.1: snapshot the pre-mutation document (after
            # validation, so a rejected input pushes no no-op snapshot).
            self._push_history()
            self.document.entries.append(entry)
            return entry
        raise ValueError(
            f"an entry at address 0x{address:X} already exists - use Edit"
        )

    def edit_entry(
        self, address_text: str, value_text: str, bytes_text: str
    ) -> ChangeEntry:
        """
        Summary:
            Replace the entry declared at the typed address with a rebuilt
            entry of either kind (LLR-003.4 edit, both kinds).

        Args:
            address_text (str): The address field of the target entry.
            value_text (str): The new string-value field.
            bytes_text (str): The new hex-bytes field (non-blank wins).

        Returns:
            ChangeEntry: The replacement entry now held at that address.

        Raises:
            ValueError: When the address or content fields are invalid.
            KeyError: When no entry declares that address.

        Dependencies:
            Uses:
                - parse_address / _build_entry / _entry_index
            Used by:
                - app.py ``edit_entry`` action routing
        """
        address = parse_address(address_text)
        index = self._entry_index(address)
        entry = self._build_entry(address, value_text, bytes_text)
        # US-068a / LLR-068a.1: snapshot the pre-mutation document (after the
        # index lookup + build, so a KeyError / invalid input pushes nothing).
        self._push_history()
        self.document.entries[index] = entry
        return entry

    def remove_entry(self, address_text: str) -> None:
        """
        Summary:
            Remove the entry declared at the typed address (LLR-003.4
            remove).

        Args:
            address_text (str): The address field of the target entry.

        Raises:
            ValueError: When the address field is blank / invalid.
            KeyError: When no entry declares that address.

        Dependencies:
            Uses:
                - parse_address / _entry_index
            Used by:
                - app.py ``remove_entry`` action routing
        """
        address = parse_address(address_text)
        index = self._entry_index(address)
        # US-068a / LLR-068a.1: snapshot the pre-mutation document (after the
        # index lookup, so a KeyError on an absent address pushes nothing).
        self._push_history()
        del self.document.entries[index]

    def entry_seed_json(self, index: int) -> str:
        """
        Summary:
            Serialize the entry at ``index`` to its canonical wire-form JSON
            as a SINGLE entry object (US-068b / LLR-068b.2) — the seed the
            per-entry JSON popup (``EntryJsonScreen``) opens with. Distinct
            from the whole-set popup seed (the full document): this returns
            just ``{"type", "address", "value"|"bytes"}`` for one entry, so
            the operator edits one entry in isolation.

        Args:
            index (int): The zero-based entry index — the selected row of
                ``#patch_doc_entries_table`` (document order).

        Returns:
            str: The one entry's canonical wire-form JSON, ``indent=2``.

        Raises:
            IndexError: When ``index`` is out of range (the caller
                bounds-checks against ``document.entries`` first).

        Data Flow:
            - Wrap the single entry in a one-entry :class:`ChangeDocument`
              carrying the live document's header, run it through the
              canonical :func:`serialize_change_document` writer, then extract
              the sole ``entries[0]`` object — so the seed uses the SAME wire
              form the per-entry parse route (:meth:`edit_entry_json`) accepts
              and no entry-encoding logic is duplicated here.

        Dependencies:
            Uses:
                - serialize_change_document
            Used by:
                - app.py ``on_patch_editor_panel_entry_edit_json_requested``
        """
        entry = self.document.entries[index]
        probe = ChangeDocument(
            format=self.document.format,
            version=self.document.version,
            kind=self.document.kind,
            encoding=self.document.encoding,
            value_mode=self.document.value_mode,
            entries=[entry],
        )
        payload = json.loads(serialize_change_document(probe))
        return json.dumps(payload["entries"][0], indent=2)

    def edit_entry_json(self, index: int, text: str) -> ChangeActionResult:
        """
        Summary:
            Replace ONLY the entry at ``index`` with an entry parsed from the
            per-entry JSON popup's edited text (US-068b / LLR-068b.3), leaving
            every other entry byte-identical. The edited single-entry text is
            routed through the EXISTING validated document parser
            (:func:`parse_change_document`) by splicing it into a one-entry
            envelope built from the live document's header — the SAME
            collect-don't-abort seam :meth:`load_text` uses — so per-entry
            byte-validity / address-grammar rules and markup-safety apply and
            NO new parse/apply path is introduced. Malformed JSON, or an entry
            the parser rejects, leaves the document untouched and comes back as
            a non-``ok`` result carrying the collected findings (never an
            exception). A successful edit is a history-eligible mutation: it
            snapshots the prior document (LLR-068a.1) before the in-place
            replace.

        Args:
            index (int): The zero-based index of the entry to replace.
            text (str): The edited single-entry JSON from the popup — one wire
                entry object (``{"type", "address", "value"|"bytes"}``).

        Returns:
            ChangeActionResult: ``ok`` is ``True`` and ``message`` reports the
            edit when the text parsed to exactly one valid entry; otherwise
            ``ok`` is ``False``, the document is unchanged, and ``issues``
            carries every collected finding.

        Raises:
            KeyError: When ``index`` is out of range for the current document.

        Data Flow:
            - Bounds-check ``index``; build a one-entry envelope from the live
              header + the raw edited entry text; parse it through
              :func:`parse_change_document` (collect-don't-abort).
            - Reject (no mutation) when the parse produced an ERROR or did not
              yield exactly one entry; otherwise snapshot the document and
              replace ``entries[index]`` with the parsed entry.

        Dependencies:
            Uses:
                - parse_change_document / _push_history
            Used by:
                - app.py ``_apply_entry_json_edit`` (per-entry popup Confirm)
        """
        if index < 0 or index >= len(self.document.entries):
            raise KeyError(f"no change entry at index {index}")
        # Route the edited entry through the validated document parser by
        # splicing the raw text into a one-entry envelope built from the live
        # document's (already-canonical) header. Malformed text makes the whole
        # envelope invalid JSON, so parse_change_document reports MF-JSON-PARSE
        # — identical to the whole-set popup route; the untrusted text is
        # parsed, never eval'd.
        header = json.dumps(
            {
                "format": self.document.format,
                "version": self.document.version,
                "kind": self.document.kind,
                "encoding": self.document.encoding,
                "value_mode": self.document.value_mode,
            }
        )
        envelope_text = f'{header[:-1]}, "entries": [{text}]}}'
        probe = parse_change_document(envelope_text)
        if probe.has_errors or len(probe.entries) != 1:
            return ChangeActionResult(
                message="Patch Editor: entry edit rejected - see findings.",
                issues=list(probe.issues),
                ok=False,
            )
        self._push_history()
        self.document.entries[index] = probe.entries[0]
        return ChangeActionResult(
            message=f"Patch Editor: entry {index} updated.",
            issues=[],
            ok=True,
        )

    # ------------------------------------------------------------------
    # Document lifecycle — load / validate / save (LLR-003.4)
    # ------------------------------------------------------------------

    def load(self, path_text: str, base_dir: Path) -> ChangeActionResult:
        """
        Summary:
            Read a v2 change/check JSON file into the owned document,
            replacing it (LLR-003.4 load). A legacy ``.cdfx`` or v1 JSON
            file comes back as an empty document carrying exactly one ERROR
            finding (``MF-JSON-PARSE`` / ``CHG-V1-FORMAT`` — LLR-003.5);
            the reader never raises.

        Args:
            path_text (str): The user-typed change-file path — resolved by
                ``read_change_document`` through
                ``workspace.resolve_input_path``.
            base_dir (Path): The directory a relative ``path_text`` resolves
                against — normally the app working directory.

        Returns:
            ChangeActionResult: ``ok`` is ``True`` when the document parsed
            with no ERROR finding; ``message`` reports the kind / entry /
            error counts; ``issues`` carries every collected finding.

        Data Flow:
            - Delegate to ``read_change_document`` (collect-don't-abort);
              **replace** the owned document so the table and the
              declaration-fault rendering reflect the file (LLR-002.8: a
              re-load is how a corrected document clears prior faults).
            - Reset ``last_summary`` — a fresh document has no apply yet.

        Dependencies:
            Uses:
                - read_change_document
            Used by:
                - app.py ``load_doc`` action routing
        """
        document = read_change_document(path_text.strip(), base_dir)
        # US-068a / LLR-068a.1: snapshot the outgoing document before the
        # replace, so an undo can restore the pre-load change-set.
        self._push_history()
        self.document = document
        self.last_summary = None
        error_count = sum(
            1
            for issue in document.issues
            if issue.severity is ValidationSeverity.ERROR
        )
        return ChangeActionResult(
            message=(
                f"Loaded {document.kind}: {len(document.entries)} entr"
                f"{'y' if len(document.entries) == 1 else 'ies'}, "
                f"{error_count} error(s)"
            ),
            issues=list(document.issues),
            ok=not document.has_errors,
        )

    def load_text(self, text: str) -> ChangeActionResult:
        """
        Summary:
            Parse a pasted v2 change/check document (raw JSON text) into the
            owned document, replacing it (LLR-014.2 paste seam) — the
            string-input sibling of :meth:`load`, feeding the SAME existing
            apply / containment / verify / save-back path with NO new write
            surface. A malformed paste comes back as a document carrying the
            collected findings (``MF-JSON-PARSE`` on a JSON-decode failure);
            the parser never raises.

        Args:
            text (str): The raw change-document text pasted into the Patch
                Editor paste field — parsed through
                ``changes.io.parse_change_document`` (collect-don't-abort).

        Returns:
            ChangeActionResult: ``ok`` is ``True`` when the document parsed
            with no ERROR finding; ``message`` reports the kind / entry /
            error counts; ``issues`` carries every collected finding.

        Data Flow:
            - Delegate to ``parse_change_document`` (collect-don't-abort) and
              **replace** the owned document so the table and the
              declaration-fault rendering reflect the paste.
            - Reset ``last_summary`` — a fresh document has no apply yet
              (parity with :meth:`load`).

        Dependencies:
            Uses:
                - parse_change_document
            Used by:
                - app.py ``parse_paste`` action routing (LLR-014.2)
        """
        document = parse_change_document(text)
        # US-068a / LLR-068a.1: snapshot the outgoing document before the
        # replace, so an undo can restore the pre-paste change-set.
        self._push_history()
        self.document = document
        self.last_summary = None
        error_count = sum(
            1
            for issue in document.issues
            if issue.severity is ValidationSeverity.ERROR
        )
        return ChangeActionResult(
            message=(
                f"Loaded {document.kind}: {len(document.entries)} entr"
                f"{'y' if len(document.entries) == 1 else 'ies'}, "
                f"{error_count} error(s)"
            ),
            issues=list(document.issues),
            ok=not document.has_errors,
        )

    def validate(
        self, ranges: Optional[Sequence[Tuple[int, int]]]
    ) -> ChangeActionResult:
        """
        Summary:
            Re-validate the owned document: recompute the intra-document
            collision findings over the current entries and stamp each
            entry's image-containment status (LLR-003.4 validate; the
            LLR-002.8 clean-re-validate path that clears stale collision
            faults).

        Args:
            ranges (Optional[Sequence[Tuple[int, int]]]): The loaded image's
                contiguous ``(start, end)`` ranges; ``None`` = no image
                (every entry ``unvalidated-no-image``).

        Returns:
            ChangeActionResult: ``ok`` is ``True`` when no ERROR-severity
            finding remains; ``message`` reports entry / error / warning
            counts; ``issues`` is the refreshed full finding list.

        Data Flow:
            - Keep the read-time structural / metadata / per-entry findings
              (they describe the source file and cannot be edited away);
              drop prior ``CHG-COLLISION`` findings and recompute them from
              the current entries (entry mutation can create or fix
              collisions).
            - Stamp containment via ``classify_containment``.

        Dependencies:
            Uses:
                - collision_issues / classify_containment
            Used by:
                - app.py ``validate_doc`` action routing
        """
        retained = [
            issue
            for issue in self.document.issues
            if issue.code != CHG_COLLISION
        ]
        self.document.issues = retained + collision_issues(
            self.document.entries
        )
        classify_containment(self.document, ranges)
        error_count = sum(
            1
            for issue in self.document.issues
            if issue.severity is ValidationSeverity.ERROR
        )
        warning_count = sum(
            1
            for issue in self.document.issues
            if issue.severity is ValidationSeverity.WARNING
        )
        return ChangeActionResult(
            message=(
                f"Validate: {len(self.document.entries)} entr"
                f"{'y' if len(self.document.entries) == 1 else 'ies'}, "
                f"{error_count} error(s), {warning_count} warning(s)"
            ),
            issues=list(self.document.issues),
            ok=not self.document.has_errors,
        )

    def save(
        self, base_dir: Path, file_name: str = DEFAULT_CHANGE_FILE_NAME
    ) -> ChangeActionResult:
        """
        Summary:
            Write the owned document to a v2 JSON file inside the work area
            via ``write_change_document`` (LLR-003.4 save; canonical wire
            grammar, staged containment).

        Args:
            base_dir (Path): The app base directory whose
                ``.s19tool/workarea/`` is the containment root.
            file_name (str): The desired file name; a collision is
                dedup-suffixed by the writer — never a silent clobber.

        Returns:
            ChangeActionResult: ``ok`` is ``True`` with the written path in
            ``message`` when a file was produced; ``False`` when the write
            target failed work-area containment validation.

        Dependencies:
            Uses:
                - write_change_document
            Used by:
                - app.py ``save_doc`` action routing
        """
        path, issues = write_change_document(
            self.document, base_dir, file_name=file_name
        )
        if path is None:
            return ChangeActionResult(
                message="Change-set write rejected - see issues",
                issues=issues,
                ok=False,
            )
        return ChangeActionResult(
            message=f"Saved change-set to {path.name}",
            issues=issues,
            ok=True,
        )

    # ------------------------------------------------------------------
    # Apply + save-back (LLR-002.7 service half)
    # ------------------------------------------------------------------

    def apply(
        self,
        mem_map: Optional[Dict[int, int]],
        ranges: Optional[Sequence[Tuple[int, int]]],
        mac_records: Optional[Sequence[dict]],
        a2l_tags: Optional[Sequence[dict]],
        *,
        variant_id: Optional[str] = None,
    ) -> ChangeSummary:
        """
        Summary:
            Apply the owned document to the loaded image via the E2 engine
            and record the resulting :class:`ChangeSummary` (LLR-003.4
            apply). Collision findings are refreshed first so the apply gate
            judges the document's current entries.

        Args:
            mem_map (Optional[Dict[int, int]]): ``LoadedFile.mem_map`` —
                mutated in place at applied entries' addresses; ``None``
                when no image is loaded.
            ranges (Optional[Sequence[Tuple[int, int]]]): The image's
                contiguous ranges; ``None`` = no image.
            mac_records (Optional[Sequence[dict]]): Parsed MAC records for
                the informative linkage classification.
            a2l_tags (Optional[Sequence[dict]]): Enriched A2L tags for the
                linkage classification.
            variant_id (Optional[str]): The variant identifier recorded in
                the summary (the loaded file's stem until US-005 lands).

        Returns:
            ChangeSummary: The engine's summary — disposition counts,
            per-entry before/after records, linkage, and the document's
            declaration faults (LLR-002.8). Stored as ``last_summary`` so
            the save-back flow can stamp ``saved_path``.

        Data Flow:
            - Refresh collisions (the :meth:`validate` rule) so an
              interactively created collision blocks the apply.
            - Delegate to ``apply_change_document``; store and return the
              summary.

        Dependencies:
            Uses:
                - apply_change_document / collision_issues
            Used by:
                - app.py ``apply_doc`` action routing
        """
        retained = [
            issue
            for issue in self.document.issues
            if issue.code != CHG_COLLISION
        ]
        self.document.issues = retained + collision_issues(
            self.document.entries
        )
        summary = apply_change_document(
            self.document,
            mem_map,
            ranges,
            mac_records,
            a2l_tags,
            variant_id=variant_id,
        )
        self.last_summary = summary
        return summary

    def save_patched(
        self,
        mem_map: Dict[int, int],
        ranges: Sequence[Tuple[int, int]],
        dest_dir: Path,
        filename: str,
        *,
        source_kind: str,
        bytes_per_line: int = 32,
        s0_header: bytes | None = None,
        source_image_path: Optional[Path] = None,
    ) -> ChangeActionResult:
        """
        Summary:
            Persist the post-apply image under the operator-confirmed
            filename via ``save_patched_image``, stamp the written path onto
            ``last_summary.saved_path`` (and the caller's source image onto
            ``last_summary.source_image_path`` — the LLR-038.2 B-2 provenance
            stamp), then verify-on-save: re-read the
            written file and diff it against the intended map, stamping the
            ``VerifyResult`` onto ``last_summary.verify_result`` (HLR-002
            service half + HLR-003 wiring, §6.2 C-10 back-compatible carrier).
            The F-S-01 sanitizer and the staged containment live in the
            engine; ``save_patched_image``'s 2-tuple return is unchanged (M-1).

        Args:
            mem_map (Dict[int, int]): The post-apply address-to-byte map.
            ranges (Sequence[Tuple[int, int]]): The image's contiguous
                ranges.
            dest_dir (Path): The active project directory (or the work-area
                root when no project is active).
            filename (str): The operator-typed target name — sanitized /
                refused by the engine (F-S-01).
            source_kind (str): ``LoadedFile.file_type``; ``"s19"`` and
                ``"hex"`` are persisted (US-008), any other source (e.g.
                ``"mac"``) is refused with ``CHG-HEX-SAVE-UNSUPPORTED``.
            bytes_per_line (int): Data bytes per emitted S19 record,
                ``{16, 32}`` (default 32); forwarded to ``save_patched_image``
                and applied on the S19 branch only (LLR-015.3).
            s0_header (bytes | None): Optional populated S0 header, forwarded
                to ``save_patched_image`` and applied on the S19 branch only
                (LLR-015.3).
            source_image_path (Optional[Path]): The image file this patched
                map was loaded from (``LoadedFile.path``; the app handler
                passes it at I4) — stamped onto
                ``last_summary.source_image_path`` beside ``saved_path`` so
                the before/after composer can detect a stale summary
                (LLR-038.2, B-2). Runtime-only: never serialized by
                ``ChangeSummary.to_dict``.

        Returns:
            ChangeActionResult: ``ok`` ``True`` with the written file name
            in ``message`` when the image was persisted; ``False`` with the
            refusal findings otherwise (``saved_path`` stays ``None``).

        Dependencies:
            Uses:
                - save_patched_image
                - verify_written_image
            Used by:
                - app.py save-back confirm handling
        """
        path, issues = save_patched_image(
            mem_map,
            ranges,
            dest_dir,
            filename,
            source_kind=source_kind,
            bytes_per_line=bytes_per_line,
            s0_header=s0_header,
        )
        if self.last_summary is not None:
            self.last_summary.saved_path = path
            self.last_summary.source_image_path = source_image_path
        if path is None:
            return ChangeActionResult(
                message="Patched image not saved - see issues",
                issues=issues,
                ok=False,
            )
        # Verify-on-save (HLR-003, §6.2 C-10 back-compatible carrier): re-read
        # the just-written file and diff it against the intended map. The
        # VerifyResult rides last_summary — save_patched_image's 2-tuple return
        # is untouched (M-1). collect-don't-abort: a mismatch never unlinks the
        # written file; surfacing is the TUI's job (HLR-004, I4).
        verify = verify_written_image(path, mem_map, source_kind)
        if self.last_summary is not None:
            self.last_summary.verify_result = verify
        return ChangeActionResult(
            message=f"Patched image saved as {path.name}",
            issues=issues,
            ok=True,
        )

    # ------------------------------------------------------------------
    # Run checks — the E4 engine through the injectable seam (LLR-004.5)
    # ------------------------------------------------------------------

    def run_checks(
        self,
        mem_map: Optional[Dict[int, int]],
        ranges: Optional[Sequence[Tuple[int, int]]],
        mac_records: Optional[Sequence[dict]] = None,
        a2l_tags: Optional[Sequence[dict]] = None,
    ) -> ChangeActionResult:
        """
        Summary:
            Execute the owned check document through the ``check_runner``
            seam (LLR-004.5) — the real E4 engine
            (``changes.check.run_check_document``) by default, injectable
            for tests.

        Args:
            mem_map (Optional[Dict[int, int]]): The loaded image's
                address-to-byte map (never mutated by a check run —
                LLR-004.2).
            ranges (Optional[Sequence[Tuple[int, int]]]): The image's
                contiguous ranges.
            mac_records (Optional[Sequence[dict]]): Parsed MAC records for
                linkage.
            a2l_tags (Optional[Sequence[dict]]): Enriched A2L tags for
                linkage.

        Returns:
            ChangeActionResult: The three aggregate counts in ``message``
            (the LLR-004.5 status line), ``ok`` ``True`` when nothing
            failed, the result's carried ``issues`` (B-2), and the result
            object stored as ``last_check_result`` for :meth:`check_rows`.

        Data Flow:
            - Call ``check_runner(document, mem_map, ranges, mac_records,
              a2l_tags)``; store the result; read its ``aggregates``
              mapping for the status counts.

        Dependencies:
            Uses:
                - self.check_runner (run_check_document by default)
            Used by:
                - app.py ``run_checks`` action routing

        Note (batch-33 LLR-051.4): on a BLOCKED run
            (``run_blocked_reason`` set on the engine result) the
            message is ``Checks: not run — {reason} ({counts})`` and
            ``ok`` is ``False``; on a runnable run the message stays
            the three-count line and ``ok`` is ``failed == 0``.
        """
        result = self.check_runner(
            self.document, mem_map, ranges, mac_records, a2l_tags
        )
        self.last_check_result = result
        # LLR-077.2: stamp the result with the INPUTS it was run over, so the
        # glyph can refuse to describe a document or an image it never saw.
        self._last_check_stamp = (
            self._document_signature(),
            self.image_generation,
        )
        aggregates = dict(getattr(result, "aggregates", {}) or {})
        passed = int(aggregates.get("passed", 0))
        failed = int(aggregates.get("failed", 0))
        uncheckable = int(aggregates.get("uncheckable", 0))
        # batch-33 (LLR-051.4 / AT-051b): a BLOCKED run explains itself
        # loudly in the status message (the untruncated `result.message`
        # reaches `#patch_checks_status`; the app log shows only the
        # capped prefix) and reports ok=False on the returned result — the
        # counts still follow so report consumers keep their anchors.
        blocked_reason = getattr(result, "run_blocked_reason", None)
        if blocked_reason:
            return ChangeActionResult(
                message=(
                    f"Checks: not run — {blocked_reason} "
                    f"({passed} passed, {failed} failed, "
                    f"{uncheckable} uncheckable)"
                ),
                issues=list(getattr(result, "issues", []) or []),
                ok=False,
            )
        return ChangeActionResult(
            message=(
                f"Checks: {passed} passed, {failed} failed, "
                f"{uncheckable} uncheckable"
            ),
            issues=list(getattr(result, "issues", []) or []),
            ok=failed == 0,
        )

    def check_aggregates(self) -> dict[str, int]:
        """
        Summary:
            Return the last check run's three aggregate counts, or an
            all-zero mapping when no result is current — the CHECKS
            pass/fail strip's data source (LLR-078.2).

        Returns:
            dict[str, int]: Every key of :data:`CHECK_AGGREGATE_KEYS`
            (``passed`` / ``failed`` / ``uncheckable``) in canonical order,
            each an ``int``. Never partial: A3 guarantees the engine emits
            all three even at zero, and the ``.get(key, 0)`` default holds
            the contract if a duck-typed seam ever does not.

        Data Flow:
            - Read ``last_check_result.aggregates``; coerce each key to
              ``int``. ``last_check_result is None`` — no run yet, or an
              ``undo``/``redo`` reset it (``:538`` / ``:570``) — yields the
              all-zero mapping, which is how the strip CLEARS: it rides the
              EXISTING reset rather than re-implementing invalidation.
            - The cleared mapping is deliberately indistinguishable from a
              0-entry run's aggregates: both are honestly "nothing passed,
              nothing failed, nothing was uncheckable".

        Dependencies:
            Uses:
                - CHECK_AGGREGATE_KEYS ; self.last_check_result
            Used by:
                - app.py, threaded into
                  ``PatchEditorPanel.refresh_check_results`` at BOTH call
                  sites (LLR-078.3)
                - tests/test_tui_patch_checks_strip.py

        Example:
            >>> service = ChangeService()
            >>> service.check_aggregates()
            {'passed': 0, 'failed': 0, 'uncheckable': 0}
        """
        result = self.last_check_result
        if result is None:
            return {key: 0 for key in CHECK_AGGREGATE_KEYS}
        aggregates = getattr(result, "aggregates", None) or {}
        return {key: int(aggregates.get(key, 0)) for key in CHECK_AGGREGATE_KEYS}

    def check_rows(self) -> list[CheckResultRow]:
        """
        Summary:
            Shape the last check-run result into display rows, one per
            entry, coloured via ``css_class_for_severity`` (LLR-004.5:
            fail → ``sev-error``, uncheckable → ``sev-warning``, pass →
            ``sev-ok`` — the Phase-3 colour-policy decision).

        Returns:
            list[CheckResultRow]: One row per result entry in result order;
            empty when no check run happened (or the seam was unfilled).

        Data Flow:
            - Read the duck-shaped ``entries`` records of
              ``last_check_result`` (the LLR-004.3 per-entry field set);
              render address range, expected / actual hex, and the result
              token; map the token to a severity class. Uncheckable rows
              append the entry's ``reason`` in parentheses (batch-33
              LLR-051.5); pass/fail rows are unchanged.

        Dependencies:
            Uses:
                - css_class_for_severity / _CHECK_RESULT_SEVERITY
            Used by:
                - PatchEditorPanel.refresh_check_results (via app.py)
        """
        result = self.last_check_result
        if result is None:
            return []
        rows: list[CheckResultRow] = []
        for record in getattr(result, "entries", []) or []:
            token = str(getattr(record, "result", "uncheckable"))
            severity = _CHECK_RESULT_SEVERITY.get(
                token, ValidationSeverity.WARNING
            )
            start = int(getattr(record, "address_start", 0))
            end = int(getattr(record, "address_end", start + 1))
            expected = " ".join(
                f"{byte:02X}"
                for byte in (getattr(record, "expected_bytes", ()) or ())
            )
            actual_bytes = getattr(record, "actual_bytes", None)
            actual = (
                " ".join(f"{byte:02X}" for byte in actual_bytes)
                if actual_bytes is not None
                else "-"
            )
            # batch-33 (LLR-051.5 / AT-051a): every uncheckable row names
            # its reason; pass/fail rows are unchanged (reason is None).
            reason = getattr(record, "reason", None)
            suffix = f" ({reason})" if reason else ""
            rows.append(
                CheckResultRow(
                    text=(
                        f"0x{start:X}-0x{end - 1:X} expected [{expected}] "
                        f"actual [{actual}] -> {token}{suffix}"
                    ),
                    css_class=css_class_for_severity(severity),
                )
            )
        return rows

    def check_display_rows(self) -> list[CheckDisplayRow]:
        """
        Summary:
            Shape the last check-run result into GROUPED display rows for the
            dedicated CHECKS screen (batch-49, LLR-084.2), one per entry —
            each carrying the ``result`` token (grouping key), the entry's
            ``address_start`` (for the hex peek), a markup-safe row ``text``,
            the ``sev-*`` css class for the result, and the entry's
            ``linkage_symbol`` (rendered in its own cell). Distinct from the
            flat :meth:`check_rows` the Patch Editor renders: this exposes the
            per-entry ADDRESS and keeps ``linkage_symbol`` apart from ``text``
            so the CHECKS widget can group + peek + colour + C-17-render.

        Returns:
            list[CheckDisplayRow]: One :class:`CheckDisplayRow` per result
            entry in result order; empty when no check run is current
            (``last_check_result is None`` — no run yet, or an ``undo`` /
            ``redo`` reset it), mirroring :meth:`check_rows`.

        Data Flow:
            - Read the duck-shaped ``entries`` records of
              ``last_check_result`` (the LLR-004.3 per-entry field set); map
              each ``result`` token → severity via
              :data:`_CHECK_RESULT_SEVERITY` → ``css_class_for_severity``;
              compose ``text`` from the author-domain address range +
              expected / actual hex + the result token, appending the
              file-derived ``reason`` only when present (uncheckable rows).
              ``linkage_symbol`` rides its own field, never folded into
              ``text``.

        Dependencies:
            Uses:
                - css_class_for_severity / _CHECK_RESULT_SEVERITY
                - CheckDisplayRow
            Used by:
                - S19TuiApp.update_checks_view (batch-49 Inc-3)
                - tests/test_tui_checks_view.py

        Example:
            >>> service = ChangeService()
            >>> service.check_display_rows()
            []
        """
        result = self.last_check_result
        if result is None:
            return []
        rows: list[CheckDisplayRow] = []
        for record in getattr(result, "entries", []) or []:
            token = str(getattr(record, "result", "uncheckable"))
            severity = _CHECK_RESULT_SEVERITY.get(
                token, ValidationSeverity.WARNING
            )
            start = int(getattr(record, "address_start", 0))
            end = int(getattr(record, "address_end", start + 1))
            expected = " ".join(
                f"{byte:02X}"
                for byte in (getattr(record, "expected_bytes", ()) or ())
            )
            actual_bytes = getattr(record, "actual_bytes", None)
            actual = (
                " ".join(f"{byte:02X}" for byte in actual_bytes)
                if actual_bytes is not None
                else "-"
            )
            reason = getattr(record, "reason", None)
            suffix = f" ({reason})" if reason else ""
            rows.append(
                CheckDisplayRow(
                    result=token,
                    address=start,
                    text=(
                        f"0x{start:X}-0x{end - 1:X} expected [{expected}] "
                        f"actual [{actual}] -> {token}{suffix}"
                    ),
                    css_class=css_class_for_severity(severity),
                    linkage_symbol=getattr(record, "linkage_symbol", None),
                )
            )
        return rows

    # ------------------------------------------------------------------
    # Check-result provenance (batch-48 LLR-077.2)
    # ------------------------------------------------------------------

    def set_image_generation(self, generation: int) -> None:
        """
        Summary:
            Record which image generation is currently loaded (LLR-077.2).

            The token is OWNED BY ``app.py`` — a monotonic counter bumped on
            every image install — and pushed here so :meth:`rows` can tell a
            check result that describes the LIVE image from one that describes
            a previous load. This service is constructed once at app init and
            never rebuilt on load, so without this push a completed run
            outlives the image it was run against.

        Args:
            generation (int): The app's monotonic image-load counter. Values
                are compared for equality only; the service reads no meaning
                into the number itself.

        Returns:
            None

        Data Flow:
            - Store the token; :meth:`run_checks` snapshots it into
              ``_last_check_stamp``; :meth:`rows` compares live vs stamped.

        Dependencies:
            Used by:
                - ``S19TuiApp._apply_prepared_load`` (the single install
                  point every load path funnels through)

        Example:
            >>> service = ChangeService()
            >>> service.set_image_generation(1)
            >>> service.image_generation
            1
        """
        self.image_generation = generation

    def _document_signature(self) -> Tuple[Tuple[str, int, Tuple[int, ...]], ...]:
        """
        Summary:
            Fingerprint the live document's entries for the LLR-077.2 stamp.

            The per-entry tuple is ``(entry_type, address, encoded_bytes)`` in
            document order, so an added, removed, reordered, or in-place-edited
            entry all change it. Containment ``status`` is deliberately EXCLUDED
            — ``rows`` re-stamps it on every call, and it is an output of
            classification, not an input the check run consumed.

        Returns:
            Tuple[Tuple[str, int, Tuple[int, ...]], ...]: The ordered per-entry
            fingerprint; empty for an empty document.

        Data Flow:
            - Read ``self.document.entries``; ``encoded_bytes`` is already an
              immutable tuple (``ChangeEntry.__post_init__``), so the result is
              directly comparable.

        Dependencies:
            Used by:
                - run_checks (records the stamp) / rows (compares it)

        Example:
            >>> service = ChangeService()
            >>> service._document_signature()
            ()
        """
        return tuple(
            (entry.entry_type, entry.address, entry.encoded_bytes)
            for entry in self.document.entries
        )

    def _check_glyphs(self) -> list[str]:
        """
        Summary:
            Derive the per-entry check glyphs of the last run, in document
            order — but ONLY while that run's two-part provenance stamp still
            matches the live document and the live image (LLR-077.1/.2).

        Returns:
            list[str]: One glyph per RESULT record, positionally aligned to the
            document's entries. Empty when no run has happened or when either
            stamp part is stale — the caller then renders
            :data:`GLYPH_NO_RESULT` for every row (the honest degradation).

        Data Flow:
            - Refuse on ``last_check_result is None`` or on a stamp mismatch.
            - Otherwise map each record's ``result`` token through
              ``_CHECK_RESULT_GLYPH``; an unrecognised token → ``◐``.

        Dependencies:
            Uses:
                - _document_signature / _CHECK_RESULT_GLYPH
            Used by:
                - rows

        Example:
            >>> ChangeService()._check_glyphs()
            []
        """
        result = self.last_check_result
        if result is None:
            return []
        live_stamp = (self._document_signature(), self.image_generation)
        if self._last_check_stamp != live_stamp:
            return []
        return [
            _CHECK_RESULT_GLYPH.get(
                str(getattr(record, "result", "")), GLYPH_UNCHECKABLE
            )
            for record in (getattr(result, "entries", []) or [])
        ]

    # ------------------------------------------------------------------
    # Display shaping (entries table + declaration faults)
    # ------------------------------------------------------------------

    def rows(
        self, ranges: Optional[Sequence[Tuple[int, int]]]
    ) -> list[ChangeEntryRow]:
        """
        Summary:
            Stamp image containment and render one :class:`ChangeEntryRow`
            per document entry for the entries table (LLR-003.1 columns;
            the LLR-002.8 per-entry fault marker).

        Args:
            ranges (Optional[Sequence[Tuple[int, int]]]): The loaded image's
                contiguous ranges; ``None`` marks every entry
                ``unvalidated-no-image``.

        Returns:
            list[ChangeEntryRow]: One row per entry in document order —
            kind, hex address, value-or-bytes preview, containment status
            (`` / fault``-suffixed when an ERROR finding names the entry's
            address), the last apply's linkage classification (``"-"``
            before any apply), and the last check run's per-entry
            ``check_glyph`` (batch-48 LLR-077.1).

        Data Flow:
            - ``classify_containment`` stamps each entry's status.
            - ERROR-severity issue addresses mark matching rows faulted.
            - Linkage text joins from ``last_summary`` per address range.
            - ``_check_glyphs`` supplies the per-entry verdict glyph, joined
              **BY DOCUMENT-ORDER INDEX** (LLR-077.1).

        Dependencies:
            Uses:
                - classify_containment / _check_glyphs
            Used by:
                - PatchEditorPanel.refresh_entries (via app.py)

        Note (LLR-077.1 — the join key is POSITIONAL, never the address):
            ``CheckRunEntry`` records are built "one per document entry in
            document order" (``changes/model.py:660-661``) and carry no id, so
            ``glyphs[i]`` describes ``entries[i]``. Address-matching would be
            wrong twice over: it re-derives a key the contract already fixes,
            and it collapses two entries that share a start address. The
            entries table is ``cursor_type="row"``, so the row index the user's
            cursor lands on IS this index — the chain is index-keyed end to end.

        Note (why ``glyphs`` may be SHORTER than ``entries``):
            A stale or refused run yields ``[]`` and every row falls back to
            ``·``. The ``check_runner`` seam is injectable, so a stub may also
            return fewer records than the document has entries; the bounds
            check keeps that a missing glyph rather than an ``IndexError``.
        """
        classify_containment(self.document, ranges)
        glyphs = self._check_glyphs()
        fault_addresses = {
            issue.address
            for issue in self.document.issues
            if issue.severity is ValidationSeverity.ERROR
            and issue.address is not None
        }
        linkage_by_start: Dict[int, str] = {}
        if self.last_summary is not None:
            for record in self.last_summary.entries:
                linkage_by_start[record.address_start] = record.linkage
        rendered: list[ChangeEntryRow] = []
        for index, entry in enumerate(self.document.entries):
            if entry.entry_type == ENTRY_KIND_STRING:
                value_text = (
                    entry.value
                    if isinstance(entry.value, str)
                    else f"{len(entry.encoded_bytes)} code(s)"
                )
            else:
                preview = " ".join(
                    f"{byte:02X}"
                    for byte in entry.encoded_bytes[:_ROW_BYTES_PREVIEW]
                )
                if len(entry.encoded_bytes) > _ROW_BYTES_PREVIEW:
                    preview += f" .. ({len(entry.encoded_bytes)} bytes)"
                value_text = preview
            status_text = entry.status.value
            if entry.address in fault_addresses:
                status_text += " / fault"
            rendered.append(
                ChangeEntryRow(
                    kind_text=entry.entry_type,
                    address_text=f"0x{entry.address:X}",
                    value_text=value_text,
                    status_text=status_text,
                    linkage_text=linkage_by_start.get(entry.address, "-"),
                    check_glyph=(
                        glyphs[index]
                        if index < len(glyphs)
                        else GLYPH_NO_RESULT
                    ),
                    # LLR-080.3: the card's span origin + "after" bytes, raw.
                    # `address_text` is formatted and `value_text` is elided,
                    # so neither can serve — the card needs the ints.
                    address=entry.address,
                    encoded_bytes=entry.encoded_bytes,
                )
            )
        return rendered

    def issue_lines(self) -> list[str]:
        """
        Summary:
            Render the document's current declaration faults as one display
            line per finding — the persistent fault listing the panel shows
            until a clean re-validate (LLR-002.8).

        Returns:
            list[str]: ``[CODE] severity: message`` lines in issue order;
            empty when the document is clean.

        Dependencies:
            Used by:
                - PatchEditorPanel.refresh_issues (via app.py)
        """
        return [
            f"[{issue.code}] {issue.severity.value}: {issue.message}"
            for issue in self.document.issues
        ]


# ---------------------------------------------------------------------------
# Headless project entry point (LLR-004.4)
# ---------------------------------------------------------------------------


def run_checks_for_project(
    check_path: Path,
    image_path: Path,
    mac_path: Optional[Path] = None,
    a2l_path: Optional[Path] = None,
) -> CheckRunResult:
    """
    Summary:
        Execute one check file against one project image entirely headless —
        the LLR-004.4 service-level entry point: path inputs, ONE
        :class:`CheckRunResult` out, carrying its own declaration-fault
        ``issues`` (B-2). No Textual app is constructed anywhere on this
        path (verified by the subprocess-isolated import probe in
        ``tests/test_checks_engine.py`` — F-Q-07).

    Args:
        check_path (Path): The v2 ``kind="check"`` JSON document to run.
            Read through ``read_change_document`` (the one shared reader,
            LLR-004.1) with the file's own directory as the resolution base.
        image_path (Path): The S19 or Intel HEX image to check against —
            ``.hex`` / ``.ihex`` suffixes parse as Intel HEX, anything else
            as S19, matching the loader split of the TUI load path.
        mac_path (Optional[Path]): Optional ``.mac`` file parsed via
            ``parse_mac_file`` for the informative linkage classification.
        a2l_path (Optional[Path]): Optional A2L file parsed via
            ``parse_a2l_file`` and enriched against the image
            (``enrich_tags_and_render``) for the linkage classification.

    Returns:
        CheckRunResult: The §6.2 C-6 results object (LLR-004.3) —
        ``variant_id`` is the image filename stem, ``source_path`` the
        resolved check file, ``issues`` the check document's collected
        declaration faults. A faulted or wrong-kind document yields the
        all-``uncheckable`` not-runnable outcome with its issues carried.

    Data Flow:
        - ``read_change_document(check_path)`` → the check document
          (collect-don't-abort; faults ride the result).
        - Parse the image and build the ``LoadedFile`` snapshot through the
          load-service parse path (``build_loaded_s19`` /
          ``build_loaded_hex``) — the same enrichment the TUI worker uses,
          minus any UI thread.
        - Parse the optional MAC / A2L linkage sources.
        - Delegate to :func:`~s19_app.tui.changes.check.run_check_document`.

    Dependencies:
        Uses:
            - read_change_document
            - S19File / IntelHexFile
            - build_loaded_s19 / build_loaded_hex
            - parse_mac_file / parse_a2l_file / enrich_tags_and_render
            - run_check_document
        Used by:
            - tests/test_checks_engine.py::test_headless_project_run
            - The E6 variant-execution layer (later increment).

    Example:
        >>> result = run_checks_for_project(
        ...     Path("checks.json"), Path("prg.s19"),
        ... )  # doctest: +SKIP
    """
    document = read_change_document(str(check_path), check_path.parent)
    a2l_data = parse_a2l_file(a2l_path) if a2l_path is not None else None
    if image_path.suffix.lower() in {".hex", ".ihex"}:
        loaded = build_loaded_hex(
            image_path, IntelHexFile(str(image_path)), a2l_path, a2l_data
        )
    else:
        loaded = build_loaded_s19(
            image_path, S19File(str(image_path)), a2l_path, a2l_data
        )
    mac_records = (
        parse_mac_file(mac_path)["records"] if mac_path is not None else None
    )
    a2l_tags = (
        enrich_tags_and_render(a2l_data, loaded.mem_map)[0]
        if a2l_data
        else None
    )
    return run_check_document(
        document,
        loaded.mem_map,
        loaded.ranges,
        mac_records,
        a2l_tags,
        variant_id=image_path.stem,
    )
