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
    write_change_document,
)
from ..changes.check import run_check_document
from ..changes.model import CheckRunResult
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

#: How many byte tokens an entries-table value cell shows before eliding.
_ROW_BYTES_PREVIEW = 8


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

    Returns:
        None: Dataclass container.

    Dependencies:
        Used by:
            - ChangeService.rows
            - PatchEditorPanel.refresh_entries (the screen widget)
    """

    kind_text: str
    address_text: str
    value_text: str
    status_text: str
    linkage_text: str


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
        del self.document.entries[self._entry_index(address)]

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
    ) -> ChangeActionResult:
        """
        Summary:
            Persist the post-apply image under the operator-confirmed
            filename via ``save_patched_image`` and stamp the written path
            onto ``last_summary.saved_path`` (the LLR-002.7 service half;
            the F-S-01 sanitizer and the staged containment live in the
            engine).

        Args:
            mem_map (Dict[int, int]): The post-apply address-to-byte map.
            ranges (Sequence[Tuple[int, int]]): The image's contiguous
                ranges.
            dest_dir (Path): The active project directory (or the work-area
                root when no project is active).
            filename (str): The operator-typed target name — sanitized /
                refused by the engine (F-S-01).
            source_kind (str): ``LoadedFile.file_type``; non-``"s19"`` is
                refused with the ``CHG-HEX-SAVE-UNSUPPORTED`` finding (D-1).

        Returns:
            ChangeActionResult: ``ok`` ``True`` with the written file name
            in ``message`` when the image was persisted; ``False`` with the
            refusal findings otherwise (``saved_path`` stays ``None``).

        Dependencies:
            Uses:
                - save_patched_image
            Used by:
                - app.py save-back confirm handling
        """
        path, issues = save_patched_image(
            mem_map, ranges, dest_dir, filename, source_kind=source_kind
        )
        if self.last_summary is not None:
            self.last_summary.saved_path = path
        if path is None:
            return ChangeActionResult(
                message="Patched image not saved - see issues",
                issues=issues,
                ok=False,
            )
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
        """
        result = self.check_runner(
            self.document, mem_map, ranges, mac_records, a2l_tags
        )
        self.last_check_result = result
        aggregates = dict(getattr(result, "aggregates", {}) or {})
        passed = int(aggregates.get("passed", 0))
        failed = int(aggregates.get("failed", 0))
        uncheckable = int(aggregates.get("uncheckable", 0))
        return ChangeActionResult(
            message=(
                f"Checks: {passed} passed, {failed} failed, "
                f"{uncheckable} uncheckable"
            ),
            issues=list(getattr(result, "issues", []) or []),
            ok=failed == 0,
        )

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
              token; map the token to a severity class.

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
            rows.append(
                CheckResultRow(
                    text=(
                        f"0x{start:X}-0x{end - 1:X} expected [{expected}] "
                        f"actual [{actual}] -> {token}"
                    ),
                    css_class=css_class_for_severity(severity),
                )
            )
        return rows

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
            address), and the last apply's linkage classification (``"-"``
            before any apply).

        Data Flow:
            - ``classify_containment`` stamps each entry's status.
            - ERROR-severity issue addresses mark matching rows faulted.
            - Linkage text joins from ``last_summary`` per address range.

        Dependencies:
            Uses:
                - classify_containment
            Used by:
                - PatchEditorPanel.refresh_entries (via app.py)
        """
        classify_containment(self.document, ranges)
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
        for entry in self.document.entries:
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
