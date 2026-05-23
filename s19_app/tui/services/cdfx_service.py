"""
CDFX service — orchestrates the Patch Editor's calls into the ``cdfx`` package.

This module is the thin orchestration layer between the Patch Editor screen
(``screens_directionb.PatchEditorPanel``) / ``app.py`` and the ``cdfx`` package
(``ChangeList`` / ``resolve_against_a2l`` / ``format_value`` / ``read_cdfx`` /
``write_cdfx_to_workarea`` and, batch-04, the memory-field / unified-change-set
modules). It mirrors the existing ``tui/services/`` pattern —
``a2l_service.enrich_tags_and_render`` — so the screen and ``app.py`` stay
presentational and carry no XML / JSON / model logic (constraint C-7,
LLR-007.5 / LLR-009.2).

The service owns a single :class:`~s19_app.tui.cdfx.changeset.UnifiedChangeSet`
— the parameter half (a plain ``ChangeList``) and the memory-field half (a
``MemoryChangeList``) — and exposes the operations the Patch Editor needs:

- :meth:`CdfxService.add_entry` / :meth:`edit_entry` / :meth:`remove_entry` —
  mutate the parameter half (HLR-001 of batch-03), mapping an empty array-index
  field to a ``None``-index scalar entry and a typed integer to an array
  element.
- :meth:`CdfxService.add_memory_change` / :meth:`edit_memory_change` /
  :meth:`remove_memory_change` — mutate the memory-field half (HLR-001 of
  batch-04 / LLR-009.2).
- :meth:`CdfxService.rows` — resolve the parameter half against the loaded A2L
  and render one display row per entry for the screen's parameter table
  (HLR-002 / HLR-003 / LLR-007.1).
- :meth:`CdfxService.memory_rows` — validate the memory half against the loaded
  image ranges and render one display row per entry (address, hex value,
  status) for the screen's memory table (HLR-002 / HLR-003 / LLR-009.1).
- :meth:`CdfxService.save` / :meth:`load` — round-trip the parameter half to /
  from a ``.cdfx`` file (the batch-03 path, retained).
- :meth:`CdfxService.save_unified` / :meth:`load_unified` — round-trip the
  whole unified change-set to / from one JSON file via
  ``write_unified_to_workarea`` / ``read_unified`` (HLR-005 / HLR-006 /
  LLR-009.3).
- :meth:`CdfxService.export_selective` — split the unified change-set into a
  ``.cdfx`` parameter file and a JSON memory-field file via ``export_unified``
  (HLR-007 / LLR-009.3).

No XML or JSON is parsed or serialized here — every format concern is delegated
to the ``cdfx`` package. The service only sequences those calls and shapes
their results for the view.

Implements the orchestration arm of LLR-007.1..LLR-007.4 (batch-03) and the
service arm of LLR-009.1..LLR-009.3 (batch-04, increment 8).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ...validation.model import ValidationIssue
from ..cdfx import (
    ChangeList,
    ChangeListEntry,
    ExportResult,
    MemoryChange,
    UnifiedChangeSet,
    format_memory_value,
    read_cdfx,
    read_unified,
    validate_memory_changes,
    write_cdfx_to_workarea,
    write_unified_to_workarea,
)
from ..cdfx.display import format_value
from ..cdfx.export import export_unified
from ..cdfx.resolve import resolve_against_a2l


@dataclass(slots=True)
class PatchRow:
    """
    Summary:
        One display row of the Patch Editor change-list table — the resolved,
        formatted view of a single :class:`ChangeListEntry`.

    Args:
        parameter_name (str): The A2L parameter name of the entry.
        index_text (str): The array index as display text — the empty string
            for a ``None``-index scalar / string entry, the integer's decimal
            text for an array-element entry.
        value_text (str): The entry's value rendered through
            :func:`~s19_app.tui.cdfx.display.format_value` against its resolved
            A2L type — decimal / hex / signed / float / quoted string.
        status_text (str): The entry's :class:`ResolutionStatus` token.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :meth:`CdfxService.rows` from a resolved change-list entry.
        - Consumed by ``PatchEditorPanel.refresh_rows`` to fill the table.

    Dependencies:
        Used by:
            - CdfxService.rows
            - PatchEditorPanel (the screen widget)
    """

    parameter_name: str
    index_text: str
    value_text: str
    status_text: str


@dataclass(slots=True)
class CdfxActionResult:
    """
    Summary:
        The outcome of a save or load action — a status message plus the
        ``ValidationIssue`` list the screen surfaces through the status path.

    Args:
        message (str): A short human-readable summary of the action for the
            status line (for example the written file name or the entry count
            recovered from a load).
        issues (list[ValidationIssue]): Every ``ValidationIssue`` the
            underlying ``cdfx`` call produced — write-time ``W-*`` issues for a
            save, read-time ``R-*`` issues for a load. May be empty.
        ok (bool): ``True`` when the action completed (a file was written, or a
            document parsed); ``False`` when it was rejected outright (for
            example a containment failure with no file produced).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Returned by :meth:`CdfxService.save` / :meth:`CdfxService.load`.
        - The screen / ``app.py`` reads ``message`` for ``set_status`` and
          ``issues`` to render the finding list.

    Dependencies:
        Used by:
            - CdfxService.save / CdfxService.load
            - PatchEditorPanel / app.py status wiring
    """

    message: str
    issues: list[ValidationIssue]
    ok: bool


def parse_array_index(index_text: str) -> Optional[int]:
    """
    Summary:
        Map a Patch Editor array-index input field to an ``Optional[int]``
        change-list ``array_index`` (the LLR-001.1 ``None``-vs-integer key).

    Args:
        index_text (str): The raw text of the index ``Input``. An empty or
            whitespace-only string is a scalar / string entry; an integer
            string is an array element.

    Returns:
        Optional[int]: ``None`` when ``index_text`` is blank — the scalar /
        ASCII-string discriminator; the parsed non-negative ``int`` otherwise.

    Raises:
        ValueError: When ``index_text`` is non-blank but is not a valid
            non-negative integer — the screen reports it as a status message.

    Data Flow:
        - A blank field short-circuits to ``None`` (a scalar entry).
        - Otherwise the text is parsed as an ``int``; a negative value is
          rejected so it never reaches the resolver's range check.

    Dependencies:
        Used by:
            - CdfxService.add_entry / CdfxService.edit_entry
            - PatchEditorPanel (the screen widget)

    Example:
        >>> parse_array_index("")
        >>> parse_array_index("2")
        2
    """
    stripped = index_text.strip()
    if not stripped:
        return None
    index = int(stripped)
    if index < 0:
        raise ValueError(f"array index must be non-negative, got {index}")
    return index


def parse_value(value_text: str) -> object:
    """
    Summary:
        Coerce a Patch Editor value input field to a stored physical value —
        an ``int`` when integral, a ``float`` when fractional, else the raw
        string (an ASCII-string parameter's value).

    Args:
        value_text (str): The raw text of the value ``Input``.

    Returns:
        object: The physical value to store on the entry — ``int``, ``float``
        or ``str``. The change-list stores it verbatim (LLR-003.3); the display
        layer derives the rendered form.

    Data Flow:
        - An integer-looking string parses to ``int`` (exact at any magnitude,
          finding Q-10).
        - A float-looking string parses to ``float``.
        - Anything else is kept as the raw string — the engineer's literal
          input for an ASCII-string parameter.

    Dependencies:
        Used by:
            - CdfxService.add_entry / CdfxService.edit_entry
            - PatchEditorPanel (the screen widget)

    Example:
        >>> parse_value("23")
        23
        >>> parse_value("REV_C")
        'REV_C'
    """
    stripped = value_text.strip()
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        return value_text


@dataclass(slots=True)
class MemoryPatchRow:
    """
    Summary:
        One display row of the Patch Editor memory-change table — the
        validated, hex-rendered view of a single ``MemoryChange`` entry.

    Args:
        address_text (str): The entry's memory start address as ``0x``-prefixed
            uppercase hexadecimal — the engineer reads addresses in hex.
        value_text (str): The entry's ``new_bytes`` rendered through
            :func:`~s19_app.tui.cdfx.memory_display.format_memory_value` — the
            primary space-separated two-digit uppercase hex form (LLR-009.1).
        status_text (str): The entry's :class:`MemoryStatus` token — one of
            ``inside`` / ``partial`` / ``outside`` / ``unvalidated-no-image``.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :meth:`CdfxService.memory_rows` from a validated
          memory-change entry.
        - Consumed by ``PatchEditorPanel.refresh_memory_rows`` to fill the
          memory-change table.

    Dependencies:
        Used by:
            - CdfxService.memory_rows
            - PatchEditorPanel (the screen widget)
    """

    address_text: str
    value_text: str
    status_text: str


def parse_address(address_text: str) -> int:
    """
    Summary:
        Map a Patch Editor memory-address input field to a non-negative
        integer memory address (LLR-009.2).

    Args:
        address_text (str): The raw text of the address ``Input``. Accepts a
            ``0x``-prefixed hexadecimal literal or a plain decimal literal —
            ``int(text, 0)`` honours the prefix.

    Returns:
        int: The parsed non-negative integer memory address.

    Raises:
        ValueError: When ``address_text`` is blank, is not a valid integer
            literal, or is negative — the screen reports it as a status
            message rather than crashing.

    Data Flow:
        - Strip the field, parse with base-0 so ``0x`` is honoured, reject a
          negative result before it reaches the memory-change model.

    Dependencies:
        Used by:
            - CdfxService.add_memory_change / CdfxService.edit_memory_change /
              CdfxService.remove_memory_change

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
        Map a Patch Editor new-bytes input field to an ordered list of integer
        byte values (LLR-009.2).

    Args:
        bytes_text (str): The raw text of the new-bytes ``Input`` — a run of
            byte tokens separated by whitespace and/or commas. Each token is a
            ``0x``-prefixed hex literal or a plain decimal literal; a bare
            two-digit hex string (for example ``DE AD BE EF``) is also accepted
            so the engineer can paste a hex-dump fragment directly.

    Returns:
        list[int]: The parsed byte values in input order. Range checking
        (0-255) and the empty-run rejection are left to
        ``MemoryChange.__post_init__`` so there is one authoritative byte-range
        rule (LLR-002.5); this helper only tokenises and parses.

    Raises:
        ValueError: When ``bytes_text`` holds a token that is neither a valid
            integer literal nor a bare hex byte string.

    Data Flow:
        - Split on commas and whitespace, drop empty tokens.
        - Parse each token base-0; a token that fails base-0 but is a pure hex
          string is retried as base-16 (the bare-hex-dump convenience).

    Dependencies:
        Used by:
            - CdfxService.add_memory_change / CdfxService.edit_memory_change

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
            # A bare hex-dump byte like "DE" has no 0x prefix; retry base-16.
            try:
                values.append(int(token, 16))
            except ValueError:
                raise ValueError(
                    f"invalid byte token {token!r} - use hex (0x1F or 1F) "
                    "or decimal"
                ) from None
    return values


class CdfxService:
    """
    Summary:
        Stateful orchestration of the Patch Editor's patch set — owns one
        :class:`UnifiedChangeSet` (a parameter ``ChangeList`` half and a
        memory-field ``MemoryChangeList`` half) and sequences the
        ``cdfx``-package calls the screen needs.

    The service is the only object that touches the ``cdfx`` package on the
    Patch Editor path: the screen widget and ``app.py`` call these methods and
    render the results, holding no XML / JSON / model logic themselves
    (constraint C-7 / LLR-007.5 / LLR-009.2). One service instance lives per
    app; its unified change-set is the single source of truth for both Patch
    Editor tables.

    Args:
        None: Construct with an empty unified change-set.

    Data Flow:
        - ``add_entry`` / ``edit_entry`` / ``remove_entry`` mutate the
          parameter half; ``add_memory_change`` / ``edit_memory_change`` /
          ``remove_memory_change`` mutate the memory-field half.
        - ``rows`` resolves the parameter half against the supplied enriched
          A2L tags and renders display rows; ``memory_rows`` validates the
          memory half against the loaded image ranges and renders display rows.
        - ``save`` / ``load`` round-trip the parameter half to / from a
          ``.cdfx`` file; ``save_unified`` / ``load_unified`` round-trip the
          whole unified change-set to / from one JSON file; ``export_selective``
          splits it into a ``.cdfx`` plus a memory-field JSON file.

    Dependencies:
        Uses:
            - UnifiedChangeSet (the owned model — both halves)
            - resolve_against_a2l / format_value (resolution + display)
            - validate_memory_changes / format_memory_value (memory display)
            - write_cdfx_to_workarea / read_cdfx (the CDFX format handler)
            - write_unified_to_workarea / read_unified (the unified-file
              handler)
            - export_unified (the selective-export coordinator)
        Used by:
            - PatchEditorPanel and S19TuiApp (the Patch Editor screen)
    """

    def __init__(self) -> None:
        #: The unified change-set backing both Patch Editor tables — the
        #: parameter half and the memory-field half (LLR-009.1).
        self.unified: UnifiedChangeSet = UnifiedChangeSet()

    @property
    def change_list(self) -> ChangeList:
        """
        Summary:
            The parameter half of the owned unified change-set — the batch-03
            ``ChangeList``.

        Returns:
            ChangeList: ``self.unified.parameters``. Exposed as a property so
            the batch-03 callers and tests that read ``service.change_list``
            keep working unchanged while the service now owns a whole
            ``UnifiedChangeSet``.

        Data Flow:
            - Reads ``self.unified.parameters``.
        """
        return self.unified.parameters

    @change_list.setter
    def change_list(self, value: ChangeList) -> None:
        """Replace the parameter half of the unified change-set (used by load)."""
        self.unified.parameters = value

    def add_entry(
        self,
        parameter_name: str,
        index_text: str,
        value_text: str,
    ) -> ChangeListEntry:
        """
        Summary:
            Add (or update in place) a change-list entry from the screen's
            name / index / value input fields (LLR-007.2 add).

        Args:
            parameter_name (str): The A2L parameter name typed by the engineer.
            index_text (str): The array-index field — blank for a scalar /
                string entry, an integer for an array element.
            value_text (str): The value field — coerced to ``int`` / ``float``
                / ``str`` by :func:`parse_value`.

        Returns:
            ChangeListEntry: The entry now held under ``(parameter_name,
            array_index)`` — newly created or updated in place (LLR-001.3).

        Raises:
            ValueError: When ``parameter_name`` is blank, or ``index_text`` is
                a non-blank non-integer / negative value.

        Data Flow:
            - Parse the index and value fields, then delegate to
              ``ChangeList.add`` — a re-add on an existing identity updates.

        Dependencies:
            Uses:
                - parse_array_index / parse_value
            Used by:
                - PatchEditorPanel add action
        """
        name = parameter_name.strip()
        if not name:
            raise ValueError("parameter name must not be empty")
        array_index = parse_array_index(index_text)
        value = parse_value(value_text)
        return self.change_list.add(name, array_index, value)

    def edit_entry(
        self,
        parameter_name: str,
        index_text: str,
        value_text: str,
    ) -> ChangeListEntry:
        """
        Summary:
            Change the stored value of an existing change-list entry identified
            by name + index (LLR-007.2 edit).

        Args:
            parameter_name (str): The A2L parameter name of the target entry.
            index_text (str): The array-index field — blank for a scalar /
                string entry, an integer for an array element.
            value_text (str): The new value field.

        Returns:
            ChangeListEntry: The updated entry.

        Raises:
            ValueError: When ``parameter_name`` is blank or ``index_text`` is
                an invalid index.
            KeyError: When no entry with that identity exists.

        Dependencies:
            Uses:
                - parse_array_index / parse_value
            Used by:
                - PatchEditorPanel edit action
        """
        name = parameter_name.strip()
        if not name:
            raise ValueError("parameter name must not be empty")
        array_index = parse_array_index(index_text)
        value = parse_value(value_text)
        return self.change_list.edit(name, array_index, value)

    def remove_entry(self, parameter_name: str, index_text: str) -> None:
        """
        Summary:
            Remove the change-list entry identified by name + index
            (LLR-007.2 remove).

        Args:
            parameter_name (str): The A2L parameter name of the target entry.
            index_text (str): The array-index field — blank for a scalar /
                string entry, an integer for an array element.

        Raises:
            ValueError: When ``parameter_name`` is blank or ``index_text`` is
                an invalid index.
            KeyError: When no entry with that identity exists.

        Dependencies:
            Uses:
                - parse_array_index
            Used by:
                - PatchEditorPanel remove action
        """
        name = parameter_name.strip()
        if not name:
            raise ValueError("parameter name must not be empty")
        array_index = parse_array_index(index_text)
        self.change_list.remove(name, array_index)

    def rows(self, a2l_tags: Optional[list[dict[str, Any]]]) -> list[PatchRow]:
        """
        Summary:
            Resolve the change-list against the loaded A2L and render one
            :class:`PatchRow` per entry for the Patch Editor table (LLR-007.1).

        Args:
            a2l_tags (Optional[list[dict]]): The enriched A2L tags — the app's
                ``_a2l_enriched_tags`` cache. ``None`` (or empty) means no A2L
                is loaded; every entry then resolves ``unresolved-no-a2l`` and
                values render as plain decimal (LLR-002.4 / LLR-003.2).

        Returns:
            list[PatchRow]: One row per change-list entry, in the change-list's
            deterministic insertion order (LLR-001.4).

        Data Flow:
            - Resolve the change-list against the A2L tags (this also stamps
              each entry's ``status``).
            - For each entry, look up its resolved type and format its value.

        Dependencies:
            Uses:
                - resolve_against_a2l / format_value
            Used by:
                - PatchEditorPanel.refresh_rows
        """
        resolution = resolve_against_a2l(self.change_list, a2l_tags)
        rendered: list[PatchRow] = []
        for entry in self.change_list.entries:
            resolved_type = resolution.type_for(entry)
            index_text = (
                "" if entry.array_index is None else str(entry.array_index)
            )
            rendered.append(
                PatchRow(
                    parameter_name=entry.parameter_name,
                    index_text=index_text,
                    value_text=format_value(entry, resolved_type),
                    status_text=entry.status.value,
                )
            )
        return rendered

    def is_empty(self) -> bool:
        """
        Summary:
            Report whether the change-list has no entries — the screen's
            empty-state condition (LLR-007.6).

        Returns:
            bool: ``True`` when the change-list is empty.

        Dependencies:
            Used by:
                - PatchEditorPanel.refresh_rows
        """
        return len(self.change_list) == 0

    def save(
        self,
        base_dir: Path,
        a2l_tags: Optional[list[dict[str, Any]]],
        file_name: str = "patchset.cdfx",
    ) -> CdfxActionResult:
        """
        Summary:
            Serialize the change-list to a ``.cdfx`` file inside the work area
            (LLR-007.3) through the containment-checked write path (LLR-007.7).

        Args:
            base_dir (Path): The app base directory whose ``.s19tool/workarea/``
                is the containment root the ``.cdfx`` is written into.
            a2l_tags (Optional[list[dict]]): The enriched A2L tags — resolution
                runs first so the writer knows each parameter's category.
            file_name (str): The desired ``.cdfx`` file name; a collision is
                dedup-suffixed by ``write_cdfx_to_workarea``.

        Returns:
            CdfxActionResult: ``ok`` is ``True`` with the written path in
            ``message`` when a file was produced; ``ok`` is ``False`` when the
            write target failed containment validation (no file written).

        Data Flow:
            - Resolve the change-list, then call ``write_cdfx_to_workarea``.
            - Shape the ``(path, issues)`` result into a ``CdfxActionResult``.

        Dependencies:
            Uses:
                - resolve_against_a2l / write_cdfx_to_workarea
            Used by:
                - PatchEditorPanel / app.py save action
        """
        resolution = resolve_against_a2l(self.change_list, a2l_tags)
        path, issues = write_cdfx_to_workarea(
            self.change_list,
            resolution,
            base_dir,
            file_name=file_name,
        )
        if path is None:
            return CdfxActionResult(
                message="CDFX write rejected - see issues",
                issues=issues,
                ok=False,
            )
        return CdfxActionResult(
            message=f"Saved change-list to {path}",
            issues=issues,
            ok=True,
        )

    def load(
        self,
        path_text: str,
        base_dir: Path,
        a2l_tags: Optional[list[dict[str, Any]]],
    ) -> CdfxActionResult:
        """
        Summary:
            Parse a ``.cdfx`` file into the change-list (LLR-007.4) through the
            path-resolving, XML-safe read path of the ``cdfx`` reader.

        Args:
            path_text (str): The user-typed ``.cdfx`` path — resolved by
                ``read_cdfx`` through ``workspace.resolve_input_path``
                (LLR-005.5).
            base_dir (Path): The directory a relative ``path_text`` resolves
                against — normally the app working directory.
            a2l_tags (Optional[list[dict]]): The enriched A2L tags for the
                LLR-008 cross-check; ``None`` skips the cross-check.

        Returns:
            CdfxActionResult: ``ok`` is ``True`` (a document was parsed, even
            with issues); ``message`` reports the recovered entry count.

        Data Flow:
            - Call ``read_cdfx``; on success **replace** the owned change-list
              with the parsed one so the table reflects the loaded file.
            - A malformed file still returns an (often empty) change-list plus
              ``R-*`` issues — collect-don't-abort, never a crash (HLR-005).

        Dependencies:
            Uses:
                - read_cdfx
            Used by:
                - PatchEditorPanel / app.py load action
        """
        loaded, issues = read_cdfx(
            path_text.strip(),
            a2l_tags=a2l_tags,
            base_dir=base_dir,
        )
        self.change_list = loaded
        return CdfxActionResult(
            message=f"Loaded {len(loaded)} change-list entr"
            f"{'y' if len(loaded) == 1 else 'ies'} from {path_text.strip()}",
            issues=issues,
            ok=True,
        )

    # -----------------------------------------------------------------------
    # Memory-field half — add / edit / remove / display (LLR-009.1, LLR-009.2)
    # -----------------------------------------------------------------------

    def add_memory_change(
        self, address_text: str, bytes_text: str
    ) -> MemoryChange:
        """
        Summary:
            Add (or update in place) a memory-change entry from the screen's
            address / new-bytes input fields (LLR-009.2 add).

        Args:
            address_text (str): The memory-address field — a ``0x``-prefixed
                hex or plain decimal literal, parsed by :func:`parse_address`.
            bytes_text (str): The new-bytes field — a run of hex / decimal byte
                tokens, parsed by :func:`parse_new_bytes`.

        Returns:
            MemoryChange: The entry now held under ``address`` — newly created
            or updated in place (LLR-001.3 identity).

        Raises:
            ValueError: When the address field is blank / invalid / negative,
                a byte token is unparseable, or the byte run is empty or holds
                a byte outside 0-255 (propagated from ``MemoryChange``).

        Data Flow:
            - Parse the address and the byte run, then delegate to
              ``MemoryChangeList.add`` — a re-add on an existing address
              updates in place.

        Dependencies:
            Uses:
                - parse_address / parse_new_bytes
            Used by:
                - PatchEditorPanel memory-change add action
        """
        address = parse_address(address_text)
        new_bytes = parse_new_bytes(bytes_text)
        return self.unified.memory.add(address, new_bytes)

    def edit_memory_change(
        self, address_text: str, bytes_text: str
    ) -> MemoryChange:
        """
        Summary:
            Change the stored bytes of an existing memory-change entry
            identified by its address (LLR-009.2 edit).

        Args:
            address_text (str): The memory-address field of the target entry.
            bytes_text (str): The new byte-run field.

        Returns:
            MemoryChange: The updated entry.

        Raises:
            ValueError: When the address or byte tokens are invalid.
            KeyError: When no memory-change entry with that address exists.

        Dependencies:
            Uses:
                - parse_address / parse_new_bytes
            Used by:
                - PatchEditorPanel memory-change edit action
        """
        address = parse_address(address_text)
        new_bytes = parse_new_bytes(bytes_text)
        return self.unified.memory.edit(address, new_bytes)

    def remove_memory_change(self, address_text: str) -> None:
        """
        Summary:
            Remove the memory-change entry identified by its address
            (LLR-009.2 remove).

        Args:
            address_text (str): The memory-address field of the target entry.

        Raises:
            ValueError: When the address field is blank / invalid.
            KeyError: When no memory-change entry with that address exists.

        Dependencies:
            Uses:
                - parse_address
            Used by:
                - PatchEditorPanel memory-change remove action
        """
        address = parse_address(address_text)
        self.unified.memory.remove(address)

    def memory_rows(
        self, loaded_ranges: Optional[list[tuple[int, int]]]
    ) -> list[MemoryPatchRow]:
        """
        Summary:
            Validate the memory-field half against the loaded image ranges and
            render one :class:`MemoryPatchRow` per entry for the Patch Editor
            memory table (LLR-009.1).

        Args:
            loaded_ranges (Optional[list[tuple[int, int]]]): The loaded image's
                contiguous ``(start, end)`` address ranges — the app's
                ``current_file.ranges``. ``None`` (no image loaded) marks every
                entry ``unvalidated-no-image`` (LLR-002.3).

        Returns:
            list[MemoryPatchRow]: One row per memory-change entry, in the
            memory-change list's deterministic insertion order (LLR-001.4) —
            address in hex, the hex rendering of the bytes, and the validation
            status token.

        Data Flow:
            - Run ``validate_memory_changes`` (this stamps each entry's
              ``status`` against the ranges and collects issues — the issues
              are surfaced separately by ``memory_validation_issues``).
            - For each entry, render its bytes via ``format_memory_value`` and
              build a display row.

        Dependencies:
            Uses:
                - validate_memory_changes / format_memory_value
            Used by:
                - PatchEditorPanel.refresh_memory_rows
        """
        validate_memory_changes(self.unified.memory, loaded_ranges)
        rendered: list[MemoryPatchRow] = []
        for entry in self.unified.memory.entries:
            rendering = format_memory_value(entry.new_bytes)
            rendered.append(
                MemoryPatchRow(
                    address_text=f"0x{entry.address:X}",
                    value_text=rendering.hex,
                    status_text=entry.status.value,
                )
            )
        return rendered

    def memory_validation_issues(
        self, loaded_ranges: Optional[list[tuple[int, int]]]
    ) -> list[ValidationIssue]:
        """
        Summary:
            Validate the memory-field half against the loaded image ranges and
            return the collected ``ValidationIssue`` list for the status path
            (LLR-009.2 / LLR-008.3).

        Args:
            loaded_ranges (Optional[list[tuple[int, int]]]): The loaded image's
                ``(start, end)`` ranges; ``None`` skips range validation.

        Returns:
            list[ValidationIssue]: One warning per partial / outside / overlap
            finding — collect-don't-abort, never raised. May be empty.

        Data Flow:
            - Delegates to ``validate_memory_changes``; the same call
              re-stamps each entry's status, so it is cheap to run beside
              :meth:`memory_rows`.

        Dependencies:
            Uses:
                - validate_memory_changes
            Used by:
                - PatchEditorPanel / app.py memory-change action wiring
        """
        return validate_memory_changes(self.unified.memory, loaded_ranges)

    def memory_is_empty(self) -> bool:
        """
        Summary:
            Report whether the memory-field half has no entries — the memory
            table's empty-state condition (LLR-009.1).

        Returns:
            bool: ``True`` when the memory-change list is empty.

        Dependencies:
            Used by:
                - PatchEditorPanel.refresh_memory_rows
        """
        return len(self.unified.memory) == 0

    # -----------------------------------------------------------------------
    # Unified change-set file + selective export (LLR-009.3)
    # -----------------------------------------------------------------------

    def save_unified(
        self, base_dir: Path, file_name: str = "patchset.json"
    ) -> CdfxActionResult:
        """
        Summary:
            Write the whole unified change-set — both halves — to one JSON file
            inside the work area via ``write_unified_to_workarea`` (HLR-005 /
            LLR-009.3).

        Args:
            base_dir (Path): The app base directory whose ``.s19tool/workarea/``
                is the containment root the JSON file is written into.
            file_name (str): The desired unified-file name; a collision is
                dedup-suffixed by ``write_unified_to_workarea``.

        Returns:
            CdfxActionResult: ``ok`` is ``True`` with the written path in
            ``message`` when a file was produced; ``ok`` is ``False`` when the
            write target failed work-area containment validation.

        Data Flow:
            - Call ``write_unified_to_workarea`` with the owned unified
              change-set; shape the ``(path, issues)`` result.

        Dependencies:
            Uses:
                - write_unified_to_workarea
            Used by:
                - PatchEditorPanel / app.py save-unified action
        """
        path, issues = write_unified_to_workarea(
            self.unified, base_dir, file_name=file_name
        )
        if path is None:
            return CdfxActionResult(
                message="Unified change-set write rejected - see issues",
                issues=issues,
                ok=False,
            )
        return CdfxActionResult(
            message=f"Saved unified change-set to {path}",
            issues=issues,
            ok=True,
        )

    def load_unified(
        self, path_text: str, base_dir: Path
    ) -> CdfxActionResult:
        """
        Summary:
            Parse a unified change-set JSON file into the owned unified
            change-set, replacing both halves (HLR-006 / LLR-009.3).

        Args:
            path_text (str): The user-typed unified-file path — resolved by
                ``read_unified`` through ``workspace.resolve_input_path``.
            base_dir (Path): The directory a relative ``path_text`` resolves
                against — normally the app working directory.

        Returns:
            CdfxActionResult: ``ok`` is ``True`` (a document was parsed, even
            with issues); ``message`` reports the recovered per-half counts.

        Data Flow:
            - Call ``read_unified``; on return **replace** the owned unified
              change-set with the parsed one so both tables reflect the file.
            - A malformed file still returns an (often empty) change-set plus
              ``MF-*`` issues — collect-don't-abort, never a crash (HLR-006).

        Dependencies:
            Uses:
                - read_unified
            Used by:
                - PatchEditorPanel / app.py load-unified action
        """
        loaded, issues = read_unified(path_text.strip(), base_dir)
        self.unified = loaded
        param_count, memory_count = loaded.counts()
        return CdfxActionResult(
            message=(
                f"Loaded {param_count} parameter + {memory_count} memory "
                f"change(s) from {path_text.strip()}"
            ),
            issues=issues,
            ok=True,
        )

    def export_selective(
        self,
        base_dir: Path,
        a2l_tags: Optional[list[dict[str, Any]]],
        cdfx_file_name: str = "export.cdfx",
        memory_field_file_name: str = "export-memory.json",
    ) -> ExportResult:
        """
        Summary:
            Split the unified change-set into a ``.cdfx`` parameter-half file
            and a separate JSON memory-field-half file via ``export_unified``
            (HLR-007 / LLR-009.3).

        Args:
            base_dir (Path): The app base directory whose ``.s19tool/workarea/``
                is the containment root both files are written into.
            a2l_tags (Optional[list[dict]]): The enriched A2L tags the parameter
                half is re-resolved against at export time; ``None`` exports an
                unresolved parameter half plus one informational issue
                (LLR-007.5).
            cdfx_file_name (str): The desired ``.cdfx`` file name.
            memory_field_file_name (str): The desired memory-field JSON name.

        Returns:
            ExportResult: The two written file paths and the combined,
            per-half-tagged ``ValidationIssue`` list — surfaced unchanged to
            the screen / ``app.py``.

        Data Flow:
            - Delegate the whole split to ``export_unified``; the service adds
              no export logic of its own (constraint C-7 / LLR-009.2).

        Dependencies:
            Uses:
                - export_unified
            Used by:
                - PatchEditorPanel / app.py selective-export action
        """
        return export_unified(
            self.unified,
            a2l_tags,
            base_dir,
            cdfx_file_name=cdfx_file_name,
            memory_field_file_name=memory_field_file_name,
        )
