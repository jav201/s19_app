"""
A2L parameter resolution for the CDFX change-list — s19_app batch-03, increment 2.

Each :class:`~s19_app.tui.cdfx.changelist.ChangeListEntry` the engineer builds
in the Patch Editor names an A2L parameter and an array index, but carries no
type metadata of its own. This module resolves an entry against the **loaded
A2L** so the writer (increment 4) and the display layer (increment 3) know the
parameter's data type, element count and characteristic kind.

Resolution runs through the **enriched** A2L pipeline — the tags produced by
``a2l.enrich_a2l_tags_with_values`` over a ``parse_a2l_file`` payload — not the
bare ``extract_a2l_tags`` output. A bare ``extract_a2l_tags`` ``CHARACTERISTIC``
tag has ``datatype = None``; only after enrichment / ``_resolve_record_layout``
are the decode-relevant fields (``decode_type``, ``element_count``,
``char_type``) populated (constraint C-1, Phase-2 finding A-01). This module
**consumes** that enriched output; it never re-parses A2L text and never
modifies ``a2l.py``.

The resolution verdict per entry is two things: a ``ResolutionStatus`` (stamped
onto the entry's declared ``status`` field) and the resolved A2L type metadata.
The change-list model (increment 1) has no field to hold the type metadata, so
this module returns it alongside the change-list in a :class:`ResolutionResult`
rather than mutating a non-existent attribute — the model is left untouched.

Implements LLR-002.1..LLR-002.4.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .changelist import ChangeList, ChangeListEntry, EntryKey, ResolutionStatus


@dataclass(slots=True)
class ResolvedType:
    """
    Summary:
        The A2L type metadata resolved for one change-list entry — the
        downstream-facing result of matching an entry against an enriched A2L
        tag.

    Args:
        char_type (str | None): The A2L ``CHARACTERISTIC`` kind token
            (``VALUE`` / ``VAL_BLK`` / ``ASCII`` / ``CURVE`` / ``MAP`` / ...) —
            the enriched tag's ``char_type`` field. Drives the CDFX instance
            ``CATEGORY`` (increment 4) and the ASCII display branch
            (increment 3). ``None`` when the matched tag carried no kind (for
            example an A2L ``MEASUREMENT``).
        datatype (str | None): The ASAP2 numeric data-type token
            (``UWORD`` / ``SLONG`` / ``FLOAT32_IEEE`` / ...). Taken from the
            enriched tag's ``decode_type`` — the field populated after record-
            layout resolution — because a ``CHARACTERISTIC`` tag's bare
            ``datatype`` is ``None`` (A-01). ``None`` when no data type could
            be resolved.
        element_count (int): Number of elements the A2L parameter holds — ``1``
            for a scalar, ``k`` for a 1-D array of length ``k``. Used for the
            array-index range check (LLR-002.3).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :func:`_resolve_entry` from one enriched A2L tag.
        - Collected into :attr:`ResolutionResult.resolved_types` for the
          writer / display layers to read.

    Dependencies:
        Used by:
            - ResolutionResult
            - The CDFX writer and display layer (later increments).
    """

    char_type: str | None = None
    datatype: str | None = None
    element_count: int = 1


@dataclass(slots=True)
class ResolutionResult:
    """
    Summary:
        The outcome of resolving a change-list against an enriched A2L — the
        resolved change-list plus the resolved A2L type metadata keyed by
        entry identity.

    Args:
        change_list (ChangeList): The same change-list passed to
            :func:`resolve_against_a2l`, with every entry's ``status`` field
            now stamped with its resolution verdict.
        resolved_types (dict[EntryKey, ResolvedType]): The resolved A2L type
            metadata, keyed by the entry's ``(parameter_name, array_index)``
            identity. An entry is present in this map exactly when its name
            matched an A2L parameter — that is, for ``RESOLVED`` and
            ``INDEX_OUT_OF_RANGE`` entries (an out-of-range index still
            resolved the *parameter*, so its type is known). ``UNRESOLVED`` and
            ``UNRESOLVED_NO_A2L`` entries have no entry in the map.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Populated by :func:`resolve_against_a2l`; ``resolved_types`` is empty
          when no A2L was supplied.
        - The writer (increment 4) reads ``resolved_types`` to pick each
          ``SW-INSTANCE``'s ``CATEGORY``; the display layer (increment 3) reads
          it to pick the value format.

    Dependencies:
        Uses:
            - ResolvedType
        Used by:
            - resolve_against_a2l (returned to its callers)
    """

    change_list: ChangeList
    resolved_types: dict[EntryKey, ResolvedType] = field(default_factory=dict)

    def type_for(self, entry: ChangeListEntry) -> ResolvedType | None:
        """
        Summary:
            Return the resolved A2L type for one entry, or ``None`` when the
            entry's name did not match an A2L parameter.

        Args:
            entry (ChangeListEntry): A change-list entry whose identity is
                looked up in :attr:`resolved_types`.

        Returns:
            ResolvedType | None: The matched type metadata, or ``None`` for an
            ``UNRESOLVED`` / ``UNRESOLVED_NO_A2L`` entry.

        Dependencies:
            Used by:
                - The CDFX writer and display layer (later increments).
        """
        return self.resolved_types.get(entry.key)


def resolve_against_a2l(
    change_list: ChangeList,
    enriched_a2l_tags: list[dict] | None,
) -> ResolutionResult:
    """
    Summary:
        Resolve every change-list entry against the enriched A2L tags,
        stamping each entry's resolution status and collecting the resolved
        A2L type metadata.

    Args:
        change_list (ChangeList): The change-list whose entries are resolved.
            Each entry's declared ``status`` field is overwritten in place.
        enriched_a2l_tags (list[dict] | None): The enriched A2L tags — the
            output of ``a2l.enrich_a2l_tags_with_values`` over a
            ``parse_a2l_file`` payload (constraint C-1). Each tag dict is read
            for ``name``, ``char_type``, ``decode_type`` and ``element_count``.
            ``None`` (or an empty list) means no A2L is loaded.

    Returns:
        ResolutionResult: The resolved change-list and the per-entry resolved
        type metadata. Each entry's ``status`` is one of:
            - ``RESOLVED`` — name + index matched an A2L parameter; the entry's
              ``ResolvedType`` is in ``resolved_types`` (LLR-002.1).
            - ``UNRESOLVED`` — the name matched no A2L parameter (LLR-002.2).
            - ``INDEX_OUT_OF_RANGE`` — the entry's integer ``array_index`` is
              negative or not less than the matched parameter's
              ``element_count`` (LLR-002.3); the parameter still resolved, so
              its type is in ``resolved_types``. A ``None`` index (scalar /
              string entry) is never range-checked.
            - ``UNRESOLVED_NO_A2L`` — no A2L tags were supplied (LLR-002.4).

    Raises:
        None: Resolution never raises on an unknown name, an out-of-range
            index, or a missing A2L — every failure mode is a status, not an
            exception (LLR-002.2/002.3/002.4 "shall not raise").

    Data Flow:
        - When no A2L tags are supplied, mark every entry ``UNRESOLVED_NO_A2L``
          and return a result with an empty type map (LLR-002.4).
        - Otherwise index the enriched tags by ``name`` for O(1) lookup.
        - For each entry, delegate the per-entry verdict to
          :func:`_resolve_entry`, which stamps ``status`` and contributes to
          the resolved-type map.

    Dependencies:
        Uses:
            - _resolve_entry
        Used by:
            - The CDFX service / Patch Editor screen (increment 7), after an
              A2L is loaded and a change-list is built.

    Example:
        >>> from s19_app.tui.a2l import parse_a2l_file, enrich_a2l_tags_with_values
        >>> tags = enrich_a2l_tags_with_values(parse_a2l_file(path), None)
        >>> result = resolve_against_a2l(change_list, tags)  # doctest: +SKIP
    """
    result = ResolutionResult(change_list=change_list)

    if not enriched_a2l_tags:
        for entry in change_list.entries:
            entry.status = ResolutionStatus.UNRESOLVED_NO_A2L
        return result

    tags_by_name: dict[str, dict] = {
        str(tag.get("name")): tag
        for tag in enriched_a2l_tags
        if tag.get("name")
    }

    for entry in change_list.entries:
        _resolve_entry(entry, tags_by_name, result)
    return result


def _resolve_entry(
    entry: ChangeListEntry,
    tags_by_name: dict[str, dict],
    result: ResolutionResult,
) -> None:
    """
    Summary:
        Resolve one change-list entry against the name-indexed enriched A2L
        tags, stamping its status and recording its resolved type.

    Args:
        entry (ChangeListEntry): The entry to resolve. Its ``status`` field is
            overwritten in place.
        tags_by_name (dict[str, dict]): Enriched A2L tags keyed by ``name`` —
            built once by :func:`resolve_against_a2l` so this helper does an
            O(1) lookup per entry.
        result (ResolutionResult): The accumulating result; a matched entry's
            ``ResolvedType`` is added to ``result.resolved_types``.

    Returns:
        None: The entry and the result are mutated in place.

    Data Flow:
        - Look the entry's ``parameter_name`` up; an unknown name is
          ``UNRESOLVED`` with no resolved-type entry (LLR-002.2).
        - Read ``char_type`` / ``decode_type`` / ``element_count`` from the
          matched enriched tag into a ``ResolvedType`` and record it — the
          parameter resolved even when the index is out of range.
        - Range-check ``array_index`` against ``element_count`` **only when it
          is an integer**: a negative index or one not less than the count is
          ``INDEX_OUT_OF_RANGE`` (LLR-002.3). A ``None`` index (a scalar or
          string entry, LLR-001.1) skips the range check and resolves on name
          alone; comparing ``None`` would raise ``TypeError``.

    Dependencies:
        Uses:
            - ResolvedType
            - _element_count_of
        Used by:
            - resolve_against_a2l
    """
    tag = tags_by_name.get(entry.parameter_name)
    if tag is None:
        entry.status = ResolutionStatus.UNRESOLVED
        return

    resolved = ResolvedType(
        char_type=tag.get("char_type"),
        datatype=tag.get("decode_type"),
        element_count=_element_count_of(tag),
    )
    result.resolved_types[entry.key] = resolved

    index = entry.array_index
    if isinstance(index, int) and (
        index < 0 or index >= resolved.element_count
    ):
        entry.status = ResolutionStatus.INDEX_OUT_OF_RANGE
        return

    entry.status = ResolutionStatus.RESOLVED


def _element_count_of(tag: dict) -> int:
    """
    Summary:
        Read an enriched A2L tag's element count as a positive ``int``,
        defaulting to a scalar when the field is absent or unusable.

    Args:
        tag (dict): One enriched A2L tag dict. Its ``element_count`` field is
            populated by ``a2l._resolve_record_layout`` (``1`` for a scalar,
            ``k`` for a 1-D array).

    Returns:
        int: The element count, clamped to a minimum of ``1`` — a scalar
            parameter (``element_count`` 1) and a tag with a missing or
            non-numeric count both resolve to ``1`` so the LLR-002.3 range
            check has a well-defined upper bound.

    Data Flow:
        - Coerce ``element_count`` to ``int``; on a missing or non-numeric
          value fall back to ``1``.
        - Clamp the result so the count is never below ``1``.

    Dependencies:
        Used by:
            - _resolve_entry
    """
    raw = tag.get("element_count")
    try:
        count = int(raw)
    except (TypeError, ValueError):
        return 1
    return max(1, count)
