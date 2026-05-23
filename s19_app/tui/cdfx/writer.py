"""
CDFX (ASAM CDF 2.0) writer + standalone ``W-*`` validator — s19_app batch-03,
increments 4 and 6.

This module serializes a resolved :class:`~s19_app.tui.cdfx.changelist.ChangeList`
into a structurally valid CDF 2.0 ``.cdfx`` document and provides the
standalone write-time ``W-*`` rule validator.

The writer (:func:`write_cdfx`) builds, with the standard-library
``xml.etree.ElementTree`` only (constraint C-2 — no new dependency):

- the ``MSRSW`` root with ``SHORT-NAME`` + ``CATEGORY=CDF20`` (LLR-004.1);
- the ``SW-SYSTEMS/SW-SYSTEM/SW-INSTANCE-SPEC/SW-INSTANCE-TREE`` backbone, each
  container carrying a ``SHORT-NAME`` (LLR-004.1);
- **one ``SW-INSTANCE`` per distinct resolved ``parameter_name``** — not one
  per change-list entry (LLR-004.2 / LLR-004.9). Before emitting, the writer
  **groups** the writable entries by ``parameter_name``: a group of
  integer-``array_index`` entries is **coalesced** into a single ``VAL_BLK``
  ``SW-INSTANCE`` whose one ``VG`` carries one positional ``V`` per element,
  ordered ascending by ``array_index``; a ``None``-``array_index`` entry stays
  its own ``VALUE`` / ``BOOLEAN`` / ``ASCII`` instance. Groups are emitted in
  the order of **first appearance** of their ``parameter_name`` in
  ``ChangeList.entries`` — two deterministic rules (first-appearance across
  groups, ascending ``array_index`` within a group), so two writes of the same
  change-list are byte-identical (LLR-001.4);
- a ``SW-VALUE-CONT/SW-VALUES-PHYS`` carrying ``V`` (scalar), one ``VG`` of
  positional ``V`` (1-D array) or ``VT`` (ASCII string) — the change-list
  ``array_index`` is the *positional* order of the ``V`` elements only, never a
  ``SW-ARRAY-INDEX`` element (LLR-004.3, finding A-09);
- a leading ``Created with s19_app CDF 2.0 Writer`` tool-identification XML
  comment (LLR-004.7);
- IEEE float ``V`` text at full ``repr()`` precision so a write→read cycle is
  exact and needs no float tolerance (LLR-004.8).

A "writable" entry is one whose resolution ``status`` is ``RESOLVED``. Entries
that are ``UNRESOLVED`` or ``INDEX_OUT_OF_RANGE`` are **excluded** from the
output, each producing one warning ``ValidationIssue`` (LLR-004.5); the writer
gates on the entry ``status``, not on "is a resolved type present" — an
``INDEX_OUT_OF_RANGE`` entry still has a resolved type (increment-2 risk note).
A coalesced integer-``array_index`` group whose indices do **not** form the
contiguous gapless zero-based sequence ``0, 1, …, N-1`` is a **sparse array**:
the writer emits no ``SW-INSTANCE`` for it and one warning ``ValidationIssue``
with code ``W-ARRAY-SPARSE`` naming the parameter, and never synthesizes a
``V`` for a missing index (LLR-004.9 sparse rule). If zero entries are writable
— whether the change-list is literally empty, every entry was excluded, or
every array group was rejected as sparse — the writer still emits a valid
backbone-only document plus one ``W-EMPTY-CHANGELIST`` warning (LLR-004.6).

:func:`validate_w_rules` is the **standalone** ``W-*`` validator: given a built
``ElementTree`` element it checks the §7 write-time structural rules and
returns one ``ValidationIssue`` per violation. It is testable in isolation
(Phase-2 Q-05) — crafted broken trees provoke the codes a correct writer can
never emit (``W-XML-WELLFORMED``, ``W-ROOT-MSRSW``, ``W-BACKBONE``,
``W-CATEGORY-VALUE-CONSISTENT``).

:func:`write_cdfx_to_workarea` is the **work-area-contained write path**
(LLR-007.7, increment 8): it serializes the change-list with :func:`write_cdfx`,
then places the bytes on disk through ``workspace.copy_into_workarea`` — the
existing, already-hardened containment helper, **reused, not re-implemented**.
The final target must resolve under a ``.s19tool/workarea/`` root; a target
that is, or whose traversed parents include, a symbolic link / NTFS reparse
point is rejected; an existing-name target is dedup-suffixed (``_<N>`` before
the suffix) — no silent clobber. A containment / reparse-point rejection is
surfaced as one write-side ``W-WRITE-CONTAINMENT`` ``ValidationIssue``, never an
uncaught exception (collect-don't-abort). No new write path is introduced — the
writer produces bytes, writes them to a work-area temp file, and lets
``copy_into_workarea`` perform the containment-checked final placement (DD-10).

Implements LLR-004.1..LLR-004.9, LLR-006.1 and LLR-007.7.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from ...validation.model import ValidationIssue, ValidationSeverity
from ..workspace import (
    WORKAREA_TEMP,
    WorkareaContainmentError,
    copy_into_workarea,
    ensure_workarea,
)
from .changelist import ChangeList, ChangeListEntry, ResolutionStatus
from .resolve import ResolutionResult, ResolvedType

# ---------------------------------------------------------------------------
# Constants — the CDF 2.0 contract this writer targets.
# ---------------------------------------------------------------------------

# The artifact tag every CDFX ValidationIssue carries (LLR-006.3 / DD-5).
CDFX_ARTIFACT = "cdfx"

# The MSRSW/CATEGORY version token the writer always emits (constraint C-6).
CDF20_CATEGORY = "CDF20"

# The SW-INSTANCE-TREE CATEGORY: a non-variant-coded dataset (research §8 OQ-4).
INSTANCE_TREE_CATEGORY = "NO_VCD"

# The leading tool-identification XML comment (LLR-004.7). The surrounding
# spaces keep the rendered ``<!-- ... -->`` readable.
TOOL_NOTE_TEXT = " Created with s19_app CDF 2.0 Writer "

# Default SHORT-NAMEs for the backbone containers — the document is a parameter
# patch set; these names are cosmetic identity, not a join key.
DEFAULT_ROOT_NAME = "S19APP_PATCH"
DEFAULT_SYSTEM_NAME = "ECU1"
DEFAULT_INSTANCE_TREE_NAME = "PatchSet"

# The editable instance categories (research §7 W-INSTANCE-CATEGORY). A 1-D
# array is VAL_BLK; a scalar is VALUE; an ASCII string is ASCII; a boolean-like
# scalar is BOOLEAN.
EDITABLE_CATEGORIES: frozenset[str] = frozenset(
    {"VALUE", "BOOLEAN", "VAL_BLK", "ASCII"}
)

# A2L char_type tokens that select the ASCII (string) instance category.
_ASCII_CHAR_TYPE = "ASCII"
# A2L char_type tokens that select the 1-D array (VAL_BLK) instance category.
_VAL_BLK_CHAR_TYPE = "VAL_BLK"


# ---------------------------------------------------------------------------
# Writer.
# ---------------------------------------------------------------------------


def write_cdfx(
    change_list: ChangeList,
    resolution: ResolutionResult,
) -> tuple[bytes, list[ValidationIssue]]:
    """
    Summary:
        Serialize a resolved change-list to a CDF 2.0 ``.cdfx`` byte stream and
        collect every write-time ``ValidationIssue``.

    Args:
        change_list (ChangeList): The change-list to serialize. Its entries are
            written in insertion order (``ChangeList.entries``); the writer
            adds no second ordering rule, so the output is byte-identical
            across repeated writes of the same change-list (LLR-001.4).
        resolution (ResolutionResult): The result of resolving ``change_list``
            against the loaded A2L — its ``type_for`` lookup supplies each
            entry's ``ResolvedType`` (the A2L ``char_type`` that picks the
            instance ``CATEGORY``). The resolution must have been produced for
            this same change-list; entry ``status`` fields are read to gate
            which entries are written.

    Returns:
        tuple[bytes, list[ValidationIssue]]: The serialized ``.cdfx`` document
        as UTF-8 bytes (XML declaration + leading tool-note comment + ``MSRSW``
        tree), and the list of write-time issues:
            - one warning per ``UNRESOLVED`` / ``INDEX_OUT_OF_RANGE`` entry
              excluded from the output (code ``W-INSTANCE-EXCLUDED``,
              LLR-004.5);
            - one warning per ``parameter_name`` whose coalesced array group is
              **sparse** — its integer indices are not the contiguous gapless
              zero-based sequence ``0, 1, …, N-1`` (code ``W-ARRAY-SPARSE``,
              LLR-004.9); the whole group is excluded;
            - exactly one ``W-EMPTY-CHANGELIST`` warning when zero
              ``SW-INSTANCE`` elements were written (LLR-004.6), in addition to
              any exclusion / sparse warnings.
        The byte stream is always well-formed and always carries a valid
        backbone, even when no instance is written.

    Raises:
        None: The writer never raises on an unresolved, sparse, or empty
            change-list — every case is reported as a ``ValidationIssue``
            record, not an exception (LLR-004.5/004.6/004.9
            collect-don't-abort).

    Data Flow:
        - Iterate ``change_list.entries`` in insertion order; partition each
          entry into "writable" (``status == RESOLVED``) or "excluded", and
          emit one ``W-INSTANCE-EXCLUDED`` warning per excluded entry.
        - Group the writable entries by ``parameter_name``, preserving each
          name's first-appearance order in ``ChangeList.entries`` (LLR-004.9).
        - Build the ``MSRSW`` backbone, then per group emit: one coalesced
          ``VAL_BLK`` ``SW-INSTANCE`` for an integer-``array_index`` group, one
          ``VALUE`` / ``BOOLEAN`` / ``ASCII`` ``SW-INSTANCE`` for a
          ``None``-``array_index`` entry. A sparse integer-index group emits no
          instance and one ``W-ARRAY-SPARSE`` warning.
        - Emit one ``W-EMPTY-CHANGELIST`` warning when nothing was written.
        - Serialize the tree, prepending the XML declaration and the
          tool-identification comment.

    Dependencies:
        Uses:
            - _build_backbone
            - _group_writable_entries
            - _append_group
            - _serialize
            - _exclusion_issue
            - _empty_changelist_issue
        Used by:
            - The CDFX service / Patch Editor save action (increment 9).

    Example:
        >>> from s19_app.tui.cdfx.changelist import ChangeList
        >>> from s19_app.tui.cdfx.resolve import resolve_against_a2l
        >>> cl = ChangeList()
        >>> cl.add("IGN_ADVANCE_BASE", None, 23)  # doctest: +SKIP
        >>> result = resolve_against_a2l(cl, enriched_tags)  # doctest: +SKIP
        >>> data, issues = write_cdfx(cl, result)  # doctest: +SKIP
    """
    issues: list[ValidationIssue] = []

    msrsw, instance_tree = _build_backbone()

    writable: list[ChangeListEntry] = []
    for entry in change_list.entries:
        if entry.status is ResolutionStatus.RESOLVED:
            writable.append(entry)
        else:
            issues.append(_exclusion_issue(entry))

    written = 0
    for group in _group_writable_entries(writable):
        written += _append_group(instance_tree, group, resolution, issues)

    if written == 0:
        issues.append(_empty_changelist_issue())

    return _serialize(msrsw), issues


def write_cdfx_to_workarea(
    change_list: ChangeList,
    resolution: ResolutionResult,
    base_dir: Path,
    file_name: str = "patchset.cdfx",
) -> tuple[Path | None, list[ValidationIssue]]:
    """
    Summary:
        Serialize a change-list to a ``.cdfx`` file placed inside the
        work-area, containment-validating the write target through the existing
        ``workspace.copy_into_workarea`` helper (LLR-007.7).

    Args:
        change_list (ChangeList): The change-list to serialize — passed
            straight to :func:`write_cdfx`.
        resolution (ResolutionResult): The resolution result for
            ``change_list`` — passed straight to :func:`write_cdfx`.
        base_dir (Path): The app base directory whose ``.s19tool/workarea/`` is
            the containment root the ``.cdfx`` is written into. The work-area
            structure is created if absent (``ensure_workarea``).
        file_name (str): The desired ``.cdfx`` file name. A name that collides
            with an existing file in the work area is dedup-suffixed (``_<N>``
            before the suffix) by ``copy_into_workarea`` — never a silent
            clobber.

    Returns:
        tuple[Path | None, list[ValidationIssue]]: The absolute path of the
        written ``.cdfx`` file and the issue list, or ``(None, issues)`` when
        the write target failed containment validation. The issue list carries
        every :func:`write_cdfx` ``W-*`` issue; a containment / reparse-point
        rejection adds one ``W-WRITE-CONTAINMENT`` warning and the path is
        ``None``.

    Raises:
        None: A containment, reparse-point, or overwrite failure is reported as
            a ``W-WRITE-CONTAINMENT`` ``ValidationIssue``, never raised
            (LLR-007.7 collect-don't-abort). ``WorkareaContainmentError`` from
            the reused helper is caught and converted here.

    Data Flow:
        - Serialize ``change_list`` with :func:`write_cdfx` — collect its
          ``W-*`` issues.
        - Ensure the ``.s19tool/workarea/`` structure; stage the bytes under
          the engineer's chosen name in ``.s19tool/workarea/temp/`` (no new
          write path — the bytes need a real source file for
          ``copy_into_workarea``, and ``temp/`` is itself inside the work area,
          DD-10).
        - Call ``copy_into_workarea`` to place the staged file in the work-area
          root: it resolves the target under ``.s19tool/workarea/``, rejects a
          reparse-point traversal, and dedup-suffixes a name collision —
          reused, not re-implemented.
        - A ``WorkareaContainmentError`` becomes one ``W-WRITE-CONTAINMENT``
          warning and a ``None`` path; the staged temp file is removed either
          way.

    Dependencies:
        Uses:
            - write_cdfx
            - ensure_workarea
            - copy_into_workarea
            - _safe_name
            - _containment_issue
        Used by:
            - The CDFX service / Patch Editor save action (increment 9).

    Example:
        >>> path, issues = write_cdfx_to_workarea(cl, result, base_dir)  # doctest: +SKIP
    """
    data, issues = write_cdfx(change_list, resolution)

    workarea = ensure_workarea(base_dir)
    # Stage the bytes under the engineer's chosen name inside the work-area
    # temp/ dir, so copy_into_workarea's dedup keys off that name. temp/ is
    # itself inside the work area — no bytes ever land outside it.
    staged = workarea / WORKAREA_TEMP / _safe_name(file_name)
    try:
        staged.write_bytes(data)
        target = copy_into_workarea(staged, workarea)
        return target, issues
    except WorkareaContainmentError as exc:
        issues.append(_containment_issue(str(exc)))
        return None, issues
    finally:
        try:
            staged.unlink()
        except OSError:
            pass


def _safe_name(file_name: str) -> str:
    """
    Summary:
        Reduce a requested ``.cdfx`` file name to its bare name component with a
        ``.cdfx`` suffix, so the write target cannot escape the work area via
        the file name itself.

    Args:
        file_name (str): The engineer-requested file name — possibly carrying
            path separators or no suffix.

    Returns:
        str: The bare name (``Path.name`` — directory components stripped) with
        a ``.cdfx`` suffix forced on. An empty result falls back to
        ``patchset.cdfx``.

    Data Flow:
        - Strip any directory component with ``Path(...).name``.
        - Force a ``.cdfx`` suffix; fall back to ``patchset.cdfx`` when empty.

    Dependencies:
        Used by:
            - write_cdfx_to_workarea
    """
    bare = Path(file_name).name.strip()
    if not bare:
        return "patchset.cdfx"
    if not bare.lower().endswith(".cdfx"):
        bare = f"{bare}.cdfx"
    return bare


def _containment_issue(detail: str) -> ValidationIssue:
    """
    Summary:
        Build the warning ``ValidationIssue`` for a ``.cdfx`` write target that
        failed work-area containment validation (LLR-007.7).

    Args:
        detail (str): The ``WorkareaContainmentError`` detail message — names
            the rejected target and the reason (outside the work area, or a
            reparse-point traversal).

    Returns:
        ValidationIssue: A warning-level issue with code ``W-WRITE-CONTAINMENT``
        and artifact ``cdfx``. The write produced no file.

    Dependencies:
        Used by:
            - write_cdfx_to_workarea
    """
    return ValidationIssue(
        code="W-WRITE-CONTAINMENT",
        severity=ValidationSeverity.WARNING,
        message=(
            f"the .cdfx write target failed work-area containment "
            f"validation — no file was written: {detail}"
        ),
        artifact=CDFX_ARTIFACT,
    )


def _group_writable_entries(
    writable: list[ChangeListEntry],
) -> list[list[ChangeListEntry]]:
    """
    Summary:
        Group writable change-list entries by ``parameter_name``, preserving
        each name's first-appearance order (LLR-004.9 / LLR-001.4).

    Args:
        writable (list[ChangeListEntry]): The ``RESOLVED`` entries, in
            change-list insertion order.

    Returns:
        list[list[ChangeListEntry]]: One inner list per distinct
        ``parameter_name``, the outer list ordered by the name's **first
        appearance** in ``writable`` and each inner list keeping the entries'
        insertion order. The caller coalesces an integer-``array_index`` group
        into one ``VAL_BLK`` instance and emits a ``None``-index entry as its
        own scalar/string instance.

    Data Flow:
        - Walk ``writable`` once, appending each entry to its name's bucket and
          recording the name on first sight to fix the group order.

    Dependencies:
        Used by:
            - write_cdfx
    """
    groups: dict[str, list[ChangeListEntry]] = {}
    for entry in writable:
        groups.setdefault(entry.parameter_name, []).append(entry)
    return list(groups.values())


def _append_group(
    instance_tree: ET.Element,
    group: list[ChangeListEntry],
    resolution: ResolutionResult,
    issues: list[ValidationIssue],
) -> int:
    """
    Summary:
        Emit the ``SW-INSTANCE`` element(s) for one ``parameter_name`` group
        and report a sparse array group, returning the number of instances
        written (LLR-004.2 / LLR-004.3 / LLR-004.9).

    Args:
        instance_tree (ET.Element): The ``SW-INSTANCE-TREE`` element to append
            to.
        group (list[ChangeListEntry]): The writable entries that share one
            ``parameter_name``, in change-list insertion order.
        resolution (ResolutionResult): The resolution result — supplies each
            entry's ``ResolvedType`` for the instance ``CATEGORY``.
        issues (list[ValidationIssue]): The accumulating issue list, appended
            to in place (one ``W-ARRAY-SPARSE`` per rejected sparse group).

    Returns:
        int: The number of ``SW-INSTANCE`` elements appended — ``1`` for a
        ``None``-``array_index`` scalar/string entry or a contiguous
        integer-``array_index`` array group, ``0`` for a rejected sparse array
        group.

    Data Flow:
        - A single ``None``-``array_index`` entry → one scalar/string instance.
        - An integer-``array_index`` group whose indices are the contiguous
          gapless zero-based sequence ``0…N-1`` → one coalesced ``VAL_BLK``
          instance with one ascending-``V`` ``VG``.
        - A sparse integer-``array_index`` group → no instance, one
          ``W-ARRAY-SPARSE`` warning naming the parameter (LLR-004.9). The
          writer never synthesizes a ``V`` for a missing index.
        - A ``None`` entry mixed with integer entries under one name (a
          model-permitted but resolution-impossible state, increment-6 risk
          note) is treated as separate ``None``-index instances plus an
          integer-index group — no merge rule is invented.

    Dependencies:
        Uses:
            - _append_scalar_instance
            - _append_array_instance
            - _is_contiguous_zero_based
            - _sparse_array_issue
        Used by:
            - write_cdfx
    """
    scalars = [e for e in group if e.array_index is None]
    array_entries = [e for e in group if isinstance(e.array_index, int)]

    written = 0
    for entry in scalars:
        _append_scalar_instance(instance_tree, entry, resolution.type_for(entry))
        written += 1

    if array_entries:
        ordered = sorted(array_entries, key=lambda e: e.array_index)
        indices = [e.array_index for e in ordered]
        if _is_contiguous_zero_based(indices):
            _append_array_instance(
                instance_tree, ordered, resolution.type_for(ordered[0])
            )
            written += 1
        else:
            issues.append(
                _sparse_array_issue(array_entries[0].parameter_name, indices)
            )

    return written


def _is_contiguous_zero_based(indices: list[int]) -> bool:
    """
    Summary:
        Decide whether a sorted list of array indices is the contiguous
        gapless zero-based sequence ``0, 1, …, N-1`` (LLR-004.9).

    Args:
        indices (list[int]): The array indices of one coalesced group, sorted
            ascending.

    Returns:
        bool: ``True`` when ``indices == [0, 1, …, len(indices) - 1]`` — the
        only shape a positional ``VG`` can represent without inventing a value
        for a missing slot. ``False`` for a gap (``[0, 2]``), a non-zero lowest
        index (``[1, 2]``), or a duplicate index.

    Data Flow:
        - Compare the sorted indices against ``range(len(indices))``.

    Dependencies:
        Used by:
            - _append_group
    """
    return indices == list(range(len(indices)))


def _build_backbone() -> tuple[ET.Element, ET.Element]:
    """
    Summary:
        Build the empty CDF 2.0 ``MSRSW`` backbone and return its root and the
        ``SW-INSTANCE-TREE`` element instances are appended to (LLR-004.1).

    Returns:
        tuple[ET.Element, ET.Element]: The ``MSRSW`` root element and the
        ``SW-INSTANCE-TREE`` element nested inside it. The chain
        ``MSRSW → SW-SYSTEMS → SW-SYSTEM → SW-INSTANCE-SPEC →
        SW-INSTANCE-TREE`` is built; ``MSRSW`` carries a ``SHORT-NAME`` and a
        ``CATEGORY=CDF20``, every container carries a ``SHORT-NAME``, and the
        instance tree carries its ``NO_VCD`` ``CATEGORY``.

    Data Flow:
        - Create each backbone element top-down with ``ET.SubElement``.
        - Populate the mandatory ``SHORT-NAME`` / ``CATEGORY`` leaves.

    Dependencies:
        Uses:
            - _text_child
        Used by:
            - write_cdfx
    """
    msrsw = ET.Element("MSRSW")
    _text_child(msrsw, "SHORT-NAME", DEFAULT_ROOT_NAME)
    _text_child(msrsw, "CATEGORY", CDF20_CATEGORY)

    sw_systems = ET.SubElement(msrsw, "SW-SYSTEMS")
    sw_system = ET.SubElement(sw_systems, "SW-SYSTEM")
    _text_child(sw_system, "SHORT-NAME", DEFAULT_SYSTEM_NAME)

    instance_spec = ET.SubElement(sw_system, "SW-INSTANCE-SPEC")
    instance_tree = ET.SubElement(instance_spec, "SW-INSTANCE-TREE")
    _text_child(instance_tree, "SHORT-NAME", DEFAULT_INSTANCE_TREE_NAME)
    _text_child(instance_tree, "CATEGORY", INSTANCE_TREE_CATEGORY)

    return msrsw, instance_tree


def _append_scalar_instance(
    instance_tree: ET.Element,
    entry: ChangeListEntry,
    resolved_type: ResolvedType | None,
) -> None:
    """
    Summary:
        Append one scalar/string ``SW-INSTANCE`` for a ``None``-``array_index``
        change-list entry (LLR-004.2, LLR-004.3).

    Args:
        instance_tree (ET.Element): The ``SW-INSTANCE-TREE`` element to append
            the new ``SW-INSTANCE`` to.
        entry (ChangeListEntry): The writable entry whose ``array_index`` is
            ``None`` — a scalar (``VALUE`` / ``BOOLEAN``) or ASCII-string
            parameter. Its ``parameter_name`` becomes the instance
            ``SHORT-NAME`` and its ``value`` becomes the physical value.
        resolved_type (ResolvedType | None): The entry's resolved A2L type. Its
            ``char_type`` selects the instance ``CATEGORY``; ``None`` (which
            should not occur for a ``RESOLVED`` entry) falls back to ``VALUE``.

    Returns:
        None: The ``instance_tree`` element is mutated in place.

    Data Flow:
        - Append ``SW-INSTANCE`` with a ``SHORT-NAME`` of the parameter name.
        - Pick the ``CATEGORY`` from the resolved ``char_type``; a ``VAL_BLK``
          ``char_type`` on a ``None``-index entry is written as a scalar
          ``VALUE`` — a ``None``-index entry is never an array element, so it
          cannot carry a ``VG``.
        - Build ``SW-VALUE-CONT/SW-VALUES-PHYS`` and encode the value as a
          single bare ``V`` (scalar) or a single ``VT`` (ASCII string).

    Dependencies:
        Uses:
            - _category_for
            - _text_child
            - _value_text
        Used by:
            - _append_group
    """
    instance = ET.SubElement(instance_tree, "SW-INSTANCE")
    _text_child(instance, "SHORT-NAME", entry.parameter_name)

    category = _category_for(resolved_type)

    value_cont = ET.SubElement(instance, "SW-VALUE-CONT")
    values_phys = ET.SubElement(value_cont, "SW-VALUES-PHYS")

    if category == "ASCII":
        # An ASCII string parameter: a single VT text value (LLR-004.3).
        _text_child(instance, "CATEGORY", "ASCII")
        vt = ET.SubElement(values_phys, "VT")
        vt.text = "" if entry.value is None else str(entry.value)
        return

    # A scalar parameter: exactly one bare V (LLR-004.3). A VAL_BLK char_type on
    # a None-index entry has no array elements to coalesce, so it is written as
    # a scalar VALUE rather than an empty VG; _category_for only ever yields
    # VALUE / VAL_BLK / ASCII, so the scalar category is always VALUE here.
    _text_child(instance, "CATEGORY", "VALUE")
    v = ET.SubElement(values_phys, "V")
    v.text = _value_text(entry.value)


def _append_array_instance(
    instance_tree: ET.Element,
    ordered_entries: list[ChangeListEntry],
    resolved_type: ResolvedType | None,
) -> None:
    """
    Summary:
        Append one coalesced ``VAL_BLK`` ``SW-INSTANCE`` for a contiguous
        zero-based group of integer-``array_index`` entries (LLR-004.9).

    Args:
        instance_tree (ET.Element): The ``SW-INSTANCE-TREE`` element to append
            the new ``SW-INSTANCE`` to.
        ordered_entries (list[ChangeListEntry]): The array-element entries of
            one ``parameter_name``, already **sorted ascending by
            ``array_index``** and verified contiguous and zero-based by the
            caller — entry *i* is element *i* of the array.
        resolved_type (ResolvedType | None): The resolved A2L type of the
            array parameter; only used to confirm the category is ``VAL_BLK``.

    Returns:
        None: The ``instance_tree`` element is mutated in place.

    Data Flow:
        - Append one ``SW-INSTANCE`` with ``CATEGORY=VAL_BLK`` and the shared
          ``SHORT-NAME``.
        - Build ``SW-VALUE-CONT/SW-VALUES-PHYS`` with **one** ``VG`` containing
          one positional ``V`` per entry, in the supplied ascending order. The
          ``array_index`` is the ``V`` position only — never a
          ``SW-ARRAY-INDEX`` element (LLR-004.3, finding A-09).

    Dependencies:
        Uses:
            - _text_child
            - _value_text
        Used by:
            - _append_group
    """
    instance = ET.SubElement(instance_tree, "SW-INSTANCE")
    _text_child(instance, "SHORT-NAME", ordered_entries[0].parameter_name)
    _text_child(instance, "CATEGORY", "VAL_BLK")

    value_cont = ET.SubElement(instance, "SW-VALUE-CONT")
    values_phys = ET.SubElement(value_cont, "SW-VALUES-PHYS")
    vg = ET.SubElement(values_phys, "VG")
    for entry in ordered_entries:
        v = ET.SubElement(vg, "V")
        v.text = _value_text(entry.value)


def _category_for(resolved_type: ResolvedType | None) -> str:
    """
    Summary:
        Pick the CDFX instance ``CATEGORY`` from a resolved A2L type.

    Args:
        resolved_type (ResolvedType | None): The entry's resolved A2L type;
            ``char_type`` carries the A2L characteristic kind.

    Returns:
        str: One of the editable categories — ``ASCII`` for an ``ASCII``
        ``char_type``, ``VAL_BLK`` for a ``VAL_BLK`` ``char_type``, otherwise
        ``VALUE`` (the scalar default; ``None`` or any other ``char_type``
        falls here).

    Data Flow:
        - Read ``resolved_type.char_type`` and map it to a CDFX category token.

    Dependencies:
        Used by:
            - _append_instance
    """
    if resolved_type is None:
        return "VALUE"
    if resolved_type.char_type == _ASCII_CHAR_TYPE:
        return "ASCII"
    if resolved_type.char_type == _VAL_BLK_CHAR_TYPE:
        return "VAL_BLK"
    return "VALUE"


def _value_text(value: int | float | str | None) -> str:
    """
    Summary:
        Render a physical value as the text content of a ``V`` element,
        emitting IEEE floats at full ``repr()`` precision (LLR-004.8).

    Args:
        value (int | float | str | None): The entry's stored physical value.

    Returns:
        str: The numeric text for ``V``. A ``float`` is rendered with
        ``repr()`` so a write→read cycle is exact and needs no tolerance
        (LLR-004.8) — ``repr(0.1)`` is ``'0.1'``, ``repr(5e-324)`` keeps the
        denormal. An ``int`` is rendered with ``str()`` (exact at any
        magnitude, finding Q-10). A ``str`` or ``None`` is rendered as its
        plain text / the empty string — the writer never raises here; a
        non-numeric scalar value is surfaced by the read-time validator.

    Data Flow:
        - A ``bool`` is an ``int`` subclass; render it as ``0`` / ``1``.
        - A ``float`` uses ``repr()``; an ``int`` uses ``str()``; anything
          else uses ``str()`` (or the empty string for ``None``).

    Dependencies:
        Used by:
            - _append_instance
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(int(value))
    if isinstance(value, float):
        # repr() is the shortest text that round-trips the binary64 value
        # exactly — full precision, no tolerance needed on read (LLR-004.8).
        return repr(value)
    if isinstance(value, int):
        return str(value)
    return str(value)


def _text_child(parent: ET.Element, tag: str, text: str) -> ET.Element:
    """
    Summary:
        Create a child element with text content under ``parent``.

    Args:
        parent (ET.Element): The element to append the child to.
        tag (str): The child element's tag name.
        text (str): The child's text content.

    Returns:
        ET.Element: The newly created child element.

    Dependencies:
        Used by:
            - _build_backbone
            - _append_instance
    """
    child = ET.SubElement(parent, tag)
    child.text = text
    return child


def _serialize(msrsw: ET.Element) -> bytes:
    """
    Summary:
        Serialize the ``MSRSW`` tree to a UTF-8 ``.cdfx`` byte stream with the
        XML declaration and the leading tool-identification comment.

    Args:
        msrsw (ET.Element): The fully built ``MSRSW`` root element.

    Returns:
        bytes: The complete ``.cdfx`` document — ``<?xml ...?>`` declaration,
        then the ``Created with s19_app CDF 2.0 Writer`` XML comment, then the
        serialized ``MSRSW`` tree, all UTF-8 encoded. The comment is emitted as
        raw text *between* the declaration and the root so the document stays
        well-formed and re-parseable (``ElementTree`` discards the comment on
        re-parse, so tests assert it against the raw bytes — increment-4 risk
        note).

    Data Flow:
        - ``ET.tostring`` serializes the ``MSRSW`` tree (no declaration).
        - Prepend the XML declaration and the ``<!-- ... -->`` comment line.

    Dependencies:
        Used by:
            - write_cdfx
    """
    body = ET.tostring(msrsw, encoding="unicode")
    document = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<!--{TOOL_NOTE_TEXT}-->\n"
        f"{body}"
    )
    return document.encode("utf-8")


def _exclusion_issue(entry: ChangeListEntry) -> ValidationIssue:
    """
    Summary:
        Build the warning ``ValidationIssue`` for a change-list entry excluded
        from the write because it did not resolve (LLR-004.5).

    Args:
        entry (ChangeListEntry): The excluded entry — its ``status`` is
            ``UNRESOLVED`` or ``INDEX_OUT_OF_RANGE``.

    Returns:
        ValidationIssue: A warning-level issue (code ``W-INSTANCE-EXCLUDED``,
        artifact ``cdfx``) naming the excluded parameter and its status.

    Dependencies:
        Used by:
            - write_cdfx
    """
    return ValidationIssue(
        code="W-INSTANCE-EXCLUDED",
        severity=ValidationSeverity.WARNING,
        message=(
            f"change-list entry {entry.parameter_name}[{entry.array_index}] "
            f"excluded from the .cdfx write: {entry.status.value}"
        ),
        artifact=CDFX_ARTIFACT,
        symbol=entry.parameter_name,
    )


def _sparse_array_issue(
    parameter_name: str,
    indices: list[int],
) -> ValidationIssue:
    """
    Summary:
        Build the warning ``ValidationIssue`` for an array group rejected
        because its ``array_index`` values are sparse — not the contiguous
        gapless zero-based sequence ``0…N-1`` (LLR-004.9).

    Args:
        parameter_name (str): The ``parameter_name`` of the rejected group.
        indices (list[int]): The group's ``array_index`` values, sorted
            ascending — included in the message so the engineer sees which
            indices were present and can spot the gap / non-zero start.

    Returns:
        ValidationIssue: A warning-level issue (code ``W-ARRAY-SPARSE``,
        artifact ``cdfx``) naming the parameter. The whole group is excluded
        from the write — a positional ``VG`` cannot represent a sparse array
        without inventing a value for a missing slot, so the writer rejects it
        rather than gap-fills (calibration-safety, LLR-004.9 rationale).

    Dependencies:
        Used by:
            - _append_group
    """
    return ValidationIssue(
        code="W-ARRAY-SPARSE",
        severity=ValidationSeverity.WARNING,
        message=(
            f"array parameter {parameter_name} has a sparse array_index set "
            f"{indices} — not the contiguous zero-based range 0..{len(indices) - 1}"
            f"; the whole parameter is excluded from the .cdfx write (no value "
            f"is synthesized for a missing index)"
        ),
        artifact=CDFX_ARTIFACT,
        symbol=parameter_name,
    )


def _empty_changelist_issue() -> ValidationIssue:
    """
    Summary:
        Build the warning ``ValidationIssue`` emitted when a write produced
        zero ``SW-INSTANCE`` elements (LLR-004.6).

    Returns:
        ValidationIssue: A warning-level issue with code ``W-EMPTY-CHANGELIST``
        and artifact ``cdfx``. Fires on the zero-*writable* condition — a
        literally-empty change-list or one where every entry was excluded
        (LLR-004.6 / finding A-05).

    Dependencies:
        Used by:
            - write_cdfx
    """
    return ValidationIssue(
        code="W-EMPTY-CHANGELIST",
        severity=ValidationSeverity.WARNING,
        message=(
            "the .cdfx write produced no SW-INSTANCE: the change-list has no "
            "writable (resolved) entries"
        ),
        artifact=CDFX_ARTIFACT,
    )


# ---------------------------------------------------------------------------
# Standalone W-* validator (LLR-006.1).
# ---------------------------------------------------------------------------


def validate_w_rules(root: ET.Element) -> list[ValidationIssue]:
    """
    Summary:
        Check a built CDFX element tree against the §7 write-time ``W-*``
        structural rules and return one ``ValidationIssue`` per violation
        (LLR-006.1).

    Args:
        root (ET.Element): The root element of a CDFX tree — normally an
            ``MSRSW`` element produced by :func:`write_cdfx`, but the validator
            is **standalone**: it accepts any element so a crafted broken tree
            can provoke each rule for testing (Phase-2 Q-05).

    Returns:
        list[ValidationIssue]: One issue per ``W-*`` rule violation, each with
        the rule's documented code (``W-ROOT-MSRSW``, ``W-BACKBONE``,
        ``W-INSTANCE-NAME``, ``W-INSTANCE-CATEGORY``, ``W-VALUE-PRESENT``,
        ``W-CATEGORY-VALUE-CONSISTENT``) at ``ERROR`` severity and artifact
        ``cdfx``. An empty list means the tree passes every ``W-*`` rule. A
        correct :func:`write_cdfx` output always returns an empty list — the
        invariant codes (``W-ROOT-MSRSW`` / ``W-BACKBONE`` /
        ``W-CATEGORY-VALUE-CONSISTENT``) are only reachable on a deliberately
        broken tree.

    Raises:
        None: The validator collects every violation and never raises; a
            broken tree is reported, not thrown (collect-don't-abort).

    Data Flow:
        - Check the root tag is ``MSRSW`` (``W-ROOT-MSRSW``); if not, the
          backbone / instance checks are skipped (the tree shape is unknown).
        - Locate the ``SW-INSTANCE-TREE`` backbone (``W-BACKBONE``).
        - For each ``SW-INSTANCE`` under the backbone, check its ``SHORT-NAME``
          (``W-INSTANCE-NAME``), ``CATEGORY`` (``W-INSTANCE-CATEGORY``), value
          presence (``W-VALUE-PRESENT``), and category↔value-shape consistency
          (``W-CATEGORY-VALUE-CONSISTENT``).
        - ``W-XML-WELLFORMED`` is **not** checked here: well-formedness is a
          property of a *byte stream*, not of an already-parsed element tree —
          :func:`validate_w_rules_bytes` covers it.

    Dependencies:
        Uses:
            - _w_issue
            - _find_instance_tree
            - _check_instance
        Used by:
            - The CDFX writer self-check and the standalone ``W-*`` tests
              (TC-019b..g).

    Example:
        >>> from xml.etree import ElementTree as ET
        >>> bad = ET.Element("NOT-MSRSW")
        >>> [i.code for i in validate_w_rules(bad)]
        ['W-ROOT-MSRSW']
    """
    issues: list[ValidationIssue] = []

    if _local_name(root.tag) != "MSRSW":
        issues.append(
            _w_issue(
                "W-ROOT-MSRSW",
                f"root element is <{_local_name(root.tag)}>, expected <MSRSW>",
            )
        )
        # The tree shape is unknown — backbone / instance checks would be
        # noise. Stop after the root verdict.
        return issues

    instance_tree = _find_instance_tree(root)
    if instance_tree is None:
        issues.append(
            _w_issue(
                "W-BACKBONE",
                "the SW-SYSTEMS/SW-SYSTEM/SW-INSTANCE-SPEC/SW-INSTANCE-TREE "
                "backbone is incomplete or missing",
            )
        )
        return issues

    for instance in _direct_instances(instance_tree):
        _check_instance(instance, issues)

    return issues


def validate_w_rules_bytes(data: bytes) -> list[ValidationIssue]:
    """
    Summary:
        Check a serialized CDFX byte stream against every write-time ``W-*``
        rule, including ``W-XML-WELLFORMED`` (LLR-006.1).

    Args:
        data (bytes): A serialized ``.cdfx`` document — for example the first
            element of the :func:`write_cdfx` return tuple, or a crafted
            non-well-formed byte string fed by TC-019a.

    Returns:
        list[ValidationIssue]: ``[W-XML-WELLFORMED]`` (single ``ERROR`` issue)
        when ``data`` is not well-formed XML; otherwise the result of
        :func:`validate_w_rules` on the parsed root. A correct
        :func:`write_cdfx` byte stream returns an empty list.

    Raises:
        None: A parse failure is reported as ``W-XML-WELLFORMED``, never
            re-raised (collect-don't-abort).

    Data Flow:
        - Parse ``data`` with ``ElementTree``; a ``ParseError`` becomes one
          ``W-XML-WELLFORMED`` issue and short-circuits the structural checks.
        - Otherwise delegate to :func:`validate_w_rules`.

    Dependencies:
        Uses:
            - validate_w_rules
            - _w_issue
        Used by:
            - The standalone ``W-XML-WELLFORMED`` test (TC-019a).

    Example:
        >>> [i.code for i in validate_w_rules_bytes(b"<MSRSW><unclosed>")]
        ['W-XML-WELLFORMED']
    """
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        return [
            _w_issue(
                "W-XML-WELLFORMED",
                f"CDFX output is not well-formed XML: {exc}",
            )
        ]
    return validate_w_rules(root)


def _check_instance(
    instance: ET.Element,
    issues: list[ValidationIssue],
) -> None:
    """
    Summary:
        Apply the per-``SW-INSTANCE`` ``W-*`` rules to one instance element,
        appending one issue per violation.

    Args:
        instance (ET.Element): A ``SW-INSTANCE`` element.
        issues (list[ValidationIssue]): The accumulating issue list, appended
            to in place.

    Returns:
        None: ``issues`` is mutated in place.

    Data Flow:
        - ``W-INSTANCE-NAME`` — a non-empty ``SHORT-NAME`` is present.
        - ``W-INSTANCE-CATEGORY`` — ``CATEGORY`` is in the editable set.
        - ``W-VALUE-PRESENT`` — ``SW-VALUE-CONT/SW-VALUES-PHYS`` carries at
          least one ``V`` / ``VT`` (directly or inside a ``VG``).
        - ``W-CATEGORY-VALUE-CONSISTENT`` — the value shape matches the
          category (``VALUE``/``BOOLEAN`` → exactly one ``V``; ``VAL_BLK`` →
          a ``VG`` or ≥1 ``V``; ``ASCII`` → exactly one ``VT``).

    Dependencies:
        Uses:
            - _w_issue
            - _instance_label
            - _value_shape
        Used by:
            - validate_w_rules
    """
    label = _instance_label(instance)

    short_name = _child_text(instance, "SHORT-NAME")
    if not (short_name and short_name.strip()):
        issues.append(
            _w_issue("W-INSTANCE-NAME", f"{label} has an empty SHORT-NAME")
        )

    category = (_child_text(instance, "CATEGORY") or "").strip()
    if category not in EDITABLE_CATEGORIES:
        issues.append(
            _w_issue(
                "W-INSTANCE-CATEGORY",
                f"{label} CATEGORY '{category}' is not in the editable set "
                f"(VALUE / BOOLEAN / VAL_BLK / ASCII)",
            )
        )

    v_count, vt_count, vg_count = _value_shape(instance)
    if v_count == 0 and vt_count == 0:
        issues.append(
            _w_issue(
                "W-VALUE-PRESENT",
                f"{label} has no V or VT value in SW-VALUE-CONT/"
                f"SW-VALUES-PHYS",
            )
        )

    if not _category_value_consistent(category, v_count, vt_count, vg_count):
        issues.append(
            _w_issue(
                "W-CATEGORY-VALUE-CONSISTENT",
                f"{label} CATEGORY '{category}' is inconsistent with its "
                f"value shape (V={v_count}, VT={vt_count}, VG={vg_count})",
            )
        )


def _category_value_consistent(
    category: str,
    v_count: int,
    vt_count: int,
    vg_count: int,
) -> bool:
    """
    Summary:
        Decide whether a ``SW-INSTANCE``'s value shape matches its
        ``CATEGORY`` (the ``W-CATEGORY-VALUE-CONSISTENT`` rule).

    Args:
        category (str): The instance ``CATEGORY`` token.
        v_count (int): Number of ``V`` elements in ``SW-VALUES-PHYS`` (counting
            those inside a ``VG``).
        vt_count (int): Number of ``VT`` elements in ``SW-VALUES-PHYS``.
        vg_count (int): Number of ``VG`` elements directly under
            ``SW-VALUES-PHYS``.

    Returns:
        bool: ``True`` when the shape is consistent —
            - ``VALUE`` / ``BOOLEAN`` → exactly one ``V``, directly under
              ``SW-VALUES-PHYS`` (no ``VG``), and no ``VT``;
            - ``VAL_BLK`` → a ``VG`` present, or at least one ``V``;
            - ``ASCII`` → exactly one ``VT`` and no ``V``;
            - any other category → not consistency-checked here
              (``W-INSTANCE-CATEGORY`` already flags it).

    Data Flow:
        - Branch on the category token and test the value counts.

    Dependencies:
        Used by:
            - _check_instance
    """
    if category in ("VALUE", "BOOLEAN"):
        # A scalar value is one bare V — a VG would make it an array shape.
        return v_count == 1 and vt_count == 0 and vg_count == 0
    if category == "VAL_BLK":
        return vg_count >= 1 or v_count >= 1
    if category == "ASCII":
        return vt_count == 1 and v_count == 0
    # An unsupported category is already flagged by W-INSTANCE-CATEGORY; do not
    # double-report its value shape.
    return True


def _value_shape(instance: ET.Element) -> tuple[int, int, int]:
    """
    Summary:
        Count the ``V`` / ``VT`` / ``VG`` value elements of a ``SW-INSTANCE``.

    Args:
        instance (ET.Element): A ``SW-INSTANCE`` element.

    Returns:
        tuple[int, int, int]: ``(v_count, vt_count, vg_count)`` —
            - ``v_count`` — all ``V`` elements under ``SW-VALUES-PHYS``,
              including those nested in a ``VG``;
            - ``vt_count`` — all ``VT`` elements under ``SW-VALUES-PHYS``;
            - ``vg_count`` — ``VG`` elements directly under ``SW-VALUES-PHYS``.
        ``(0, 0, 0)`` when the instance has no ``SW-VALUE-CONT/SW-VALUES-PHYS``.

    Data Flow:
        - Descend ``SW-VALUE-CONT → SW-VALUES-PHYS`` by local name.
        - Walk the subtree counting ``V`` / ``VT`` / ``VG``.

    Dependencies:
        Uses:
            - _first_child
        Used by:
            - _check_instance
    """
    value_cont = _first_child(instance, "SW-VALUE-CONT")
    if value_cont is None:
        return (0, 0, 0)
    values_phys = _first_child(value_cont, "SW-VALUES-PHYS")
    if values_phys is None:
        return (0, 0, 0)

    v_count = 0
    vt_count = 0
    vg_count = 0
    for elem in values_phys.iter():
        name = _local_name(elem.tag)
        if name == "V":
            v_count += 1
        elif name == "VT":
            vt_count += 1
        elif name == "VG":
            vg_count += 1
    return (v_count, vt_count, vg_count)


def _find_instance_tree(root: ET.Element) -> ET.Element | None:
    """
    Summary:
        Locate the ``SW-INSTANCE-TREE`` backbone element under an ``MSRSW``
        root (the ``W-BACKBONE`` rule's positive case).

    Args:
        root (ET.Element): An ``MSRSW`` root element.

    Returns:
        ET.Element | None: The ``SW-INSTANCE-TREE`` element when the full
        ``SW-SYSTEMS → SW-SYSTEM → SW-INSTANCE-SPEC → SW-INSTANCE-TREE`` chain
        is present, otherwise ``None`` (an incomplete backbone).

    Data Flow:
        - Walk the backbone chain by local name, one level at a time; a missing
          link returns ``None``.

    Dependencies:
        Uses:
            - _first_child
        Used by:
            - validate_w_rules
    """
    sw_systems = _first_child(root, "SW-SYSTEMS")
    if sw_systems is None:
        return None
    sw_system = _first_child(sw_systems, "SW-SYSTEM")
    if sw_system is None:
        return None
    instance_spec = _first_child(sw_system, "SW-INSTANCE-SPEC")
    if instance_spec is None:
        return None
    return _first_child(instance_spec, "SW-INSTANCE-TREE")


def _direct_instances(instance_tree: ET.Element) -> list[ET.Element]:
    """
    Summary:
        Return the ``SW-INSTANCE`` elements that are direct children of the
        ``SW-INSTANCE-TREE`` backbone.

    Args:
        instance_tree (ET.Element): The ``SW-INSTANCE-TREE`` element.

    Returns:
        list[ET.Element]: Every direct-child element whose local name is
        ``SW-INSTANCE``, in document order.

    Dependencies:
        Uses:
            - _local_name
        Used by:
            - validate_w_rules
    """
    return [
        child
        for child in instance_tree
        if _local_name(child.tag) == "SW-INSTANCE"
    ]


def _first_child(parent: ET.Element, tag: str) -> ET.Element | None:
    """
    Summary:
        Return the first direct-child element of ``parent`` whose local name
        matches ``tag`` (namespace-tolerant).

    Args:
        parent (ET.Element): The element to search the direct children of.
        tag (str): The local element name to match.

    Returns:
        ET.Element | None: The first matching child, or ``None``.

    Dependencies:
        Uses:
            - _local_name
        Used by:
            - _find_instance_tree
            - _value_shape
    """
    for child in parent:
        if _local_name(child.tag) == tag:
            return child
    return None


def _child_text(parent: ET.Element, tag: str) -> str | None:
    """
    Summary:
        Return the text of the first direct child of ``parent`` named ``tag``.

    Args:
        parent (ET.Element): The element to search.
        tag (str): The local element name to match.

    Returns:
        str | None: The matching child's ``text`` (possibly ``None`` if the
        element is empty), or ``None`` when no such child exists.

    Dependencies:
        Uses:
            - _first_child
        Used by:
            - _check_instance
            - _instance_label
    """
    child = _first_child(parent, tag)
    return None if child is None else child.text


def _instance_label(instance: ET.Element) -> str:
    """
    Summary:
        Build a human-readable label for a ``SW-INSTANCE`` for issue messages.

    Args:
        instance (ET.Element): A ``SW-INSTANCE`` element.

    Returns:
        str: ``SW-INSTANCE '<name>'`` when the instance has a non-empty
        ``SHORT-NAME``, otherwise ``SW-INSTANCE (no SHORT-NAME)``.

    Dependencies:
        Uses:
            - _child_text
        Used by:
            - _check_instance
    """
    name = (_child_text(instance, "SHORT-NAME") or "").strip()
    if name:
        return f"SW-INSTANCE '{name}'"
    return "SW-INSTANCE (no SHORT-NAME)"


def _local_name(tag: str) -> str:
    """
    Summary:
        Strip an XML-namespace prefix from an ``ElementTree`` tag so a
        namespaced ``{uri}LocalName`` matches its bare local name.

    Args:
        tag (str): An ``ElementTree`` element ``tag`` — either a plain local
            name or the ``{namespace-uri}LocalName`` form ``ElementTree``
            produces when a default ``xmlns`` is declared.

    Returns:
        str: The local name with any ``{...}`` namespace prefix removed.

    Data Flow:
        - When the tag starts with ``{``, return the part after ``}``.

    Dependencies:
        Used by:
            - validate_w_rules
            - _value_shape
            - _direct_instances
            - _first_child
    """
    if tag.startswith("{"):
        return tag.rsplit("}", 1)[-1]
    return tag


def _w_issue(code: str, message: str) -> ValidationIssue:
    """
    Summary:
        Build an ``ERROR``-severity write-time ``ValidationIssue`` with the
        ``cdfx`` artifact tag.

    Args:
        code (str): The ``W-*`` rule code.
        message (str): The human-readable explanation.

    Returns:
        ValidationIssue: The issue, severity ``ERROR``, artifact ``cdfx``. All
        structural ``W-*`` rules are errors (research §7).

    Dependencies:
        Used by:
            - validate_w_rules
            - validate_w_rules_bytes
            - _check_instance
    """
    return ValidationIssue(
        code=code,
        severity=ValidationSeverity.ERROR,
        message=message,
        artifact=CDFX_ARTIFACT,
    )
