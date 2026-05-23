"""
CDFX (ASAM CDF 2.0) reader + read-time ``R-*`` validator — s19_app batch-03,
increment 7.

This module parses a well-formed ``.cdfx`` document back into a
:class:`~s19_app.tui.cdfx.changelist.ChangeList` and collects every read-time
finding as a :class:`~s19_app.validation.model.ValidationIssue`, mirroring the
project's collect-don't-abort culture: a malformed instance is skipped and
flagged, never thrown.

:func:`read_cdfx` builds, with the standard-library ``xml.etree.ElementTree``
only (constraint C-2 — no new dependency):

- a namespace-tolerant parse — ``ElementTree`` namespace-qualifies every tag
  as ``{uri}LocalName`` when a default ``xmlns`` is declared, so the reader
  matches on the **local name** with any ``{...}`` prefix stripped
  (``_local_name``, LLR-005.3 / RK-3);
- a ``SW-INSTANCE`` lookup **scoped to the ``SW-INSTANCE-TREE`` backbone** —
  an instance placed elsewhere in the document (for example inside
  ``ADMIN-DATA``) is **not** absorbed into the change-list (LLR-005.3 / S-006);
- the **inverse of the LLR-004.9 writer coalescing** (LLR-005.6): a ``VAL_BLK``
  instance whose ``SW-VALUE-CONT/SW-VALUES-PHYS`` carries a ``VG`` of *N* ``V``
  elements is **expanded** into *N* change-list entries ``(name, 0…N-1)``; a
  ``VALUE`` / ``BOOLEAN`` instance carrying a ``V`` is one scalar entry with
  ``array_index = None``; an ``ASCII`` instance carrying a ``VT`` is one string
  entry with ``array_index = None``;
- the read-time ``R-*`` structural rules of ``design-input/cdfx-research.md``
  §7 — ``R-XML-PARSE``, ``R-ROOT-MSRSW``, ``R-VERSION-UNKNOWN``,
  ``R-BACKBONE-MISSING``, ``R-INSTANCE-NO-NAME``, ``R-INSTANCE-NO-VALUE``,
  ``R-CATEGORY-UNSUPPORTED``, ``R-CATEGORY-VALUE-MISMATCH``,
  ``R-VALUE-NOT-NUMERIC`` — one ``ValidationIssue`` per violation
  (LLR-006.2/.4/.5);
- the A2L cross-check (LLR-008.1..008.3) when enriched A2L tags are supplied —
  ``R-NAME-NOT-IN-A2L`` for an instance whose name matches no A2L parameter,
  ``R-ARRAY-LEN-MISMATCH`` for an array whose ``V`` count differs from the A2L
  ``element_count``; both suppressed when no A2L is supplied.

A leading or embedded writer- / tool-identification XML comment (for example
``Created with CANape … CDF 2.0 Writer``) is non-significant content:
``ElementTree`` discards comments on parse, so the reader tolerates and ignores
them with no issue (LLR-006.7).

**XML safety (increment 8).** The reader defends three resource-exhaustion /
information-disclosure vectors before and during the parse, all surfaced as one
``R-XML-PARSE`` ``ValidationIssue`` (collect-don't-abort — no crash, no hang, no
external file read):

- a **pre-read / pre-parse 256 MB byte cap** (``DEFAULT_COPY_SIZE_CAP_BYTES``,
  reused from ``workspace.py`` — one consistent ingest cap, LLR-006.8). For a
  *path* source the cap is checked against the file's on-disk
  ``stat().st_size`` *before* ``Path.read_bytes`` — so an over-cap file is
  never read into memory at all, mirroring ``workspace.copy_into_workarea``'s
  ``stat()``-before-copy guard. The same cap is then re-checked against the
  in-memory byte length *before* ``ElementTree`` builds any tree, so an
  oversized document (including a ``bytes`` source) is never loaded into the
  DOM;
- a **DOCTYPE / ``<!ENTITY>`` rejection** (LLR-006.6 / CV-04). The reader parses
  with an ``expat`` parser whose ``StartDoctypeDeclHandler`` raises on the
  ``<!DOCTYPE`` declaration itself — *before* any ``<!ENTITY>`` declaration is
  read and long before any entity is expanded. This is the stdlib-only defense
  against the billion-laughs (internal-entity amplification) and external-entity
  (``SYSTEM`` / ``PUBLIC`` file-read) vectors; no ``defusedxml`` dependency is
  introduced (constraint C-2). A conformant CDF 2.0 ``.cdfx`` carries no
  ``DOCTYPE``, so a valid file is unaffected;
- a **nesting-depth bound** (LLR-006.8). The expat ``StartElementHandler``
  tracks element depth and raises once it exceeds ``MAX_NESTING_DEPTH``, so a
  pathologically deep document is rejected without unbounded recursion.

The load path resolves a user-supplied ``.cdfx`` path through
``workspace.resolve_input_path`` (LLR-005.5) — the same shared helper every
other user-typed input path in the app uses; an unresolvable path is rejected
as one ``R-XML-PARSE`` issue with no file opened.

Implements LLR-005.1..LLR-005.6, LLR-006.2/.3/.4/.5/.6/.7/.8 and
LLR-008.1..LLR-008.3.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET
from xml.parsers import expat

from ...validation.model import ValidationIssue, ValidationSeverity
from ..workspace import DEFAULT_COPY_SIZE_CAP_BYTES, resolve_input_path
from .changelist import ChangeList, ResolutionStatus

# ---------------------------------------------------------------------------
# Constants — the CDF 2.0 contract this reader accepts.
# ---------------------------------------------------------------------------

# The artifact tag every CDFX ValidationIssue carries (LLR-006.3 / DD-5).
CDFX_ARTIFACT = "cdfx"

# The MSRSW/CATEGORY version token of the targeted CDF version (constraint
# C-6). A different token is tolerated with an R-VERSION-UNKNOWN info issue.
CDF20_CATEGORY = "CDF20"

# The instance categories this batch can read into editable change-list
# entries (research §7). Any other category is read-only (R-CATEGORY-
# UNSUPPORTED) — see LLR-006.5.
SCALAR_CATEGORIES: frozenset[str] = frozenset({"VALUE", "BOOLEAN"})
ARRAY_CATEGORY = "VAL_BLK"
STRING_CATEGORY = "ASCII"
EDITABLE_CATEGORIES: frozenset[str] = (
    SCALAR_CATEGORIES | {ARRAY_CATEGORY, STRING_CATEGORY}
)

# The pre-parse byte cap (LLR-006.8). Reused verbatim from ``workspace.py`` so
# the ``.cdfx`` ingest cap is the same 256 MB the app applies to every other
# file it ingests — one consistent number, not a new one (DD-11).
MAX_CDFX_SIZE_BYTES = DEFAULT_COPY_SIZE_CAP_BYTES

# The XML element nesting-depth bound (LLR-006.8). A conformant CDF 2.0 ``.cdfx``
# nests at most ~9 levels (research §3); 100 is a generous ceiling that still
# rejects a pathologically deep document long before unbounded recursion or
# memory growth becomes a concern.
MAX_NESTING_DEPTH = 100


# ---------------------------------------------------------------------------
# XML-safety exceptions — internal signals, never surface to a caller.
# ---------------------------------------------------------------------------


class _UnsafeXmlError(Exception):
    """
    Raised inside the ``expat`` parse when the ``.cdfx`` input trips an
    XML-safety bound — a ``DOCTYPE`` / ``<!ENTITY>`` declaration (LLR-006.6) or
    an element nesting depth past :data:`MAX_NESTING_DEPTH` (LLR-006.8).

    This is an internal control-flow signal: :func:`_safe_parse` catches it and
    converts it into one ``R-XML-PARSE`` ``ValidationIssue``. It never escapes
    :func:`read_cdfx` (HLR-005 collect-don't-abort).
    """


def _probe_size(data: bytes) -> int:
    """
    Summary:
        Report the byte size of the ``.cdfx`` input for the pre-parse 256 MB
        cap check (LLR-006.8).

    Args:
        data (bytes): The raw ``.cdfx`` document bytes.

    Returns:
        int: ``len(data)`` — the input's byte size.

    Data Flow:
        - Return ``len(data)``.

    Dependencies:
        Used by:
            - read_cdfx

    Notes:
        This is the **injectable size-probe seam**: a test can monkeypatch
        ``reader._probe_size`` to report an over-cap size for a small in-memory
        document, exercising the pre-parse size-reject path without writing a
        real 256 MB file (TC-035).
    """
    return len(data)


# ---------------------------------------------------------------------------
# Reader.
# ---------------------------------------------------------------------------


def read_cdfx(
    source: bytes | str | Path,
    a2l_tags: list[dict] | None = None,
    base_dir: Path | None = None,
) -> tuple[ChangeList, list[ValidationIssue]]:
    """
    Summary:
        Parse a ``.cdfx`` document into a change-list and collect every
        read-time ``ValidationIssue``, enforcing the XML-safety bounds first.

    Args:
        source (bytes | str | Path): The ``.cdfx`` document. ``bytes`` are
            parsed directly (the in-memory test path); a ``str`` / ``Path`` is a
            user-supplied path resolved through ``workspace.resolve_input_path``
            against ``base_dir`` (LLR-005.5) and then read as bytes — an
            unresolvable path is rejected as one ``R-XML-PARSE`` issue with no
            file opened.
        a2l_tags (list[dict] | None): The enriched A2L tags — the output of
            ``a2l.enrich_a2l_tags_with_values`` — used for the LLR-008
            cross-check. Each tag dict is read for ``name`` and
            ``element_count``. ``None`` (or an empty list) means no A2L is
            loaded and the cross-check is skipped entirely (LLR-008.3).
        base_dir (Path | None): The directory ``resolve_input_path`` resolves a
            relative ``source`` path against — normally the app's working
            directory. Ignored when ``source`` is ``bytes`` (no path to
            resolve). ``None`` falls back to the current working directory.

    Returns:
        tuple[ChangeList, list[ValidationIssue]]: The recovered change-list and
        the list of read-time issues. Every entry's ``status`` is
        ``RESOLVED`` for a supported editable category and ``UNRESOLVED`` for
        an unsupported (read-only) category. The issue list carries one
        ``ValidationIssue`` per ``R-*`` rule violation; an empty change-list is
        returned when the path does not resolve, the input exceeds the 256 MB
        cap, the input carries a ``DOCTYPE`` / ``<!ENTITY>`` declaration, the
        nesting-depth bound is exceeded, the document does not parse, is not
        rooted at ``MSRSW``, or has no locatable instance-tree backbone.

    Raises:
        None: The reader never raises — an unresolvable path, an oversized
            input, a malicious ``DOCTYPE`` / entity payload, a too-deep tree,
            malformed XML, a missing root / backbone, or a bad instance are
            each a ``ValidationIssue`` record, not an exception (HLR-005
            collect-don't-abort).

    Data Flow:
        - Resolve ``source`` to bytes: ``bytes`` pass through; a path is
          resolved through ``resolve_input_path`` (LLR-005.5) and read — an
          unresolvable path becomes one ``R-XML-PARSE`` issue, no file opened.
        - Reject an input larger than ``MAX_CDFX_SIZE_BYTES`` *before* parsing
          (LLR-006.8) as one ``R-XML-PARSE`` issue.
        - Parse with the XML-safety parser: a ``DOCTYPE`` / ``<!ENTITY>``
          declaration (LLR-006.6) or a tree past ``MAX_NESTING_DEPTH``
          (LLR-006.8) is rejected before any entity expansion; a ``ParseError``
          becomes one ``R-XML-PARSE`` issue and an empty change-list.
        - Verify the root local name is ``MSRSW`` (``R-ROOT-MSRSW``) and note
          a non-``CDF20`` version token (``R-VERSION-UNKNOWN``).
        - Locate the ``SW-INSTANCE-TREE`` backbone (``R-BACKBONE-MISSING`` when
          absent); collect its direct-child ``SW-INSTANCE`` elements.
        - For each instance, apply the per-instance ``R-*`` rules, expand it
          into change-list entries per its category (LLR-005.6), and — when
          A2L tags were supplied — run the LLR-008 cross-check. A violating
          instance is skipped; the others continue (Q-04).

    Dependencies:
        Uses:
            - _resolve_source
            - _safe_parse
            - _parse_issue
            - _find_instance_tree
            - _direct_instances
            - _read_instance
            - _cross_check_instance
        Used by:
            - The CDFX service / Patch Editor load action (increment 9).

    Example:
        >>> from s19_app.tui.cdfx.reader import read_cdfx
        >>> change_list, issues = read_cdfx(b"<MSRSW>...</MSRSW>")  # doctest: +SKIP
    """
    change_list = ChangeList()
    issues: list[ValidationIssue] = []

    data = _resolve_source(source, base_dir, issues)
    if data is None:
        return change_list, issues

    size = _probe_size(data)
    if size > MAX_CDFX_SIZE_BYTES:
        issues.append(
            _parse_issue(
                f"the .cdfx input is {size} bytes, over the "
                f"{MAX_CDFX_SIZE_BYTES}-byte ({MAX_CDFX_SIZE_BYTES // (1024 * 1024)} "
                f"MB) read cap — rejected before parsing"
            )
        )
        return change_list, issues

    root = _safe_parse(data, issues)
    if root is None:
        return change_list, issues

    if _local_name(root.tag) != "MSRSW":
        issues.append(
            _r_issue(
                "R-ROOT-MSRSW",
                ValidationSeverity.ERROR,
                f"root element is <{_local_name(root.tag)}>, expected <MSRSW>",
            )
        )
        return change_list, issues

    version = (_child_text(root, "CATEGORY") or "").strip()
    if version != CDF20_CATEGORY:
        issues.append(
            _r_issue(
                "R-VERSION-UNKNOWN",
                ValidationSeverity.INFO,
                f"MSRSW/CATEGORY is '{version}', not '{CDF20_CATEGORY}' — the "
                f"file is read but its CDF version is not the targeted CDF 2.0",
            )
        )

    instance_tree = _find_instance_tree(root)
    if instance_tree is None:
        issues.append(
            _r_issue(
                "R-BACKBONE-MISSING",
                ValidationSeverity.ERROR,
                "the SW-SYSTEMS/SW-SYSTEM/SW-INSTANCE-SPEC/SW-INSTANCE-TREE "
                "backbone could not be located — no SW-INSTANCE can be read",
            )
        )
        return change_list, issues

    tags_by_name = _index_a2l_tags(a2l_tags)

    for instance in _direct_instances(instance_tree):
        _read_instance(instance, change_list, issues)
        _cross_check_instance(instance, tags_by_name, issues)

    return change_list, issues


def _read_instance(
    instance: ET.Element,
    change_list: ChangeList,
    issues: list[ValidationIssue],
) -> None:
    """
    Summary:
        Read one ``SW-INSTANCE`` element, apply the per-instance ``R-*`` rules
        and expand it into change-list entries (LLR-005.6, LLR-006.2/.5).

    Args:
        instance (ET.Element): A ``SW-INSTANCE`` element under the
            instance-tree backbone.
        change_list (ChangeList): The change-list being built; entries are
            appended in place.
        issues (list[ValidationIssue]): The accumulating issue list, appended
            to in place.

    Returns:
        None: ``change_list`` and ``issues`` are mutated in place.

    Data Flow:
        - A missing / empty ``SHORT-NAME`` is ``R-INSTANCE-NO-NAME`` — the
          instance is skipped (no entry can be keyed without a name).
        - An unsupported ``CATEGORY`` (``MAP`` / ``STRUCTURE`` / ``*_ARRAY``
          …) is ``R-CATEGORY-UNSUPPORTED``: one read-only ``UNRESOLVED`` entry
          carrying the raw text of the first ``V`` / ``VT`` is added so the
          instance is visible but not editable (LLR-006.5).
        - A ``V``/``VT``-free instance is ``R-INSTANCE-NO-VALUE`` — skipped.
        - A supported category is expanded per LLR-005.6: ``ASCII`` → one
          string entry; ``VALUE``/``BOOLEAN`` → one scalar entry; ``VAL_BLK``
          → *N* entries ``(name, 0…N-1)``. A category↔value-shape mismatch is
          ``R-CATEGORY-VALUE-MISMATCH`` but the value(s) are still read.

    Dependencies:
        Uses:
            - _values_phys_of
            - _collect_values
            - _decode_numeric
            - _add_scalar_entry
            - _add_string_entry
            - _add_array_entries
        Used by:
            - read_cdfx
    """
    name = (_child_text(instance, "SHORT-NAME") or "").strip()
    if not name:
        issues.append(
            _r_issue(
                "R-INSTANCE-NO-NAME",
                ValidationSeverity.ERROR,
                "a SW-INSTANCE has no SHORT-NAME — the instance is skipped",
            )
        )
        return

    category = (_child_text(instance, "CATEGORY") or "").strip()

    values_phys = _values_phys_of(instance)
    v_texts, vt_texts = _collect_values(values_phys)

    if not v_texts and not vt_texts:
        issues.append(
            _r_issue(
                "R-INSTANCE-NO-VALUE",
                ValidationSeverity.ERROR,
                f"SW-INSTANCE '{name}' has no readable V or VT value in "
                f"SW-VALUE-CONT/SW-VALUES-PHYS — the instance is skipped",
            )
        )
        return

    if category not in EDITABLE_CATEGORIES:
        # An unsupported / multi-dimensional category — read-only, not fatal
        # (LLR-006.5). The first available raw value text is kept so the
        # instance is still visible in the change-list.
        issues.append(
            _r_issue(
                "R-CATEGORY-UNSUPPORTED",
                ValidationSeverity.WARNING,
                f"SW-INSTANCE '{name}' has CATEGORY '{category}', outside the "
                f"editable set (VALUE / BOOLEAN / VAL_BLK / ASCII) — loaded "
                f"read-only",
            )
        )
        raw = vt_texts[0] if vt_texts else v_texts[0]
        change_list.add(name, None, raw, ResolutionStatus.UNRESOLVED)
        return

    if category == STRING_CATEGORY:
        _check_value_shape(name, category, v_texts, vt_texts, issues)
        _add_string_entry(change_list, name, vt_texts)
        return

    if category in SCALAR_CATEGORIES:
        _check_value_shape(name, category, v_texts, vt_texts, issues)
        _add_scalar_entry(change_list, name, v_texts, issues)
        return

    # category == VAL_BLK — expand the VG into N positional entries (LLR-005.6).
    _check_value_shape(name, category, v_texts, vt_texts, issues)
    _add_array_entries(change_list, name, v_texts, issues)


def _check_value_shape(
    name: str,
    category: str,
    v_texts: list[str],
    vt_texts: list[str],
    issues: list[ValidationIssue],
) -> None:
    """
    Summary:
        Flag a ``SW-INSTANCE`` whose value shape does not match its
        ``CATEGORY`` with ``R-CATEGORY-VALUE-MISMATCH`` (LLR-006.2).

    Args:
        name (str): The instance ``SHORT-NAME`` (for the issue message).
        category (str): The instance ``CATEGORY`` token — one of the editable
            categories.
        v_texts (list[str]): The text content of every ``V`` element read.
        vt_texts (list[str]): The text content of every ``VT`` element read.
        issues (list[ValidationIssue]): The accumulating issue list, appended
            to in place.

    Returns:
        None: ``issues`` is mutated in place when the shape is inconsistent.

    Data Flow:
        - ``VALUE`` / ``BOOLEAN`` expects exactly one ``V`` and no ``VT``.
        - ``ASCII`` expects exactly one ``VT`` and no ``V``.
        - ``VAL_BLK`` expects at least one ``V`` and no ``VT``.
        The value(s) are still read by the caller — the mismatch is flagged,
        not fatal (research §7 ``R-CATEGORY-VALUE-MISMATCH`` is a warning).

    Dependencies:
        Uses:
            - _r_issue
        Used by:
            - _read_instance
    """
    consistent = True
    if category in SCALAR_CATEGORIES:
        consistent = len(v_texts) == 1 and not vt_texts
    elif category == STRING_CATEGORY:
        consistent = len(vt_texts) == 1 and not v_texts
    elif category == ARRAY_CATEGORY:
        consistent = len(v_texts) >= 1 and not vt_texts

    if not consistent:
        issues.append(
            _r_issue(
                "R-CATEGORY-VALUE-MISMATCH",
                ValidationSeverity.WARNING,
                f"SW-INSTANCE '{name}' CATEGORY '{category}' does not match "
                f"its value shape (V={len(v_texts)}, VT={len(vt_texts)}) — "
                f"the value(s) are still read",
            )
        )


def _add_scalar_entry(
    change_list: ChangeList,
    name: str,
    v_texts: list[str],
    issues: list[ValidationIssue],
) -> None:
    """
    Summary:
        Expand a ``VALUE`` / ``BOOLEAN`` instance into one scalar change-list
        entry with ``array_index = None`` (LLR-005.6).

    Args:
        change_list (ChangeList): The change-list being built.
        name (str): The parameter name (the instance ``SHORT-NAME``).
        v_texts (list[str]): The text of the instance's ``V`` element(s); the
            first is the scalar value.
        issues (list[ValidationIssue]): The accumulating issue list — a
            non-numeric ``V`` adds one ``R-VALUE-NOT-NUMERIC`` warning.

    Returns:
        None: ``change_list`` and ``issues`` are mutated in place.

    Data Flow:
        - Decode the first ``V`` text; the entry is added with
          ``array_index = None`` and status ``RESOLVED`` — the inverse of the
          writer's scalar ``SW-INSTANCE`` (LLR-004.3).

    Dependencies:
        Uses:
            - _decode_numeric
        Used by:
            - _read_instance
    """
    value = _decode_numeric(v_texts[0], name, None, issues)
    change_list.add(name, None, value, ResolutionStatus.RESOLVED)


def _add_string_entry(
    change_list: ChangeList,
    name: str,
    vt_texts: list[str],
) -> None:
    """
    Summary:
        Expand an ``ASCII`` instance into one string change-list entry with
        ``array_index = None`` (LLR-005.6).

    Args:
        change_list (ChangeList): The change-list being built.
        name (str): The parameter name (the instance ``SHORT-NAME``).
        vt_texts (list[str]): The text of the instance's ``VT`` element(s); the
            first is the string value.

    Returns:
        None: ``change_list`` is mutated in place.

    Data Flow:
        - The first ``VT`` text is stored verbatim as the entry value with
          ``array_index = None`` and status ``RESOLVED`` — the inverse of the
          writer's ``ASCII`` ``SW-INSTANCE`` (LLR-004.3). A ``VT`` is never
          numeric-decoded.

    Dependencies:
        Used by:
            - _read_instance
    """
    change_list.add(name, None, vt_texts[0], ResolutionStatus.RESOLVED)


def _add_array_entries(
    change_list: ChangeList,
    name: str,
    v_texts: list[str],
    issues: list[ValidationIssue],
) -> None:
    """
    Summary:
        Expand a ``VAL_BLK`` instance into *N* array-element change-list
        entries ``(name, 0…N-1)`` — the inverse of the LLR-004.9 writer
        coalescing (LLR-005.6).

    Args:
        change_list (ChangeList): The change-list being built.
        name (str): The parameter name (the instance ``SHORT-NAME``).
        v_texts (list[str]): The text of every ``V`` element read, in document
            order — the *i*-th ``V`` is array element *i*.
        issues (list[ValidationIssue]): The accumulating issue list — a
            non-numeric ``V`` adds one ``R-VALUE-NOT-NUMERIC`` warning.

    Returns:
        None: ``change_list`` and ``issues`` are mutated in place.

    Data Flow:
        - Walk ``v_texts`` positionally; the *i*-th value (zero-based) is added
          as ``(name, array_index = i)`` with status ``RESOLVED``, so the
          entries span the contiguous index range ``0 … N-1``. The writer only
          ever emits a gapless zero-based ``VG`` (LLR-004.9 rejects sparse
          arrays before write), so positional expansion is exact.

    Dependencies:
        Uses:
            - _decode_numeric
        Used by:
            - _read_instance
    """
    for index, text in enumerate(v_texts):
        value = _decode_numeric(text, name, index, issues)
        change_list.add(name, index, value, ResolutionStatus.RESOLVED)


# ---------------------------------------------------------------------------
# Value decoding.
# ---------------------------------------------------------------------------


def _decode_numeric(
    text: str | None,
    name: str,
    array_index: int | None,
    issues: list[ValidationIssue],
) -> int | float | str:
    """
    Summary:
        Decode the text content of a ``V`` element into a numeric value,
        flagging a non-numeric ``V`` with ``R-VALUE-NOT-NUMERIC`` (LLR-005.4 /
        LLR-006.2).

    Args:
        text (str | None): The ``V`` element's text content, or ``None`` for an
            empty ``<V/>``.
        name (str): The owning instance's ``SHORT-NAME`` (for the issue
            message).
        array_index (int | None): The element's array index (``None`` for a
            scalar) — included in the issue message so the engineer can locate
            the bad value.
        issues (list[ValidationIssue]): The accumulating issue list, appended
            to in place when the text does not parse as a number.

    Returns:
        int | float | str: The decoded value — an ``int`` for a decimal /
        hexadecimal / binary integer literal, a ``float`` for a fractional or
        exponential literal. When the text parses as neither, the raw text is
        returned unchanged (kept as a string, research §7
        ``R-VALUE-NOT-NUMERIC`` "value kept as raw text") and one warning issue
        is appended.

    Data Flow:
        - Try a base-prefixed integer (``0x`` hex, ``0b`` binary — ``0b`` is a
          tolerant superset, OQ-7), then a plain decimal integer, then a
          ``float`` (decimal / exponential).
        - On every parse failing, return the raw text and append one
          ``R-VALUE-NOT-NUMERIC`` warning.

    Dependencies:
        Uses:
            - _r_issue
        Used by:
            - _add_scalar_entry
            - _add_array_entries
    """
    raw = "" if text is None else text.strip()

    parsed = _try_parse_number(raw)
    if parsed is not None:
        return parsed

    label = name if array_index is None else f"{name}[{array_index}]"
    issues.append(
        _r_issue(
            "R-VALUE-NOT-NUMERIC",
            ValidationSeverity.WARNING,
            f"SW-INSTANCE '{label}' has a V value '{raw}' that is not a "
            f"decimal / exponential / hexadecimal number — kept as raw text",
        )
    )
    return raw


def _try_parse_number(raw: str) -> int | float | None:
    """
    Summary:
        Parse a ``V`` text token as an integer or float, returning ``None``
        when it is neither (LLR-005.4).

    Args:
        raw (str): The trimmed text content of a ``V`` element.

    Returns:
        int | float | None: An ``int`` for a hexadecimal (``0x``), binary
        (``0b`` — tolerant superset, OQ-7) or plain decimal integer; a
        ``float`` for a fractional / exponential literal; ``None`` when the
        token parses as no number.

    Data Flow:
        - An empty token is not a number — return ``None``.
        - A ``0x`` / ``0X`` / ``0b`` / ``0B`` prefix selects ``int(raw, 0)``;
          a plain ``int`` is tried next, then ``float``.

    Dependencies:
        Used by:
            - _decode_numeric
    """
    if not raw:
        return None

    lowered = raw.lower()
    if lowered.startswith(("0x", "-0x", "+0x", "0b", "-0b", "+0b")):
        try:
            # int(token, 0) honours the 0x / 0b prefix; 0b is accepted as a
            # tolerant superset only (OQ-7 — not a normative CDF binary form).
            return int(raw, 0)
        except ValueError:
            return None

    try:
        return int(raw)
    except ValueError:
        pass

    try:
        return float(raw)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# A2L cross-check (LLR-008.1..008.3).
# ---------------------------------------------------------------------------


def _index_a2l_tags(a2l_tags: list[dict] | None) -> dict[str, dict] | None:
    """
    Summary:
        Index the enriched A2L tags by parameter name for the LLR-008
        cross-check, returning ``None`` when no A2L is loaded.

    Args:
        a2l_tags (list[dict] | None): The enriched A2L tags, or ``None`` /
            empty when no A2L is loaded.

    Returns:
        dict[str, dict] | None: The tags keyed by their ``name`` field, or
        ``None`` when no A2L was supplied — the ``None`` return is the signal
        :func:`_cross_check_instance` reads to skip the cross-check entirely
        (LLR-008.3).

    Data Flow:
        - A falsy ``a2l_tags`` (``None`` or empty list) returns ``None``.
        - Otherwise build a ``name → tag`` dict, ignoring tags with no name.

    Dependencies:
        Used by:
            - read_cdfx
    """
    if not a2l_tags:
        return None
    return {
        str(tag.get("name")): tag
        for tag in a2l_tags
        if tag.get("name")
    }


def _cross_check_instance(
    instance: ET.Element,
    tags_by_name: dict[str, dict] | None,
    issues: list[ValidationIssue],
) -> None:
    """
    Summary:
        Cross-check one ``SW-INSTANCE`` against the loaded A2L, emitting
        ``R-NAME-NOT-IN-A2L`` / ``R-ARRAY-LEN-MISMATCH`` warnings (LLR-008).

    Args:
        instance (ET.Element): A ``SW-INSTANCE`` element under the
            instance-tree backbone.
        tags_by_name (dict[str, dict] | None): The enriched A2L tags keyed by
            name, or ``None`` when no A2L is loaded — ``None`` skips the whole
            cross-check (LLR-008.3).
        issues (list[ValidationIssue]): The accumulating issue list, appended
            to in place.

    Returns:
        None: ``issues`` is mutated in place.

    Data Flow:
        - When ``tags_by_name`` is ``None`` (no A2L), return immediately —
          neither cross-check code is emitted (LLR-008.3).
        - A nameless instance is already flagged ``R-INSTANCE-NO-NAME`` by the
          reader; it is silently skipped here.
        - An instance name absent from the A2L is ``R-NAME-NOT-IN-A2L``
          (LLR-008.1); the array-length check is then not applicable.
        - For a matched array instance, compare the ``V`` count against the
          A2L ``element_count``; a difference is ``R-ARRAY-LEN-MISMATCH``
          (LLR-008.2). The ``V`` count is taken positionally (LLR-005.6), so
          the check is independent of the expansion.

    Dependencies:
        Uses:
            - _values_phys_of
            - _collect_values
        Used by:
            - read_cdfx
    """
    if tags_by_name is None:
        return

    name = (_child_text(instance, "SHORT-NAME") or "").strip()
    if not name:
        return

    tag = tags_by_name.get(name)
    if tag is None:
        issues.append(
            _r_issue(
                "R-NAME-NOT-IN-A2L",
                ValidationSeverity.WARNING,
                f"SW-INSTANCE '{name}' matches no loaded A2L parameter",
            )
        )
        return

    category = (_child_text(instance, "CATEGORY") or "").strip()
    if category != ARRAY_CATEGORY:
        return

    v_texts, _vt_texts = _collect_values(_values_phys_of(instance))
    expected = _element_count_of(tag)
    if len(v_texts) != expected:
        issues.append(
            _r_issue(
                "R-ARRAY-LEN-MISMATCH",
                ValidationSeverity.WARNING,
                f"SW-INSTANCE '{name}' has {len(v_texts)} array element(s) but "
                f"the A2L parameter declares element_count {expected}",
            )
        )


def _element_count_of(tag: dict) -> int:
    """
    Summary:
        Read an enriched A2L tag's element count as a positive ``int``,
        defaulting to a scalar when the field is absent or unusable.

    Args:
        tag (dict): One enriched A2L tag dict — its ``element_count`` field is
            populated by the A2L enrichment pipeline.

    Returns:
        int: The element count, clamped to a minimum of ``1`` — a missing or
        non-numeric count resolves to ``1`` so the LLR-008.2 comparison has a
        well-defined value. Mirrors ``resolve._element_count_of``.

    Data Flow:
        - Coerce ``element_count`` to ``int``; fall back to ``1`` on a missing
          or non-numeric value, then clamp to a minimum of ``1``.

    Dependencies:
        Used by:
            - _cross_check_instance
    """
    raw = tag.get("element_count")
    try:
        count = int(raw)
    except (TypeError, ValueError):
        return 1
    return max(1, count)


# ---------------------------------------------------------------------------
# XML navigation helpers (namespace-tolerant) — mirror writer.py.
# ---------------------------------------------------------------------------


def _resolve_source(
    source: bytes | str | Path,
    base_dir: Path | None,
    issues: list[ValidationIssue],
) -> bytes | None:
    """
    Summary:
        Resolve the ``.cdfx`` ``source`` to raw bytes, resolving a user-supplied
        path through ``workspace.resolve_input_path`` first (LLR-005.5).

    Args:
        source (bytes | str | Path): The document — ``bytes`` are returned
            unchanged (the in-memory path); a ``str`` / ``Path`` is a
            user-supplied path that must be resolved before any file is opened.
        base_dir (Path | None): The directory ``resolve_input_path`` resolves a
            relative path against; ``None`` falls back to the current working
            directory.
        issues (list[ValidationIssue]): The accumulating issue list — an
            unresolvable path appends one ``R-XML-PARSE`` issue.

    Returns:
        bytes | None: The raw document bytes, or ``None`` when the path could
        not be resolved by ``resolve_input_path`` or the on-disk file exceeds
        the ``MAX_CDFX_SIZE_BYTES`` cap — in which case one ``R-XML-PARSE``
        issue has been appended and **no file content was read into memory**
        (LLR-005.5 / LLR-006.8).

    Data Flow:
        - ``bytes`` pass straight through — there is no path to resolve.
        - A ``str`` / ``Path`` is run through ``resolve_input_path``; a ``None``
          result (unresolvable) is rejected as one ``R-XML-PARSE`` issue with
          no open attempt.
        - The resolved path's on-disk size is checked with ``Path.stat`` —
          ``st_size`` — *before* the file is read; an over-cap file is rejected
          as one ``R-XML-PARSE`` issue and ``Path.read_bytes`` is **not**
          called, so a pathologically large file is never loaded into memory.
          This mirrors ``workspace.copy_into_workarea``'s
          ``stat().st_size``-before-copy guard (LLR-006.8 / S8-2).
        - A within-cap path is read with ``Path.read_bytes``.

    Dependencies:
        Uses:
            - resolve_input_path
            - _parse_issue
        Used by:
            - read_cdfx

    Notes:
        The on-disk ``stat().st_size`` check here is the size guard for a
        *path* source; ``read_cdfx`` additionally runs the ``_probe_size`` seam
        on the resolved bytes (and on a ``bytes`` source, which has no on-disk
        size). A path source is therefore size-checked twice — once on disk
        before the read, once in memory after — and the on-disk check is what
        keeps an over-cap file from ever being loaded.
    """
    if isinstance(source, bytes):
        return source

    resolved = resolve_input_path(Path(source), base_dir or Path.cwd())
    if resolved is None:
        issues.append(
            _parse_issue(
                f"the .cdfx path '{source}' could not be resolved — no file "
                f"was opened"
            )
        )
        return None

    # Check the on-disk size BEFORE reading the file into memory (LLR-006.8 /
    # S8-2) — an over-cap file is rejected without `read_bytes`, so a
    # pathologically large file never lands in the process's memory. Mirrors
    # `workspace.copy_into_workarea`'s `stat().st_size`-before-copy guard.
    try:
        disk_size = resolved.stat().st_size
    except OSError as exc:
        issues.append(
            _parse_issue(
                f"the .cdfx path '{source}' could not be stat'd: {exc} — "
                f"no file content was read"
            )
        )
        return None
    if disk_size > MAX_CDFX_SIZE_BYTES:
        issues.append(
            _parse_issue(
                f"the .cdfx file '{source}' is {disk_size} bytes on disk, over "
                f"the {MAX_CDFX_SIZE_BYTES}-byte "
                f"({MAX_CDFX_SIZE_BYTES // (1024 * 1024)} MB) read cap — "
                f"rejected before the file was read into memory"
            )
        )
        return None

    return resolved.read_bytes()


def _safe_parse(
    data: bytes,
    issues: list[ValidationIssue],
) -> ET.Element | None:
    """
    Summary:
        Parse ``.cdfx`` bytes into an element tree under the XML-safety bounds —
        rejecting a ``DOCTYPE`` / ``<!ENTITY>`` declaration before any entity
        expansion (LLR-006.6) and a tree past the nesting-depth bound
        (LLR-006.8).

    Args:
        data (bytes): The raw ``.cdfx`` document bytes — already known to be
            within the 256 MB cap (the caller checks size first).
        issues (list[ValidationIssue]): The accumulating issue list — any
            safety-bound trip or a plain parse failure appends exactly one
            ``R-XML-PARSE`` issue.

    Returns:
        ET.Element | None: The parsed root element, or ``None`` when the input
        carried a ``DOCTYPE`` / ``<!ENTITY>`` declaration, exceeded the
        nesting-depth bound, or was not well-formed XML — in which case exactly
        one ``R-XML-PARSE`` issue has been appended.

    Data Flow:
        - Build a raw ``expat`` parser whose ``StartDoctypeDeclHandler`` raises
          ``_UnsafeXmlError`` on the ``<!DOCTYPE`` declaration itself — this
          fires *before* expat reads any ``<!ENTITY>`` declaration, so no entity
          is ever declared or expanded (CV-04). ``EntityDeclHandler`` raises too
          as belt-and-suspenders.
        - The ``StartElementHandler`` tracks element depth and raises
          ``_UnsafeXmlError`` once it passes ``MAX_NESTING_DEPTH``.
        - Drive the parser with an ``ElementTree.TreeBuilder``; an
          ``_UnsafeXmlError`` or an ``expat.ExpatError`` is converted to one
          ``R-XML-PARSE`` issue.

    Dependencies:
        Uses:
            - _parse_issue
        Used by:
            - read_cdfx
    """
    builder = ET.TreeBuilder()
    parser = expat.ParserCreate(namespace_separator="}")
    depth = 0

    def start_doctype(name, system_id, public_id, has_internal_subset):  # noqa: ANN001
        # Fires on the `<!DOCTYPE` token — before any `<!ENTITY>` declaration is
        # read and long before any entity is expanded (CV-04). A conformant
        # CDF 2.0 .cdfx has no DOCTYPE, so this never trips on valid input.
        raise _UnsafeXmlError(
            "the .cdfx file declares a DOCTYPE — rejected before any entity "
            "is declared or expanded (XML-safety, LLR-006.6)"
        )

    def entity_decl(*_args):  # noqa: ANN002
        # Belt-and-suspenders: a DOCTYPE-less but entity-declaring document is
        # not valid XML anyway, but the handler raises rather than expand.
        raise _UnsafeXmlError(
            "the .cdfx file declares an XML entity — rejected before expansion "
            "(XML-safety, LLR-006.6)"
        )

    def start_element(tag, attrs):  # noqa: ANN001
        nonlocal depth
        depth += 1
        if depth > MAX_NESTING_DEPTH:
            raise _UnsafeXmlError(
                f"the .cdfx file nests XML elements past the depth bound of "
                f"{MAX_NESTING_DEPTH} (XML-safety, LLR-006.8)"
            )
        # ElementTree expects a leading '{' on a namespaced tag; expat's
        # namespace_separator form omits it — reconstruct so _local_name and
        # the rest of the reader behave exactly as under ET.fromstring.
        builder.start("{" + tag if "}" in tag else tag, attrs)

    def end_element(tag):  # noqa: ANN001
        nonlocal depth
        depth -= 1
        builder.end("{" + tag if "}" in tag else tag)

    parser.StartDoctypeDeclHandler = start_doctype
    parser.EntityDeclHandler = entity_decl
    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.CharacterDataHandler = builder.data

    try:
        parser.Parse(data, True)
        return builder.close()
    except _UnsafeXmlError as exc:
        issues.append(_parse_issue(str(exc)))
        return None
    except expat.ExpatError as exc:
        issues.append(
            _parse_issue(f"the .cdfx file is not well-formed XML: {exc}")
        )
        return None


def _find_instance_tree(root: ET.Element) -> ET.Element | None:
    """
    Summary:
        Locate the ``SW-INSTANCE-TREE`` backbone element under an ``MSRSW``
        root, namespace-tolerant (LLR-005.3 / S-006).

    Args:
        root (ET.Element): An ``MSRSW`` root element.

    Returns:
        ET.Element | None: The ``SW-INSTANCE-TREE`` element when the full
        ``SW-SYSTEMS → SW-SYSTEM → SW-INSTANCE-SPEC → SW-INSTANCE-TREE`` chain
        is present, otherwise ``None`` (the backbone could not be located).

    Data Flow:
        - Walk the backbone chain one level at a time by local name; a missing
          link returns ``None``.

    Dependencies:
        Uses:
            - _first_child
        Used by:
            - read_cdfx
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
        ``SW-INSTANCE-TREE`` backbone (LLR-005.3 / S-006).

    Args:
        instance_tree (ET.Element): The ``SW-INSTANCE-TREE`` element.

    Returns:
        list[ET.Element]: Every direct-child element whose local name is
        ``SW-INSTANCE``, in document order. Scoping to direct children of the
        backbone prevents a ``SW-INSTANCE`` placed elsewhere in the document
        (for example inside ``ADMIN-DATA``) from being absorbed into the
        change-list.

    Dependencies:
        Uses:
            - _local_name
        Used by:
            - read_cdfx
    """
    return [
        child
        for child in instance_tree
        if _local_name(child.tag) == "SW-INSTANCE"
    ]


def _values_phys_of(instance: ET.Element) -> ET.Element | None:
    """
    Summary:
        Descend a ``SW-INSTANCE`` to its ``SW-VALUE-CONT/SW-VALUES-PHYS``
        element, namespace-tolerant.

    Args:
        instance (ET.Element): A ``SW-INSTANCE`` element.

    Returns:
        ET.Element | None: The ``SW-VALUES-PHYS`` element, or ``None`` when the
        ``SW-VALUE-CONT`` / ``SW-VALUES-PHYS`` chain is incomplete.

    Data Flow:
        - Descend ``SW-VALUE-CONT → SW-VALUES-PHYS`` by local name.

    Dependencies:
        Uses:
            - _first_child
        Used by:
            - _read_instance
            - _cross_check_instance
    """
    value_cont = _first_child(instance, "SW-VALUE-CONT")
    if value_cont is None:
        return None
    return _first_child(value_cont, "SW-VALUES-PHYS")


def _collect_values(
    values_phys: ET.Element | None,
) -> tuple[list[str], list[str]]:
    """
    Summary:
        Collect the text of every ``V`` and ``VT`` element under a
        ``SW-VALUES-PHYS`` element, in document order (LLR-005.6).

    Args:
        values_phys (ET.Element | None): The ``SW-VALUES-PHYS`` element, or
            ``None`` when the instance has no value container.

    Returns:
        tuple[list[str], list[str]]: ``(v_texts, vt_texts)`` — the text content
        of every ``V`` element and of every ``VT`` element. ``V`` elements
        nested inside a ``VG`` are collected too (a ``VAL_BLK`` array's values
        live inside one ``VG``), in document order so positional expansion is
        exact. An empty / self-closing element contributes the empty string.
        ``([], [])`` when ``values_phys`` is ``None``.

    Data Flow:
        - Walk the ``SW-VALUES-PHYS`` subtree with ``iter``; a ``VG`` is a
          transparent container — its ``V`` children are gathered into the
          same flat list.

    Dependencies:
        Uses:
            - _local_name
        Used by:
            - _read_instance
            - _cross_check_instance
    """
    if values_phys is None:
        return [], []

    v_texts: list[str] = []
    vt_texts: list[str] = []
    for elem in values_phys.iter():
        local = _local_name(elem.tag)
        if local == "V":
            v_texts.append(elem.text or "")
        elif local == "VT":
            vt_texts.append(elem.text or "")
    return v_texts, vt_texts


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
            - _values_phys_of
            - _child_text
    """
    for child in parent:
        if _local_name(child.tag) == tag:
            return child
    return None


def _child_text(parent: ET.Element, tag: str) -> str | None:
    """
    Summary:
        Return the text of the first direct child of ``parent`` named ``tag``
        (namespace-tolerant).

    Args:
        parent (ET.Element): The element to search.
        tag (str): The local element name to match.

    Returns:
        str | None: The matching child's ``text`` (possibly ``None`` when the
        element is empty), or ``None`` when no such child exists.

    Dependencies:
        Uses:
            - _first_child
        Used by:
            - read_cdfx
            - _read_instance
            - _cross_check_instance
    """
    child = _first_child(parent, tag)
    return None if child is None else child.text


def _local_name(tag: str) -> str:
    """
    Summary:
        Strip an XML-namespace prefix from an ``ElementTree`` tag so a
        namespaced ``{uri}LocalName`` matches its bare local name (LLR-005.3).

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
            - _find_instance_tree
            - _direct_instances
            - _collect_values
            - _first_child
    """
    if tag.startswith("{"):
        return tag.rsplit("}", 1)[-1]
    return tag


# ---------------------------------------------------------------------------
# Issue construction.
# ---------------------------------------------------------------------------


def _r_issue(
    code: str,
    severity: ValidationSeverity,
    message: str,
) -> ValidationIssue:
    """
    Summary:
        Build a read-time ``R-*`` ``ValidationIssue`` with the ``cdfx``
        artifact tag (LLR-006.3).

    Args:
        code (str): The ``R-*`` rule code.
        severity (ValidationSeverity): The rule's documented severity — read
            rules vary (``R-XML-PARSE`` / ``R-ROOT-MSRSW`` are errors,
            ``R-VERSION-UNKNOWN`` is info, the cross-check codes are warnings),
            so severity is passed in rather than fixed (unlike the writer's
            all-error ``W-*`` rules).
        message (str): The human-readable explanation.

    Returns:
        ValidationIssue: The issue, artifact ``cdfx``.

    Dependencies:
        Used by:
            - read_cdfx
            - _read_instance
            - _check_value_shape
            - _decode_numeric
            - _cross_check_instance
            - _parse_issue
    """
    return ValidationIssue(
        code=code,
        severity=severity,
        message=message,
        artifact=CDFX_ARTIFACT,
    )


def _parse_issue(message: str) -> ValidationIssue:
    """
    Summary:
        Build the error-level ``R-XML-PARSE`` ``ValidationIssue`` for a
        ``.cdfx`` that did not parse as well-formed XML (LLR-005.2).

    Args:
        message (str): The human-readable explanation, including the
            ``ElementTree`` parse-error detail.

    Returns:
        ValidationIssue: An ``ERROR``-severity issue with code ``R-XML-PARSE``
        and artifact ``cdfx``.

    Dependencies:
        Uses:
            - _r_issue
        Used by:
            - read_cdfx
    """
    return _r_issue("R-XML-PARSE", ValidationSeverity.ERROR, message)
