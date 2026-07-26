"""Render file-derived text inert inside a markdown report's grammar (batch-62).

This module is a LEAF: it imports nothing from ``s19_app`` and nothing beyond the
stdlib. That is load-bearing, not stylistic — ``flow_report_service`` and
``diff_report_service`` both import FROM ``report_service`` (``:63`` / ``:97``),
so a shared escaper living in either generator would be a hard circular import
for the third consumer (D-4).

Two modes, selected by a truth table on two observable properties of the value
(``01-requirements.md`` §4), never by per-field judgement:

===========================================  ==================  ========
Value can contain the run root / abs. path   Context is a cell   Mode
===========================================  ==================  ========
no                                           no                  A
no                                           yes                 A
yes                                          no                  B
yes                                          yes                 FORBIDDEN
===========================================  ==================  ========

**Mode A** (:func:`md_safe`) escapes every markdown-structural character. Escapes
render invisibly, so paths, symbols and addresses stay readable.

**Mode B** (:func:`md_code`) is for values that must survive **byte-identical**
because a downstream consumer substitutes their raw bytes — the golden
canonicaliser replaces ``str(run_root)`` verbatim, and any transformation of the
path bytes defeats it, leaking an absolute operator path into the compared
output (CN-6 / R-1). Mode B therefore escapes nothing and is emitted inside a
code span by its caller.

Two contracts a caller MUST honour, both of which the escape set alone does not
give you:

1. **Column-0 precondition (D-10, amended A-43).** Block starters are defused by
   two controls, not one. :func:`_normalise` collapses ``\\r\\n\\t`` to a space
   so a value cannot reach column 0 of its own line, and
   :func:`_escape_leading_block_starter` handles the case that defeats the
   first: an emission site whose literal prefix is itself a list marker
   (``f"- {md_safe(path)}"``), where a value of ``1) x`` still opens a list and
   ``- x`` silently loses its marker. Interior ``-`` is never escaped, so
   ``mac-linked`` stays readable.
2. **Mode B is forbidden inside a table cell (D-6).** A raw ``|`` inside a code
   span still splits the cell — Mode B protects grammar, not table structure.

``!`` is deliberately absent from :data:`MD_ESCAPE`: the image construct is dead
only because ``[`` and ``]`` are escaped. Removing either re-enables outbound
image requests from the exported file.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Tuple

#: Markdown-structural characters escaped by :func:`md_safe`, **in application
#: order**. ``\\`` MUST stay at index 0 so an inserted escape is never
#: re-escaped by a later pass. ``&`` is index 1 because an un-escaped entity is
#: decoded by the reader — ``&vert;`` renders as ``|`` and forges a table
#: fragment while every parsed token stays ``text``, which no token-type
#: assertion can see (batch-62 F1). ``~`` kills strikethrough; ``/``, ``.`` and
#: ``@`` defuse the three linkify families — scheme (``http://x``),
#: protocol-relative (``//x``) and **fuzzy** (``www.evil.com``, ``evil.com``,
#: ``ops@evil.com``), which need neither scheme nor slash.
MD_ESCAPE: Tuple[str, ...] = (
    "\\", "&", "|", "*", "_", "[", "]", "<", ">", "#", "~", "/", ".", "@", "`",
)

#: Appended to a Mode-A value truncated at its caller's ``limit``. Deliberately
#: DISTINCT from ``validation.model._TRUNCATION_MARKER`` (``"…[truncated]"``);
#: a test pins the difference so merging them is a conscious act, never a
#: false-GREEN from a test importing the wrong one (batch-62 M-3).
TRUNCATION_MARKER = "… (truncated)"

#: Substituted for a character that cannot be represented faithfully — a dropped
#: format/control character in either mode, and a backtick in Mode B. A report
#: is an evidentiary record: a silently deleted character turns one symbol into
#: a different one, so the loss is made VISIBLE rather than hidden (F3/F8).
LOSS_MARKER = "�"

#: Emitted when nothing survives, so a cell is never blank and Mode B never
#: emits a bare ``````.
EMPTY_MARKER = "(empty)"

#: Unicode categories dropped by :func:`_normalise`. ``Cc``/``Cf`` cover C0, C1,
#: RLO, ZWSP and BOM. ``Zl``/``Zp`` are NOT optional: ``U+2028 LINE SEPARATOR``
#: is ``Zl``, so it passes a ``Cc``/``Cf``-only filter *and* the ``\\r\\n\\t``
#: collapse, and it displays as a line break the bytes do not contain. ``Cs``
#: (lone surrogates, reachable from a POSIX filename read with
#: ``surrogateescape``) is included because leaving it out contradicted this
#: function's own contract: the value survived normalisation and then raised
#: ``UnicodeEncodeError`` at write time — fail-closed, but by accident rather
#: than by the stated design.
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

#: Block starters escaped ONLY in leading position (see
#: :func:`_escape_leading_block_starter`). ``#`` and ``>`` are absent because
#: :data:`MD_ESCAPE` already escapes them everywhere.
_LEADING_BLOCK_CHARS = ("-", "+", "=")

#: ``1)`` opens an ordered list and ``)`` is not in :data:`MD_ESCAPE`. Its
#: sibling ``1.`` needs no rule here — ``.`` is escaped unconditionally.
_ORDERED_PAREN_RE = re.compile(r"^\d{1,9}\)")

#: Multiple of ``limit`` scanned before normalisation. A 10 MB A2L symbol name
#: would otherwise cost several full-string passes and a 10M-element generator
#: before a 240-character cap fires.
_INPUT_SCAN_FACTOR = 8


def _normalise(text: str) -> str:
    """Collapse line structure and replace unrepresentable characters.

    Summary:
        Applies the two transformations both modes share, in the order the
        block-starter argument depends on: ``\\r``, ``\\n`` and ``\\t`` become a
        single space FIRST (so no value can reach column 0), then any character
        in :data:`_DROP_CATEGORIES` becomes :data:`LOSS_MARKER`.

    Args:
        text (str): The already-``str``-rendered value.

    Returns:
        str: Single-line text carrying no format or control characters.

    Data Flow:
        - Called by :func:`md_safe` and :func:`md_code` before any mode-specific
          step, so both inherit the column-0 guarantee.

    Dependencies:
        Uses:
            - unicodedata.category
        Used by:
            - md_safe / md_code

    Example:
        >>> _normalise("a\\nb")
        'a b'
    """
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return "".join(
        LOSS_MARKER if unicodedata.category(ch) in _DROP_CATEGORIES else ch
        for ch in text
    )


def _escape_leading_block_starter(text: str) -> str:
    """Neutralise a block starter sitting at the FRONT of an escaped value.

    Summary:
        The batch's original ruling held that a non-empty literal prefix at the
        emission site is enough to keep a value out of column 0, so ``-``, ``+``
        and ``=`` need not be escaped — escaping them would render ``mac-linked``
        as ``mac\\-linked`` at every kebab-case identifier.

        That is true for a prefix like ``| `` or ``# ``, and **false when the
        prefix is itself a list marker**, which is a real emission shape
        (``f"- {md_safe(path)}"``). Measured behind a ``"- "`` prefix:

        ====================  ===================================================
        ``1) item``           opens an ordered list — ``)`` is not in MD_ESCAPE
        ``---``               emits an ``hr``
        ``- item``            the marker is CONSUMED; the reader sees ``item``
        ====================  ===================================================

        The last one is the interesting failure: it opens no construct, so a
        grammar-only assertion scores it inert while the displayed value silently
        loses its first two characters.

        Escaping only in leading position costs nothing in readability — an
        interior ``-`` is untouched — and a leading ``\\-`` renders as ``-``.

    Args:
        text (str): The value AFTER the :data:`MD_ESCAPE` pass, so a backslash
            inserted here is never re-escaped.

    Returns:
        str: The same text with a leading block starter defused.

    Data Flow:
        - Final step of :func:`md_safe`. Mode B does not need it: a code span
          cannot start a block.

    Dependencies:
        Uses:
            - _LEADING_BLOCK_CHARS / _ORDERED_PAREN_RE
        Used by:
            - md_safe

    Example:
        >>> _escape_leading_block_starter("- item")
        '\\\\- item'
    """
    if text[:1] in _LEADING_BLOCK_CHARS:
        return "\\" + text
    match = _ORDERED_PAREN_RE.match(text)
    if match:
        return text[: match.end() - 1] + "\\)" + text[match.end():]
    return text


def md_safe(value: object, *, limit: int) -> str:
    """Escape ``value`` so it renders literally anywhere but column 0 (Mode A).

    Summary:
        Normalises, truncates, then escapes every character in
        :data:`MD_ESCAPE`. Truncation happens BEFORE escaping because escaping
        can only grow the string. Nothing is deleted: a backtick is escaped, not
        removed, so the value that reaches the reader is the value that was in
        the file.

        ``limit`` is keyword-only and REQUIRED. Every call site states its own
        cap, because the fields this escaper protects have wildly different
        upstream bounds — an ``issue.message`` is scrubbed at 500 while an NTFS
        basename reaches 255 — and a single shared default silently truncated
        ~20 of them (batch-62 M-5 / M-2).

    Args:
        value (object): The raw, untrusted value; rendered via ``str()``.
        limit (int): Character cap applied before escaping.

    Returns:
        str: Inert text, never empty — :data:`EMPTY_MARKER` when nothing
        survives.

    Raises:
        Exception: Whatever ``str(value)`` raises is allowed to PROPAGATE. This
            is deliberate and normative (D-18): escaping failure must abort
            report generation rather than fall through to the raw value, and a
            broad ``except`` here would be a silent bypass of the whole control.

    Data Flow:
        - ``file-derived value → md_safe → report line → markdown reader``.

    Dependencies:
        Uses:
            - _normalise / MD_ESCAPE / TRUNCATION_MARKER / EMPTY_MARKER
        Used by:
            - flow_report_service._md_safe
            - report_service (Mode-A fields)

    Example:
        >>> md_safe("a|b `c` http://x", limit=240)
        'a\\\\|b \\\\`c\\\\` http:\\\\/\\\\/x'
    """
    text = str(value)[: limit * _INPUT_SCAN_FACTOR]
    text = _normalise(text).strip()
    if len(text) > limit:
        text = text[:limit].rstrip() + TRUNCATION_MARKER
    for ch in MD_ESCAPE:  # backslash FIRST — never double-escape
        text = text.replace(ch, "\\" + ch)
    return _escape_leading_block_starter(text) or EMPTY_MARKER


def md_code(value: object) -> str:
    """Render ``value`` byte-faithfully for emission inside a code span (Mode B).

    Summary:
        Normalises and neutralises the only character that can close a code span
        — the backtick — and changes NOTHING else. No escaping, no truncation.

        Both omissions are required, not conveniences. Escaping is inert inside
        a code span, so a backslash would be displayed rather than consumed.
        Truncation is excluded because a Mode-B value is an absolute path whose
        length depends on the operator's home directory and temp-root depth: a
        cap would fire on one machine and not another, making any golden that
        contains one machine-dependent (the failure CN-6 exists to prevent,
        arriving through a different door).

        Mode B is therefore LOSSY on backtick-bearing values, which is why the
        backtick becomes a visible :data:`LOSS_MARKER` instead of vanishing —
        escaping it is impossible here, but silently dropping it would record a
        different path than the one on disk.

    Args:
        value (object): The raw, untrusted value; rendered via ``str()``.

    Returns:
        str: Text safe to place between single backticks, never empty.

    Raises:
        Exception: ``str(value)`` failures propagate — see :func:`md_safe`.

    Data Flow:
        - ``path → md_code → ``\\`` + value + ``\\`` → report line``. The caller
          owns the wrap; this function never adds it.

    Dependencies:
        Uses:
            - _normalise / LOSS_MARKER / EMPTY_MARKER
        Used by:
            - report_service (Mode-B path fields)

    Example:
        >>> md_code("/tmp/a.s19")
        '/tmp/a.s19'
    """
    text = _normalise(str(value)).replace("`", LOSS_MARKER).strip()
    return text or EMPTY_MARKER
