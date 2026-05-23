"""
CDFX reader tests — s19_app batch-03, increment 7.

Covers ``s19_app/tui/cdfx/reader.py`` :func:`read_cdfx` — parsing a well-formed
CDF 2.0 ``.cdfx`` document back into a change-list:

  - TC-015 — reader parses a well-formed ``.cdfx`` into entries (LLR-005.1).
  - TC-016 — reader tolerates malformed XML (LLR-005.2).
  - TC-017 — reader tolerates producer-specific variation: namespaced XML,
             extra optional siblings and a leading tool-note comment
             (LLR-005.3, LLR-006.7).
  - TC-018 — reader decodes numeric value notations (LLR-005.4).
  - TC-022 — CDFX issues reuse the ``ValidationIssue`` model (LLR-006.3).
  - TC-034 — reader tolerates a writer / tool-identification note (LLR-006.7).
  - TC-039 — reader expands a ``VAL_BLK`` instance into array-element entries;
             ``VALUE`` / ``ASCII`` expand to one ``array_index=None`` entry —
             the read-side inverse of the LLR-004.9 writer coalescing
             (LLR-005.6).

The ``R-*`` structural / version / cross-check rules are exercised in
``tests/test_cdfx_r_rules.py``. Every fixture here is synthetic and built
in-test (constraint C-9); ``make_minimal_cdfx`` is the §5 minimal-example shape
of ``design-input/cdfx-research.md``.
"""

from __future__ import annotations

from s19_app.tui.cdfx import ChangeList, read_cdfx
from s19_app.tui.cdfx.changelist import ResolutionStatus
from s19_app.validation.model import ValidationIssue, ValidationSeverity


# ---------------------------------------------------------------------------
# Synthetic .cdfx fixtures — built in-test, no static files on disk.
# ---------------------------------------------------------------------------


def make_minimal_cdfx() -> bytes:
    """Build the §5 minimal-example ``.cdfx``: one VALUE, one VAL_BLK, one ASCII.

    The ``VAL_BLK`` carries one ``VG`` of three ``V`` — the exact shape the
    coalescing writer (LLR-004.9) emits, so the increment-10 round-trip closes.
    """
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b"<MSRSW>"
        b"<SHORT-NAME>S19APP_PATCH</SHORT-NAME>"
        b"<CATEGORY>CDF20</CATEGORY>"
        b"<SW-SYSTEMS><SW-SYSTEM><SHORT-NAME>ECU1</SHORT-NAME>"
        b"<SW-INSTANCE-SPEC><SW-INSTANCE-TREE>"
        b"<SHORT-NAME>PatchSet</SHORT-NAME><CATEGORY>NO_VCD</CATEGORY>"
        b"<SW-INSTANCE><SHORT-NAME>IGN_ADVANCE_BASE</SHORT-NAME>"
        b"<CATEGORY>VALUE</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>12.5</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"<SW-INSTANCE><SHORT-NAME>FUEL_TRIM_TABLE</SHORT-NAME>"
        b"<CATEGORY>VAL_BLK</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><VG><V>23</V><V>24</V><V>25</V></VG>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"<SW-INSTANCE><SHORT-NAME>CAL_LABEL</SHORT-NAME>"
        b"<CATEGORY>ASCII</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><VT>REV_C</VT>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"</SW-INSTANCE-TREE></SW-INSTANCE-SPEC></SW-SYSTEM></SW-SYSTEMS>"
        b"</MSRSW>"
    )


def make_variant_cdfx() -> bytes:
    """A valid namespaced ``.cdfx`` with extra optional siblings (LLR-005.3).

    The root declares a default ``xmlns`` (so ``ElementTree`` namespace-
    qualifies every tag) and the document carries ``ADMIN-DATA`` /
    ``SW-CS-HISTORY`` / ``SW-CS-FLAGS`` siblings the reader must ignore.
    """
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<MSRSW xmlns="http://www.asam.net/schema/cdf">'
        b"<SHORT-NAME>S19APP_PATCH</SHORT-NAME>"
        b"<CATEGORY>CDF20</CATEGORY>"
        b"<ADMIN-DATA><LANGUAGE>en</LANGUAGE></ADMIN-DATA>"
        b"<SW-SYSTEMS><SW-SYSTEM><SHORT-NAME>ECU1</SHORT-NAME>"
        b"<SW-INSTANCE-SPEC><SW-INSTANCE-TREE>"
        b"<SHORT-NAME>PatchSet</SHORT-NAME><CATEGORY>NO_VCD</CATEGORY>"
        b"<SW-INSTANCE><SHORT-NAME>IGN_ADVANCE_BASE</SHORT-NAME>"
        b"<CATEGORY>VALUE</CATEGORY>"
        b"<SW-CS-HISTORY><CSUS>edited</CSUS></SW-CS-HISTORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>7</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT>"
        b"<SW-CS-FLAGS><SW-CS-FLAG>MATURE</SW-CS-FLAG></SW-CS-FLAGS>"
        b"</SW-INSTANCE>"
        b"</SW-INSTANCE-TREE></SW-INSTANCE-SPEC></SW-SYSTEM></SW-SYSTEMS>"
        b"</MSRSW>"
    )


def make_tool_note_cdfx() -> bytes:
    """The ``make_minimal_cdfx`` shape with a leading tool-note XML comment.

    Production ``.cdfx`` files carry a ``Created with …`` writer note
    (research §2.1); the reader must treat it as non-significant content
    (LLR-006.7).
    """
    minimal = make_minimal_cdfx()
    decl, body = minimal.split(b"\n", 1)
    return decl + b"\n<!-- Created with CANape 21.0 CDF 2.0 Writer -->\n" + body


def _entries_by_key(change_list: ChangeList) -> dict[tuple, object]:
    """Map each entry's ``(name, array_index)`` identity to its value."""
    return {e.key: e.value for e in change_list.entries}


# ---------------------------------------------------------------------------
# TC-015 — reader parses a well-formed .cdfx into entries (LLR-005.1)
# ---------------------------------------------------------------------------


def test_tc015_minimal_cdfx_parses_to_three_entries() -> None:
    """A well-formed ``.cdfx`` parses to entries with correct names and values.

    LLR-005.1: the reader locates each ``SW-INSTANCE`` under the backbone and
    produces change-list entries. The minimal example carries one ``VALUE``,
    one ``VAL_BLK`` (three ``V``) and one ``ASCII`` — the ``VAL_BLK`` expands
    to three array entries (LLR-005.6), so the change-list holds five entries.
    """
    change_list, issues = read_cdfx(make_minimal_cdfx())

    by_key = _entries_by_key(change_list)
    assert by_key[("IGN_ADVANCE_BASE", None)] == 12.5
    assert by_key[("FUEL_TRIM_TABLE", 0)] == 23
    assert by_key[("FUEL_TRIM_TABLE", 1)] == 24
    assert by_key[("FUEL_TRIM_TABLE", 2)] == 25
    assert by_key[("CAL_LABEL", None)] == "REV_C"
    assert len(change_list) == 5
    assert issues == []


def test_tc015_parsed_entries_are_marked_resolved() -> None:
    """Every entry from a supported category is stamped ``RESOLVED``.

    LLR-005.1: a readable instance of an editable category produces an entry
    the Patch Editor can show and re-write — its status is ``RESOLVED``, not
    the model's ``UNRESOLVED_NO_A2L`` default.
    """
    change_list, _issues = read_cdfx(make_minimal_cdfx())

    assert all(
        e.status is ResolutionStatus.RESOLVED for e in change_list.entries
    )


# ---------------------------------------------------------------------------
# TC-016 — reader tolerates malformed XML (LLR-005.2)
# ---------------------------------------------------------------------------


def test_tc016_truncated_file_yields_one_parse_issue_no_crash() -> None:
    """A truncated/garbage file → one ``R-XML-PARSE`` error, empty change-list.

    LLR-005.2: a non-well-formed ``.cdfx`` must not raise — the reader returns
    an empty change-list and exactly one error-level ``R-XML-PARSE`` issue, so
    the engineer sees the failure rather than a stack trace.
    """
    change_list, issues = read_cdfx(b"<MSRSW><SW-SYSTEMS><unclosed>")

    assert len(change_list) == 0
    assert len(issues) == 1
    assert issues[0].code == "R-XML-PARSE"
    assert issues[0].severity is ValidationSeverity.ERROR


def test_tc016_garbage_bytes_do_not_raise() -> None:
    """Non-XML garbage bytes are reported, never thrown (LLR-005.2)."""
    change_list, issues = read_cdfx(b"\x00\x01not xml at all\xff")

    assert len(change_list) == 0
    assert [i.code for i in issues] == ["R-XML-PARSE"]


# ---------------------------------------------------------------------------
# TC-017 — reader tolerates producer-specific variation (LLR-005.3, LLR-006.7)
# ---------------------------------------------------------------------------


def test_tc017_namespaced_cdfx_with_extra_siblings_reads_all_instances() -> None:
    """A namespaced ``.cdfx`` with optional siblings still reads its instances.

    LLR-005.3 / RK-3: a default ``xmlns`` makes ``ElementTree`` return
    ``{uri}Local`` tags — a literal match would miss every element. The reader
    matches on the local name, so the namespaced instance is found, and the
    ``ADMIN-DATA`` / ``SW-CS-HISTORY`` / ``SW-CS-FLAGS`` siblings are ignored.
    """
    change_list, issues = read_cdfx(make_variant_cdfx())

    by_key = _entries_by_key(change_list)
    assert by_key == {("IGN_ADVANCE_BASE", None): 7}
    assert issues == []


def test_tc017_instance_outside_backbone_is_not_absorbed() -> None:
    """A ``SW-INSTANCE`` placed outside the backbone is not read (S-006).

    LLR-005.3: the reader scopes the instance search to the direct children of
    ``SW-INSTANCE-TREE``. An instance crafted inside ``ADMIN-DATA`` must not be
    silently absorbed into the change-list as a real entry.
    """
    crafted = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b"<MSRSW><SHORT-NAME>P</SHORT-NAME><CATEGORY>CDF20</CATEGORY>"
        b"<ADMIN-DATA>"
        b"<SW-INSTANCE><SHORT-NAME>SMUGGLED</SHORT-NAME>"
        b"<CATEGORY>VALUE</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>99</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"</ADMIN-DATA>"
        b"<SW-SYSTEMS><SW-SYSTEM><SHORT-NAME>ECU1</SHORT-NAME>"
        b"<SW-INSTANCE-SPEC><SW-INSTANCE-TREE>"
        b"<SHORT-NAME>PatchSet</SHORT-NAME>"
        b"<SW-INSTANCE><SHORT-NAME>REAL</SHORT-NAME>"
        b"<CATEGORY>VALUE</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>1</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"</SW-INSTANCE-TREE></SW-INSTANCE-SPEC></SW-SYSTEM></SW-SYSTEMS>"
        b"</MSRSW>"
    )

    change_list, _issues = read_cdfx(crafted)

    assert {e.parameter_name for e in change_list.entries} == {"REAL"}
    assert change_list.get("SMUGGLED") is None


# ---------------------------------------------------------------------------
# TC-018 — reader decodes numeric value notations (LLR-005.4)
# ---------------------------------------------------------------------------


def _single_value_cdfx(v_text: str) -> bytes:
    """A minimal ``.cdfx`` with one ``VALUE`` instance carrying ``v_text``."""
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<MSRSW><SHORT-NAME>P</SHORT-NAME><CATEGORY>CDF20</CATEGORY>"
        b"<SW-SYSTEMS><SW-SYSTEM><SHORT-NAME>ECU1</SHORT-NAME>"
        b"<SW-INSTANCE-SPEC><SW-INSTANCE-TREE><SHORT-NAME>PatchSet</SHORT-NAME>"
        b"<SW-INSTANCE><SHORT-NAME>P0</SHORT-NAME><CATEGORY>VALUE</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>" + v_text.encode() + b"</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"</SW-INSTANCE-TREE></SW-INSTANCE-SPEC></SW-SYSTEM></SW-SYSTEMS>"
        b"</MSRSW>"
    )


def test_tc018_hexadecimal_v_decodes_to_integer() -> None:
    """``<V>0x17</V>`` decodes to the integer 23 (LLR-005.4).

    LLR-005.4: CDF allows ``V`` text in hexadecimal notation; the reader
    decodes a ``0x`` literal to its integer value.
    """
    change_list, issues = read_cdfx(_single_value_cdfx("0x17"))

    assert change_list.get("P0").value == 23
    assert issues == []


def test_tc018_exponential_v_decodes_to_float() -> None:
    """``<V>1.5e1</V>`` decodes to the float 15.0 (LLR-005.4)."""
    change_list, issues = read_cdfx(_single_value_cdfx("1.5e1"))

    value = change_list.get("P0").value
    assert value == 15.0 and isinstance(value, float)
    assert issues == []


def test_tc018_plain_decimal_v_decodes_to_integer() -> None:
    """Plain decimal ``V`` text decodes to an integer (LLR-005.4)."""
    change_list, _issues = read_cdfx(_single_value_cdfx("42"))

    value = change_list.get("P0").value
    assert value == 42 and isinstance(value, int)


def test_tc018_binary_v_is_a_tolerant_superset_not_a_requirement() -> None:
    """``<V>0b101</V>`` is decoded as a tolerant superset only (OQ-7).

    A-07 dropped ``0b`` as a normative CDF binary form, so this test documents
    the *tolerant acceptance* — it does not assert ``0b`` as a requirement. If
    a future CDF binary lexeme is pinned, only this assertion changes.
    """
    change_list, _issues = read_cdfx(_single_value_cdfx("0b101"))

    # The reader accepts 0b as a tolerant superset; if it ever stops, the
    # value falls back to raw text — neither is a TC-018 failure (OQ-7).
    assert change_list.get("P0").value in (5, "0b101")


# ---------------------------------------------------------------------------
# TC-022 — CDFX issues reuse the ValidationIssue model (LLR-006.3)
# ---------------------------------------------------------------------------


def test_tc022_read_issue_is_a_validationissue_tagged_cdfx() -> None:
    """Every CDFX read finding is a ``ValidationIssue`` with ``artifact=cdfx``.

    LLR-006.3 / DD-5: the reader reuses the project's issue model — no new
    issue type. A malformed-file read surfaces an ``R-XML-PARSE`` issue whose
    ``artifact`` is ``cdfx``.
    """
    _change_list, issues = read_cdfx(b"<MSRSW><broken>")

    assert len(issues) == 1
    issue = issues[0]
    assert isinstance(issue, ValidationIssue)
    assert issue.artifact == "cdfx"


def test_tc022_read_issue_severity_round_trips_through_color_policy() -> None:
    """A CDFX issue's severity yields a valid ``sev-*`` CSS class (LLR-006.3).

    The severity must round-trip through ``color_policy.css_class_for_severity``
    so the TUI can colour the issue exactly as it colours every other domain's
    findings.
    """
    from s19_app.tui.color_policy import css_class_for_severity

    _change_list, issues = read_cdfx(b"<MSRSW><broken>")

    css_class = css_class_for_severity(issues[0].severity)
    assert css_class.startswith("sev-")


# ---------------------------------------------------------------------------
# TC-034 — reader tolerates a writer / tool-identification note (LLR-006.7)
# ---------------------------------------------------------------------------


def test_tc034_leading_tool_note_comment_is_ignored() -> None:
    """A leading ``Created with …`` XML comment is non-significant (LLR-006.7).

    LLR-006.7: production ``.cdfx`` files carry a tool-identification comment;
    the reader must read every ``SW-INSTANCE`` and emit zero comment-related
    issues — the note is content to ignore, not a parse error.
    """
    change_list, issues = read_cdfx(make_tool_note_cdfx())

    # The tool note changes nothing: same five entries as the minimal file.
    assert len(change_list) == 5
    assert issues == []


# ---------------------------------------------------------------------------
# TC-039 — reader expands VAL_BLK / VALUE / ASCII (LLR-005.6)
# ---------------------------------------------------------------------------


def test_tc039_val_blk_expands_to_n_array_element_entries() -> None:
    """A ``VAL_BLK`` ``VG`` of N ``V`` expands to entries ``(name, 0…N-1)``.

    LLR-005.6: the read-side inverse of the LLR-004.9 writer coalescing. The
    writer collapses N array entries into one ``VAL_BLK`` instance; the reader
    must expand that instance back into exactly the keys ``(name, 0)…
    (name, N-1)`` — a wrong base (``1…N``) silently breaks the round-trip.
    """
    change_list, issues = read_cdfx(make_minimal_cdfx())

    array_keys = sorted(
        e.array_index
        for e in change_list.entries
        if e.parameter_name == "FUEL_TRIM_TABLE"
    )
    assert array_keys == [0, 1, 2]
    assert issues == []


def test_tc039_value_instance_expands_to_one_scalar_none_index_entry() -> None:
    """A ``VALUE`` instance expands to one entry with ``array_index is None``.

    LLR-005.6: a scalar parameter is not an array element — its recovered
    entry must carry ``array_index = None``, not the integer ``0`` (which would
    make it indistinguishable from element 0 of an array, LLR-001.1).
    """
    change_list, _issues = read_cdfx(make_minimal_cdfx())

    scalar = change_list.get("IGN_ADVANCE_BASE")
    assert scalar is not None
    assert scalar.array_index is None


def test_tc039_ascii_instance_expands_to_one_string_none_index_entry() -> None:
    """An ``ASCII`` instance expands to one string entry, ``array_index=None``.

    LLR-005.6: an ASCII string parameter, like a scalar, carries
    ``array_index = None``; its value is the ``VT`` text, kept as a string and
    never numeric-decoded.
    """
    change_list, _issues = read_cdfx(make_minimal_cdfx())

    string_entry = change_list.get("CAL_LABEL")
    assert string_entry is not None
    assert string_entry.array_index is None
    assert string_entry.value == "REV_C"


def test_tc039_boolean_instance_expands_to_one_scalar_none_index_entry() -> None:
    """A ``BOOLEAN`` instance expands like a scalar — ``array_index is None``.

    LLR-005.6: ``BOOLEAN`` is in the scalar category set; its single ``V`` is
    one ``array_index = None`` entry, the same shape as ``VALUE``.
    """
    boolean_cdfx = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<MSRSW><SHORT-NAME>P</SHORT-NAME><CATEGORY>CDF20</CATEGORY>"
        b"<SW-SYSTEMS><SW-SYSTEM><SHORT-NAME>ECU1</SHORT-NAME>"
        b"<SW-INSTANCE-SPEC><SW-INSTANCE-TREE><SHORT-NAME>PatchSet</SHORT-NAME>"
        b"<SW-INSTANCE><SHORT-NAME>ENABLE_FLAG</SHORT-NAME>"
        b"<CATEGORY>BOOLEAN</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>1</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"</SW-INSTANCE-TREE></SW-INSTANCE-SPEC></SW-SYSTEM></SW-SYSTEMS>"
        b"</MSRSW>"
    )

    change_list, issues = read_cdfx(boolean_cdfx)

    entry = change_list.get("ENABLE_FLAG")
    assert entry is not None
    assert entry.array_index is None and entry.value == 1
    assert issues == []
