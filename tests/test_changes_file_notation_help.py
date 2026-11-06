"""TC-1802 — the changes-file notation in the per-window usage help (batch-96).

The 2026-10-18 PDF-bug request: a window that changes files (the Patch
Editor's change-set JSON) must document the file notation in its embedded
help so an operator can hand-author the JSON in a plain text editor. The
copy ships as a new, CODE-AUTHORED section of
``window_help.WINDOW_HELP_SECTIONS`` — ``changes_file_notation`` — beside
the nine ``help_sections.md`` sections of batch-95 (TC-707). The TC-707
census stays scoped to the nine md-authored keys, so the new section is
censused HERE.

The section's minimal example is not just text: it must parse CLEAN
through the shipped reader (``changes.io.parse_change_document``) and
resolve to the documented bytes — the help may never document a file the
app itself refuses (the acceptance-oracle rule).

Coverage map (test -> TC):

- TC-1802 — ``test_tc1802_changes_file_notation_section_ships`` /
  ``test_tc1802_notation_documents_the_wire_fields`` /
  ``test_tc1802_minimal_example_parses_with_the_shipped_reader`` /
  ``test_tc1802_nine_md_sections_intact_tenth_section_added``: the new
  section exists under ``changes_file_notation`` with the title "Changes
  file notation" and >= 3 non-empty steps; the body names every stable
  wire field of the v2 envelope and entry grammar (changes/io.py
  LLR-001.1/.2 — format/version/kind/encoding/value_mode/entries, the
  bytes/string entry kinds with address/bytes/value, the optional
  symbol); the fenced minimal example parses error-free through the
  shipped reader into the documented bytes entry; and the data home holds
  EXACTLY the twelve code-authored sections (batch-101 Inc 14, D-3: the
  nine-section ``help_sections.md`` census is retired and no test reads
  the draft).
"""
from __future__ import annotations

import re

from s19_app.tui.changes.io import parse_change_document
from s19_app.tui.window_help import WINDOW_HELP_SECTIONS, section_body_text

#: The sections still ported from the untracked ``help_sections.md`` draft
#: (TC-707's ``_EXPECTED_KEYS``). Named supersession (batch-101 Inc 14,
#: orchestrator ruling D-3): the last four (``checks``, ``a2l``, ``workspace``,
#: ``split_join_export``) are rewritten code-authored (F-37 / D7-26), the draft
#: is in no clone, and no test reads it any more. The set is empty.
_MD_AUTHORED_KEYS: frozenset = frozenset()

#: The twelve keys of the data home, all code-authored (R-WHELP.7).
_ALL_KEYS = frozenset(
    {
        "patch",
        "checks",
        "crc_designer",
        "reports",
        "map",
        "flow",
        "a2l",
        "workspace",
        "split_join_export",
        "flow_execution",
        "check_editor",
        "changes_file_notation",
    }
)

#: The batch-96 section under test.
SECTION_KEY = "changes_file_notation"

#: Its authored title (short, per the operator's request wording).
EXPECTED_TITLE = "Changes file notation"


def test_tc1802_changes_file_notation_section_ships() -> None:
    """TC-1802 (the section exists): ``changes_file_notation`` ships in the
    data home with the expected title and >= 3 non-empty numbered steps —
    the same shape contract every TC-707 section meets."""
    assert SECTION_KEY in WINDOW_HELP_SECTIONS, (
        "the changes-file notation section must ship in WINDOW_HELP_SECTIONS"
    )
    section = WINDOW_HELP_SECTIONS[SECTION_KEY]
    assert section["title"] == EXPECTED_TITLE
    steps = section["steps"]
    assert isinstance(steps, tuple) and len(steps) >= 3, (
        "the notation section ships >= 3 numbered steps like every section"
    )
    for step in steps:
        assert isinstance(step, str) and step.strip(), (
            "no empty step may ship (a blank modal is the boundary the "
            "contract forbids)"
        )


def test_tc1802_notation_documents_the_wire_fields() -> None:
    """TC-1802 (the notation is faithful): the rendered body names every
    stable wire field of the v2 grammar — the five envelope fields
    (``format`` ``s19app-changeset``, ``version`` ``2.0``, ``kind``,
    ``encoding``, ``value_mode``, the ``entries`` array) and the entry
    fields (``type`` bytes/string, ``address``, ``bytes``, ``value``, the
    optional ``symbol``) — so a hand-written file can be assembled from
    the help alone."""
    body = section_body_text(SECTION_KEY)
    for token in (
        "s19app-changeset",
        '"version": "2.0"',
        '"kind"',
        '"encoding"',
        '"value_mode"',
        '"entries"',
        '"type": "bytes"',
        '"address"',
        '"bytes"',
        "`string`",
        "`value`",
        "`symbol`",
    ):
        assert token in body, (
            f"the notation help must document the wire field {token!r} — "
            f"a hand-written file is assembled from this help alone"
        )


def test_tc1802_minimal_example_parses_with_the_shipped_reader() -> None:
    """TC-1802 (the acceptance oracle): the section's fenced minimal
    example parses CLEAN through the shipped v2 reader and resolves to the
    documented entry — one bytes patch at 0x800020 with run DE AD BE EF.
    The help never documents a file the app itself refuses."""
    body = section_body_text(SECTION_KEY)
    match = re.search(r"```json\n(.*?)\n```", body, re.DOTALL)
    assert match, "the notation section must ship a fenced json example"
    document = parse_change_document(match.group(1))
    assert not document.has_errors, [
        (issue.code, issue.message) for issue in document.issues
    ]
    assert document.format == "s19app-changeset"
    assert document.version == "2.0"
    assert document.kind == "change"
    assert len(document.entries) == 1
    entry = document.entries[0]
    assert entry.entry_type == "bytes"
    assert entry.address == 0x800020
    assert entry.encoded_bytes == (0xDE, 0xAD, 0xBE, 0xEF)


def test_tc1802_nine_md_sections_intact_tenth_section_added() -> None:
    """TC-1802 (the no-disturbance census; node name kept, it no longer reads
    the md): the data home holds EXACTLY the twelve code-authored sections
    (R-WHELP.12/4 guard), this tenth key among them.

    Named supersession (batch-101 Inc 14, D-3): the four sections that were
    still checked against ``help_sections.md`` are rewritten code-authored and
    no test reads the draft. Negative control: a data home missing one key, or
    holding one more, differs from the twelve.
    """
    assert _MD_AUTHORED_KEYS == frozenset()
    assert SECTION_KEY in _ALL_KEYS
    assert frozenset(WINDOW_HELP_SECTIONS) == _ALL_KEYS, (
        "the data home must hold exactly the twelve code-authored sections"
    )
    assert _key_census_defects(WINDOW_HELP_SECTIONS) == {}
    # Negative controls (E5 C-8, F6): the same detector run on a data home
    # missing one key, and on one holding an extra key, reports each.
    missing = {k: v for k, v in WINDOW_HELP_SECTIONS.items() if k != "a2l"}
    assert _key_census_defects(missing) == {"missing": ["a2l"]}
    extra = {**WINDOW_HELP_SECTIONS, "extra": WINDOW_HELP_SECTIONS["a2l"]}
    assert _key_census_defects(extra) == {"extra": ["extra"]}


def _key_census_defects(sections) -> dict:
    """The keys a data home lacks or holds beyond the twelve (R-WHELP.12/4)."""
    keys = frozenset(sections)
    defects = {}
    if _ALL_KEYS - keys:
        defects["missing"] = sorted(_ALL_KEYS - keys)
    if keys - _ALL_KEYS:
        defects["extra"] = sorted(keys - _ALL_KEYS)
    return defects
