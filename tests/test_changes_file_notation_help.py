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
  shipped reader into the documented bytes entry; and the nine batch-95
  sections are still present and verbatim against ``help_sections.md``,
  with the data home grown to EXACTLY those nine plus this one.
"""
from __future__ import annotations

import re
from pathlib import Path

from s19_app.tui.changes.io import parse_change_document
from s19_app.tui.window_help import WINDOW_HELP_SECTIONS, section_body_text

#: The authored-copy source of the nine batch-95 sections (TC-707's
#: fidelity census) — read-only here; this file only re-asserts that the
#: nine stayed intact.
_HELP_SECTIONS_MD = (
    Path(__file__).resolve().parent.parent
    / "prototypes"
    / "cambios_10_12_2026"
    / "help_sections.md"
)

#: The nine batch-95 md-authored section keys (TC-707's ``_EXPECTED_KEYS``)
#: — the frozen census this new section must not disturb.
_MD_AUTHORED_KEYS = frozenset(
    {
        # batch-97 Inc-4 (named supersession, D25): ``patch`` is rewritten
        # code-authored (LLR-148.6) and leaves the md census. At the Inc-4
        # gate (operator, 2026-10-21) ``crc_designer`` and ``reports`` follow:
        # code names their folder, the untracked draft keeps its wording.
        # batch-97 Inc-5 (named supersession, D25): ``flow`` is rewritten
        # code-authored too and leaves the md census.
        "checks",
        "map",
        "a2l",
        "workspace",
        "split_join_export",
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
    """TC-1802 (the no-disturbance census): the data home holds EXACTLY
    the nine batch-95 md-authored sections plus this one tenth key — and
    every one of the nine is still a verbatim port of
    ``help_sections.md`` (title + every step string), so the batch-96
    addition disturbed nothing the batch-95 contract froze."""
    # Named supersession (batch-97 Inc-3): the code-authored ``check_editor``
    # section (LLR-148.6) joins the data home; it is not an md port either.
    assert frozenset(WINDOW_HELP_SECTIONS) == _MD_AUTHORED_KEYS | {
        SECTION_KEY,
        "check_editor",
        "patch",
        "crc_designer",
        "reports",
        "flow",
    }, (
        "the data home must hold exactly the nine md-authored sections "
        "plus the batch-96 changes_file_notation and batch-97 check_editor "
        "sections"
    )
    md_text = _HELP_SECTIONS_MD.read_text(encoding="utf-8")
    normalized_md = re.sub(r"\s+", " ", md_text)
    for key in _MD_AUTHORED_KEYS:
        section = WINDOW_HELP_SECTIONS[key]
        title = str(section["title"])
        assert title in normalized_md, (
            f"{key}: the batch-95 title {title!r} must stay in the md"
        )
        for step in section["steps"]:
            assert step in normalized_md, (
                f"{key}: batch-95 step drifted from help_sections.md: "
                f"{step!r}"
            )
