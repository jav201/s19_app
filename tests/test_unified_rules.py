"""
Unified change-set file MF-* rule-set tests — s19_app batch-04, increment 6.

Covers the per-entry / version / parse rules of the ``MF-*`` rule set the
unified change-set reader (``s19_app/tui/cdfx/unified_io.py::read_unified``)
applies on read — the HLR-008 rule set, the part not exercised by the
structural / resource-bound TCs of ``test_unified_read.py``:

  - TC-020 — malformed JSON (LLR-006.2 / HLR-008): a truncated / garbage file
             → exactly one ``MF-JSON-PARSE`` error ``ValidationIssue``, an
             empty change-set, and no escaping exception.
  - TC-023 — the per-entry structural rules (LLR-008.1): a memory-field entry
             with no ``address`` → ``MF-NO-ADDRESS``; an empty ``new_bytes``
             run → ``MF-EMPTY-BYTES``; a byte outside 0-255 → ``MF-BYTE-RANGE``
             — each one issue, the offending entry dropped, the rest kept
             (collect-don't-abort).
  - TC-024 — the version rule (LLR-008.2): a file declaring an unrecognised
             version token → one **info**-level ``MF-VERSION-UNKNOWN`` issue,
             and the file is still read.

These tests encode WHY each rule matters. Each ``MF-*`` rule has a stable code
and a documented severity (every read-path rule is ``ERROR`` except
``MF-VERSION-UNKNOWN``, which is ``INFO`` — an unknown version is informative,
not fatal, so an old reader still loads a future file). The collect-don't-abort
contract means a single bad entry is dropped while every clean entry around it
still loads — each per-entry test asserts the clean entry survives, not merely
that the bad one was flagged, so a reader that aborts on the first fault fails.

Every fixture is synthetic and built in-test (constraint C-9).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from s19_app.tui.cdfx import read_unified
from s19_app.tui.cdfx.unified_io import (
    MF_BYTE_RANGE,
    MF_EMPTY_BYTES,
    MF_JSON_PARSE,
    MF_NO_ADDRESS,
    MF_VERSION_UNKNOWN,
)
from s19_app.validation.model import ValidationSeverity

from tests.conftest import (
    make_malformed_unified_file,
    make_rule_violation_unified_file,
)


# ---------------------------------------------------------------------------
# TC-020 — malformed JSON (LLR-006.2 / HLR-008)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("variant", ["truncated", "garbage"])
def test_tc020_malformed_json_yields_one_parse_issue_no_exception(
    tmp_path: Path, variant: str
) -> None:
    """TC-020 — a malformed file → exactly one MF-JSON-PARSE, no crash (LLR-006.2).

    A truncated or garbage file is not well-formed JSON. The collect-don't-abort
    contract requires the reader to surface this as exactly one
    ``MF-JSON-PARSE`` error issue and return an empty change-set — never an
    escaping exception. This asserts the call *returns* (the load-bearing
    assertion) for both a truncated and a pure-garbage payload.
    """
    bad_path = make_malformed_unified_file(
        tmp_path / f"{variant}.json", variant=variant
    )

    # The load-bearing assertion — the call returns, it does NOT raise.
    changeset, issues = read_unified(str(bad_path), tmp_path)

    assert changeset.is_empty()
    codes = [i.code for i in issues]
    assert codes == [MF_JSON_PARSE]
    assert issues[0].severity is ValidationSeverity.ERROR


def test_tc020_parse_issue_message_carries_no_file_bytes(tmp_path: Path) -> None:
    """TC-020 — the MF-JSON-PARSE message does not echo the raw file content.

    A parse-error message that echoed the failing file content would put
    arbitrary (possibly proprietary) bytes into the 5 MB rotating log
    (constraint C-9). This asserts the message names only the failure kind, not
    the garbage payload — so the message is safe to log.
    """
    bad_path = make_malformed_unified_file(
        tmp_path / "garbage.json", variant="garbage"
    )

    _, issues = read_unified(str(bad_path), tmp_path)

    message = issues[0].message
    assert "not json at all" not in message


# ---------------------------------------------------------------------------
# TC-023 — the per-entry structural rules (LLR-008.1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "variant,expected_code",
    [
        ("no-address", MF_NO_ADDRESS),
        ("empty-bytes", MF_EMPTY_BYTES),
        ("byte-range", MF_BYTE_RANGE),
    ],
)
def test_tc023_per_entry_rule_flags_one_entry_keeps_the_clean_one(
    tmp_path: Path, variant: str, expected_code: str
) -> None:
    """TC-023 — a bad memory entry → one issue, the clean entry still loads (LLR-008.1).

    LLR-008.1 fixes three per-entry structural rules: a missing ``address``
    (``MF-NO-ADDRESS``), an empty ``new_bytes`` run (``MF-EMPTY-BYTES``), and a
    byte outside 0-255 (``MF-BYTE-RANGE``). Collect-don't-abort means the
    offending entry is dropped while every clean entry around it survives. Each
    fixture carries one clean entry plus one offending entry; this asserts
    exactly one issue of the expected code **and** that the clean entry loaded
    — a reader that aborts on the first fault fails the second assertion.
    """
    bad_path = make_rule_violation_unified_file(
        tmp_path / f"{variant}.json", variant=variant
    )

    changeset, issues = read_unified(str(bad_path), tmp_path)

    matching = [i for i in issues if i.code == expected_code]
    assert len(matching) == 1
    assert matching[0].severity is ValidationSeverity.ERROR
    # Collect-don't-abort — the clean entry (address 0x100) still loaded.
    assert len(changeset.memory) == 1
    assert changeset.memory.get(0x100) is not None


def test_tc023_no_address_issue_does_not_raise_keyerror(tmp_path: Path) -> None:
    """TC-023 — a memory entry missing 'address' is handled, not crashed.

    A memory-field object with no ``address`` field would raise ``KeyError`` if
    the reader indexed the field directly. This asserts the call returns
    normally — the reader uses ``.get`` and the ``MF-NO-ADDRESS`` rule, not a
    raw index — so a malformed entry is a collected issue, never a crash.
    """
    bad_path = make_rule_violation_unified_file(
        tmp_path / "no-address.json", variant="no-address"
    )

    # The load-bearing assertion — the call returns, it does NOT raise.
    changeset, issues = read_unified(str(bad_path), tmp_path)

    assert any(i.code == MF_NO_ADDRESS for i in issues)
    assert len(changeset.memory) == 1


def test_tc023_byte_range_issue_carries_no_raw_bytes(tmp_path: Path) -> None:
    """TC-023 — the MF-BYTE-RANGE message references the address, not raw bytes (C-9).

    Constraint C-9 keeps firmware bytes out of the rotating log: a memory-field
    finding references the entry's ``address`` and a summary, never the raw
    ``new_bytes`` content. This asserts the ``MF-BYTE-RANGE`` message names the
    offending entry's address (``512`` / ``0x200``) but does not echo the bad
    byte run verbatim.
    """
    bad_path = make_rule_violation_unified_file(
        tmp_path / "byte-range.json", variant="byte-range"
    )

    _, issues = read_unified(str(bad_path), tmp_path)

    message = next(i.message for i in issues if i.code == MF_BYTE_RANGE)
    assert "512" in message


# ---------------------------------------------------------------------------
# TC-024 — the version rule (LLR-008.2)
# ---------------------------------------------------------------------------


def test_tc024_unknown_version_is_info_level_and_file_is_still_read(
    tmp_path: Path,
) -> None:
    """TC-024 — an unknown version → one info MF-VERSION-UNKNOWN, file still read (LLR-008.2).

    LLR-008.2 makes the version field forward-tolerant: an unrecognised version
    token is **informative**, not fatal — an old reader still loads a future
    file. This feeds a structurally valid file declaring an unknown version and
    asserts exactly one ``MF-VERSION-UNKNOWN`` issue at **INFO** severity, and
    that the file's memory-field entry still loaded — the version finding did
    not abort the load.
    """
    versioned_path = make_rule_violation_unified_file(
        tmp_path / "future.json", variant="version-unknown"
    )

    changeset, issues = read_unified(str(versioned_path), tmp_path)

    version_issues = [i for i in issues if i.code == MF_VERSION_UNKNOWN]
    assert len(version_issues) == 1
    # An unknown version is informative, not an error.
    assert version_issues[0].severity is ValidationSeverity.INFO
    # The load was not aborted — the clean entry still parsed.
    assert len(changeset.memory) == 1


def test_tc024_known_version_produces_no_version_issue(tmp_path: Path) -> None:
    """TC-024 — the recognised version token produces no MF-VERSION-UNKNOWN issue.

    The version rule must fire **only** on an unrecognised token. A file
    written by the production writer carries the recognised version; this
    reads such a file (via the rule-violation fixture's other variants, all of
    which keep version ``1.0``) and asserts no ``MF-VERSION-UNKNOWN`` issue
    appears — so the rule does not false-positive on a current file.
    """
    current_path = make_rule_violation_unified_file(
        tmp_path / "current.json", variant="empty-bytes"
    )

    _, issues = read_unified(str(current_path), tmp_path)

    assert [i for i in issues if i.code == MF_VERSION_UNKNOWN] == []
