"""
Change-set file rule tests — s19_app batch-04, increment 6; re-pointed to the
v2 reader (``s19_app/tui/changes/io.py::read_change_document``) at batch-07
E3b (§6.6 dispositions).

Covers the parse-rejection and version arms of the read rule set:

  - TC-020 — malformed JSON (truncated / garbage bytes) → exactly one
             ``MF-JSON-PARSE`` error issue, an empty document, no exception;
             and the parse-issue message never embeds the file's raw bytes
             (C-9).
  - TC-023 — FOLDED at E3b: the per-entry rule arms (missing address, empty
             bytes, out-of-range byte, skip-and-continue, no-KeyError, C-9
             message discipline) are carried by
             ``test_changes_schema.py::test_entry_faults`` — the v2 wire
             grammar renamed the rule codes (``CHG-ADDRESS-SYNTAX`` /
             ``CHG-VALUE-EMPTY`` / ``CHG-BYTES-SYNTAX``) and that suite
             asserts each exact code with a trailing clean entry kept.
  - TC-024 — REWRITTEN to the v2 envelope: the v2 metadata rules validate
             ``format`` / ``kind`` / ``encoding`` / ``value_mode`` but are
             deliberately version-tolerant — an unrecognised ``version``
             token produces no finding and the file is still read (the
             forward-compat intent the batch-04 INFO-level
             ``MF-VERSION-UNKNOWN`` carried), and the current ``"2.0"``
             token produces no finding either.

The collect-don't-abort intent is unchanged: a parse rejection is a collected
``ValidationIssue``, never an escaping exception, and never a leak of file
content into the message text. Every fixture is synthetic and built in-test
(constraint C-9).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from s19_app.tui.changes.io import (
    MF_JSON_PARSE,
    read_change_document,
)
from s19_app.validation.model import ValidationSeverity

from tests.conftest import make_malformed_unified_file


# ---------------------------------------------------------------------------
# TC-020 — malformed JSON is one parse issue, never an exception
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("variant", ["truncated", "garbage"])
def test_tc020_malformed_json_yields_one_parse_issue_no_exception(
    tmp_path: Path, variant: str
) -> None:
    """TC-020 — a malformed file → exactly one MF-JSON-PARSE, no crash.

    A truncated or garbage file is not well-formed JSON. The
    collect-don't-abort contract requires the reader to surface this as
    exactly one ``MF-JSON-PARSE`` error issue and return an empty document —
    never an escaping exception. This asserts the call *returns* (the
    load-bearing assertion) for both a truncated and a pure-garbage payload.
    """
    bad_path = make_malformed_unified_file(
        tmp_path / f"{variant}.json", variant=variant
    )

    # The load-bearing assertion — the call returns, it does NOT raise.
    document = read_change_document(str(bad_path), tmp_path)

    assert document.entries == []
    codes = [i.code for i in document.issues]
    assert codes == [MF_JSON_PARSE]
    assert document.issues[0].severity is ValidationSeverity.ERROR


def test_tc020_parse_issue_message_carries_no_file_bytes(tmp_path: Path) -> None:
    """TC-020 — the MF-JSON-PARSE message does not echo the raw file content.

    A parse-error message that echoed the failing file content would put
    arbitrary (possibly proprietary) bytes into the 5 MB rotating log
    (constraint C-9). This asserts the message names only the failure kind,
    not the garbage payload — so the message is safe to log.
    """
    bad_path = make_malformed_unified_file(
        tmp_path / "garbage.json", variant="garbage"
    )

    document = read_change_document(str(bad_path), tmp_path)

    message = document.issues[0].message
    assert "not json at all" not in message


# ---------------------------------------------------------------------------
# TC-024 — version tolerance (REWRITTEN to the v2 envelope)
# ---------------------------------------------------------------------------


def _v2_payload_with_version(version: object) -> bytes:
    """A minimal valid v2 document carrying the given version token."""
    return (
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": version,
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": [
                    {"type": "bytes", "address": "0x100", "bytes": "41 42"}
                ],
            }
        )
        + "\n"
    ).encode("utf-8")


def test_tc024_unknown_version_is_tolerated_and_file_is_still_read(
    tmp_path: Path,
) -> None:
    """TC-024 — a future version token produces no finding; entries are read.

    The v2 envelope rules (LLR-001.3) validate ``format`` / ``kind`` /
    ``encoding`` / ``value_mode`` and are deliberately tolerant of the
    ``version`` field, so a file written by a newer tool still loads — the
    forward-compat intent of the batch-04 INFO-level version finding, now
    with no finding at all. A regression that starts hard-rejecting unknown
    versions fails this test.
    """
    path = tmp_path / "future.json"
    path.write_bytes(_v2_payload_with_version("99.0-from-the-future"))

    document = read_change_document(str(path), tmp_path)

    assert document.issues == []
    assert [e.address for e in document.entries] == [0x100]
    assert document.version == "99.0-from-the-future"


def test_tc024_known_version_produces_no_version_issue(tmp_path: Path) -> None:
    """TC-024 — the current ``"2.0"`` version token produces no finding."""
    path = tmp_path / "current.json"
    path.write_bytes(_v2_payload_with_version("2.0"))

    document = read_change_document(str(path), tmp_path)

    assert document.issues == []
    assert len(document.entries) == 1
