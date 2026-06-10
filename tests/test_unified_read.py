"""
Change-set file read tests — s19_app batch-04, increment 6; re-pointed to the
v2 reader (``s19_app/tui/changes/io.py::read_change_document``) at batch-07
E3b (§6.6 dispositions).

Covers the structural / resource-bound parts of the read rule set:

  - TC-019 — FOLDED at E3b: the both-halves parse intent is carried by
             ``test_changes_schema.py::test_metadata_roundtrip`` (envelope)
             and ``test_change_service.py::test_v2_save_load_round_trip``
             (entry content) — the v2 document has no halves.
  - TC-014 — a well-formed-but-wrong-shape document: a bare ``[]``, a bare
             ``42``, or a bare string → exactly one ``MF-BAD-STRUCTURE``
             error issue, an empty document, and **no** escaping ``KeyError``;
             an object with no v2 envelope → the faulted-envelope outcome
             (one ERROR per missing metadata field, zero entries — F-A-16).
  - TC-021 — path resolution: a valid path is resolved through
             ``workspace.resolve_input_path`` and read; an unresolvable path
             yields exactly one error ``ValidationIssue`` and **no file is
             opened** (asserted via a no-open spy on ``Path.open``).
  - TC-022 — read-path size bound: with the injectable size-probe stubbed
             over the 256 MB cap, the reader produces exactly one
             ``MF-SIZE-CAP`` issue, an empty document, and ``json.load`` is
             never reached — the size check precedes parsing.
  - TC-035 — deeply-nested JSON: a document nested deep enough to overflow
             the stdlib parser's recursion → exactly one ``MF-JSON-PARSE``
             issue, an empty document, and **no** escaping ``RecursionError``.
  - TC-037 — decoded-structure ceilings: the breach arms are FOLDED into
             ``test_changes_schema.py::test_resource_ceilings_entry_count`` /
             ``test_resource_ceilings_encoded_run_length`` (the v2 seam
             lowers the ceiling instead of manufacturing 100k-entry files);
             the C-9 message arm is kept here against the seam.

These tests encode WHY each behaviour matters. The collect-don't-abort
contract means every failure mode — a wrong shape, a deeply-nested document,
an unresolvable path, an over-cap file — must surface as a collected
``ValidationIssue`` and never as an escaping exception; each test asserts the
*absence* of the escape as the load-bearing assertion, not merely that an
issue was produced. TC-021 and TC-022 assert the security boundary: an
arbitrary path is never opened, and an over-cap file is never read into
memory.

Every fixture is synthetic and built in-test (constraint C-9).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from s19_app.tui.changes import io as changes_io
from s19_app.tui.changes.io import (
    MF_BAD_STRUCTURE,
    MF_ENTRY_LIMIT,
    MF_JSON_PARSE,
    MF_PATH_UNRESOLVED,
    MF_SIZE_CAP,
    READ_SIZE_CAP_BYTES,
    read_change_document,
)
from s19_app.validation.model import ValidationSeverity

from tests.conftest import (
    make_change_file,
    make_deeply_nested_unified_file,
    make_malformed_unified_file,
)


# ---------------------------------------------------------------------------
# TC-014 — well-formed-but-wrong-shape document
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "variant",
    ["bare-list", "bare-int", "bare-string"],
)
def test_tc014_wrong_shape_document_yields_one_bad_structure_issue_no_keyerror(
    tmp_path: Path, variant: str
) -> None:
    """TC-014 — a non-object document → one MF-BAD-STRUCTURE, no KeyError.

    A well-formed JSON document that is not a JSON object (``[]``, ``42``, a
    bare string) trips neither a parse error nor any per-entry rule — there
    are no entries. Without the ``MF-BAD-STRUCTURE`` shape guard, a reader
    indexing ``document["entries"]`` would raise an uncaught error. This
    asserts the *absence of the escape* — the call must return normally —
    and exactly one ``MF-BAD-STRUCTURE`` error issue.
    """
    bad_path = make_malformed_unified_file(
        tmp_path / f"{variant}.json", variant=variant
    )

    # The load-bearing assertion: the call returns, it does NOT raise.
    document = read_change_document(str(bad_path), tmp_path)

    assert document.entries == []
    codes = [i.code for i in document.issues]
    assert codes == [MF_BAD_STRUCTURE]
    assert document.issues[0].severity is ValidationSeverity.ERROR


def test_tc014_object_without_v2_envelope_is_a_faulted_envelope(
    tmp_path: Path,
) -> None:
    """TC-014 (REWRITTEN to the v2 envelope) — an object with none of the
    five metadata fields collects one ERROR per missing envelope rule and
    yields zero entries (the faulted-envelope contract, F-A-16).

    The batch-04 reader reported a single ``MF-BAD-STRUCTURE`` for a
    "no-halves" object; the v2 reader validates the envelope field by field
    (collect-don't-abort), so every fault is named, and entry content is
    never interpreted under a faulted envelope.
    """
    bad_path = make_malformed_unified_file(
        tmp_path / "no-envelope.json", variant="no-envelope"
    )

    document = read_change_document(str(bad_path), tmp_path)

    assert document.entries == []
    codes = sorted(i.code for i in document.issues)
    assert codes == sorted(
        [
            "CHG-FORMAT",
            "CHG-KIND-UNKNOWN",
            "CHG-ENCODING-UNKNOWN",
            "CHG-VALUE-MODE-UNKNOWN",
            MF_BAD_STRUCTURE,  # the 'entries' array is absent
        ]
    )
    for issue in document.issues:
        assert issue.severity is ValidationSeverity.ERROR


def test_tc014_wrong_shape_document_is_parseable_json(tmp_path: Path) -> None:
    """TC-014 — the wrong-shape fixture really is well-formed JSON.

    The envelope faults are meaningful only when separated from
    ``MF-JSON-PARSE``: the document must parse cleanly and still be the wrong
    shape. This asserts the fixture is genuinely valid JSON, so the test
    exercises the envelope guard and not the parse-error path.
    """
    bad_path = make_malformed_unified_file(
        tmp_path / "no-envelope.json", variant="no-envelope"
    )

    # Parses without error — it is the *shape* that is wrong, not the syntax.
    parsed = json.loads(bad_path.read_bytes())
    assert isinstance(parsed, dict) and "entries" not in parsed


# ---------------------------------------------------------------------------
# TC-021 — path resolution
# ---------------------------------------------------------------------------


def test_tc021_valid_path_is_resolved_and_read(tmp_path: Path) -> None:
    """TC-021 — a valid change-file path is resolved via resolve_input_path.

    The reader resolves a user-supplied path through
    ``workspace.resolve_input_path`` before opening it. This passes a path
    that resolves and asserts the file is read into a populated document —
    the resolution path works end to end.
    """
    change_path = make_change_file(tmp_path / "cs.json")

    document = read_change_document(str(change_path), tmp_path)

    assert document.issues == []
    assert len(document.entries) == 3


def test_tc021_unresolvable_path_yields_one_issue_and_opens_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-021 — an unresolvable path → one issue, no file opened.

    An unresolvable path must surface as one error ``ValidationIssue`` and the
    reader must **not** open an arbitrary location. This installs a no-open spy
    on ``Path.open`` and asserts it is never called — the load-bearing security
    assertion — and that exactly one ``MF-PATH-UNRESOLVED`` error issue is
    produced for the missing path.
    """
    open_calls: list[Path] = []
    real_open = Path.open

    def _spy_open(self: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        open_calls.append(self)
        return real_open(self, *args, **kwargs)  # pragma: no cover - never hit

    monkeypatch.setattr(Path, "open", _spy_open)

    document = read_change_document(
        str(tmp_path / "does-not-exist.json"), tmp_path
    )

    # The load-bearing assertion — no file was opened.
    assert open_calls == []
    assert document.entries == []
    codes = [i.code for i in document.issues]
    assert codes == [MF_PATH_UNRESOLVED]
    assert document.issues[0].severity is ValidationSeverity.ERROR


# ---------------------------------------------------------------------------
# TC-022 — read-path size bound
# ---------------------------------------------------------------------------


def test_tc022_oversized_file_is_rejected_before_json_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-022 — an over-cap file → one MF-SIZE-CAP, json.load never reached.

    The 256 MB on-disk size cap is enforced **before** parsing — the file is
    never read into memory. This stubs the injectable size-probe to report an
    over-cap byte size and installs a spy on ``json.load`` that fails the
    test if called. The load-bearing assertion is that ``json.load`` is never
    reached: the size check precedes parsing.
    """
    # A real, small, well-formed file — only the probe reports it as oversized.
    change_path = make_change_file(tmp_path / "small.json")

    load_calls: list[object] = []

    def _spy_load(*args: object, **kwargs: object) -> object:
        load_calls.append(args)
        raise AssertionError("json.load must not be reached for an over-cap file")

    monkeypatch.setattr(changes_io.json, "load", _spy_load)

    document = read_change_document(
        str(change_path),
        tmp_path,
        size_probe=lambda _: READ_SIZE_CAP_BYTES + 1,
    )

    # The load-bearing assertion — the file was never parsed into memory.
    assert load_calls == []
    assert document.entries == []
    codes = [i.code for i in document.issues]
    assert codes == [MF_SIZE_CAP]
    assert document.issues[0].severity is ValidationSeverity.ERROR


def test_tc022_at_cap_file_is_not_rejected(tmp_path: Path) -> None:
    """TC-022 — a file exactly at the cap is read, only *over* the cap is rejected.

    The cap is a strict ``>`` bound — a file *at* exactly 256 MB is still
    readable. This stubs the probe to report exactly the cap and asserts the
    reader proceeds to parse, so the boundary is pinned and an off-by-one in
    the comparison fails the test.
    """
    change_path = make_change_file(tmp_path / "small.json")

    document = read_change_document(
        str(change_path), tmp_path, size_probe=lambda _: READ_SIZE_CAP_BYTES
    )

    assert [i.code for i in document.issues if i.code == MF_SIZE_CAP] == []
    assert len(document.entries) == 3


# ---------------------------------------------------------------------------
# TC-035 — deeply-nested JSON
# ---------------------------------------------------------------------------


def test_tc035_deeply_nested_json_yields_one_parse_issue_no_recursionerror(
    tmp_path: Path,
) -> None:
    """TC-035 — a deeply-nested document → one MF-JSON-PARSE, no RecursionError.

    ``RecursionError`` is a ``RuntimeError``, **not** a ``json.JSONDecodeError``
    — a document nested deep enough overflows the stdlib parser's C recursion,
    and an ``except json.JSONDecodeError`` clause alone would let it escape and
    crash the load. This feeds a 120k-deep document and asserts the call
    *returns* (the load-bearing assertion — no escaping ``RecursionError``)
    with exactly one ``MF-JSON-PARSE`` error issue and an empty document.
    """
    deep_path = make_deeply_nested_unified_file(tmp_path / "deep.json")

    # The load-bearing assertion — the call returns, it does NOT raise
    # RecursionError. If the except clause missed RecursionError this line
    # would raise instead of binding the document.
    document = read_change_document(str(deep_path), tmp_path)

    assert document.entries == []
    codes = [i.code for i in document.issues]
    assert codes == [MF_JSON_PARSE]
    assert document.issues[0].severity is ValidationSeverity.ERROR


# ---------------------------------------------------------------------------
# TC-037 — decoded-structure ceiling, C-9 message arm. (The entry-count and
# run-length breach arms are folded into the E1 seam-based tests — see the
# module docstring.)
# ---------------------------------------------------------------------------


def test_tc037_entry_limit_message_carries_no_raw_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-037 — the MF-ENTRY-LIMIT message references a count, not raw bytes (C-9).

    Constraint C-9 keeps proprietary firmware bytes out of the rotating log:
    a finding references the entry's address and a count, never the raw byte
    content. The over-run fixture's run is all zero bytes; this asserts the
    message carries the byte *count* and the run-length *ceiling* but not a
    literal byte sequence (neither the wire's ``00 00`` token spelling nor a
    decimal list).
    """
    monkeypatch.setattr(changes_io, "MF_RUN_LENGTH_CEILING", 4)
    over = 4 + 1
    payload = {
        "format": "s19app-changeset",
        "version": "2.0",
        "kind": "change",
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": [
            {
                "type": "bytes",
                "address": "0x400",
                "bytes": " ".join(["00"] * over),
            }
        ],
    }
    over_path = tmp_path / "longrun.json"
    over_path.write_text(json.dumps(payload), encoding="utf-8")

    document = read_change_document(str(over_path), tmp_path)

    message = next(
        i.message for i in document.issues if i.code == MF_ENTRY_LIMIT
    )
    assert str(over) in message
    assert "4" in message
    # No literal byte run leaked into the message.
    assert "00 00" not in message
    assert "0, 0, 0" not in message
