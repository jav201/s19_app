"""
v2 change-file schema tests — batch-07 increment E1 (TC-001..TC-004, TC-007,
TC-008).

Covers LLR-001.1 (metadata round-trip), LLR-001.2 (entry shapes under the
strict wire grammar), LLR-001.3 (metadata faults, faulted envelope →
zero entries, text-codec allowlist), LLR-001.4 (per-entry faults incl.
broadened encode-failure coverage, C-9 no-raw-content), LLR-001.7 (resource
ceilings, size cap BEFORE parse, pre-encode guard), and LLR-001.8 (v1 hard
break with CHG-FORMAT suppression — F-A-03).

All access goes through the package facade ``s19_app.tui.changes``;
ceiling monkeypatching targets the implementation module
``s19_app.tui.changes.io`` (the functions read module globals at call time).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

import s19_app.tui.changes.io as changes_io
from s19_app.tui.changes import (
    CHG_ADDRESS_SYNTAX,
    CHG_BYTES_SYNTAX,
    CHG_ENCODE_FAIL,
    CHG_ENCODING_UNKNOWN,
    CHG_FORMAT,
    CHG_KIND_UNKNOWN,
    CHG_V1_FORMAT,
    CHG_VALUE_EMPTY,
    CHG_VALUE_MODE_UNKNOWN,
    FORMAT_ID,
    FORMAT_VERSION,
    MF_BAD_STRUCTURE,
    MF_ENTRY_LIMIT,
    MF_JSON_PARSE,
    MF_PATH_UNRESOLVED,
    MF_SIZE_CAP,
    READ_SIZE_CAP_BYTES,
    ChangeDocument,
    ChangeEntry,
    read_change_document,
    write_change_document,
)
from s19_app.tui.changes.io import DUMMY_CHANGESET_TEXT, parse_change_document
from s19_app.validation.model import ValidationSeverity


def _v2_payload(**overrides: object) -> dict:
    """Return a minimal valid v2 document dict with ``overrides`` applied."""
    payload: dict = {
        "format": FORMAT_ID,
        "version": FORMAT_VERSION,
        "kind": "change",
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": [],
    }
    payload.update(overrides)
    return payload


def _write_json(tmp_path: Path, payload: object, name: str = "doc.json") -> str:
    """Write ``payload`` as JSON under ``tmp_path`` and return the path text."""
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# TC-001 — LLR-001.1: metadata round-trip through write → read.
# ---------------------------------------------------------------------------


def test_metadata_roundtrip(tmp_path: Path) -> None:
    """All 5 metadata fields survive write→read byte-identical (LLR-001.1)."""
    document = ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="check",
        encoding="latin-1",
        value_mode="codes",
        entries=[
            ChangeEntry(
                "string", 0x80001000, (54, 56, 55), value=(54, 56, 55)
            ),
            ChangeEntry("bytes", 0x800020, (0xDE, 0xAD)),
        ],
    )
    written_path, write_issues = write_change_document(document, tmp_path)
    assert write_issues == []
    assert written_path is not None

    loaded = read_change_document(str(written_path), tmp_path)
    assert loaded.issues == []
    # The 5 metadata fields, byte-identical (deliberately non-default values
    # for kind / encoding / value_mode so a hardcoded reader default cannot
    # fake the round-trip).
    assert loaded.format == FORMAT_ID
    assert loaded.version == FORMAT_VERSION
    assert loaded.kind == "check"
    assert loaded.encoding == "latin-1"
    assert loaded.value_mode == "codes"
    # Entries survive with encoded-byte fidelity.
    assert [(e.entry_type, e.address, e.encoded_bytes) for e in loaded.entries] == [
        ("string", 0x80001000, (54, 56, 55)),
        ("bytes", 0x800020, (0xDE, 0xAD)),
    ]


# ---------------------------------------------------------------------------
# TC-002 — LLR-001.2: entry shapes under the strict wire grammar.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value_mode", "entry", "expected"),
    [
        # -- accepted shapes --------------------------------------------------
        pytest.param(
            "text",
            {"type": "string", "address": "0x80001000", "value": "ABC"},
            ("accept", 0x80001000, (65, 66, 67)),
            id="accept-string-text",
        ),
        pytest.param(
            "text",
            {"type": "bytes", "address": "0x800020", "bytes": "DE AD BE EF"},
            ("accept", 0x800020, (0xDE, 0xAD, 0xBE, 0xEF)),
            id="accept-bytes-multi-token",
        ),
        pytest.param(
            "text",
            {"type": "bytes", "address": "0x800020", "bytes": "ff"},
            ("accept", 0x800020, (0xFF,)),
            id="accept-bytes-lowercase-token",
        ),
        pytest.param(
            "text",
            {"type": "bytes", "address": 4096, "bytes": "01"},
            ("accept", 4096, (0x01,)),
            id="accept-integer-address",
        ),
        pytest.param(
            "codes",
            {"type": "string", "address": "0x100", "value": [54, 56, 55]},
            ("accept", 0x100, (54, 56, 55)),
            id="accept-string-codes",
        ),
        # -- rejected shapes (strict wire grammar) ----------------------------
        pytest.param(
            "text",
            {"type": "bytes", "address": "80001000", "bytes": "01"},
            ("reject", CHG_ADDRESS_SYNTAX),
            id="reject-address-no-0x-prefix",
        ),
        pytest.param(
            "text",
            {"type": "bytes", "address": -5, "bytes": "01"},
            ("reject", CHG_ADDRESS_SYNTAX),
            id="reject-address-negative-int",
        ),
        pytest.param(
            "text",
            {"type": "bytes", "address": True, "bytes": "01"},
            ("reject", CHG_ADDRESS_SYNTAX),
            id="reject-address-json-bool",
        ),
        pytest.param(
            "text",
            {"type": "bytes", "address": "0x100", "bytes": "DE,AD"},
            ("reject", CHG_BYTES_SYNTAX),
            id="reject-bytes-comma-separated",
        ),
        pytest.param(
            "text",
            {"type": "bytes", "address": "0x100", "bytes": "0xFF"},
            ("reject", CHG_BYTES_SYNTAX),
            id="reject-bytes-0x-prefixed-token",
        ),
        pytest.param(
            "text",
            {"type": "bytes", "address": "0x100", "bytes": "F"},
            ("reject", CHG_BYTES_SYNTAX),
            id="reject-bytes-single-digit-token",
        ),
    ],
)
def test_entry_shapes(
    tmp_path: Path,
    value_mode: str,
    entry: dict,
    expected: tuple,
) -> None:
    """Strict wire grammar: each shape parses exactly or is rejected with the
    exact CHG-* code (LLR-001.2)."""
    path_text = _write_json(
        tmp_path, _v2_payload(value_mode=value_mode, entries=[entry])
    )
    document = read_change_document(path_text, tmp_path)

    if expected[0] == "accept":
        _, address, encoded = expected
        assert document.issues == []
        assert len(document.entries) == 1
        assert document.entries[0].address == address
        assert document.entries[0].encoded_bytes == encoded
    else:
        _, code = expected
        assert [issue.code for issue in document.issues] == [code]
        assert document.entries == []


# ---------------------------------------------------------------------------
# TC-003 — LLR-001.3: metadata faults, one exact code each, zero entries.
# ---------------------------------------------------------------------------

_VALID_ENTRY = {"type": "bytes", "address": "0x100", "bytes": "01"}


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    [
        pytest.param(
            _v2_payload(format="not-a-known-format", entries=[_VALID_ENTRY]),
            CHG_FORMAT,
            id="format-unrecognized",
        ),
        pytest.param(
            _v2_payload(kind="patch", entries=[_VALID_ENTRY]),
            CHG_KIND_UNKNOWN,
            id="kind-unrecognized",
        ),
        pytest.param(
            _v2_payload(value_mode="binary", entries=[_VALID_ENTRY]),
            CHG_VALUE_MODE_UNKNOWN,
            id="value-mode-unrecognized",
        ),
        pytest.param(
            _v2_payload(encoding="no-such-codec-zz", entries=[_VALID_ENTRY]),
            CHG_ENCODING_UNKNOWN,
            id="encoding-unresolvable",
        ),
        pytest.param(
            _v2_payload(encoding="zlib_codec", entries=[_VALID_ENTRY]),
            CHG_ENCODING_UNKNOWN,
            id="encoding-non-text-codec-allowlist",
        ),
        pytest.param(
            ["not", "an", "object"],
            MF_BAD_STRUCTURE,
            id="top-level-not-object",
        ),
        pytest.param(
            _v2_payload(entries="not-an-array"),
            MF_BAD_STRUCTURE,
            id="entries-not-an-array",
        ),
    ],
)
def test_metadata_faults(
    tmp_path: Path, payload: object, expected_code: str
) -> None:
    """Each crafted metadata fault yields exactly its one code, and the
    faulted envelope yields ZERO entries (LLR-001.3 / F-A-16)."""
    path_text = _write_json(tmp_path, payload)
    document = read_change_document(path_text, tmp_path)

    assert [issue.code for issue in document.issues] == [expected_code]
    assert document.entries == []
    assert document.has_errors


# ---------------------------------------------------------------------------
# TC-004 — LLR-001.4: per-entry faults, skip-and-continue, C-9 no raw content.
# ---------------------------------------------------------------------------

_TRAILING_VALID = {"type": "bytes", "address": "0x9000", "bytes": "7E"}


@pytest.mark.parametrize(
    ("encoding", "value_mode", "fault_entry", "expected_code", "forbidden"),
    [
        pytest.param(
            "ascii",
            "text",
            {"type": "string", "address": "0x100", "value": "SECRETPAYLOADñ"},
            CHG_ENCODE_FAIL,
            "SECRETPAYLOAD",
            id="latin1-only-char-under-ascii",
        ),
        pytest.param(
            "utf-8",
            "codes",
            {"type": "string", "address": "0x100", "value": [1114112]},
            CHG_ENCODE_FAIL,
            "1114112",
            id="code-point-past-0x10FFFF-valueerror",
        ),
        pytest.param(
            "utf-8",
            "codes",
            {"type": "string", "address": "0x100", "value": [-1]},
            CHG_ENCODE_FAIL,
            None,
            id="negative-code-point",
        ),
        pytest.param(
            "utf-8",
            "codes",
            {"type": "string", "address": "0x100", "value": ["x"]},
            CHG_ENCODE_FAIL,
            None,
            id="non-integer-code-point-typeerror",
        ),
        pytest.param(
            "utf-8",
            "text",
            {"type": "string", "address": "0x100", "value": ""},
            CHG_VALUE_EMPTY,
            None,
            id="empty-string-value",
        ),
        pytest.param(
            "utf-8",
            "text",
            {"type": "bytes", "address": "0x100", "bytes": ""},
            CHG_VALUE_EMPTY,
            None,
            id="empty-bytes-field",
        ),
        pytest.param(
            "utf-8",
            "text",
            {"type": "bytes", "address": "0x100", "bytes": "GG HH"},
            CHG_BYTES_SYNTAX,
            "GG",
            id="non-hex-bytes-tokens",
        ),
        pytest.param(
            "utf-8",
            "text",
            {"type": "string", "address": "0xZZ", "value": "A"},
            CHG_ADDRESS_SYNTAX,
            None,
            id="malformed-hex-address",
        ),
    ],
)
def test_entry_faults(
    tmp_path: Path,
    encoding: str,
    value_mode: str,
    fault_entry: dict,
    expected_code: str,
    forbidden: str | None,
) -> None:
    """Each entry fault records exactly one ERROR with the exact code, the
    entry is skipped while parsing continues, and no issue message embeds
    the fixture's raw value/byte content (LLR-001.4 / C-9)."""
    path_text = _write_json(
        tmp_path,
        _v2_payload(
            encoding=encoding,
            value_mode=value_mode,
            entries=[fault_entry, _TRAILING_VALID],
        ),
    )
    document = read_change_document(path_text, tmp_path)

    assert [issue.code for issue in document.issues] == [expected_code]
    # Skip-and-continue: the trailing valid entry was still parsed.
    assert [(e.address, e.encoded_bytes) for e in document.entries] == [
        (0x9000, (0x7E,))
    ]
    # C-9 confidentiality: messages name addresses/indices, never content.
    if forbidden is not None:
        for issue in document.issues:
            assert forbidden not in issue.message


# ---------------------------------------------------------------------------
# TC-007 — LLR-001.7: resource ceilings + path resolution.
# ---------------------------------------------------------------------------


def test_resource_ceilings_size_cap_before_parse(tmp_path: Path) -> None:
    """An over-cap size probe stops the read BEFORE json.load: the file body
    is deliberately invalid JSON, so any parse attempt would add
    MF-JSON-PARSE — only MF-SIZE-CAP may appear (LLR-001.7)."""
    path = tmp_path / "huge.json"
    path.write_text("{this is not json", encoding="utf-8")

    document = read_change_document(
        str(path), tmp_path, size_probe=lambda _: READ_SIZE_CAP_BYTES + 1
    )

    assert [issue.code for issue in document.issues] == [MF_SIZE_CAP]
    assert MF_JSON_PARSE not in [issue.code for issue in document.issues]
    assert document.entries == []


def test_resource_ceilings_entry_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Entries past the entry-count ceiling are dropped with one
    MF-ENTRY-LIMIT; the in-ceiling prefix is kept (LLR-001.7)."""
    monkeypatch.setattr(changes_io, "MF_ENTRY_COUNT_CEILING", 3)
    entries = [
        {"type": "bytes", "address": f"0x{0x100 + 16 * i:X}", "bytes": "01"}
        for i in range(5)
    ]
    path_text = _write_json(tmp_path, _v2_payload(entries=entries))

    document = read_change_document(path_text, tmp_path)

    assert [issue.code for issue in document.issues] == [MF_ENTRY_LIMIT]
    assert len(document.entries) == 3
    assert [e.address for e in document.entries] == [0x100, 0x110, 0x120]


def test_resource_ceilings_encoded_run_length(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The run-length ceiling binds on the ENCODED byte length: 3 chars that
    UTF-8-encode to 6 bytes breach a ceiling of 4 even though the raw
    character count does not (LLR-001.7)."""
    monkeypatch.setattr(changes_io, "MF_RUN_LENGTH_CEILING", 4)
    entry = {"type": "string", "address": "0x100", "value": "ééé"}
    path_text = _write_json(tmp_path, _v2_payload(entries=[entry]))

    document = read_change_document(path_text, tmp_path)

    assert [issue.code for issue in document.issues] == [MF_ENTRY_LIMIT]
    assert document.entries == []


def test_resource_ceilings_pre_encode_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The raw-length guard runs BEFORE encoding (F-S-04): an oversized codes
    array whose every element would raise on encode yields MF-ENTRY-LIMIT
    and NOT CHG-ENCODE-FAIL — proof no encode was attempted."""
    monkeypatch.setattr(changes_io, "MF_RUN_LENGTH_CEILING", 4)
    entry = {"type": "string", "address": "0x100", "value": [-1] * 6}
    path_text = _write_json(
        tmp_path, _v2_payload(value_mode="codes", entries=[entry])
    )

    document = read_change_document(path_text, tmp_path)

    codes = [issue.code for issue in document.issues]
    assert codes == [MF_ENTRY_LIMIT]
    assert CHG_ENCODE_FAIL not in codes
    assert document.entries == []


def test_resource_ceilings_path_unresolved(tmp_path: Path) -> None:
    """An unresolvable path is one MF-PATH-UNRESOLVED and no file is opened
    (LLR-001.7 — resolve_input_path is the resolution seam)."""
    document = read_change_document("no-such-file-anywhere.json", tmp_path)

    assert [issue.code for issue in document.issues] == [MF_PATH_UNRESOLVED]
    assert document.entries == []


# ---------------------------------------------------------------------------
# TC-008 — LLR-001.8: v1 hard break, CHG-FORMAT suppressed (F-A-03).
# ---------------------------------------------------------------------------


def test_v1_rejected(tmp_path: Path) -> None:
    """A batch-04-shaped v1 unified document yields exactly one
    CHG-V1-FORMAT, zero entries, and never a CHG-FORMAT (precedence rule
    F-A-03); the shape-only spelling (no format token) is caught too."""
    v1_payload = {
        "format": "s19app-unified-changeset",
        "version": "1.0",
        "parameters": [
            {
                "parameter_name": "EngineSpeedLimit",
                "array_index": None,
                "value": 4200,
                "status": "resolved",
            }
        ],
        "memory": [
            {"address": 256, "new_bytes": [1, 2], "status": "inside"},
        ],
    }
    path_text = _write_json(tmp_path, v1_payload)
    document = read_change_document(path_text, tmp_path)

    assert [issue.code for issue in document.issues] == [CHG_V1_FORMAT]
    assert document.entries == []
    assert document.has_errors

    # Shape-only v1 detection: no format token at all, but both v1 halves.
    shape_only = {"parameters": [], "memory": []}
    shape_path = _write_json(tmp_path, shape_only, name="shape_only.json")
    shaped = read_change_document(shape_path, tmp_path)

    assert [issue.code for issue in shaped.issues] == [CHG_V1_FORMAT]
    assert shaped.entries == []
    assert CHG_FORMAT not in [issue.code for issue in shaped.issues]


# ---------------------------------------------------------------------------
# Batch-13 Inc 2 — US-014 data layer: the string-input parse seam
# (LLR-014.1 dummy + LLR-014.2 parse_change_document / read delegation).
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    """Walk up from this test file to the repo root (carries pyproject.toml)."""
    current = Path(__file__).resolve().parent
    for _ in range(6):
        if (current / "pyproject.toml").exists() or (
            current / "project.toml"
        ).exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    raise AssertionError("repo root (pyproject.toml/project.toml) not found")


def test_dummy_changeset_parses(tmp_path: Path) -> None:
    """TC-206 (LLR-014.1): the pre-loaded ``DUMMY_CHANGESET_TEXT`` parses
    cleanly through the string seam.

    Encodes WHY: the dummy is the operator's editable format reference — it
    must be a *valid* kind=change document so a paste-and-parse round trip
    starts from a clean slate, never a faulted envelope. The instant the
    dummy drifts to an invalid shape (a bad address, a non-text codec) this
    fails with a non-zero ERROR count.
    """
    document = parse_change_document(DUMMY_CHANGESET_TEXT)

    assert document.kind == "change"
    assert len(document.entries) >= 1
    error_count = sum(
        1
        for issue in document.issues
        if issue.severity is ValidationSeverity.ERROR
    )
    assert error_count == 0
    # The string seam has no on-disk path (F-A-06).
    assert document.source_path is None


def test_parse_from_string_matches_file_read(tmp_path: Path) -> None:
    """TC-207 (LLR-014.2 parity, narrowed oracle — F-Q-04): for the SAME JSON,
    ``parse_change_document(text)`` and ``read_change_document(path)`` agree on
    ``entries`` and the issue-code set.

    Encodes WHY: the paste seam must be the SAME parser as the file seam, not a
    look-alike that can silently diverge. The oracle is narrowed to entries +
    issue codes (NOT whole-document ``==``) because the documents legitimately
    differ on ``source_path`` — the string seam carries ``None``, the file
    read carries the resolved path. A drift in entry interpretation OR in which
    findings are collected fails this; a benign ``source_path`` difference does
    not.
    """
    payload = _v2_payload(
        kind="change",
        entries=[
            {"type": "bytes", "address": "0x00000000", "bytes": "DE AD BE EF"},
            {"type": "string", "address": "0x00000010", "value": "ABC"},
        ],
    )
    text = json.dumps(payload)
    path_text = _write_json(tmp_path, payload)

    from_string = parse_change_document(text)
    from_file = read_change_document(path_text, tmp_path)

    assert from_string.entries == from_file.entries
    assert {issue.code for issue in from_string.issues} == {
        issue.code for issue in from_file.issues
    }
    # The path-coupled field is the documented divergence: string seam → None,
    # file seam → the resolved path.
    assert from_string.source_path is None
    assert from_file.source_path is not None


def test_parse_malformed_json_emits_mf_json_parse() -> None:
    """TC-209 (LLR-014.2, F-A-01): a malformed JSON string yields a document
    carrying ``MF-JSON-PARSE`` and does NOT raise.

    Encodes WHY: the ``MF-JSON-PARSE`` guarantee previously lived in the
    ``try/except`` wrapping ``json.load(handle)``; re-homing the seam to
    ``json.loads(text)`` must preserve that exact three-exception catch so a
    malformed *paste* still surfaces the finding under collect-don't-abort. The
    valid-parity TC alone cannot detect a dropped catch — this TC pins it.
    """
    document = parse_change_document("{ this is not valid json ]")

    assert MF_JSON_PARSE in [issue.code for issue in document.issues]
    assert document.entries == []
    assert document.has_errors


def test_read_change_document_delegates_to_parse(tmp_path: Path) -> None:
    """TC-210 (LLR-014.2 delegation guard — F-Q-01): ``read_change_document``
    invokes ``parse_change_document`` exactly once with the file payload.

    Encodes WHY: behavioral parity (TC-207) can pass while a parallel copy of
    the interpretation block drifts inside ``read_change_document``. Patching
    ``parse_change_document`` and asserting ``call_count == 1`` pins the
    refactor as *delegation*, not duplication — the failure mode that would
    let the two seams silently diverge over time.
    """
    payload = _v2_payload(
        kind="change",
        entries=[
            {"type": "bytes", "address": "0x00000000", "bytes": "DE AD BE EF"},
        ],
    )
    file_bytes = json.dumps(payload).encode("utf-8")
    path = tmp_path / "doc.json"
    path.write_bytes(file_bytes)

    sentinel = ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="change",
        encoding="utf-8",
        value_mode="text",
    )
    with mock.patch.object(
        changes_io, "parse_change_document", return_value=sentinel
    ) as parse_spy:
        result = read_change_document(str(path), tmp_path)

    assert parse_spy.call_count == 1
    (called_payload,) = parse_spy.call_args.args
    assert called_payload == file_bytes
    # read_change_document re-stamps source_path on the delegated document.
    assert result.source_path is not None


def test_no_changeset_under_examples() -> None:
    """TC-211 (LLR-014.1 tripwire — F-S-04): no ``*changeset*.json`` is ever
    committed under ``examples/``.

    Encodes WHY: ``DUMMY_CHANGESET_TEXT`` is a FAKE-valued module constant, not
    a committed file — this fails the instant any real-looking changeset JSON
    leaks into ``examples/`` (mirrors the CRC tripwire TC-114). It keeps the
    JSON-never-in-repo rule mechanically enforced for the changeset family.
    """
    examples = _repo_root() / "examples"
    assert list(examples.glob("**/*changeset*.json")) == []
