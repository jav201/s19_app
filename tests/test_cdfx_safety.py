"""
CDFX XML-safety tests — s19_app batch-03, increment 8.

Covers the XML-safety layer of ``s19_app/tui/cdfx/reader.py`` (:func:`read_cdfx`)
— the resource-exhaustion / information-disclosure defenses of
``design-input/cdfx-research.md`` §7 and ``01-requirements.md`` LLR-006.6 /
LLR-006.8:

  - TC-027a — the reader rejects a billion-laughs ``.cdfx`` (a ``DOCTYPE`` with
              nested internal ``<!ENTITY>`` declarations, no ``SYSTEM``
              reference): exactly one ``R-XML-PARSE`` issue, an empty
              change-list, and **no entity is ever expanded** (LLR-006.6).
  - TC-027b — the reader rejects an external-entity (``SYSTEM``) ``.cdfx``: the
              external ``<!ENTITY>`` ``SYSTEM`` reference points at a
              test-created **sentinel temp file of known unique content**; the
              reader surfaces one ``R-XML-PARSE`` issue and the sentinel content
              never appears anywhere — proving the external file was never read
              (LLR-006.6).
  - TC-035 — the reader rejects an oversized ``.cdfx`` **before parsing** via
             the injectable size-probe seam, and bounds XML nesting depth
             (LLR-006.8).

Every fixture is synthetic and built in-test (constraint C-9). The verdict for
TC-027a / TC-027b is the **deterministic presence of the DOCTYPE rejection** —
not "did it finish in time" — so no ``pytest`` timeout is the primary
assertion; a timeout would only ever be defense-in-depth (Phase-1 S-005).

These tests are reviewed by the Phase 2 security-reviewer — they are the
validation hook for LLR-006.6 / LLR-006.8.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from s19_app.tui.cdfx import read_cdfx
from s19_app.tui.cdfx import reader as cdfx_reader
from s19_app.validation.model import ValidationIssue


# ---------------------------------------------------------------------------
# Synthetic malicious / oversized .cdfx fixtures — built in-test.
# ---------------------------------------------------------------------------


def make_billion_laughs_cdfx() -> bytes:
    """
    Build a billion-laughs ``.cdfx``: a ``DOCTYPE`` with nested internal
    ``<!ENTITY>`` declarations and **no** ``SYSTEM`` / ``PUBLIC`` reference.

    The classic XML entity-expansion amplification payload — ``lol9`` expands
    to ~10**9 copies of ``lol`` if a parser ever expands it. The reader must
    reject the ``DOCTYPE`` declaration itself, before any entity is expanded.
    """
    return (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE MSRSW [\n"
        b'  <!ENTITY lol "lol">\n'
        b'  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
        b'  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">\n'
        b'  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
        b'  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">\n'
        b'  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">\n'
        b'  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">\n'
        b'  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">\n'
        b'  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">\n'
        b'  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">\n'
        b"]>\n"
        b"<MSRSW>"
        b"<SHORT-NAME>&lol9;</SHORT-NAME>"
        b"<CATEGORY>CDF20</CATEGORY>"
        b"</MSRSW>"
    )


def make_external_entity_cdfx(sentinel_path: Path) -> bytes:
    """
    Build an external-entity ``.cdfx``: a ``DOCTYPE`` with one external
    ``<!ENTITY>`` whose ``SYSTEM`` reference points at ``sentinel_path``.

    If a parser ever resolved the external entity it would inline the sentinel
    file's content into the parsed tree — so the test asserts that content is
    **absent** everywhere, proving the external file was never read.
    """
    uri = sentinel_path.resolve().as_uri()
    return (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE MSRSW [\n"
        b'  <!ENTITY xxe SYSTEM "' + uri.encode("ascii") + b'">\n'
        b"]>\n"
        b"<MSRSW>"
        b"<SHORT-NAME>EXT</SHORT-NAME>"
        b"<CATEGORY>CDF20</CATEGORY>"
        b"<SW-SYSTEMS><SW-SYSTEM><SHORT-NAME>E</SHORT-NAME>"
        b"<SW-INSTANCE-SPEC><SW-INSTANCE-TREE><SHORT-NAME>P</SHORT-NAME>"
        b"<SW-INSTANCE><SHORT-NAME>LEAK</SHORT-NAME><CATEGORY>ASCII</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><VT>&xxe;</VT>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"</SW-INSTANCE-TREE></SW-INSTANCE-SPEC></SW-SYSTEM></SW-SYSTEMS>"
        b"</MSRSW>"
    )


def make_minimal_cdfx() -> bytes:
    """A well-formed, DOCTYPE-free ``.cdfx`` — the under-cap / shallow control."""
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<MSRSW><SHORT-NAME>X</SHORT-NAME><CATEGORY>CDF20</CATEGORY>"
        b"<SW-SYSTEMS><SW-SYSTEM><SHORT-NAME>E</SHORT-NAME>"
        b"<SW-INSTANCE-SPEC><SW-INSTANCE-TREE><SHORT-NAME>P</SHORT-NAME>"
        b"<SW-INSTANCE><SHORT-NAME>IGN</SHORT-NAME><CATEGORY>VALUE</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>12.5</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"</SW-INSTANCE-TREE></SW-INSTANCE-SPEC></SW-SYSTEM></SW-SYSTEMS>"
        b"</MSRSW>"
    )


def make_oversized_cdfx() -> bytes:
    """A small but well-formed ``.cdfx`` — the size-probe seam reports it as
    over-cap, so the document content itself need not be 256 MB (TC-035)."""
    return make_minimal_cdfx()


def make_deeply_nested_cdfx(depth: int) -> bytes:
    """Build a well-formed ``.cdfx`` whose element nesting reaches ``depth``
    levels — past ``MAX_NESTING_DEPTH`` it must be rejected without unbounded
    recursion (TC-035)."""
    return (
        b'<?xml version="1.0"?>'
        b"<MSRSW>" + b"<x>" * depth + b"</x>" * depth + b"</MSRSW>"
    )


# ---------------------------------------------------------------------------
# Shared assertions.
# ---------------------------------------------------------------------------


def _assert_single_parse_rejection(change_list, issues) -> ValidationIssue:
    """Assert a malicious / oversized read produced exactly one ``R-XML-PARSE``
    issue and an empty change-list; return the single issue."""
    assert change_list.entries == [], (
        "a rejected .cdfx must yield an empty change-list, "
        f"got {len(change_list.entries)} entries"
    )
    assert len(issues) == 1, (
        f"expected exactly one R-XML-PARSE issue, got {[i.code for i in issues]}"
    )
    assert issues[0].code == "R-XML-PARSE"
    assert issues[0].artifact == "cdfx"
    return issues[0]


# ---------------------------------------------------------------------------
# TC-027a — billion-laughs (internal-entity) rejection.
# ---------------------------------------------------------------------------


def test_tc027a_billion_laughs_rejected_with_one_parse_issue() -> None:
    """TC-027a — a billion-laughs ``.cdfx`` is rejected as exactly one
    ``R-XML-PARSE`` issue with an empty change-list (LLR-006.6)."""
    payload = make_billion_laughs_cdfx()
    # The fixture genuinely carries a DOCTYPE — the rejection is real.
    assert b"<!DOCTYPE" in payload and b"<!ENTITY" in payload

    change_list, issues = read_cdfx(payload)

    _assert_single_parse_rejection(change_list, issues)


def test_tc027a_billion_laughs_no_entity_expanded() -> None:
    """TC-027a — the parser never expands an entity: no amplified ``lol`` text
    appears in any change-list entry or any issue message (LLR-006.6)."""
    change_list, issues = read_cdfx(make_billion_laughs_cdfx())

    # If any entity had been expanded, the amplified "lollol..." text would
    # surface in an entry value or echo in the issue message. It must not.
    assert change_list.entries == []
    for issue in issues:
        assert "lollol" not in issue.message, (
            "an expanded entity leaked into an issue message — the DOCTYPE "
            "handler did not fire before expansion"
        )
    # The single issue names the DOCTYPE rejection, not an expansion result.
    assert "DOCTYPE" in issues[0].message


def test_tc027a_billion_laughs_via_path(tmp_path: Path) -> None:
    """TC-027a — the same rejection holds when the billion-laughs ``.cdfx`` is
    read from a resolved path, not in-memory bytes (LLR-005.5 + LLR-006.6)."""
    bad = tmp_path / "billion_laughs.cdfx"
    bad.write_bytes(make_billion_laughs_cdfx())

    change_list, issues = read_cdfx(bad, base_dir=tmp_path)

    _assert_single_parse_rejection(change_list, issues)


# ---------------------------------------------------------------------------
# TC-027b — external-entity (SYSTEM) rejection.
# ---------------------------------------------------------------------------


def test_tc027b_external_entity_rejected_with_one_parse_issue(
    tmp_path: Path,
) -> None:
    """TC-027b — an external-entity ``.cdfx`` is rejected as exactly one
    ``R-XML-PARSE`` issue with an empty change-list (LLR-006.6)."""
    sentinel = tmp_path / "sentinel_secret.txt"
    sentinel.write_text("UNIQUE_SENTINEL_LEAK_MARKER_9F3A2B")
    payload = make_external_entity_cdfx(sentinel)
    assert b"<!ENTITY xxe SYSTEM" in payload

    change_list, issues = read_cdfx(payload)

    _assert_single_parse_rejection(change_list, issues)


def test_tc027b_external_entity_file_never_read(tmp_path: Path) -> None:
    """TC-027b — the external file is never read: its unique sentinel content
    appears in no parsed value, no entry field and no issue message
    (LLR-006.6)."""
    marker = "UNIQUE_SENTINEL_LEAK_MARKER_9F3A2B"
    sentinel = tmp_path / "sentinel_secret.txt"
    sentinel.write_text(marker)

    change_list, issues = read_cdfx(make_external_entity_cdfx(sentinel))

    assert change_list.entries == []
    for entry in change_list.entries:
        assert marker not in str(entry.value)
        assert marker not in str(entry.parameter_name)
    for issue in issues:
        assert marker not in issue.message, (
            "the external sentinel file's content leaked into an issue "
            "message — the external entity was resolved and read"
        )


# ---------------------------------------------------------------------------
# TC-035 — pre-parse size cap + nesting-depth bound.
# ---------------------------------------------------------------------------


def test_tc035_oversized_rejected_before_parsing(monkeypatch) -> None:
    """TC-035 — an oversized ``.cdfx`` is rejected as one ``R-XML-PARSE`` issue
    **before** the XML parser is reached (LLR-006.8)."""
    over_cap = cdfx_reader.MAX_CDFX_SIZE_BYTES + 1

    # The injectable size-probe seam: report an over-cap size for a small file.
    monkeypatch.setattr(cdfx_reader, "_probe_size", lambda data: over_cap)

    # Spy on the parse seam — it must never be reached when size rejects.
    parse_calls: list[int] = []
    real_safe_parse = cdfx_reader._safe_parse

    def spy_safe_parse(data, issues):
        parse_calls.append(1)
        return real_safe_parse(data, issues)

    monkeypatch.setattr(cdfx_reader, "_safe_parse", spy_safe_parse)

    change_list, issues = read_cdfx(make_oversized_cdfx())

    _assert_single_parse_rejection(change_list, issues)
    assert parse_calls == [], (
        "the XML parser was reached for an over-cap file — the size check "
        "must precede parsing (LLR-006.8)"
    )
    assert "read cap" in issues[0].message


def test_tc035_under_cap_file_parses_normally(monkeypatch) -> None:
    """TC-035 — a file under the size cap is parsed normally; the size check
    does not reject a legitimately small ``.cdfx``."""
    # Probe reports exactly the cap — not over it — so parsing proceeds.
    monkeypatch.setattr(
        cdfx_reader, "_probe_size", lambda data: cdfx_reader.MAX_CDFX_SIZE_BYTES
    )

    change_list, issues = read_cdfx(make_minimal_cdfx())

    assert [i.code for i in issues] == []
    assert len(change_list.entries) == 1
    assert change_list.entries[0].parameter_name == "IGN"


def test_tc035_deeply_nested_rejected_without_recursion() -> None:
    """TC-035 — a ``.cdfx`` whose element nesting exceeds ``MAX_NESTING_DEPTH``
    is rejected as one ``R-XML-PARSE`` issue, with no unbounded recursion
    (LLR-006.8)."""
    deep = make_deeply_nested_cdfx(cdfx_reader.MAX_NESTING_DEPTH + 50)

    change_list, issues = read_cdfx(deep)

    _assert_single_parse_rejection(change_list, issues)
    assert "depth" in issues[0].message


def test_tc035_oversized_path_not_read_into_memory(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-035 (S8-2) — for a *path* source, an over-cap file is rejected by the
    on-disk ``stat().st_size`` check **before** ``Path.read_bytes`` — the file
    content is never read into memory (LLR-006.8).

    The increment-8 cap measured the in-memory byte length: a path source was
    read in full and then rejected. The S8-2 fix adds a ``stat()``-before-read
    guard in ``_resolve_source`` so an over-cap file is rejected without ever
    being loaded — this test pins the guard with a ``read_bytes`` spy.

    The over-cap file is created **sparse** — ``truncate`` to a logical size
    past the cap reports that ``st_size`` without writing 256 MB of bytes to
    disk — so the test exercises a genuinely over-cap real file path.
    """
    cdfx_path = tmp_path / "oversized.cdfx"
    over_cap = cdfx_reader.MAX_CDFX_SIZE_BYTES + 1
    with cdfx_path.open("wb") as handle:
        # A sparse file: logical size is over-cap, no 256 MB of real bytes.
        handle.truncate(over_cap)
    assert cdfx_path.stat().st_size == over_cap, (
        "the test fixture is not actually over the read cap"
    )

    # Spy on read_bytes — it must NOT be called for the over-cap path.
    read_calls: list[Path] = []
    real_read_bytes = Path.read_bytes

    def spy_read_bytes(self):
        read_calls.append(self)
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", spy_read_bytes)

    change_list, issues = read_cdfx(cdfx_path, base_dir=tmp_path)

    _assert_single_parse_rejection(change_list, issues)
    assert cdfx_path not in read_calls, (
        "the over-cap .cdfx file was read into memory — the stat()-before-read "
        "guard in _resolve_source did not reject it first (S8-2 / LLR-006.8)"
    )
    assert "before the file was read" in issues[0].message


def test_tc035_under_cap_path_is_read(tmp_path: Path, monkeypatch) -> None:
    """TC-035 (S8-2) — the on-disk size guard does not reject a within-cap
    file: a normal ``.cdfx`` path is stat'd, read and parsed (the guard is
    meaningful — it gates, it does not block every path read)."""
    cdfx_path = tmp_path / "normal.cdfx"
    cdfx_path.write_bytes(make_minimal_cdfx())

    read_calls: list[Path] = []
    real_read_bytes = Path.read_bytes

    def spy_read_bytes(self):
        read_calls.append(self)
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", spy_read_bytes)

    change_list, issues = read_cdfx(cdfx_path, base_dir=tmp_path)

    assert cdfx_path in read_calls, (
        "a within-cap .cdfx path must be read — the size guard over-rejected"
    )
    assert [i.code for i in issues] == []
    assert len(change_list.entries) == 1


def test_tc035_within_depth_bound_parses() -> None:
    """TC-035 — a ``.cdfx`` nested within the depth bound parses without a
    depth rejection: the bound rejects only pathological nesting."""
    # MSRSW + a handful of nested <x> — comfortably within MAX_NESTING_DEPTH.
    shallow = make_deeply_nested_cdfx(5)

    change_list, issues = read_cdfx(shallow)

    # The document has no SW-INSTANCE backbone, so R-BACKBONE-MISSING is the
    # expected (and only) issue — crucially NOT an R-XML-PARSE depth rejection.
    assert "R-XML-PARSE" not in [i.code for i in issues], (
        "a shallow document must not trip the nesting-depth bound"
    )


# ---------------------------------------------------------------------------
# Control — a clean .cdfx is unaffected by the safety layer.
# ---------------------------------------------------------------------------


def test_clean_cdfx_unaffected_by_safety_layer() -> None:
    """A well-formed, DOCTYPE-free ``.cdfx`` of normal size parses with zero
    ``R-XML-PARSE`` issues — the safety layer costs valid input nothing."""
    change_list, issues = read_cdfx(make_minimal_cdfx())

    assert [i.code for i in issues] == []
    assert len(change_list.entries) == 1


def test_safety_layer_never_raises() -> None:
    """Every safety vector returns ``(ChangeList, list)`` and never raises —
    the collect-don't-abort contract holds for malicious input (HLR-005)."""
    sentinel_dir = Path(__file__).parent
    for payload in (
        make_billion_laughs_cdfx(),
        make_external_entity_cdfx(sentinel_dir / "conftest.py"),
        make_deeply_nested_cdfx(cdfx_reader.MAX_NESTING_DEPTH + 10),
        b"not xml at all \x00\xff",
        b"<MSRSW><unclosed>",
    ):
        change_list, issues = read_cdfx(payload)
        assert isinstance(issues, list)
        assert all(isinstance(i, ValidationIssue) for i in issues)
