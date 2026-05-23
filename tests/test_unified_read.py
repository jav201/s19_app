"""
Unified change-set file read tests — s19_app batch-04, increment 6.

Covers the read half of the unified change-set JSON file handler
(``s19_app/tui/cdfx/unified_io.py``) — ``read_unified`` and the structural /
resource-bound parts of the ``MF-*`` rule set:

  - TC-019 — the reader parses both halves (LLR-006.1): a well-formed unified
             file built by the production writer parses to a ``UnifiedChangeSet``
             with a populated parameter ``ChangeList`` and a populated
             ``MemoryChangeList``.
  - TC-014 — a well-formed-but-wrong-shape document (LLR-006.2): a bare ``[]``,
             a bare ``42``, a bare string, or an object with no recognised
             halves → exactly one ``MF-BAD-STRUCTURE`` error issue, an empty
             change-set, and **no** escaping ``KeyError``.
  - TC-021 — path resolution (LLR-006.3): a valid path is resolved through
             ``workspace.resolve_input_path`` and read; an unresolvable path
             yields exactly one error ``ValidationIssue`` and **no file is
             opened** (asserted via a no-open spy on ``Path.open``).
  - TC-022 — read-path size bound (LLR-006.4): with the injectable size-probe
             stubbed over the 256 MB cap, the reader produces exactly one
             ``MF-SIZE-CAP`` issue, an empty change-set, and ``json.load`` is
             never reached — the size check precedes parsing.
  - TC-035 — deeply-nested JSON (LLR-006.2): a document nested deep enough to
             overflow the stdlib parser's recursion → exactly one
             ``MF-JSON-PARSE`` issue, an empty change-set, and **no** escaping
             ``RecursionError``.
  - TC-037 — decoded-structure ceiling (LLR-006.5): a file declaring more
             memory-field entries than the documented ceiling, and a file
             declaring a single ``new_bytes`` run longer than the documented
             ceiling, each produce exactly one ``MF-ENTRY-LIMIT`` issue per
             breach, drop the offending entry, keep the in-ceiling entries, and
             do not raise.

These tests encode WHY each behaviour matters. The collect-don't-abort
contract (HLR-006) means every failure mode — a wrong shape, a deeply-nested
document, an unresolvable path, an over-cap or over-ceiling file — must surface
as a collected ``ValidationIssue`` and never as an escaping exception; each
test asserts the *absence* of the escape (``KeyError`` for TC-014,
``RecursionError`` for TC-035) as the load-bearing assertion, not merely that
an issue was produced. TC-021 and TC-022 assert the security boundary: an
arbitrary path is never opened, and an over-cap file is never read into memory.

Every fixture is synthetic and built in-test (constraint C-9).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from s19_app.tui.cdfx import UnifiedChangeSet, read_unified
from s19_app.tui.cdfx import unified_io
from s19_app.tui.cdfx.unified_io import (
    MF_BAD_STRUCTURE,
    MF_ENTRY_COUNT_CEILING,
    MF_ENTRY_LIMIT,
    MF_JSON_PARSE,
    MF_PATH_UNRESOLVED,
    MF_RUN_LENGTH_CEILING,
    MF_SIZE_CAP,
    READ_SIZE_CAP_BYTES,
)
from s19_app.validation.model import ValidationSeverity

from tests.conftest import (
    make_deeply_nested_unified_file,
    make_malformed_unified_file,
    make_over_ceiling_unified_file,
    make_unified_file,
)


# ---------------------------------------------------------------------------
# TC-019 — the reader parses both halves (LLR-006.1)
# ---------------------------------------------------------------------------


def test_tc019_reader_parses_both_halves(tmp_path: Path) -> None:
    """TC-019 — a well-formed unified file parses to a populated change-set (LLR-006.1).

    LLR-006.1 requires the reader to reconstruct a ``UnifiedChangeSet`` holding
    a parameter ``ChangeList`` populated from the parameter half and a
    ``MemoryChangeList`` populated from the memory-field half. This feeds the
    reader a file built by the production writer and asserts both halves come
    back populated — a reader that drops a half fails the test.
    """
    unified_path = make_unified_file(tmp_path / "cs.json")

    changeset, issues = read_unified(str(unified_path), tmp_path)

    assert isinstance(changeset, UnifiedChangeSet)
    assert issues == [], f"unexpected issues: {[i.code for i in issues]}"
    # The factory composes change_list_factory (8 entries) + the base
    # memory_change_factory (3 entries).
    assert changeset.counts() == (8, 3)
    assert not changeset.is_empty()


def test_tc019_reader_recovers_exact_parameter_and_memory_content(
    tmp_path: Path,
) -> None:
    """TC-019 — the parsed halves carry the exact entry content (LLR-006.1).

    Parsing both halves is only correct if the entry *content* survives. This
    asserts a known parameter entry and a known memory entry come back with
    their exact value / address / byte run — so a reader that parses the shape
    but mangles a field fails the test.
    """
    unified_path = make_unified_file(tmp_path / "cs.json")

    changeset, _ = read_unified(str(unified_path), tmp_path)

    scalar = changeset.parameters.get("IGN_ADVANCE_BASE", None)
    assert scalar is not None and scalar.value == 23

    # The base memory factory's first entry — 0x200, four bytes.
    first_memory = changeset.memory.entries[0]
    assert first_memory.address == 0x200
    assert first_memory.new_bytes == (0xDE, 0xAD, 0xBE, 0xEF)


# ---------------------------------------------------------------------------
# TC-014 — well-formed-but-wrong-shape document (LLR-006.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "variant",
    ["bare-list", "bare-int", "bare-string", "no-halves"],
)
def test_tc014_wrong_shape_document_yields_one_bad_structure_issue_no_keyerror(
    tmp_path: Path, variant: str
) -> None:
    """TC-014 — a wrong-shape document → one MF-BAD-STRUCTURE, no KeyError (LLR-006.2).

    A well-formed JSON document that is not a unified document (``[]``, ``42``,
    a bare string, ``{"foo": 1}``) trips neither a parse error nor any
    per-entry rule — there are no entries. Without the ``MF-BAD-STRUCTURE``
    shape guard, a reader indexing ``document["memory"]`` would raise an
    uncaught ``KeyError``. This asserts the *absence of the escape* — the call
    must return normally — and exactly one ``MF-BAD-STRUCTURE`` error issue.
    """
    bad_path = make_malformed_unified_file(
        tmp_path / f"{variant}.json", variant=variant
    )

    # The load-bearing assertion: the call returns, it does NOT raise KeyError.
    changeset, issues = read_unified(str(bad_path), tmp_path)

    assert changeset.is_empty()
    codes = [i.code for i in issues]
    assert codes == [MF_BAD_STRUCTURE]
    assert issues[0].severity is ValidationSeverity.ERROR


def test_tc014_wrong_shape_document_is_parseable_json(tmp_path: Path) -> None:
    """TC-014 — the wrong-shape fixture really is well-formed JSON.

    ``MF-BAD-STRUCTURE`` is meaningful only when separated from
    ``MF-JSON-PARSE``: the document must parse cleanly and still be the wrong
    shape. This asserts the fixture is genuinely valid JSON, so the test
    exercises the shape guard and not the parse-error path.
    """
    bad_path = make_malformed_unified_file(
        tmp_path / "no-halves.json", variant="no-halves"
    )

    # Parses without error — it is the *shape* that is wrong, not the syntax.
    parsed = json.loads(bad_path.read_bytes())
    assert isinstance(parsed, dict) and "memory" not in parsed


# ---------------------------------------------------------------------------
# TC-021 — path resolution (LLR-006.3)
# ---------------------------------------------------------------------------


def test_tc021_valid_path_is_resolved_and_read(tmp_path: Path) -> None:
    """TC-021 — a valid unified-file path is resolved via resolve_input_path (LLR-006.3).

    LLR-006.3 requires the reader to resolve a user-supplied path through
    ``workspace.resolve_input_path`` before opening it. This passes a path that
    resolves and asserts the file is read into a populated change-set — the
    resolution path works end to end.
    """
    unified_path = make_unified_file(tmp_path / "cs.json")

    changeset, issues = read_unified(str(unified_path), tmp_path)

    assert issues == []
    assert not changeset.is_empty()


def test_tc021_unresolvable_path_yields_one_issue_and_opens_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-021 — an unresolvable path → one issue, no file opened (LLR-006.3).

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

    changeset, issues = read_unified(
        str(tmp_path / "does-not-exist.json"), tmp_path
    )

    # The load-bearing assertion — no file was opened.
    assert open_calls == []
    assert changeset.is_empty()
    codes = [i.code for i in issues]
    assert codes == [MF_PATH_UNRESOLVED]
    assert issues[0].severity is ValidationSeverity.ERROR


# ---------------------------------------------------------------------------
# TC-022 — read-path size bound (LLR-006.4)
# ---------------------------------------------------------------------------


def test_tc022_oversized_file_is_rejected_before_json_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-022 — an over-cap file → one MF-SIZE-CAP, json.load never reached (LLR-006.4).

    LLR-006.4 requires the 256 MB on-disk size cap to be enforced **before**
    parsing — the file is never read into memory. This stubs the injectable
    size-probe to report an over-cap byte size and installs a spy on
    ``json.load`` that fails the test if called. The load-bearing assertion is
    that ``json.load`` is never reached: the size check precedes parsing.
    """
    # A real, small, well-formed file — only the probe reports it as oversized.
    unified_path = make_unified_file(tmp_path / "small.json")

    load_calls: list[object] = []

    def _spy_load(*args: object, **kwargs: object) -> object:
        load_calls.append(args)
        raise AssertionError("json.load must not be reached for an over-cap file")

    monkeypatch.setattr(unified_io.json, "load", _spy_load)

    changeset, issues = read_unified(
        str(unified_path),
        tmp_path,
        size_probe=lambda _: READ_SIZE_CAP_BYTES + 1,
    )

    # The load-bearing assertion — the file was never parsed into memory.
    assert load_calls == []
    assert changeset.is_empty()
    codes = [i.code for i in issues]
    assert codes == [MF_SIZE_CAP]
    assert issues[0].severity is ValidationSeverity.ERROR


def test_tc022_at_cap_file_is_not_rejected(tmp_path: Path) -> None:
    """TC-022 — a file exactly at the cap is read, only *over* the cap is rejected.

    The cap is a strict ``>`` bound — a file *at* exactly 256 MB is still
    readable. This stubs the probe to report exactly the cap and asserts the
    reader proceeds to parse, so the boundary is pinned and an off-by-one in
    the comparison fails the test.
    """
    unified_path = make_unified_file(tmp_path / "small.json")

    changeset, issues = read_unified(
        str(unified_path), tmp_path, size_probe=lambda _: READ_SIZE_CAP_BYTES
    )

    assert [i.code for i in issues if i.code == MF_SIZE_CAP] == []
    assert not changeset.is_empty()


# ---------------------------------------------------------------------------
# TC-035 — deeply-nested JSON (LLR-006.2)
# ---------------------------------------------------------------------------


def test_tc035_deeply_nested_json_yields_one_parse_issue_no_recursionerror(
    tmp_path: Path,
) -> None:
    """TC-035 — a deeply-nested document → one MF-JSON-PARSE, no RecursionError (LLR-006.2).

    ``RecursionError`` is a ``RuntimeError``, **not** a ``json.JSONDecodeError``
    — a document nested deep enough overflows the stdlib parser's C recursion,
    and an ``except json.JSONDecodeError`` clause alone would let it escape and
    crash the load. This feeds a 120k-deep document and asserts the call
    *returns* (the load-bearing assertion — no escaping ``RecursionError``)
    with exactly one ``MF-JSON-PARSE`` error issue and an empty change-set.
    """
    deep_path = make_deeply_nested_unified_file(tmp_path / "deep.json")

    # The load-bearing assertion — the call returns, it does NOT raise
    # RecursionError. If the except clause missed RecursionError this line
    # would raise instead of binding the tuple.
    changeset, issues = read_unified(str(deep_path), tmp_path)

    assert changeset.is_empty()
    codes = [i.code for i in issues]
    assert codes == [MF_JSON_PARSE]
    assert issues[0].severity is ValidationSeverity.ERROR


# ---------------------------------------------------------------------------
# TC-037 — decoded-structure ceiling (LLR-006.5)
# ---------------------------------------------------------------------------


def test_tc037_over_entry_count_ceiling_drops_overflow_keeps_rest(
    tmp_path: Path,
) -> None:
    """TC-037 — over the entry-count ceiling → one MF-ENTRY-LIMIT, rest kept (LLR-006.5).

    The 256 MB on-disk size cap bounds the file, not the decoded structure: a
    sub-cap file can declare millions of memory-field entries. LLR-006.5
    requires a decoded-structure ceiling — on a breach, exactly one
    ``MF-ENTRY-LIMIT`` issue, the offending entries dropped, the in-ceiling
    entries kept, no exception. This feeds a file declaring
    ``MF_ENTRY_COUNT_CEILING + 5`` entries and asserts exactly the in-ceiling
    prefix survives.
    """
    over_path = make_over_ceiling_unified_file(
        tmp_path / "many.json", variant="entry-count"
    )

    changeset, issues = read_unified(str(over_path), tmp_path)

    entry_limit = [i for i in issues if i.code == MF_ENTRY_LIMIT]
    assert len(entry_limit) == 1
    assert entry_limit[0].severity is ValidationSeverity.ERROR
    # The offending 5 entries are dropped; the in-ceiling prefix is kept.
    assert len(changeset.memory) == MF_ENTRY_COUNT_CEILING


def test_tc037_over_run_length_ceiling_drops_one_entry_keeps_rest(
    tmp_path: Path,
) -> None:
    """TC-037 — an over-length new_bytes run → one MF-ENTRY-LIMIT, rest kept (LLR-006.5).

    A single ``new_bytes`` run can declare hundreds of millions of integers in
    a sub-cap file. LLR-006.5 requires the per-run ceiling — on a breach the
    offending entry is dropped, the rest kept, no exception. This feeds a file
    with two clean entries plus one whose run is ``MF_RUN_LENGTH_CEILING + 1``
    bytes and asserts exactly the two clean entries survive.
    """
    over_path = make_over_ceiling_unified_file(
        tmp_path / "longrun.json", variant="run-length"
    )

    changeset, issues = read_unified(str(over_path), tmp_path)

    entry_limit = [i for i in issues if i.code == MF_ENTRY_LIMIT]
    assert len(entry_limit) == 1
    assert entry_limit[0].severity is ValidationSeverity.ERROR
    # The over-run entry is dropped; the two clean entries are kept.
    assert len(changeset.memory) == 2
    assert {e.address for e in changeset.memory.entries} == {0x100, 0x200}


def test_tc037_entry_limit_message_carries_no_raw_bytes(tmp_path: Path) -> None:
    """TC-037 — the MF-ENTRY-LIMIT message references a count, not raw bytes (C-9).

    Constraint C-9 keeps proprietary firmware bytes out of the rotating log: a
    memory-field finding references the entry's ``address`` and a count, never
    the raw ``new_bytes`` content. The over-run fixture's run is all zero bytes;
    this asserts the message carries the byte *count* and the run-length
    *ceiling* but not a long literal byte sequence.
    """
    over_path = make_over_ceiling_unified_file(
        tmp_path / "longrun.json", variant="run-length"
    )

    _, issues = read_unified(str(over_path), tmp_path)

    message = next(i.message for i in issues if i.code == MF_ENTRY_LIMIT)
    assert str(MF_RUN_LENGTH_CEILING + 1) in message
    assert str(MF_RUN_LENGTH_CEILING) in message
    # No long literal byte run leaked into the message.
    assert "0, 0, 0, 0, 0" not in message
