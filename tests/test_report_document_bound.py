"""batch-76 Inc-1 — ``HLR-108``: the emitted report document is byte-bounded.

WHAT THIS FILE GATES. The shipped generator ACCOUNTS for bytes but never gates
on them: at the batch base there was exactly **one** ``.fits(`` call against
**two** ``.consume(`` calls, and the single gate sat inside ``_hexdump_section``'s
block loop — covering neither ``emit`` nor five of the six ``put`` sites. So the
document had no byte bound at all, and the measured floor was **15.86x** the
budget at ``V=100``.

TWO VACUITY CLASSES ARE CHECKED HERE, NOT ONE.

* the vacuous PREDICATE — a check that cannot fail. Every gate node below names
  the substituted expression that reddens it, and that mutation was EXECUTED on
  a copy of the fixed tree, not reasoned about.
* the vacuous FIXTURE — a *correct* predicate that cannot fail because the
  fixture never exercises what it asserts. This is the class that blocked
  revision 1: ``AT-252``'s fixture reached ~4 kB against a 2 MB budget and was
  green on the base tree, the fixed tree AND a stubbed gate. ``TC-552`` is the
  guard: it asserts, for EACH ceiling AT separately, that that AT's own raw
  producers exceed that AT's own effective limit. A ceiling AT whose fixture
  cannot overflow is certifying nothing.

THE BASE TREE IS NOT ALWAYS THE FALSIFIER. Where the pre-fix behaviour is
"emits too much" the base tree does redden these nodes. Where it is not, the
counterfactual is a mutation on a COPY of the fixed tree, recording the
substituted expression rather than "delete the clamp" — a phrasing that names
three different mutants and cost batch-73 a false blocker.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import pytest

from s19_app.tui.changes.model import (
    ChangeSummary,
    ChangeSummaryEntry,
    CheckRunEntry,
    CheckRunResult,
)
from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services import report_service
from s19_app.tui.services.report_service import (
    REPORT_MAX_TOTAL_BYTES,
    REPORT_MAX_TRUNCATION_NOTES,
    REPORT_SECTION_KINDS,
    REPORT_VARIANT_RESERVATION_FLOOR_BYTES,
    ReportOptions,
    _disclosure_allowance,
    _line_bytes,
    _select_notes,
    generate_project_report,
)
from s19_app.tui.services.variant_execution_service import VariantExecutionResult

from conftest import canonical_report_bytes

_INSTANT = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)

_GOLDEN = (
    Path(__file__).parent / "goldens" / "batch76" / "document-bound-preflight.md"
)


# ---------------------------------------------------------------------------
# Fixtures. Sized to OVERFLOW on purpose — see TC-552.
# ---------------------------------------------------------------------------


def _entry(base: int, index: int, width: int) -> ChangeSummaryEntry:
    return ChangeSummaryEntry(
        entry_type="bytes",
        address_start=base + index * 16,
        address_end=base + index * 16 + width,
        before_bytes=tuple(range(0x10, 0x10 + width)),
        after_bytes=tuple(range(0xA0, 0xA0 + width)),
        disposition="applied",
        linkage="a2l",
        linkage_symbol=f"SYM_{index}",
    )


def _result(
    vid: str, rows: int, files: int = 1, width: int = 8, mem: int = 0
) -> VariantExecutionResult:
    """One variant with ``rows`` modification rows, ``files`` check files, and
    optionally a ``mem``-byte memory map.

    ⚠ ``mem`` is not decoration. Without it ``_hexdump_section`` short-circuits
    on "No modified regions." and the five ungated ``put`` sites this batch
    fixed are never reached — so a ceiling AT built on a mem-less fixture stays
    GREEN even with ``put`` fully ungated. Measured: restoring revision 1's
    ``_hexdump_section`` exemption left AT-250 and AT-252 green until this
    parameter existed."""
    base = 0x8000_0000
    entries = [_entry(base, i, width) for i in range(rows)]
    summary = ChangeSummary(
        source_path=Path("chg.json"),
        kind="change",
        encoding="utf-8",
        value_mode="text",
        timestamp_utc="2026-07-31T11:00:00+00:00",
        variant_id=vid,
        counts={"applied": len(entries)},
        entries=entries,
        issues=[],
    )
    checks = []
    for f in range(files):
        rows_f = [
            CheckRunEntry(
                entry_type="bytes",
                address_start=0x9000_0000 + f * 0x1000 + i * 16,
                address_end=0x9000_0000 + f * 0x1000 + i * 16 + width,
                expected_bytes=tuple(range(0x20, 0x20 + width)),
                actual_bytes=tuple(range(0x20, 0x20 + width)),
                result="pass",
                linkage="standalone",
                linkage_symbol=None,
                reason_code=None,
                reason=None,
            )
            for i in range(rows)
        ]
        checks.append(
            CheckRunResult(
                source_path=Path(f"chk{f}.json"),
                timestamp_utc="2026-07-31T11:00:00+00:00",
                variant_id=vid,
                aggregates={"passed": len(rows_f), "failed": 0, "uncheckable": 0},
                entries=rows_f,
                issues=[],
            )
        )
    return VariantExecutionResult(
        variant_id=vid,
        status="ok",
        change_summaries=[summary],
        check_results=checks,
        mem_map=(
            {base + o: (o * 7) & 0xFF for o in range(mem)} if mem else None
        ),
    )


def _variant_set(results: Sequence[VariantExecutionResult]) -> ProjectVariantSet:
    return ProjectVariantSet(
        project_name="proj",
        variants=tuple(
            VariantDescriptor(
                variant_id=r.variant_id, path=Path(f"{r.variant_id}.s19"), file_type="s19"
            )
            for r in results
        ),
        active_id=results[0].variant_id,
    )


def _generate(tmp_path: Path, results: Sequence[VariantExecutionResult]) -> Path:
    root = tmp_path / "proj"
    root.mkdir(parents=True, exist_ok=True)
    return generate_project_report(
        root,
        list(results),
        ReportOptions(),
        variant_set=_variant_set(results),
        now_fn=lambda: _INSTANT,
    )


def _raw_producer_bytes(results: Sequence[VariantExecutionResult]) -> int:
    """Σ ``_line_bytes`` over the UNGATED producers — what the document would
    cost with no gate at all. This is the number TC-552 compares to the limit."""
    total = 0
    for r in results:
        total += _line_bytes(report_service._modified_files_lines(r))
        total += _line_bytes(report_service._modifications_lines(r, None))
        total += _line_bytes(report_service._declaration_error_lines(r))
        total += _line_bytes(report_service._checklist_lines(r, None))
    return total


def _ceiling(variant_count: int, limit: int = REPORT_MAX_TOTAL_BYTES) -> int:
    return limit + _disclosure_allowance(variant_count)


# ---------------------------------------------------------------------------
# TC-552 — FIXTURE INTEGRITY. The guard against the vacuous-fixture class.
# ---------------------------------------------------------------------------


#: Cell width that makes a row as wide as the module permits. Measured, not
#: guessed: at ``rows=200`` (the row cap) and this width, ONE variant's raw
#: producers total 424 637 B, so ten of them total 4 246 370 B = **2.02x** the
#: real 2 MB budget. That is how AT-250 gates the SHIPPED cap rather than a
#: shrunken stand-in.
_WIDEST_CELL = report_service.REPORT_BYTES_PER_CELL

#: The shrunken limit the V- and F-sweeps run against. A single variant CANNOT
#: overflow the real 2 MB budget through tables — ``MAX_REPORT_ROWS_PER_VARIANT``
#: caps it at 200 rows and ``REPORT_BYTES_PER_CELL`` caps the width, for a
#: measured ceiling of 424 637 B — so the V=1 arm of AT-251 would be VACUOUS at
#: the real cap. Shrinking the limit is what the spec blesses for exactly this
#: reason, with the ceiling expressed as ``effective_limit + allowance(V)``.
_SHRUNK_LIMIT = 4096


@pytest.mark.parametrize(
    "label, results, limit",
    [
        # AT-250 runs against the REAL budget: 10 widest-cell variants.
        (
            "AT-250",
            [_result(f"v{i}", rows=200, width=_WIDEST_CELL, mem=4096) for i in range(10)],
            REPORT_MAX_TOTAL_BYTES,
        ),
        # AT-251's WORST arm is V=1 (the least raw output of the sweep). If the
        # smallest arm overflows, every larger one does.
        ("AT-251 worst arm (V=1)", [_result("v0", rows=60)], _SHRUNK_LIMIT),
        ("AT-252", [_result("v0", rows=40, files=3, mem=4096)], _SHRUNK_LIMIT),
    ],
)
def test_tc552_each_ceiling_fixture_actually_overflows_its_own_limit(
    label: str, results: List[VariantExecutionResult], limit: int
) -> None:
    """TC-552 — for EACH ceiling AT separately, its own fixture overflows its own limit.

    Intent: revision 1 scoped this to AT-250 only, and AT-252's fixture reached
    ~4 kB against a 2 MB budget — green on the base tree, on the fixed tree, and
    against a stubbed gate. A ceiling assertion over a fixture that cannot
    overflow certifies nothing, and no CODE mutation can reveal it.
    """
    raw = _raw_producer_bytes(results)
    assert raw > limit, (
        f"{label}'s fixture is VACUOUS: its raw producers total {raw} B against "
        f"an effective limit of {limit} B, so the ceiling could never be reached "
        f"and the assertion cannot fail"
    )


# ---------------------------------------------------------------------------
# AT-250 / AT-251 / AT-252 — the ceiling.
# ---------------------------------------------------------------------------


def test_at250_document_never_exceeds_the_stated_ceiling(tmp_path: Path) -> None:
    """AT-250 — content that would overflow the budget yields a bounded file.

    Mutation that reddens it (executed on a copy of the fixed tree):
    ``_EmissionGate.fits`` -> ``return True``.
    """
    results = [_result(f"v{i}", rows=200, width=_WIDEST_CELL, mem=4096) for i in range(10)]
    path = _generate(tmp_path, results)
    size = len(path.read_bytes())
    assert size <= _ceiling(len(results)), (
        f"document is {size} B, above the stated ceiling {_ceiling(len(results))} B"
    )


@pytest.mark.parametrize("variants", [1, 10, 100])
def test_at251_ceiling_holds_across_the_variant_count(
    tmp_path: Path, variants: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-251 — the ceiling is invariant in V (above the named heading term).

    Run against a shrunken limit so that EVERY arm — including V=1 — actually
    overflows; at the real cap the V=1 arm cannot, and would be vacuous.

    Mutation: the reservation ``limit // max(V, 1)`` -> ``limit``.
    """
    monkeypatch.setattr(report_service, "REPORT_MAX_TOTAL_BYTES", _SHRUNK_LIMIT)
    results = [_result(f"v{i}", rows=60) for i in range(variants)]
    path = _generate(tmp_path, results)
    size = len(path.read_bytes())
    assert size <= _ceiling(variants, limit=_SHRUNK_LIMIT), (
        f"at V={variants} the document is {size} B, above "
        f"{_ceiling(variants, limit=_SHRUNK_LIMIT)} B"
    )


@pytest.mark.parametrize("files", [1, 3, 10])
def test_at252_ceiling_holds_across_the_check_file_count(
    tmp_path: Path, files: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-252 — invariant in F, against a SHRUNK budget so the gate must fire.

    The shrunk limit is what makes this non-vacuous: rows stay UNDER
    ``MAX_REPORT_ROWS_PER_VARIANT`` so batch-74's row cap never fires and the
    only thing that can bound the document is this batch's byte gate.

    Mutation: ``put``'s ``if not gate.emit(...)`` -> unconditional emit.
    """
    monkeypatch.setattr(report_service, "REPORT_MAX_TOTAL_BYTES", _SHRUNK_LIMIT)
    results = [_result("v0", rows=40, files=files, mem=4096)]
    path = _generate(tmp_path, results)
    size = len(path.read_bytes())
    assert size <= _ceiling(1, limit=_SHRUNK_LIMIT), (
        f"at F={files} the document is {size} B, above "
        f"{_ceiling(1, limit=_SHRUNK_LIMIT)} B"
    )


# ---------------------------------------------------------------------------
# AT-253 / TC-560 — every drop is disclosed, in BYTES.
# ---------------------------------------------------------------------------


def test_at253_every_drop_is_disclosed_with_its_byte_total(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-253 — the disclosure states BYTES, and something was both kept and cut.

    Intent: revision 1 asserted "counts sum to what was actually cut" with no
    unit, which "3 sections omitted" satisfies while telling an auditor nothing
    about how much of their document is gone.

    Mutation (pair): delete the disclosure · emit it unconditionally.
    """
    monkeypatch.setattr(report_service, "REPORT_MAX_TOTAL_BYTES", 30_000)
    results = [_result(f"v{i}", rows=60) for i in range(4)]
    text = _generate(tmp_path, results).read_text(encoding="utf-8")

    assert "## Omitted content" in text, "content was refused but never disclosed"
    disclosed = [ln for ln in text.splitlines() if ln.startswith("- ") and "bytes " in ln]
    assert disclosed, "the disclosure block states no byte total"
    total = sum(
        int(ln.split("bytes ")[1].split(",")[0].split(" ")[0].rstrip(")").strip())
        for ln in disclosed
    )
    assert total > 0, "a refusal was recorded with a zero byte cost"
    # kept > 0 AND cut > 0 — a report that dropped everything, or nothing,
    # cannot discriminate a partial-refusal bug.
    assert text.count("## Variant:") == 4, "a variant vanished"
    assert "| Address |" in text, "nothing at all was kept — the fixture is degenerate"


def test_tc560_disclosed_bytes_equal_the_refused_line_bytes() -> None:
    """TC-560 — the disclosed byte total IS Σ ``_line_bytes(refused)``.

    Asserted at the accumulator rather than through the rendered text, so the
    arithmetic is checked against the function that produces it, not against a
    substring of its own rendering.
    """
    gate = report_service._EmissionGate(limit=100)
    batch = ["x" * 500]
    cost = _line_bytes(batch)
    assert gate.emit(batch, "modifications") is False
    assert gate.refusals.total_bytes() == cost
    assert gate.refusals.lines["modifications"] == len(batch)
    assert gate.refusals.sections["modifications"] == 1


# ---------------------------------------------------------------------------
# AT-254 — the F7 fairness property (operator ruling).
# ---------------------------------------------------------------------------


def test_at254_no_variant_vanishes_when_the_budget_is_spent_early(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-254 — EVERY variant gets a section heading, even exhausted early.

    Intent: with global first-fit over attacker-ordered input, an early oversized
    variant blanks every later one — so *who gets documented* becomes the
    attacker's choice. The per-variant reservation makes it structural.

    Mutation: the reservation -> global first-fit (drop ``begin_variant``).
    """
    monkeypatch.setattr(report_service, "REPORT_MAX_TOTAL_BYTES", 9000)
    # v0 is a deliberate hog; v1..v5 are small. Under first-fit v0 eats the
    # document and the rest are left as bare headings.
    results = [_result("v0", rows=70)] + [
        _result(f"v{i}", rows=5) for i in range(1, 6)
    ]
    text = _generate(tmp_path, results).read_text(encoding="utf-8")

    # (a) LLR-108.5 — no variant vanishes.
    for r in results:
        assert f"## Variant: {r.variant_id}" in text, (
            f"variant {r.variant_id!r} has no section — the hog starved it"
        )

    # (b) LLR-108.4 — and each one gets REAL CONTENT, not just a heading.
    #
    # ⚠ This half is the one that actually tests fairness, and the first draft of
    # this node did NOT have it. Asserting only (a) was INERT: a heading costs
    # ~20 B and is emitted unconditionally, so it survives ANY allocation
    # policy. The node stayed GREEN under both mutations that were supposed to
    # redden it — reservation -> global first-fit, and heading -> gated — which
    # is C-40's definition of a predicate that cannot gate what it claims to.
    # Executed, not argued: both mutations now redden it.
    sections = text.split("## Variant: ")[1:]
    assert len(sections) == len(results)
    starved = [
        section.splitlines()[0]
        for section in sections
        if len([ln for ln in section.splitlines()[1:] if ln.strip()]) < 3
    ]
    assert not starved, (
        f"variants {starved} got a heading but no audit record — the hog "
        f"consumed the shares of the variants after it, which is exactly the "
        f"attacker-chooses-who-is-documented property the reservation prevents"
    )


# ---------------------------------------------------------------------------
# AT-255 / AT-256 — PINs. Green on the base tree; they guard collateral damage
# and CANNOT discriminate the change. Labelled, per Phase-2 M-1.
# ---------------------------------------------------------------------------


def test_at264_every_variant_heading_survives_a_fully_exhausted_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-264 — at a budget of 1 byte, EVERY variant heading is still present.

    ⚠ This arm exists because AT-254's "no variant vanishes" clause was INERT on
    its own: a heading costs ~20 B, so at any realistic budget it fits whether
    or not it is gated, and mutating it to a gated emit left the node green.
    Driving the budget to 1 B is what makes the unconditional emission
    (LLR-108.5) the ONLY reason a heading can appear. Executed: gating the
    heading now reddens this node.
    """
    monkeypatch.setattr(report_service, "REPORT_MAX_TOTAL_BYTES", 1)
    results = [_result(f"v{i}", rows=5) for i in range(6)]
    text = _generate(tmp_path, results).read_text(encoding="utf-8")
    missing = [r.variant_id for r in results if f"## Variant: {r.variant_id}" not in text]
    assert not missing, (
        f"variants {missing} vanished from the audit record at an exhausted "
        f"budget — the heading is not being emitted unconditionally"
    )


def test_at255_pin_exhausted_report_is_still_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-255 (PIN) — a budget-exhausted report still exists, is non-empty, has a header.

    This is the acceptance that decided P-16: the header is O(1) (measured flat
    at 181 B from V=1 to V=20 000) and is emitted unconditionally, because
    literal uniform gating would refuse the document's own title at large V and
    contradict this node.
    """
    monkeypatch.setattr(report_service, "REPORT_MAX_TOTAL_BYTES", 1)
    results = [_result("v0", rows=200)]
    path = _generate(tmp_path, results)
    text = path.read_text(encoding="utf-8")

    assert path.exists()
    assert text.strip(), "the report is empty"
    assert text.startswith("# Project report: proj"), "the header was refused"


def test_at256_pin_under_cap_report_is_byte_identical_to_the_inc0_golden(
    tmp_path: Path,
) -> None:
    """AT-256 (PIN) — the bound is INVISIBLE where it does not fire.

    The golden was captured at Inc-0 from the SHIPPED producer, in its own
    commit, so it cannot certify this rewrite against itself (C-12). The fixture
    is duplicated verbatim from that capture script; drift makes this node fail,
    which is the correct signal.
    """
    results = _inc0_fixture()
    root = tmp_path / "proj"
    root.mkdir(parents=True, exist_ok=True)
    path = generate_project_report(
        root,
        results,
        ReportOptions(),
        variant_set=_inc0_variant_set(),
        now_fn=lambda: _INSTANT,
    )
    assert _GOLDEN.exists(), f"the Inc-0 golden is missing at {_GOLDEN}"
    produced = canonical_report_bytes(path.read_bytes(), tmp_path)
    stored = canonical_report_bytes(_GOLDEN.read_bytes(), None)
    assert produced == stored, (
        "the under-cap report drifted from the Inc-0 golden — the gate fired "
        "where it must not"
    )


def _inc0_fixture() -> List[VariantExecutionResult]:
    """Copied VERBATIM from ``.dev-flow/2026-07-31-batch-76/inc0-capture-golden.py``."""
    results: List[VariantExecutionResult] = []
    for v in range(3):
        base = 0x8000_0000 + v * 0x1000
        mods = [
            ChangeSummaryEntry(
                entry_type="bytes",
                address_start=base + i * 16,
                address_end=base + i * 16 + (i % 4) + 1,
                before_bytes=tuple(range(0x10, 0x10 + (i % 4) + 1)),
                after_bytes=tuple(range(0xA0, 0xA0 + (i % 4) + 1)),
                disposition="applied" if i % 3 else "skipped",
                linkage="a2l" if i % 2 else "standalone",
                linkage_symbol=f"SYM_{v}_{i}" if i % 2 else None,
            )
            for i in range(6)
        ]
        summary = ChangeSummary(
            source_path=Path("chg.json"),
            kind="change",
            encoding="utf-8",
            value_mode="text",
            timestamp_utc="2026-07-31T11:00:00+00:00",
            variant_id=f"v{v}",
            counts={"applied": sum(1 for m in mods if m.disposition == "applied")},
            entries=mods,
            issues=[],
        )
        checks = [
            CheckRunEntry(
                entry_type="bytes",
                address_start=0x9000_0000 + v * 0x1000 + i * 16,
                address_end=0x9000_0000 + v * 0x1000 + i * 16 + (i % 3) + 1,
                expected_bytes=tuple(range(0x20, 0x20 + (i % 3) + 1)),
                actual_bytes=tuple(range(0x20, 0x20 + (i % 3) + 1)),
                result="pass" if i % 2 else "fail",
                linkage="standalone",
                linkage_symbol=None,
                reason_code=None,
                reason=None,
            )
            for i in range(4)
        ]
        check = CheckRunResult(
            source_path=Path("chk.json"),
            timestamp_utc="2026-07-31T11:00:00+00:00",
            variant_id=f"v{v}",
            aggregates={
                "passed": sum(1 for c in checks if c.result == "pass"),
                "failed": sum(1 for c in checks if c.result == "fail"),
                "uncheckable": 0,
            },
            entries=checks,
            issues=[],
        )
        mem_map: Dict[int, int] = {
            base + offset: (offset * 7 + v) & 0xFF for offset in range(0, 128)
        }
        results.append(
            VariantExecutionResult(
                variant_id=f"v{v}",
                status="ok",
                change_summaries=[summary],
                check_results=[check],
                mem_map=mem_map,
            )
        )
    return results


def _inc0_variant_set() -> ProjectVariantSet:
    """Copied VERBATIM from the Inc-0 capture script."""
    return ProjectVariantSet(
        project_name="proj",
        variants=tuple(
            VariantDescriptor(
                variant_id=f"v{v}", path=Path(f"v{v}.s19"), file_type="s19"
            )
            for v in range(3)
        ),
        active_id="v0",
    )


# ---------------------------------------------------------------------------
# TC-553 / TC-554 — the AST census, and its positive control.
# ---------------------------------------------------------------------------

#: The two functions that compose the document. Recorded LEXICALLY: "reachable
#: from" is not statically computable, and a walk that silently returns nothing
#: passes an emptiness census.
_COMPOSING_FUNCTIONS = ("generate_project_report", "_hexdump_section")

#: The only names allowed to grow the document.
_ADMITTED_SINKS = {"emit", "emit_unconditional", "put"}


def _ungated_appends(source: str, function: str) -> List[str]:
    """Every ``*.append``/``*.extend`` in ``function`` that is not an admitted sink."""
    tree = ast.parse(source)
    target = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == function
    )
    found: List[str] = []
    for node in ast.walk(target):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in ("append", "extend"):
            continue
        base = node.func.value
        name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "?")
        # ``notes``/``out`` accumulators that never reach the document are fine;
        # the document's own line list is not.
        if name in ("lines", "out"):
            found.append(f"{function}: {name}.{node.func.attr} at line {node.lineno}")
    return found


def test_tc553_no_producer_writes_to_the_document_outside_the_gate() -> None:
    """TC-553 — every line into the document goes through the gate.

    The census is asserted NON-EMPTY in TC-554 (a broken walk returns zero and
    would pass an emptiness assertion silently), and the exclusion set here has
    cardinality 0 — there are no grandfathered sites.
    """
    source = inspect.getsource(report_service)
    problems: List[str] = []
    for function in _COMPOSING_FUNCTIONS:
        problems.extend(_ungated_appends(source, function))
    assert not problems, "ungated writes into the document:\n" + "\n".join(problems)


def test_tc573_the_hexdump_seam_refuses_when_the_gate_is_exhausted() -> None:
    """TC-573 — LLR-108.3 asserted AT THE SEAM, not through the document ceiling.

    ⚠ Why this node exists, stated plainly. The obvious way to gate ``put`` is to
    let a ceiling AT catch it — and that DOES NOT WORK here, which the mutation
    matrix showed rather than argued: restoring revision 1's ``_hexdump_section``
    exemption left AT-250 and AT-252 GREEN. Two independent reasons, both real:

      * batch-74's ``REPORT_MAX_REGIONS_PER_VARIANT`` already bounds how much
        hexdump ONE variant can emit, so an ungated ``put`` overshoots by a
        bounded amount per variant rather than without limit;
      * against a SHRUNKEN limit the disclosure allowance (~47 kB) dwarfs the
        limit, so a modest overshoot hides inside the ceiling's own slack.

    So the ceiling is the wrong instrument for this clause. This asserts the
    property directly: with the budget already spent, the seam admits nothing.
    Under the exemption it admits everything, and this node reddens.
    """
    result = _result("v0", rows=8, mem=512)
    gate = report_service._EmissionGate(limit=1)
    gate.emit(["x" * 40], "preamble")  # spend the budget
    before = len(gate.lines)
    report_service._hexdump_section(result, ReportOptions(), gate)
    # The unconditional TRUNCATED marker and the blank line that closes it are
    # allowance-charged by design ("explicit beats silent"), so they are not
    # "admitted content" -- everything else would be.
    admitted = [
        ln
        for ln in gate.lines[before:]
        if ln.strip() and not ln.startswith("> TRUNCATED:")
    ]
    assert admitted == [], (
        f"the hexdump seam admitted {len(admitted)} line(s) past an exhausted "
        f"budget — put is not gating (LLR-108.3): {admitted[:3]}"
    )
    assert gate.refusals.sections.get("memory-regions", 0) > 0, (
        "the seam refused content but recorded no refusal, so the disclosure "
        "would under-report what is missing"
    )


def test_tc554_the_census_walk_actually_finds_a_planted_write() -> None:
    """TC-554 — positive control. Plant an ungated write in a COPY; census must see it.

    Without this, TC-553 asserts a list is empty — and a walk that finds nothing
    because it is broken is indistinguishable from a clean tree.
    """
    planted = (
        "def generate_project_report():\n"
        "    lines = []\n"
        "    lines.append('smuggled past the gate')\n"
    )
    found = _ungated_appends(planted, "generate_project_report")
    assert found, "the census walk is broken — it cannot see a planted ungated write"
    assert len(found) == 1


# ---------------------------------------------------------------------------
# TC-555 / TC-556 — the derived constants.
# ---------------------------------------------------------------------------


def test_tc555_allowance_is_recomputed_independently_and_discriminates() -> None:
    """TC-555 — recompute the allowance in the TEST, never by calling the product helper.

    Intent: revision 1 asserted ``ALLOWANCE == _derive()``, which is an identity
    and cannot fail. Here the O(V) slope is re-derived from two measured points
    and compared to the closed-set cardinality the design claims bounds it.
    """
    # The V-dependent term must be exactly linear in V, and its slope must be
    # the per-variant heading + marker allowance — not an emergent number.
    a0, a1, a10 = (_disclosure_allowance(v) for v in (0, 1, 10))
    slope_1 = a1 - a0
    slope_10 = (a10 - a0) / 10
    assert slope_1 == slope_10, "the O(V) term is not linear in V"
    # Discriminating arm: the block scales with the CLOSED label set, so a
    # shorter set must produce a smaller allowance. If it does not, the label
    # tuple is not actually driving the derivation.
    assert a0 > len(REPORT_SECTION_KINDS), "the allowance ignores the label set"
    assert _disclosure_allowance(100) > _disclosure_allowance(10)


def test_tc556_reservation_floor_covers_a_real_minimal_variant_record(
    tmp_path: Path,
) -> None:
    """TC-556 — the floor is DERIVED and covers a measured minimal audit record.

    The relation is asserted, not the number: a hard-coded 394 would go stale
    the moment a section heading is renamed, and this batch's own backlog warns
    that every carried figure in this area has drifted.
    """
    one = len(_generate(tmp_path / "a", [_result("v0", rows=0)]).read_bytes())
    two = len(
        _generate(
            tmp_path / "b", [_result("v0", rows=0), _result("v1", rows=0)]
        ).read_bytes()
    )
    marginal = two - one
    assert marginal > 0, "adding a variant cost nothing — the fixture is degenerate"
    assert REPORT_VARIANT_RESERVATION_FLOOR_BYTES >= marginal, (
        f"the floor {REPORT_VARIANT_RESERVATION_FLOOR_BYTES} B cannot carry one "
        f"variant's minimal record, measured at {marginal} B"
    )


# ---------------------------------------------------------------------------
# TC-557 / TC-558 — gate-before-commit, and non-latching.
# ---------------------------------------------------------------------------


def test_tc557_a_refused_batch_does_not_grow_the_document() -> None:
    """TC-557 — the gate is consulted BEFORE the lines are committed.

    A gate that appends and then checks has already corrupted the document.
    """
    gate = report_service._EmissionGate(limit=50)
    assert gate.emit(["x" * 500], "modifications") is False
    assert gate.lines == [], "a refused batch still grew the document"


def test_tc558_refusal_does_not_latch() -> None:
    """TC-558 — a small batch AFTER a refused large one is still admitted.

    Intent: latching would make the document's contents depend on emission
    ORDER, which is attacker-controlled. LLR-102.2 had no node at all in
    revision 1.
    """
    gate = report_service._EmissionGate(limit=200)
    assert gate.emit(["y" * 5000], "modifications") is False
    assert gate.emit(["small"], "checklists") is True, "the gate latched"
    assert "small" in gate.lines


def test_tc574_reservation_and_budget_must_BOTH_admit() -> None:
    """TC-574 — P-27. Reservation-only gating would break the ceiling.

    A floored reservation over-subscribes the document
    (``Σ = V·max(CAP//V, floor)``, measured 48.8x CAP at V=100 000), so an
    admission has to satisfy the document budget as well as the variant's share.
    Here the reservation is generous and the DOCUMENT budget is what must refuse.
    """
    gate = report_service._EmissionGate(limit=100)
    gate.begin_variant(0, reservation=10_000)  # far larger than the document
    assert gate.emit(["z" * 500], "modifications") is False, (
        "the document budget was ignored in favour of the variant reservation — "
        "this is exactly how a large-V report would blow the ceiling"
    )


# ---------------------------------------------------------------------------
# TC-559 — the round-robin appendix.
# ---------------------------------------------------------------------------


def test_tc559_appendix_retention_is_round_robin_not_first_come() -> None:
    """TC-559 — one note per variant before any variant's second.

    Intent: ``notes[:CAP]`` retains the EARLIEST, so an attacker floods with
    cheap notes from variants ordered ahead and evicts the note naming the real
    target. The last variant's note must survive a flood from the first.
    """
    cap = 4
    flood: List[Tuple[int, str]] = [(0, f"hog-{i}") for i in range(20)]
    flood.append((9, "the-target"))
    selected, not_itemised, distinct = _select_notes(flood, cap)

    assert "the-target" in selected, (
        "a flood from variant 0 evicted the last variant's note — retention is "
        "first-come, not round-robin"
    )
    assert len(selected) == cap
    # the conservation invariant: nothing is silently dropped
    assert len(selected) + not_itemised == len(flood)
    assert distinct >= 1


def test_tc575_appendix_cap_is_inert_below_the_cap() -> None:
    """TC-575 — under the cap every note is itemised and nothing is summarised."""
    notes = [(i, f"n{i}") for i in range(3)]
    selected, not_itemised, distinct = _select_notes(notes, REPORT_MAX_TRUNCATION_NOTES)
    assert len(selected) == 3
    assert not_itemised == 0
    assert distinct == 0


# ---------------------------------------------------------------------------
# TC-561 — the disclosure block's line count is O(1) in V and F.
# ---------------------------------------------------------------------------


def test_tc561_disclosure_line_count_is_bounded_by_the_closed_label_set() -> None:
    """TC-561 — the block cannot grow with V or F.

    Revision 1's per-refusal disclosure was O(V): ~558 lines at V=100 against a
    ~1 kB allowance, so a CORRECT implementation reddened the ceiling AT.
    """
    refusals = report_service._Refusals()
    # 500 refusals across 200 variants, spread over every kind.
    for i in range(500):
        kind = REPORT_SECTION_KINDS[i % len(REPORT_SECTION_KINDS)]
        refusals.record(kind, ["line"], 10, i % 200)
    block = report_service._disclosure_lines(refusals)
    # header (2) + at most one row per kind + trailing blank
    assert len(block) <= len(REPORT_SECTION_KINDS) + 3, (
        f"the disclosure block is {len(block)} lines — it grew with the refusal count"
    )
    # and no operator-derived string leaked in: only integers after "variants "
    for line in block:
        if "variants " in line:
            listed = line.split("variants ")[1].rstrip(")")
            for token in listed.replace("+", " ").replace("more", " ").split(","):
                token = token.strip()
                if token:
                    assert token.split()[0].isdigit(), (
                        f"a non-integer reached the disclosure: {token!r}"
                    )
