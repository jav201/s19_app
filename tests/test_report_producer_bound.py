"""batch-74 Inc-1 — acceptance + test nodes for R-TUI-101 / HLR-105 / LLR-105.x.

``report_service._modifications_lines`` is an UNBOUNDED producer on two
independent axes (spec ``01-requirements.md`` §2 US-B74-1):

1. **Row cardinality.** It materialises TWO full-population lists before any
   output exists — the ``entries`` flattening and, under a filter, the ``kept``
   filter list — then emits one row per entry with no cap.
2. **Byte-run width.** ``_format_bytes`` renders the WHOLE run, and the wire
   ceiling on one run is ``MF_RUN_LENGTH_CEILING = 1_048_576`` bytes, so a
   single row can cost ~6 MiB.

The two axes are mutually invariant (§2.7 P-22), so they carry separate ATs.

Node inventory — every node names its owning requirement:

- **AT-240** LLR-105.1 · cardinality bound, observed on the WRITTEN report.
- **AT-242** LLR-105.3 + 105.5 · byte-cell width bound + the elided-count cue.
- **AT-244** LLR-105.4′ · the dropped count is the **kept** count minus the cap,
  never the population count.
- **AT-247** LLR-105.x · positive control: an under-cap, in-domain, sub-width
  report stays **byte-identical** to the shipped producer's output. The golden
  was captured at Inc-0 from the SHIPPED producer (C-12), so it cannot certify
  the rewrite against itself.
- **AT-248** LLR-105.1 · the §5.1 resident-memory oracle.
- **TC-540..TC-545** white-box nodes for the cap arms, the width arms, count
  correctness, the notice's content, the no-bare-literal source rule, and the
  oracle's own discrimination.

Two mechanisms this module is required to use:

1. **Every cap value is read off the module OBJECT inside the test body** — an
   AT quotes the constant, never its value (LLR-105.6), and ``TC-544`` enforces
   that mechanically over this file's own AST.
2. **Notice counting is SECTION-SCOPED.** The report carries several
   pre-existing ``> TRUNCATED:`` emitters, so a report-wide grep is not an
   oracle. :func:`_section_scope` RAISES when the heading is missing, so "no
   notice" can never be confused with "no scope".

Confidentiality (F-S-07): every fixture below is a synthetic in-memory object
graph written under ``tmp_path`` — never operator firmware, never a repo write.
"""

from __future__ import annotations

import ast
import inspect
import re
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import pytest

from s19_app.range_index import build_sorted_range_index
from s19_app.tui.changes.model import (
    CHECK_AGGREGATE_KEYS,
    DISPOSITION_DOMAIN,
    ChangeSummary,
    ChangeSummaryEntry,
    CheckRunEntry,
    CheckRunResult,
)
from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services import report_service
from s19_app.tui.services.report_filter import ReportFilterMatcher
from s19_app.tui.services.report_service import (
    ReportOptions,
    generate_project_report,
)
from s19_app.tui.services.variant_execution_service import VariantExecutionResult

from conftest import canonical_report_bytes

#: Fixed report clock, so a generated document is a deterministic artefact.
_FIXED_INSTANT = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)

#: The Inc-0 pre-flight golden (AT-247), captured from the SHIPPED producer.
_GOLDEN = Path(__file__).parent / "goldens" / "batch74" / (
    "producer-bound-positive-control.md"
)

#: A table row of either producer — both open with the ``Address`` cell.
_ROW_RE = re.compile(r"^\| 0x")

#: Any Markdown heading, whatever its depth — the section-scope terminator.
_HEADING_RE = re.compile(r"^#{1,6} ")


def _cap() -> int:
    """Return ``MAX_REPORT_ROWS_PER_VARIANT`` off the module object."""
    return int(report_service.MAX_REPORT_ROWS_PER_VARIANT)


def _bytes_per_cell() -> int:
    """Return ``REPORT_BYTES_PER_CELL`` off the module object."""
    return int(report_service.REPORT_BYTES_PER_CELL)


def _cue(dropped: int) -> str:
    """Render the byte-cell cue for ``dropped`` elided values."""
    return report_service.REPORT_BYTES_TRUNCATION_CUE_FMT.format(dropped=dropped)


# ---------------------------------------------------------------------------
# Fixture builders — synthetic object graphs, never a parsed file
# ---------------------------------------------------------------------------


def _counts(applied: int = 0) -> Dict[str, int]:
    """Build a ``ChangeSummary.counts`` mapping over the disposition domain."""
    counts = {token: 0 for token in DISPOSITION_DOMAIN}
    counts["applied"] = applied
    return counts


def _aggregates() -> Dict[str, int]:
    """Build an all-zero ``CheckRunResult.aggregates`` mapping."""
    return {key: 0 for key in CHECK_AGGREGATE_KEYS}


def _entry(
    start: int,
    *,
    run: Sequence[int] = (0x01,),
    symbol: Optional[str] = None,
) -> ChangeSummaryEntry:
    """Build one applied ``ChangeSummaryEntry`` carrying ``run`` bytes."""
    return ChangeSummaryEntry(
        entry_type="bytes",
        address_start=start,
        address_end=start + len(run),
        before_bytes=tuple(run),
        after_bytes=tuple(run),
        disposition="applied",
        linkage="a2l" if symbol else "standalone",
        linkage_symbol=symbol,
    )


def _check_entry(
    start: int,
    *,
    run: Sequence[int] = (0x01,),
    symbol: Optional[str] = None,
) -> CheckRunEntry:
    """Build one passing ``CheckRunEntry`` carrying ``run`` bytes."""
    return CheckRunEntry(
        entry_type="bytes",
        address_start=start,
        address_end=start + len(run),
        expected_bytes=tuple(run),
        actual_bytes=tuple(run),
        result="pass",
        linkage="a2l" if symbol else "standalone",
        linkage_symbol=symbol,
        reason_code=None,
        reason=None,
    )


def _summary(
    entries: Sequence[ChangeSummaryEntry] = (),
    *,
    variant_id: Optional[str] = None,
    source: str = "chg.json",
) -> ChangeSummary:
    """Build a ``ChangeSummary`` carrying ``entries``."""
    return ChangeSummary(
        source_path=Path(source),
        kind="change",
        encoding="utf-8",
        value_mode="text",
        timestamp_utc="2026-07-31T11:00:00+00:00",
        variant_id=variant_id,
        counts=_counts(len(entries)),
        entries=list(entries),
        issues=[],
        saved_path=None,
    )


def _check(
    entries: Sequence[CheckRunEntry] = (), *, source: str = "chk.json"
) -> CheckRunResult:
    """Build a ``CheckRunResult`` carrying ``entries``."""
    return CheckRunResult(
        source_path=Path(source),
        timestamp_utc="2026-07-31T11:00:00+00:00",
        variant_id=None,
        aggregates=_aggregates(),
        entries=list(entries),
        issues=[],
    )


def _result(
    variant_id: str,
    summaries: Sequence[ChangeSummary] = (),
    checks: Sequence[CheckRunResult] = (),
) -> VariantExecutionResult:
    """Build one ``VariantExecutionResult`` for ``variant_id``."""
    return VariantExecutionResult(
        variant_id=variant_id,
        status="ok",
        change_summaries=list(summaries),
        check_results=list(checks),
    )


def _variant_set(*variant_ids: str) -> ProjectVariantSet:
    """Build the report's ``ProjectVariantSet`` inventory over ``variant_ids``."""
    descriptors = tuple(
        VariantDescriptor(
            variant_id=vid, path=Path(f"{vid}.s19"), file_type="s19"
        )
        for vid in variant_ids
    )
    return ProjectVariantSet(
        project_name="proj", variants=descriptors, active_id=variant_ids[0]
    )


def _symbol_filter(*patterns: str) -> ReportFilterMatcher:
    """Build a resolved SYMBOL-ONLY filter — no address range matches."""
    return ReportFilterMatcher(
        patterns=tuple(patterns),
        matched_index=build_sorted_range_index([]),
        source_name="fixture.json",
    )


def _generate(
    root: Path,
    results: Sequence[VariantExecutionResult],
    *,
    variant_ids: Sequence[str] = ("v0",),
    options: Optional[ReportOptions] = None,
) -> str:
    """Generate one report under ``root`` and return its written text."""
    root.mkdir(parents=True, exist_ok=True)
    path = generate_project_report(
        root,
        list(results),
        options if options is not None else ReportOptions(),
        variant_set=_variant_set(*variant_ids),
        now_fn=lambda: _FIXED_INSTANT,
    )
    return path.read_text(encoding="utf-8")


def _section_scope(text: str, variant_id: str, heading: str) -> List[str]:
    """
    Summary:
        Return the lines of ``variant_id``'s ``heading`` block — from the
        heading to the next heading of any depth, exclusive.

    Args:
        text (str): The written report text.
        variant_id (str): The variant whose per-variant section is scoped.
        heading (str): The exact section heading, e.g. ``"### Modifications"``.

    Returns:
        List[str]: The block's lines, heading excluded.

    Raises:
        AssertionError: When the variant heading or ``heading`` is absent —
            an empty scope must never be confused with "no notice".

    Data Flow:
        - Pure line scan over the written document.

    Dependencies:
        Used by:
            - AT-240 / AT-242 / AT-244 / TC-540 / TC-541 / TC-543

    Example:
        >>> _section_scope("## Variant: a\\n### M\\nx", "a", "### M")
        ['x']
    """
    lines = text.splitlines()
    try:
        start = lines.index(f"## Variant: {variant_id}")
    except ValueError:  # pragma: no cover - fixture defect, not a behaviour
        raise AssertionError(
            f"variant {variant_id!r} has no '## Variant:' heading — the "
            f"fixture never reached the producer, so any count below is "
            f"vacuous"
        )
    try:
        head = lines.index(heading, start)
    except ValueError:  # pragma: no cover - fixture defect, not a behaviour
        raise AssertionError(
            f"variant {variant_id!r} has no {heading!r} section — an absent "
            f"scope is not an empty scope"
        )
    body: List[str] = []
    for line in lines[head + 1:]:
        if _HEADING_RE.match(line):
            break
        body.append(line)
    return body


def _rows(scope: Sequence[str]) -> List[str]:
    """Return the table rows of a scoped section."""
    return [line for line in scope if _ROW_RE.match(line)]


def _notices(scope: Sequence[str]) -> List[str]:
    """Return the ``> TRUNCATED:`` notices of a scoped section."""
    return [line for line in scope if line.startswith("> TRUNCATED:")]


def _byte_cells(row: str) -> Tuple[str, str]:
    """Return the ``(Before, After)`` byte-run cells of a Modifications row."""
    cells = [cell.strip() for cell in row.split("|")]
    return cells[3], cells[4]


# ---------------------------------------------------------------------------
# AT-240 — LLR-105.1: the cardinality bound, on the WRITTEN report
# ---------------------------------------------------------------------------


def test_at240_modifications_admits_at_most_the_cap(tmp_path: Path) -> None:
    """AT-240 — ``E = CAP+1`` renders exactly ``CAP`` rows plus ONE notice.

    Intent: the producer's admitted row count is bounded by its own constant,
    not by the per-variant entry count. ``CAP+1`` is the tightest fixture that
    distinguishes a working bound from an absent one, and it is deliberately
    the boundary a ``>=``/``>`` slip would flip (§5 reddening mutation).

    Scope: that variant's ``### Modifications`` block only — the report has
    other ``> TRUNCATED:`` emitters and a report-wide count is not an oracle.
    """
    cap = _cap()
    results = [
        _result(
            "v0",
            [
                _summary(
                    [_entry(0x8000_0000 + 16 * i) for i in range(cap + 1)],
                    variant_id="v0",
                )
            ],
        )
    ]
    scope = _section_scope(
        _generate(tmp_path, results), "v0", "### Modifications"
    )

    assert len(_rows(scope)) == cap, (
        f"expected exactly MAX_REPORT_ROWS_PER_VARIANT ({cap}) admitted rows "
        f"at E = cap + 1, got {len(_rows(scope))}"
    )
    assert len(_notices(scope)) == 1, (
        f"a bound that fires must disclose itself exactly once in its own "
        f"section; got {len(_notices(scope))} notices"
    )


# ---------------------------------------------------------------------------
# AT-242 — LLR-105.3 + 105.5: byte-cell width bound and its elided-count cue
# ---------------------------------------------------------------------------


def test_at242_byte_cell_is_bounded_and_states_the_elided_count(
    tmp_path: Path,
) -> None:
    """AT-242 — a ``4·B`` run renders ``≤ 3·B − 1 + len(cue)`` and states ``3·B``.

    The predicate quotes the FORMULA, never a literal and never
    ``REPORT_CELL_CHARS``: ``3·B − 1`` already equals ``REPORT_CELL_CHARS``
    before the cue is appended, so a ``≤ REPORT_CELL_CHARS`` predicate is RED
    after a CORRECT fix (§5.2, revision 2's executed failure).

    ``len(cue)`` is derived from the INDEPENDENTLY known elided count
    ``4·B − B = 3·B`` — never from the emitted cell, which would make the
    predicate circular and unable to fail (§7 authoring note).
    """
    per_cell = _bytes_per_cell()
    run = [i % 256 for i in range(4 * per_cell)]
    elided = 4 * per_cell - per_cell
    cue = _cue(elided)
    bound = 3 * per_cell - 1 + len(cue)

    results = [
        _result("v0", [_summary([_entry(0x8000_0000, run=run)], variant_id="v0")])
    ]
    scope = _section_scope(
        _generate(tmp_path, results), "v0", "### Modifications"
    )
    rows = _rows(scope)
    assert len(rows) == 1, f"fixture must render exactly one row, got {len(rows)}"

    expected_head = " ".join(f"{value:02X}" for value in run[:per_cell])
    for label, cell in zip(("Before", "After"), _byte_cells(rows[0])):
        assert len(cell) <= bound, (
            f"{label} cell is {len(cell)} chars, over the "
            f"3·REPORT_BYTES_PER_CELL − 1 + len(cue) = {bound} bound"
        )
        assert cell == expected_head + cue, (
            f"{label} cell must be the first REPORT_BYTES_PER_CELL tokens "
            f"followed by a cue stating the true elided count {elided}"
        )


def test_at243_width_only_checklist_byte_cell_is_bounded(tmp_path: Path) -> None:
    """AT-243 (Inc-1 partial) — ``Expected``/``Actual`` obey the same width bound.

    Inc-1 only makes ``max_bytes`` REQUIRED, which forces ``_checklist_lines``'
    two call sites to pass it; the checklist ROW cap is Inc-2's. This node
    therefore asserts the width axis only — the axis Inc-1 actually closes.

    ⚠ **AT-243 is NOT discharged by this node.** §7 assigns AT-243 to Inc-2,
    where the cardinality half lands; the ``width_only`` in the node name is
    what keeps a green run here from reading as a closed AT at the Inc-2 gate.
    """
    per_cell = _bytes_per_cell()
    run = [i % 256 for i in range(4 * per_cell)]
    cue = _cue(4 * per_cell - per_cell)
    bound = 3 * per_cell - 1 + len(cue)

    results = [_result("v0", [], [_check([_check_entry(0x9000_0000, run=run)])])]
    scope = _section_scope(_generate(tmp_path, results), "v0", "#### Checklist: `chk.json`")
    rows = _rows(scope)
    assert len(rows) == 1, f"fixture must render exactly one row, got {len(rows)}"

    expected_head = " ".join(f"{value:02X}" for value in run[:per_cell])
    cells = [cell.strip() for cell in rows[0].split("|")]
    for label, cell in zip(("Expected", "Actual"), (cells[3], cells[4])):
        assert len(cell) <= bound, (
            f"{label} cell is {len(cell)} chars, over the "
            f"3·REPORT_BYTES_PER_CELL − 1 + len(cue) = {bound} bound"
        )
        assert cell == expected_head + cue, f"{label} cell is not head + cue"


# ---------------------------------------------------------------------------
# AT-244 — LLR-105.4′: the dropped count is the KEPT count, not the population
# ---------------------------------------------------------------------------

#: How far past the cap the FILTER-KEPT population is driven by AT-244/TC-542.
#: Distinct from the noise count so a population-based notice states a visibly
#: different number.
_OVERSHOOT = 137

#: Non-matching entries the filter drops. Deliberately unequal to
#: :data:`_OVERSHOOT` so ``kept`` and ``population`` can never coincide.
_NOISE = 59


def test_at244_notice_counts_the_kept_rows_not_the_population(
    tmp_path: Path,
) -> None:
    """AT-244 — under a filter, the notice states ``kept − CAP``.

    Intent (LLR-105.4′): the notice is a claim about the document — "this many
    rows that WOULD have rendered did not". Reporting ``population − CAP``
    makes that claim false by exactly the number of filtered-out rows, and a
    reader has no way to detect it. The fixture keeps ``kept`` and
    ``population`` unequal so the two candidate counts are distinguishable.
    """
    cap = _cap()
    kept = cap + _OVERSHOOT
    entries = [
        _entry(0x8000_0000 + 16 * i, symbol=f"KEEP_{i}") for i in range(kept)
    ] + [_entry(0x9000_0000 + 16 * i) for i in range(_NOISE)]

    text = _generate(
        tmp_path,
        [_result("v0", [_summary(entries, variant_id="v0")])],
        options=ReportOptions(report_filter=_symbol_filter("KEEP_*")),
    )
    scope = _section_scope(text, "v0", "### Modifications")

    assert len(_rows(scope)) == cap
    notices = _notices(scope)
    assert len(notices) == 1, f"expected one notice, got {notices}"
    assert f"{_OVERSHOOT} of {kept}" in notices[0], (
        f"the notice must state the KEPT overshoot ({_OVERSHOOT}) of the KEPT "
        f"total ({kept}); a population-based count would state "
        f"{len(entries) - cap} of {len(entries)}. Got: {notices[0]!r}"
    )


# ---------------------------------------------------------------------------
# AT-247 — positive control: byte-identity against the Inc-0 golden
# ---------------------------------------------------------------------------
#
# ``build_results`` / ``variant_set`` below are COPIED VERBATIM from the Inc-0
# capture script. If the two ever drift, this node fails — which is the correct
# signal, because the golden then no longer describes the fixture.

_CONTROL_INSTANT = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)


def build_results() -> List[VariantExecutionResult]:
    """The positive-control fixture. Copied verbatim from the Inc-0 script."""
    results = []
    for v in range(2):
        mods = [
            ChangeSummaryEntry(
                entry_type="bytes",
                address_start=0x8000_0000 + v * 0x1000 + i * 16,
                address_end=0x8000_0000 + v * 0x1000 + i * 16 + (i % 4) + 1,
                before_bytes=tuple(range(0x10, 0x10 + (i % 4) + 1)),
                after_bytes=tuple(range(0xA0, 0xA0 + (i % 4) + 1)),
                disposition="applied",
                linkage="a2l" if i % 2 else "standalone",
                linkage_symbol=f"SYM_{v}_{i}" if i % 2 else None,
            )
            for i in range(5)
        ]
        summary = ChangeSummary(
            source_path=Path("chg.json"),
            kind="change",
            encoding="utf-8",
            value_mode="text",
            timestamp_utc="2026-07-31T11:00:00+00:00",
            variant_id=f"v{v}",
            counts={"applied": len(mods)},
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
                result="pass",
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
            aggregates={"passed": len(checks), "failed": 0, "uncheckable": 0},
            entries=checks,
            issues=[],
        )
        results.append(
            VariantExecutionResult(
                variant_id=f"v{v}",
                status="ok",
                change_summaries=[summary],
                check_results=[check],
            )
        )
    return results


def variant_set() -> ProjectVariantSet:
    """The positive-control inventory. Copied verbatim from the Inc-0 script."""
    return ProjectVariantSet(
        project_name="proj",
        variants=tuple(
            VariantDescriptor(
                variant_id=f"v{v}", path=Path(f"v{v}.s19"), file_type="s19"
            )
            for v in range(2)
        ),
        active_id="v0",
    )


def test_at247_under_cap_report_is_byte_identical_to_the_shipped_output(
    tmp_path: Path,
) -> None:
    """AT-247 — an under-cap, in-domain, sub-width report does not change.

    Intent: the bounds must be invisible where they do not fire. The golden was
    captured at Inc-0 from the SHIPPED producer, in its own commit, so it
    cannot certify the rewrite against itself (C-12).
    """
    root = tmp_path / "proj"
    root.mkdir(parents=True, exist_ok=True)
    path = generate_project_report(
        root,
        build_results(),
        ReportOptions(),
        variant_set=variant_set(),
        now_fn=lambda: _CONTROL_INSTANT,
    )

    assert _GOLDEN.exists(), f"the Inc-0 golden is missing at {_GOLDEN}"
    produced = canonical_report_bytes(path.read_bytes(), tmp_path)
    stored = canonical_report_bytes(_GOLDEN.read_bytes(), None)
    assert produced == stored, (
        "the under-cap report drifted from the Inc-0 golden — the bound fired "
        "where it must not, or the untruncated rendering changed"
    )


# ---------------------------------------------------------------------------
# AT-248 / TC-545 — the §5.1 resident-memory oracle
# ---------------------------------------------------------------------------

#: §5.1 gate. Past the cap a correct producer's residency is INDEPENDENT of E,
#: so a correct implementation sits at 1.000 on any host while anything still
#: linear in E scales with E_hi / E_lo. The threshold states the property; it
#: is not calibrated to a machine.
_RESIDENCY_THRESHOLD = 1.15

#: The two measurement points, as multiples of the cap. BOTH strictly above the
#: cap — that is what makes the ratio host-invariant (§5.1).
_E_LO_MULTIPLE = 2
_E_HI_MULTIPLE = 20


def _oracle_fixture(count: int) -> VariantExecutionResult:
    """Build a one-variant fixture of ``count`` narrow entries (cardinality axis)."""
    return _result(
        "v0",
        [
            _summary(
                [_entry(0x8000_0000 + 16 * i) for i in range(count)],
                variant_id="v0",
            )
        ],
    )


def _peak(
    producer: Callable[[VariantExecutionResult], List[str]],
    result: VariantExecutionResult,
) -> int:
    """
    Summary:
        Return the ``tracemalloc`` peak inside a window opened immediately
        before ``producer(result)`` and closed immediately after.

    Args:
        producer (Callable): The row producer under measurement.
        result (VariantExecutionResult): A fixture built OUTSIDE this window
            — a fixture built inside can never go green (§5.1).

    Returns:
        int: Peak traced bytes for the producer call alone.

    Data Flow:
        - start → call → read peak → stop. Nothing else runs in the window.

    Dependencies:
        Used by:
            - AT-248 / TC-545
    """
    tracemalloc.start()
    try:
        producer(result)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _ratio(
    producer: Callable[[VariantExecutionResult], List[str]],
) -> Tuple[float, int, int]:
    """Measure ``peak(E_hi) / peak(E_lo)`` for ``producer``; fixtures built outside."""
    cap = _cap()
    lo_count = _E_LO_MULTIPLE * cap
    hi_count = _E_HI_MULTIPLE * cap
    assert lo_count > cap and hi_count > cap, (
        f"both measurement points must be strictly above the cap ({cap}); "
        f"got E_lo={lo_count}, E_hi={hi_count}. Below the cap the ratio "
        f"measures the fixture, not the bound."
    )
    lo_fixture = _oracle_fixture(lo_count)
    hi_fixture = _oracle_fixture(hi_count)
    producer(lo_fixture)  # warm-up at scale, outside every measured window
    producer(hi_fixture)
    lo_peak = _peak(producer, lo_fixture)
    hi_peak = _peak(producer, hi_fixture)
    return hi_peak / lo_peak, lo_peak, hi_peak


def test_at248_modifications_residency_is_independent_of_entry_count() -> None:
    """AT-248 — ``peak(E_hi) / peak(E_lo) ≤ 1.15`` with both points above the cap.

    Intent (§5.1): past the cap a producer that bounds its OWN allocation has
    residency independent of ``E``. The ratio is therefore 1.000 by
    construction for a correct implementation on any host, while the shipped
    producer (which flattens the whole population first) scales with
    ``E_hi / E_lo``. ``TC-545`` proves this oracle can fail.
    """
    ratio, lo_peak, hi_peak = _ratio(report_service._modifications_lines)
    assert ratio <= _RESIDENCY_THRESHOLD, (
        f"_modifications_lines residency scales with E: peak(E_lo)={lo_peak} "
        f"peak(E_hi)={hi_peak} ratio={ratio:.3f} > {_RESIDENCY_THRESHOLD}"
    )


# ---------------------------------------------------------------------------
# AT-242b — LLR-105.3's SOURCE-bounding clause, which needs a RESIDENCY oracle
# ---------------------------------------------------------------------------
#
# Every other width predicate in this file is OUTPUT-shaped, and LLR-105.3 does
# not constrain the output — it constrains WHERE the bound is applied. The two
# are not the same requirement, and the gap is executable: a format-then-slice
# `_format_bytes` (render the whole run, then cut the string) emits BYTE-IDENTICAL
# output and passes AT-242, AT-243, TC-541 and test_f17, while peaking at the
# full MF_RUN_LENGTH_CEILING rendering — the exact transient LLR-105.3 exists to
# close. AT-248 cannot see it either: its fixture's entries carry a 1-byte run,
# so it never exercises the width axis at all.
#
# A consumption counter is NOT the instrument here. §5.2 rejected it on the
# cardinality axis (P-25), and on this axis it would go RED on correct code:
# `_format_bytes` deliberately drains the iterator when the run is un-sized, so
# "values consumed" is not a proxy for "bytes resident". Residency is the only
# honest oracle, and it is the same oracle and the same gate as AT-248.


def _format_peak(run: Tuple[int, ...]) -> int:
    """
    Summary:
        Return the ``tracemalloc`` peak of ONE ``_format_bytes`` call over
        ``run``, with the fixture built and the call warmed OUTSIDE the window.

    Args:
        run (Tuple[int, ...]): The byte run, built by the caller.

    Returns:
        int: Peak traced bytes for the formatting call alone.

    Data Flow:
        - warm → start → call → read peak → stop.

    Dependencies:
        Used by:
            - AT-242b / TC-545b
    """
    per_cell = _bytes_per_cell()
    report_service._format_bytes(run, max_bytes=per_cell)
    tracemalloc.start()
    try:
        report_service._format_bytes(run, max_bytes=per_cell)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _width_ratio(formatter: Callable[[Tuple[int, ...], int], str]) -> float:
    """Measure ``peak(L_hi) / peak(L_lo)`` for ``formatter``; both L above the cap."""
    per_cell = _bytes_per_cell()
    lo_len = _E_LO_MULTIPLE * per_cell
    hi_len = _E_HI_MULTIPLE * per_cell
    assert lo_len > per_cell and hi_len > per_cell, (
        f"both run lengths must be strictly above REPORT_BYTES_PER_CELL "
        f"({per_cell}); got L_lo={lo_len}, L_hi={hi_len}. Below the cap the "
        f"ratio measures the fixture, not the bound."
    )
    lo_run = tuple(i % 256 for i in range(lo_len))
    hi_run = tuple(i % 256 for i in range(hi_len))

    def _peak_of(run: Tuple[int, ...]) -> int:
        formatter(run, per_cell)  # warm, outside the window
        tracemalloc.start()
        try:
            formatter(run, per_cell)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    return _peak_of(hi_run) / _peak_of(lo_run)


def test_at242b_byte_cell_residency_is_independent_of_run_length() -> None:
    """AT-242b — LLR-105.3: the width bound is applied at the SOURCE.

    Intent: past ``REPORT_BYTES_PER_CELL`` a formatter that stops CONSUMING has
    residency independent of the run length ``L``, so the ratio is 1.000 by
    construction on any host — the §5.1 argument, transposed to the width axis.
    A formatter that renders first and cuts after scales with ``L_hi / L_lo``
    while emitting the same bytes. ``TC-545b`` proves this oracle can fail.
    """
    per_cell = _bytes_per_cell()
    lo_len = _E_LO_MULTIPLE * per_cell
    hi_len = _E_HI_MULTIPLE * per_cell
    assert lo_len > per_cell and hi_len > per_cell, (
        f"both measurement points must be strictly above REPORT_BYTES_PER_CELL "
        f"({per_cell}); got L_lo={lo_len}, L_hi={hi_len}"
    )
    lo_peak = _format_peak(tuple(i % 256 for i in range(lo_len)))
    hi_peak = _format_peak(tuple(i % 256 for i in range(hi_len)))
    ratio = hi_peak / lo_peak
    assert ratio <= _RESIDENCY_THRESHOLD, (
        f"_format_bytes residency scales with the run length: "
        f"peak(L_lo)={lo_peak} peak(L_hi)={hi_peak} ratio={ratio:.3f} > "
        f"{_RESIDENCY_THRESHOLD} — the bound is applied to the RENDERED "
        f"string, not to the iterable"
    )


def _format_then_slice(run: Tuple[int, ...], max_bytes: int) -> str:
    """
    Summary:
        The DEFECTIVE-ON-PURPOSE width counterfactual: render the whole run,
        then cut the string. Byte-identical output to
        :func:`report_service._format_bytes`, unbounded transient.

    Args:
        run (Tuple[int, ...]): The byte run.
        max_bytes (int): The byte-VALUE cap, honoured only after the fact.

    Returns:
        str: The same string the correct implementation emits.

    Data Flow:
        - The full ``3L - 1`` character rendering exists before anything is
          cut — which is precisely the allocation LLR-105.3 forbids.

    Dependencies:
        Used by:
            - TC-545b
    """
    rendered = " ".join(f"{value:02X}" for value in run)[: 3 * max_bytes - 1]
    dropped = max(0, len(run) - max_bytes)
    if not dropped:
        return rendered
    return rendered + report_service.REPORT_BYTES_TRUNCATION_CUE_FMT.format(
        dropped=dropped
    )


def test_tc545b_the_width_residency_oracle_discriminates() -> None:
    """TC-545b — AT-242b's gate must be exceeded by the format-then-slice shape.

    Intent: this is the falsifier LLR-105.3 was missing. The counterfactual is
    first shown to be OUTPUT-EQUIVALENT — that is what makes the point, because
    it means no output-shaped predicate in this file can tell the two apart —
    and then shown to fail the residency gate that the shipped implementation
    passes. The transcript is printed so the numbers are auditable.
    """
    per_cell = _bytes_per_cell()
    for length in (per_cell - 1, per_cell, per_cell + 1, 4 * per_cell):
        run = tuple(i % 256 for i in range(length))
        assert _format_then_slice(run, per_cell) == report_service._format_bytes(
            run, max_bytes=per_cell
        ), (
            f"the counterfactual is not output-equivalent at L={length}, so it "
            f"does not demonstrate the hole it exists to demonstrate"
        )

    shipped = _width_ratio(
        lambda run, cap: report_service._format_bytes(run, max_bytes=cap)
    )
    sliced = _width_ratio(_format_then_slice)
    print(
        f"\nAT-242b width oracle (L: {_E_LO_MULTIPLE}·B -> {_E_HI_MULTIPLE}·B)\n"
        f"  SOURCE-BOUNDED (shipped) : {shipped:.3f}\n"
        f"  FORMAT-THEN-SLICE        : {sliced:.3f}\n"
        f"  gate                     : <= {_RESIDENCY_THRESHOLD}"
    )
    assert sliced > _RESIDENCY_THRESHOLD, (
        f"the format-then-slice shape passed the gate at {sliced:.3f} — "
        f"AT-242b cannot detect the defect it exists to detect"
    )
    assert shipped <= _RESIDENCY_THRESHOLD


# --- the counterfactual producers TC-545 measures ---------------------------
#
# These two are DEFECTIVE ON PURPOSE. They exist so the oracle's discrimination
# is executed rather than asserted: a threshold that nothing in the file can
# exceed is not a gate. ``_shipped_body`` is the pre-batch-74 producer body;
# ``_cap_only_body`` applies the cap but keeps the full-population flattening,
# which is the near-miss §5.1 measures at 1.921.


def _row(entry: ChangeSummaryEntry) -> str:
    """Render one Modifications row the way the producer does."""
    symbol_cell = entry.linkage_symbol if entry.linkage_symbol else "-"
    before = " ".join(f"{value:02X}" for value in entry.before_bytes)
    after = " ".join(f"{value:02X}" for value in entry.after_bytes)
    return (
        f"| 0x{entry.address_start:08X} "
        f"| {entry.address_end - entry.address_start} "
        f"| {before} | {after} | {entry.linkage} | {symbol_cell} |"
    )


def _shipped_body(result: VariantExecutionResult) -> List[str]:
    """The PRE-batch-74 producer shape: flatten the population, emit every row."""
    lines = ["### Modifications", ""]
    entries = [
        entry for summary in result.change_summaries for entry in summary.entries
    ]
    if not entries:
        return lines + ["No change entries were executed for this variant.", ""]
    lines.extend(
        [
            "| Address | Length | Before | After | Linkage | Symbol |",
            "|---|---|---|---|---|---|",
        ]
    )
    for entry in entries:
        lines.append(_row(entry))
    lines.append("")
    return lines


def _cap_only_body(result: VariantExecutionResult) -> List[str]:
    """The near-miss: capped rows, but the full-population flattening retained."""
    lines = ["### Modifications", ""]
    entries = [
        entry for summary in result.change_summaries for entry in summary.entries
    ]
    if not entries:
        return lines + ["No change entries were executed for this variant.", ""]
    lines.extend(
        [
            "| Address | Length | Before | After | Linkage | Symbol |",
            "|---|---|---|---|---|---|",
        ]
    )
    for entry in entries[: _cap()]:
        lines.append(_row(entry))
    lines.append("")
    return lines


def test_tc545_the_residency_oracle_discriminates() -> None:
    """TC-545 — re-derive §5.1's three figures on THIS tree.

    Intent: AT-248's threshold is only a gate if a defective implementation
    exceeds it. SHIPPED (no bound at all) and CAP-ONLY (bound applied AFTER a
    full-population flattening) must both fail the same predicate the real
    producer passes. The transcript is printed so the numbers are auditable.
    """
    shipped, _, _ = _ratio(_shipped_body)
    cap_only, _, _ = _ratio(_cap_only_body)
    fused, _, _ = _ratio(report_service._modifications_lines)
    print(
        f"\n§5.1 oracle re-derivation (E: {_E_LO_MULTIPLE}·CAP -> "
        f"{_E_HI_MULTIPLE}·CAP)\n"
        f"  SHIPPED  : {shipped:.3f}\n"
        f"  CAP-ONLY : {cap_only:.3f}\n"
        f"  FUSED    : {fused:.3f}\n"
        f"  gate     : <= {_RESIDENCY_THRESHOLD}"
    )
    assert shipped > _RESIDENCY_THRESHOLD, (
        f"the SHIPPED shape passed the gate at {shipped:.3f} — the oracle "
        f"cannot detect the defect it exists to detect"
    )
    assert cap_only > _RESIDENCY_THRESHOLD, (
        f"the CAP-ONLY near-miss passed the gate at {cap_only:.3f} — the "
        f"oracle does not see the retained full-population list"
    )
    assert fused <= _RESIDENCY_THRESHOLD


# ---------------------------------------------------------------------------
# TC-540..TC-544 — white-box nodes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_tc540_cap_arms(tmp_path: Path, offset: int) -> None:
    """TC-540 — LLR-105.1 cap arms at ``{CAP−1, CAP, CAP+1}``.

    Intent: the bound fires at exactly one boundary. A ``>=``/``>`` slip moves
    the notice onto the ``CAP`` arm and the row count onto ``CAP+1``.
    """
    cap = _cap()
    count = cap + offset
    results = [
        _result(
            "v0",
            [
                _summary(
                    [_entry(0x8000_0000 + 16 * i) for i in range(count)],
                    variant_id="v0",
                )
            ],
        )
    ]
    scope = _section_scope(
        _generate(tmp_path, results), "v0", "### Modifications"
    )
    assert len(_rows(scope)) == min(count, cap)
    assert len(_notices(scope)) == (1 if count > cap else 0)


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_tc541_byte_cell_width_arms(offset: int) -> None:
    """TC-541 — LLR-105.3 width arms at ``{B−1, B, B+1}`` byte values.

    Intent: at or below the cap the rendering is byte-identical to the shipped
    ``" ".join(...)``; one value over it, the cue appears and states ``1``.
    """
    per_cell = _bytes_per_cell()
    count = per_cell + offset
    run = tuple(i % 256 for i in range(count))
    rendered = report_service._format_bytes(run, max_bytes=per_cell)
    if count <= per_cell:
        assert rendered == " ".join(f"{value:02X}" for value in run)
    else:
        head = " ".join(f"{value:02X}" for value in run[:per_cell])
        assert rendered == head + _cue(count - per_cell)


def test_tc542_count_correctness_under_a_filter() -> None:
    """TC-542 — LLR-105.4′ white-box: the notice counts KEPT, not population.

    The producer is called directly so the count is observed with no report
    scaffolding between the assertion and the producer.
    """
    cap = _cap()
    kept = cap + _OVERSHOOT
    entries = [
        _entry(0x8000_0000 + 16 * i, symbol=f"KEEP_{i}") for i in range(kept)
    ] + [_entry(0x9000_0000 + 16 * i) for i in range(_NOISE)]
    lines = report_service._modifications_lines(
        _result("v0", [_summary(entries, variant_id="v0")]),
        _symbol_filter("KEEP_*"),
    )
    notices = _notices(lines)
    assert len(notices) == 1, f"expected one notice, got {notices}"
    assert f"{_OVERSHOOT} of {kept}" in notices[0], notices[0]
    assert f"of {len(entries)}" not in notices[0], (
        "the notice stated the PRE-filter population as its total"
    )


def test_tc543_notice_names_the_constant_its_value_and_the_total() -> None:
    """TC-543 — LLR-105.5: the notice is self-explaining.

    A reader who meets a truncated table must be able to find the governing
    constant by name, see the number it is set to, and know both how many rows
    were dropped and how many there were. Naming the constant is what lets a
    reader change the policy without reading the producer.
    """
    cap = _cap()
    count = cap + _OVERSHOOT
    lines = report_service._modifications_lines(
        _result(
            "v0",
            [
                _summary(
                    [_entry(0x8000_0000 + 16 * i) for i in range(count)],
                    variant_id="v0",
                )
            ],
        )
    )
    notices = _notices(lines)
    assert len(notices) == 1, f"expected one notice, got {notices}"
    notice = notices[0]
    assert "MAX_REPORT_ROWS_PER_VARIANT" in notice, notice
    assert str(cap) in notice, notice
    assert f"{_OVERSHOOT} of {count}" in notice, notice
    assert "Modifications" in notice, notice


def _int_literals(source: str) -> List[int]:
    """Return every integer constant appearing in ``source``."""
    return [
        node.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Constant) and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    ]


def test_tc544_no_bare_cap_literal_in_the_producers_or_in_this_file() -> None:
    """TC-544 — LLR-105.6: caps are named, in the producer AND in its tests.

    Intent: a bare ``200`` in either place decouples the policy from its
    constant — the producer would stop honouring a re-valued cap, and a test
    quoting the value would go RED on a legitimate policy change while still
    passing on a producer that ignores the constant entirely. The check walks
    the AST rather than grepping, because ``0x2000`` contains ``200`` and a
    substring scan would fire on it.
    """
    banned = {_cap(), _bytes_per_cell()}
    for producer in (
        report_service._modifications_lines,
        report_service._checklist_lines,
    ):
        source = inspect.getsource(producer)
        found = sorted(banned.intersection(_int_literals(source)))
        assert not found, (
            f"{producer.__name__} carries a bare cap literal {found} — use the "
            f"module constant"
        )
    own = sorted(banned.intersection(_int_literals(
        Path(__file__).read_text(encoding="utf-8")
    )))
    assert not own, (
        f"this test file quotes a cap VALUE {own} instead of the constant — an "
        f"AT quotes the constant, never its value (LLR-105.6)"
    )
