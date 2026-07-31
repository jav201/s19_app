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
from s19_app.tui.changes.io import READ_SIZE_CAP_BYTES
from s19_app.tui.services.markdown_safety import MD_ESCAPE
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


def test_at243_checklist_byte_cells_are_bounded(tmp_path: Path) -> None:
    """AT-243 (Inc-2, full) — ``Expected``/``Actual`` obey the same width bound.

    Intent (LLR-105.3): the width axis is closed at BOTH call sites, and it
    stays closed for rows that render under the Inc-2 cardinality cap. The two
    axes are mutually invariant (§2.7 P-22), so an implementation can close one
    and lose the other — the second arm below is what makes that observable.

    Inc-1 landed this node as ``width_only`` because the checklist cap did not
    exist yet; Inc-2 owns AT-243 per §7, and the cap arm is what promotes it.
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

    # Second arm — the width bound survives the CARDINALITY cap. The two axes
    # are mutually invariant, so an implementation that admits rows correctly
    # but loses `max_bytes` on the capped path is green on the arm above and
    # red here.
    cap = _cap()
    wide = [_check_entry(0x9000_0000 + 16 * i, run=run) for i in range(cap + 1)]
    capped_scope = _section_scope(
        _generate(tmp_path / "capped", [_result("v0", [], [_check(wide)])]),
        "v0",
        "#### Checklist: `chk.json`",
    )
    capped_rows = _rows(capped_scope)
    assert len(capped_rows) == cap, (
        f"the cap arm must render exactly {cap} rows, got {len(capped_rows)}"
    )
    for row in capped_rows:
        row_cells = [cell.strip() for cell in row.split("|")]
        for label, cell in zip(("Expected", "Actual"), (row_cells[3], row_cells[4])):
            assert cell == expected_head + cue, (
                f"{label} cell lost its width bound on a row admitted under "
                f"the cardinality cap — the two axes must compose"
            )


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

    # Inc-2 extension — the Address bounds get the PRODUCER-side ban too.
    #
    # They deliberately do NOT join the file-wide ban above. That ban is
    # LLR-105.6's, whose subject is the OB-4 caps; extending a whole-file
    # INTEGER-VALUE scan to a two-digit constant turns a policy-coupling
    # detector into a coincidence detector — measured: banning
    # REPORT_ADDRESS_HEX_DIGITS file-wide flags 14 occurrences in this file, and
    # every one is an address stride or a run length, not an assertion about the
    # bound. The property the ban exists to protect is enforced for the Address
    # axis by construction instead: AT-246 and TC-550 quote the DERIVATION
    # (`len("0x") + REPORT_ADDRESS_HEX_DIGITS + len(cue)`), never a value.
    address_banned = {_hex_digits(), _address_chars()}
    for producer in (
        report_service._modifications_lines,
        report_service._checklist_lines,
        report_service._format_address,
    ):
        source = inspect.getsource(producer)
        found = sorted(address_banned.intersection(_int_literals(source)))
        assert not found, (
            f"{producer.__name__} carries a bare Address-bound literal {found} "
            f"— use the module constant"
        )


# ===========================================================================
# Inc-2 — LLR-105.2 (checklist cardinality) and LLR-106.x (the Address bound)
# ===========================================================================
#
# Node inventory for this block:
#
# - **AT-241** LLR-105.2 · the checklist cap is summed ACROSS check files.
# - **AT-245** LLR-105.2 + 105.4' · count correctness across files, and a
#   saturated later file renders heading + aggregates + its own notice with NO
#   empty table header.
# - **AT-246** LLR-106.2 · the forgery gate: a truncated Address must FAIL
#   ^-?0x[0-9A-F]+$ and must state a CORRECT elided-digit count.
# - **AT-249** LLR-106.1 · the Address residency oracle.
# - **TC-546..TC-551** white-box nodes.
#
# The load-bearing lesson carried from Inc-1 (F1) is repeated verbatim on this
# axis: every OUTPUT-shaped predicate is blind to format-then-slice. AT-246
# constrains only the emitted token, so an implementation that renders the whole
# 268 MB address and cuts the string satisfies all three of its conjuncts.
# AT-249 is the falsifier, and TC-548 proves AT-249 can go red.

#: The wire-reachable Address width measured in the spec (§2 US-B74-2):
#: ``_ADDRESS_RE`` carries no digit limit and ``int(raw, 16)`` parses without
#: one, so this is a fixture SIZE, not a policy value.
_WIRE_ADDRESS_HEX_DIGITS = 100_000

#: The checklist table's header and rule — what a saturated file must OMIT.
_CHECK_TABLE_HEADER = "| Address | Length | Expected | Actual | Result |"
_CHECK_TABLE_RULE = "|---|---|---|---|---|"


def _hex_digits() -> int:
    """Return ``REPORT_ADDRESS_HEX_DIGITS`` off the module object."""
    return int(report_service.REPORT_ADDRESS_HEX_DIGITS)


def _address_chars() -> int:
    """Return ``REPORT_ADDRESS_CHARS`` off the module object."""
    return int(report_service.REPORT_ADDRESS_CHARS)


def _address_cue(dropped: int) -> str:
    """Render the Address cue for ``dropped`` elided hex digits."""
    return report_service.REPORT_ADDRESS_TRUNCATION_CUE_FMT.format(dropped=dropped)


def _wire_address(digits: int) -> int:
    """Build a wire-legal address of exactly ``digits`` hex digits."""
    return int("0x" + "F" * digits, 16)


def _address_cell(row: str) -> str:
    """Return the ``Address`` cell of a table row of either producer."""
    return row.split("|")[1].strip()


# ---------------------------------------------------------------------------
# AT-241 — LLR-105.2: the checklist cap is SUMMED across the variant's files
# ---------------------------------------------------------------------------


def test_at241_checklist_cap_is_summed_across_check_files(tmp_path: Path) -> None:
    """AT-241 — two disjoint check files admit ``CAP`` rows BETWEEN them.

    Intent: the check-file count ``F`` has no cap anywhere in the system, so a
    per-table cap would leave ``F × CAP`` rows unbounded — the bound would be a
    bound in name only. Capping per VARIANT is what makes the claim true. The
    fixture's two files are address-disjoint so a row can be attributed to its
    file on sight.
    """
    cap = _cap()
    first = _check(
        [_check_entry(0x8000_0000 + 16 * i) for i in range(cap)],
        source="chk_a.json",
    )
    second = _check(
        [_check_entry(0x9000_0000 + 16 * i) for i in range(cap)],
        source="chk_b.json",
    )
    text = _generate(tmp_path, [_result("v0", [], [first, second])])

    rows_a = _rows(_section_scope(text, "v0", "#### Checklist: `chk_a.json`"))
    rows_b = _rows(_section_scope(text, "v0", "#### Checklist: `chk_b.json`"))
    assert len(rows_a) + len(rows_b) == cap, (
        f"the cap must be summed across check files: file A rendered "
        f"{len(rows_a)} rows and file B {len(rows_b)}, total "
        f"{len(rows_a) + len(rows_b)}, expected exactly {cap}. A per-file cap "
        f"would render {2 * cap}"
    )
    assert len(rows_a) == cap and not rows_b, (
        "the budget is spent in document order — file A fills it, file B gets "
        "nothing"
    )


# ---------------------------------------------------------------------------
# AT-245 — LLR-105.2 + 105.4': count correctness + the saturated-file rendering
# ---------------------------------------------------------------------------


def test_at245_saturated_check_file_states_its_own_drop(tmp_path: Path) -> None:
    """AT-245 — under a filter each file states ITS OWN kept drop, and a file
    that arrives saturated renders heading + aggregates + notice with no table.

    Intent, two clauses:

    1. **Counts (LLR-105.4′).** The notice claims "this many rows that WOULD
       have rendered did not". Under a filter, a population-based count
       overstates it by exactly the filtered-out rows and no reader can detect
       the difference. The fixture keeps kept ≠ population in both files.
    2. **Rendering (LLR-105.2).** A reader of check file 2 must not meet an
       empty table with no local explanation — so the header and rule are
       omitted and a per-file notice takes their place.
    """
    cap = _cap()
    kept_a = cap + _OVERSHOOT
    first = _check(
        [
            _check_entry(0x8000_0000 + 16 * i, symbol=f"KEEP_A{i}")
            for i in range(kept_a)
        ]
        + [_check_entry(0xA000_0000 + 16 * i) for i in range(_NOISE)],
        source="chk_a.json",
    )
    second = _check(
        [
            _check_entry(0x9000_0000 + 16 * i, symbol=f"KEEP_B{i}")
            for i in range(_NOISE)
        ]
        + [_check_entry(0xB000_0000 + 16 * i) for i in range(_OVERSHOOT)],
        source="chk_b.json",
    )
    text = _generate(
        tmp_path,
        [_result("v0", [], [first, second])],
        options=ReportOptions(report_filter=_symbol_filter("KEEP_*")),
    )

    scope_a = _section_scope(text, "v0", "#### Checklist: `chk_a.json`")
    scope_b = _section_scope(text, "v0", "#### Checklist: `chk_b.json`")

    assert len(_rows(scope_a)) == cap
    notices_a = _notices(scope_a)
    assert len(notices_a) == 1, f"expected one notice in file A, got {notices_a}"
    assert f"{_OVERSHOOT} of {kept_a}" in notices_a[0], (
        f"file A must state its KEPT overshoot ({_OVERSHOOT}) of its KEPT total "
        f"({kept_a}); a population-based count would state "
        f"{kept_a + _NOISE - cap} of {kept_a + _NOISE}. Got: {notices_a[0]!r}"
    )

    assert not _rows(scope_b), "file B arrived saturated and must render no rows"
    notices_b = _notices(scope_b)
    assert len(notices_b) == 1, f"expected one notice in file B, got {notices_b}"
    assert f"{_NOISE} of {_NOISE}" in notices_b[0], (
        f"file B must state ITS OWN kept count ({_NOISE}); a variant-wide count "
        f"repeated under a second heading reads as a second, separate drop. "
        f"Got: {notices_b[0]!r}"
    )
    assert _CHECK_TABLE_HEADER not in scope_b and _CHECK_TABLE_RULE not in scope_b, (
        "a saturated check file emitted a table header with no rows under it — "
        "an empty table with no local explanation is what LLR-105.2 forbids"
    )
    assert any("Passed:" in line for line in scope_b), (
        "the saturated file must keep its aggregates line — the cap removes the "
        "table, not the file"
    )


# ---------------------------------------------------------------------------
# AT-246 — LLR-106.2: a truncated Address must be UNMISTAKABLE and CORRECT
# ---------------------------------------------------------------------------

#: The form a COMPLETE address takes. A truncated cell must FAIL this — that is
#: the whole point of the story: a shortened hex numeral is otherwise
#: indistinguishable from a complete one.
_COMPLETE_ADDRESS_RE = re.compile(r"^-?0x[0-9A-F]+$")


def test_at246_truncated_address_cannot_read_as_a_complete_one(
    tmp_path: Path,
) -> None:
    """AT-246 — a wire-legal 100 000-digit address renders bounded, unforgeable
    and with a CORRECT elided-digit count.

    Intent (HLR-106): bounding an address without changing its FORM closes a
    memory hole by opening a forgery hole — a truncated ``0xFFFF…`` is a
    well-formed numeral that understates the true value silently (measured
    ``2**12248`` on a 3572-digit address). All three conjuncts are required:

    - **width**, quoted as the FORMULA ``len("0x") + REPORT_ADDRESS_HEX_DIGITS +
      len(cue)``, never as ``REPORT_ADDRESS_CHARS`` and never as a literal (a
      value-quoting predicate is RED after a correct implementation — the
      revision-2 defect that already cost this batch one iteration);
    - **form**, the emitted token must FAIL :data:`_COMPLETE_ADDRESS_RE`;
    - **count**, derived INDEPENDENTLY from ``(n.bit_length() + 3) // 4``, never
      read back off the emitted cell, which would make the predicate circular.
    """
    kept = _hex_digits()
    address = _wire_address(_WIRE_ADDRESS_HEX_DIGITS)

    # Derived independently of the producer — this is the oracle, not an echo.
    total_digits = (address.bit_length() + 3) // 4
    elided = total_digits - kept
    cue = _address_cue(elided)
    bound = len("0x") + kept + len(cue)

    text = _generate(
        tmp_path, [_result("v0", [_summary([_entry(address)], variant_id="v0")])]
    )
    rows = _rows(_section_scope(text, "v0", "### Modifications"))
    assert len(rows) == 1, f"fixture must render exactly one row, got {len(rows)}"
    cell = _address_cell(rows[0])

    assert len(cell) <= bound, (
        f"the Address cell is {len(cell)} chars, over the "
        f'len("0x") + REPORT_ADDRESS_HEX_DIGITS + len(cue) = {bound} bound'
    )
    assert not _COMPLETE_ADDRESS_RE.match(cell), (
        f"the truncated Address {cell!r} still matches the COMPLETE-address "
        f"form — it is indistinguishable from a whole address and understates "
        f"the true value by 2**{4 * elided}. This is the forgery HLR-106 exists "
        f"to prevent"
    )
    assert cell.endswith(cue), (
        f"the cell must state the elided digit count {elided}, derived from "
        f"(n.bit_length() + 3) // 4 - REPORT_ADDRESS_HEX_DIGITS. Got: {cell!r}"
    )

    # SECOND SITE. LLR-106.1/106.2's scope is BOTH producers, and check entries
    # carry the same unbounded address (`changes/check.py` ← `_parse_address` ←
    # `_ADDRESS_RE`, no digit limit), so the checklist site is equally
    # wire-reachable. Executed at the increment gate: reverting ONLY the
    # checklist call site to the shipped `f"0x{…:08X}"` left every node in this
    # file green while that cell rendered 100 000 forgeable characters. §5.2
    # already registered "one AT covering both sites" as vacuous — this is that
    # rule applied to the Address axis.
    check_rows = _rows(
        _section_scope(
            _generate(
                tmp_path / "chk",
                [_result("v0", [], [_check([_check_entry(address)])])],
            ),
            "v0",
            "#### Checklist: `chk.json`",
        )
    )
    assert len(check_rows) == 1, (
        f"the checklist fixture must render exactly one row, got "
        f"{len(check_rows)}"
    )
    check_cell = _address_cell(check_rows[0])
    assert len(check_cell) <= bound, (
        f"the CHECKLIST Address cell is {len(check_cell)} chars, over the "
        f'len("0x") + REPORT_ADDRESS_HEX_DIGITS + len(cue) = {bound} bound'
    )
    assert not _COMPLETE_ADDRESS_RE.match(check_cell), (
        f"the CHECKLIST Address {check_cell[:40]!r}… still matches the "
        f"COMPLETE-address form — the forgery is closed at one producer and "
        f"open at the other"
    )
    assert check_cell.endswith(cue), (
        f"the checklist cell must state the same elided count {elided}. "
        f"Got: {check_cell!r}"
    )


# ---------------------------------------------------------------------------
# AT-249 / TC-548 — LLR-106.1: the Address bound is applied at the SOURCE
# ---------------------------------------------------------------------------
#
# This is Inc-1's F1 finding, transposed. AT-246 is OUTPUT-shaped and therefore
# blind to format-then-slice: rendering the whole address and cutting the string
# emits a BYTE-IDENTICAL cell while peaking at the full rendering. Residency is
# the only honest oracle, and it is the same oracle and the same gate as AT-248.
#
# A consumption counter is NOT usable here either — §5.2 rejected it on the
# cardinality axis (P-25), and there is nothing to "consume" in an int.

#: The two Address measurement points, as multiples of the bound. BOTH far above
#: REPORT_ADDRESS_HEX_DIGITS, so a correct implementation's residency is
#: independent of the value's size and the ratio is 1.000 by construction.
_D_LO_MULTIPLE = 1_000
_D_HI_MULTIPLE = 10_000


def _address_peak(formatter: Callable[[int], str], value: int) -> int:
    """Return the ``tracemalloc`` peak of ONE ``formatter(value)`` call.

    The value is built and the call warmed OUTSIDE the window, so the peak
    measures the formatting allocation alone (§5.1).
    """
    formatter(value)
    tracemalloc.start()
    try:
        formatter(value)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _address_ratio(formatter: Callable[[int], str]) -> Tuple[float, int, int]:
    """Measure ``peak(D_hi) / peak(D_lo)``; both digit counts above the bound."""
    kept = _hex_digits()
    lo_digits = _D_LO_MULTIPLE * kept
    hi_digits = _D_HI_MULTIPLE * kept
    assert lo_digits > kept and hi_digits > kept, (
        f"both measurement points must be strictly above "
        f"REPORT_ADDRESS_HEX_DIGITS ({kept}); got D_lo={lo_digits}, "
        f"D_hi={hi_digits}. Below the bound the ratio measures the fixture, "
        f"not the bound."
    )
    lo_value = _wire_address(lo_digits)
    hi_value = _wire_address(hi_digits)
    lo_peak = _address_peak(formatter, lo_value)
    hi_peak = _address_peak(formatter, hi_value)
    return hi_peak / lo_peak, lo_peak, hi_peak


def test_at249_address_residency_is_independent_of_digit_count() -> None:
    """AT-249 — ``peak(D_hi) / peak(D_lo) ≤ 1.15`` with both D above the bound.

    Intent (LLR-106.1): past ``REPORT_ADDRESS_HEX_DIGITS`` an implementation
    that derives the kept digits ARITHMETICALLY allocates only the shifted
    result, so its residency is independent of the value's size on any host.
    One that formats the whole value and slices scales with ``D_hi / D_lo``
    while emitting the same bytes. ``TC-548`` proves this oracle can fail.
    """
    ratio, lo_peak, hi_peak = _address_ratio(report_service._format_address)
    assert ratio <= _RESIDENCY_THRESHOLD, (
        f"_format_address residency scales with the digit count: "
        f"peak(D_lo)={lo_peak} peak(D_hi)={hi_peak} ratio={ratio:.3f} > "
        f"{_RESIDENCY_THRESHOLD} — the bound is applied to the RENDERED "
        f"string, not to the value"
    )


def _format_then_slice_address(value: int) -> str:
    """The DEFECTIVE-ON-PURPOSE Address counterfactual: render, then cut.

    Byte-identical output to :func:`report_service._format_address` for every
    value past the bound, unbounded transient — the full ``D``-character
    rendering exists before anything is cut.
    """
    kept = _hex_digits()
    total = (value.bit_length() + 3) // 4
    if total <= kept:
        return f"0x{value:08X}"
    return (
        "0x"
        + f"{value:X}"[:kept]
        + report_service.REPORT_ADDRESS_TRUNCATION_CUE_FMT.format(
            dropped=total - kept
        )
    )


def test_tc548_the_address_residency_oracle_discriminates() -> None:
    """TC-548 — AT-249's gate must be exceeded by the format-then-slice shape.

    Intent: this is the falsifier LLR-106.1 needs. The counterfactual is first
    shown to be OUTPUT-EQUIVALENT — that is the point, because it means no
    output-shaped predicate in this file, AT-246 included, can tell the two
    apart — and then shown to fail the gate the shipped implementation passes.
    """
    kept = _hex_digits()
    for digits in (kept - 1, kept, kept + 1, _D_LO_MULTIPLE * kept):
        value = _wire_address(digits)
        assert _format_then_slice_address(value) == report_service._format_address(
            value
        ), (
            f"the counterfactual is not output-equivalent at D={digits}, so it "
            f"does not demonstrate the hole it exists to demonstrate"
        )

    shipped, _, _ = _address_ratio(report_service._format_address)
    sliced, _, _ = _address_ratio(_format_then_slice_address)
    print(
        f"\nAT-249 Address oracle (D: {_D_LO_MULTIPLE}·K -> {_D_HI_MULTIPLE}·K "
        f"hex digits)\n"
        f"  SOURCE-BOUNDED (shipped) : {shipped:.3f}\n"
        f"  FORMAT-THEN-SLICE        : {sliced:.3f}\n"
        f"  gate                     : <= {_RESIDENCY_THRESHOLD}"
    )
    assert sliced > _RESIDENCY_THRESHOLD, (
        f"the format-then-slice shape passed the gate at {sliced:.3f} — AT-249 "
        f"cannot detect the defect it exists to detect"
    )
    assert shipped <= _RESIDENCY_THRESHOLD


# ---------------------------------------------------------------------------
# TC-546 / TC-547 — LLR-105.2 white-box
# ---------------------------------------------------------------------------


def test_tc546_cap_is_summed_over_three_check_files(tmp_path: Path) -> None:
    """TC-546 — three files, each holding ``CAP`` entries, render ``CAP`` rows.

    Intent: ``F`` is uncapped, so the failure this pins is ``F × CAP``. Three
    files (not two) is what distinguishes "summed" from "capped at twice".
    """
    cap = _cap()
    checks = [
        _check(
            [_check_entry(base + 16 * i) for i in range(cap)],
            source=f"chk_{name}.json",
        )
        for name, base in (
            ("a", 0x8000_0000),
            ("b", 0x9000_0000),
            ("c", 0xA000_0000),
        )
    ]
    text = _generate(tmp_path, [_result("v0", [], checks)])
    rendered = sum(
        len(_rows(_section_scope(text, "v0", f"#### Checklist: `{c.source_path}`")))
        for c in checks
    )
    assert rendered == cap, (
        f"three check files rendered {rendered} rows in total; the per-variant "
        f"cap is {cap}. A per-file cap would render {3 * cap}"
    )


@pytest.mark.parametrize("saturating", [False, True])
def test_tc547_saturated_file_omits_the_table_header(
    tmp_path: Path, saturating: bool
) -> None:
    """TC-547 — the header/rule are omitted IFF the later file arrives saturated.

    Both arms matter. Unsaturated, the second file must keep today's rendering
    exactly — an implementation that drops the header whenever a cap exists
    would be green on a one-sided predicate.
    """
    cap = _cap()
    first_count = cap if saturating else cap // 2
    checks = [
        _check(
            [_check_entry(0x8000_0000 + 16 * i) for i in range(first_count)],
            source="chk_a.json",
        ),
        _check(
            [_check_entry(0x9000_0000 + 16 * i) for i in range(_NOISE)],
            source="chk_b.json",
        ),
    ]
    scope_b = _section_scope(
        _generate(tmp_path, [_result("v0", [], checks)]),
        "v0",
        "#### Checklist: `chk_b.json`",
    )
    has_header = _CHECK_TABLE_HEADER in scope_b
    assert has_header is not saturating, (
        f"saturating={saturating}: the second file "
        f"{'kept' if has_header else 'omitted'} its table header. It must be "
        f"omitted exactly when the file arrives with the budget already spent"
    )
    assert len(_notices(scope_b)) == (1 if saturating else 0)
    assert len(_rows(scope_b)) == (0 if saturating else _NOISE)


def test_tc547b_saturated_file_with_nothing_kept_keeps_todays_empty_table(
    tmp_path: Path,
) -> None:
    """TC-547b — saturation alone does not remove a table; a DROP does.

    Intent: the third reachable combination, which TC-547's two arms cross but
    never reach. A check file can arrive saturated AND keep zero rows — the
    zero-match early return fires only when the WHOLE variant keeps nothing, so
    a variant whose first file spends the budget and whose second file is
    emptied by the filter lands exactly here.

    Nothing was dropped from file B, so a ``> TRUNCATED:`` notice there would be
    a **false statement** in an evidentiary document: it would attribute to the
    cap rows that the filter removed. Executed at the increment gate: relaxing
    the guard to ``if not saturated:`` passes every other node in this file
    while rendering file B as a heading and aggregates with **no table and no
    notice at all** — strictly worse than the behaviour this arm pins.
    """
    cap = _cap()
    checks = [
        _check(
            [
                _check_entry(0x8000_0000 + 16 * i, symbol=f"KEEP_{i}")
                for i in range(cap)
            ],
            source="chk_a.json",
        ),
        _check(
            [_check_entry(0x9000_0000 + 16 * i) for i in range(_NOISE)],
            source="chk_b.json",
        ),
    ]
    text = _generate(
        tmp_path,
        [_result("v0", [], checks)],
        options=ReportOptions(report_filter=_symbol_filter("KEEP_*")),
    )
    scope_a = _section_scope(text, "v0", "#### Checklist: `chk_a.json`")
    assert len(_rows(scope_a)) == cap, (
        "fixture defect: file A must spend the whole budget, or file B never "
        "arrives saturated and this arm proves nothing"
    )

    scope_b = _section_scope(text, "v0", "#### Checklist: `chk_b.json`")
    assert not _rows(scope_b)
    assert not _notices(scope_b), (
        f"file B lost nothing to the cap — the filter emptied it — so a "
        f"truncation notice there is a false statement. Got: {_notices(scope_b)}"
    )
    assert _CHECK_TABLE_HEADER in scope_b and _CHECK_TABLE_RULE in scope_b, (
        "a saturated file with nothing to drop must keep today's empty-table "
        "rendering; the cap removes a table only when it removed rows"
    )


def test_tc549b_a_negative_address_keeps_its_sign_through_truncation() -> None:
    """TC-549b — LLR-106.2: truncation must not turn a negative into a positive.

    Intent: the sign branch is otherwise entirely uncovered. It is **not**
    wire-reachable — ``_ADDRESS_RE`` admits no sign — so this pins a
    constructor-domain contract, and it is pinned rather than deleted because
    dropping the branch does not remove the case: ``value >> k`` on a negative
    is an ARITHMETIC shift, so a signless implementation would silently render a
    different magnitude. Rendering a positive token for a negative value is the
    same forgery class HLR-106 exists to prevent, one sign bit over.
    """
    kept = _hex_digits()
    magnitude = _wire_address(4 * kept)
    cell = report_service._format_address(-magnitude)
    assert cell.startswith("-0x"), (
        f"a truncated negative Address lost its sign and now reads as a "
        f"positive value. Got: {cell!r}"
    )
    assert cell[1:] == report_service._format_address(magnitude), (
        "the magnitude must render identically with the sign stripped"
    )
    assert not _COMPLETE_ADDRESS_RE.match(cell), (
        f"the truncated negative Address {cell!r} matches the complete-address "
        f"form"
    )


# ---------------------------------------------------------------------------
# TC-549 / TC-550 / TC-551 — LLR-106.2 / 106.3 / 106.4 white-box
# ---------------------------------------------------------------------------


def test_tc549_elided_count_comes_from_the_value_not_the_raw_string() -> None:
    """TC-549 — the elided count comes from the VALUE, never from ``len(raw)``.

    Intent (LLR-106.2, re-gate F-3): ``int('0x0FF…', 16)`` discards the wire's
    leading zeros, so ``len(raw) - 2`` and ``(n.bit_length() + 3) // 4`` differ.
    A predicate — or an implementation — written against the raw string
    misfires by exactly the number of leading zeros, and the leading-zero arm
    below is what makes that observable.
    """
    kept = _hex_digits()
    significant = 4 * kept
    zeros = 3 * kept
    raw = "0x" + "0" * zeros + "F" * significant
    value = int(raw, 16)

    expected_elided = significant - kept
    assert (value.bit_length() + 3) // 4 == significant, (
        "fixture defect: the value's digit count is not what the arm assumes"
    )
    assert len(raw) - 2 != significant, (
        "fixture defect: the leading-zero arm must make len(raw) and the "
        "value's digit count DIFFER, or it proves nothing"
    )

    cell = report_service._format_address(value)
    assert cell.endswith(_address_cue(expected_elided)), (
        f"the cue must state {expected_elided} elided digits (the VALUE's "
        f"{significant} digits minus the kept {kept}); a raw-string count would "
        f"state {len(raw) - 2 - kept}. Got: {cell!r}"
    )

    # No-truncation arm: at or below the bound the rendering is byte-identical
    # to the shipped ``f"0x{n:08X}"`` (LLR-106.2's second sentence).
    for digits in (1, kept - 1, kept):
        inside = _wire_address(digits)
        assert report_service._format_address(inside) == f"0x{inside:08X}", (
            f"an untruncated Address at D={digits} drifted from the shipped "
            f"rendering — AT-247's byte-identity would fail next"
        )

    # NON-UNIFORM arm, top nibble < 8. Every other Address fixture in this file
    # is all-``F``, and on an F-uniform value TWO independent defects are
    # invisible, both executed at the increment gate:
    #
    #   (a) WHICH digits. ``magnitude & ((1 << 4·kept) - 1)`` renders the
    #       TRAILING kept digits while the cue claims the leading ones were
    #       kept. On all-``F`` input leading and trailing are the same string.
    #   (b) THE CEILING. ``bit_length() // 4`` instead of ``(bit_length()+3)//4``
    #       — the ``+3`` is a no-op whenever the top nibble is ≥ 8, which every
    #       ``F``-leading value satisfies. The floor variant renders 17 digits,
    #       one OVER the bound, and states a count one too low.
    #
    # This is the arm that makes the formula this node QUOTES observable.
    raw_mixed = "0x1" + "123456789ABCDEF0" * 8
    mixed = int(raw_mixed, 16)
    total_mixed = (mixed.bit_length() + 3) // 4
    assert mixed.bit_length() % 4 != 0, (
        "fixture defect: the top nibble must be < 8 or the ceiling's +3 term is "
        "a no-op and arm (b) proves nothing"
    )
    assert total_mixed == len(raw_mixed) - 2, (
        "fixture defect: this arm assumes no leading zeros, so the raw string "
        "and the value's digit count agree here"
    )
    cell_mixed = report_service._format_address(mixed)
    head_mixed = cell_mixed.partition(" ")[0]
    assert head_mixed == "0x" + raw_mixed[2:2 + kept], (
        f"the cell must render the LEADING {kept} hex digits; got "
        f"{head_mixed!r}. A trailing-digit or floor-division implementation is "
        f"byte-identical to a correct one on an all-F fixture, which is why "
        f"this arm is non-uniform"
    )
    assert cell_mixed.endswith(_address_cue(total_mixed - kept)), cell_mixed


def test_tc550_address_chars_equals_its_own_derivation() -> None:
    """TC-550 — LLR-106.3: ``REPORT_ADDRESS_CHARS`` IS its derivation.

    Intent: the policy number is ``REPORT_ADDRESS_HEX_DIGITS`` and the cell
    width is its consequence. Pinning the equality is what stops the two
    drifting apart — and what stops the constant being re-derived BOTTOM-UP
    from the golden census, which would put it near the widest golden Address
    cell (10 characters) and make AT-246 red after a correct implementation.
    """
    derived = (
        len("0x")
        + _hex_digits()
        + len(_address_cue(report_service.REPORT_ADDRESS_MAX_ELIDED_DIGITS))
    )
    assert _address_chars() == derived, (
        f"REPORT_ADDRESS_CHARS = {_address_chars()} but its stated derivation "
        f"yields {derived} — the constant has drifted from its own definition"
    )
    assert (
        report_service.REPORT_ADDRESS_MAX_ELIDED_DIGITS
        == READ_SIZE_CAP_BYTES - _hex_digits()
    ), "the maximum elided count must be derived from the wire read cap"

    # The anti-bottom-up arm, EXECUTED rather than asserted: the widest Address
    # cell in any golden is what a census-driven derivation would have produced.
    widest = 0
    for golden in (Path(__file__).parent / "goldens").rglob("*.md"):
        for line in golden.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if _ROW_RE.match(line):
                widest = max(widest, len(_address_cell(line)))
    assert widest, "the census found no golden Address cell — it proves nothing"
    assert _address_chars() > widest, (
        f"REPORT_ADDRESS_CHARS ({_address_chars()}) is not above the widest "
        f"golden Address cell ({widest}) — it was derived from what is REACHED "
        f"rather than from the policy, and the bound will fire on ordinary rows"
    )
    assert len("0x") + _hex_digits() >= widest, (
        f"REPORT_ADDRESS_HEX_DIGITS ({_hex_digits()}) truncates an address that "
        f"already appears in a golden ({widest} chars) — every golden carrying "
        f"one would re-baseline"
    )


def test_tc551_the_address_cue_is_inert_in_markdown() -> None:
    """TC-551 — LLR-106.4: the Address cue cannot perturb the document.

    Intent: the Address cell is emitted UNESCAPED (both producers interpolate
    it directly) and ``CUE_ALPHABET`` covers ``_format_bytes`` only, so the cue
    carries its own inertness obligation. The natural first spelling
    ``… (+99988 more hex digits.)`` ends in ``.``, which IS in ``MD_ESCAPE``.

    The assertion is made against the real ``MD_ESCAPE`` rather than a
    hand-copied whitelist, so it cannot drift away from the escaper it protects.
    """
    template = report_service.REPORT_ADDRESS_TRUNCATION_CUE_FMT
    rendered = _address_cue(report_service.REPORT_ADDRESS_MAX_ELIDED_DIGITS)
    for label, text in (("template", template), ("rendered", rendered)):
        overlap = sorted(set(text) & set(MD_ESCAPE))
        assert not overlap, (
            f"the Address cue {label} carries Markdown-active characters "
            f"{overlap}; the cell is emitted unescaped, so they reach the "
            f"document verbatim"
        )
        assert "." not in text, f"the Address cue {label} carries '.' (MD_ESCAPE)"
        assert "|" not in text, (
            f"the Address cue {label} carries '|' and would break the table row"
        )
    assert "…" in template, (
        "the cue must carry the U+2026 ellipsis precedented by "
        "TRUNCATION_MARKER, not a three-dot spelling"
    )

    # End-to-end: the whole truncated cell is a closed alphabet.
    cell = report_service._format_address(_wire_address(_WIRE_ADDRESS_HEX_DIGITS))
    allowed = set("0123456789ABCDEF") | {"x"} | set(rendered)
    stray = sorted(set(cell) - allowed)
    assert not stray, f"the truncated Address cell emitted stray characters {stray}"


# ---------------------------------------------------------------------------
# AT-241b / TC-546b — LLR-105.2's RESIDENCY half, added at the PR gate
# ---------------------------------------------------------------------------
#
# The batch gated three surfaces with a residency oracle — `_modifications_lines`
# (AT-248), `_format_bytes` (AT-242b) and `_format_address` (AT-249) — and left
# the fourth ungated. The final PR-level review executed the gap: a
# `_checklist_lines` that renders EVERY row and slices the list at the budget is
# **output-identical** and survived all 31 nodes, at a measured residency ratio
# of 9.087 against a gate of 1.15.
#
# That is this batch's own headline lesson, arriving one surface late:
# LLR-105.1's "no intermediate full-population list" clause binds BOTH producers,
# and an output-shaped predicate cannot see the difference. The asymmetry was an
# omission, not redundancy — the identical defect shape planted in
# `_modifications_lines` IS caught, by AT-248.


def _checklist_oracle_fixture(count: int) -> VariantExecutionResult:
    """Build a one-variant, one-check-file fixture of ``count`` narrow entries."""
    return _result(
        "v0",
        [],
        [_check([_check_entry(0x8000_0000 + 16 * i) for i in range(count)])],
    )


def _checklist_ratio(
    producer: Callable[[VariantExecutionResult], List[str]],
) -> Tuple[float, int, int]:
    """Measure ``peak(E_hi) / peak(E_lo)`` for a checklist producer.

    The §5.1 oracle, unchanged in shape from :func:`_ratio` — both measurement
    points strictly above the cap, fixtures built and the producer warmed
    OUTSIDE every measured window.
    """
    cap = _cap()
    lo_count = _E_LO_MULTIPLE * cap
    hi_count = _E_HI_MULTIPLE * cap
    assert lo_count > cap and hi_count > cap, (
        f"both measurement points must be strictly above the cap ({cap}); got "
        f"E_lo={lo_count}, E_hi={hi_count}. Below the cap the ratio measures "
        f"the fixture, not the bound."
    )
    lo_fixture = _checklist_oracle_fixture(lo_count)
    hi_fixture = _checklist_oracle_fixture(hi_count)
    producer(lo_fixture)  # warm-up at scale, outside every measured window
    producer(hi_fixture)
    lo_peak = _peak(producer, lo_fixture)
    hi_peak = _peak(producer, hi_fixture)
    return hi_peak / lo_peak, lo_peak, hi_peak


def test_at241b_checklist_residency_is_independent_of_entry_count() -> None:
    """AT-241b — LLR-105.1/105.2: `_checklist_lines` bounds its OWN allocation.

    Intent (§5.1): past the cap a producer that admits rows as it finds them has
    residency independent of ``E``, so the ratio is 1.000 by construction on any
    host. One that materialises the full population and slices it emits the SAME
    DOCUMENT while peaking with ``E`` — the defect AT-248 catches on the sibling
    producer and which nothing caught here until the PR gate. ``TC-546b`` proves
    this oracle can fail.
    """
    ratio, lo_peak, hi_peak = _checklist_ratio(report_service._checklist_lines)
    assert ratio <= _RESIDENCY_THRESHOLD, (
        f"_checklist_lines residency scales with E: peak(E_lo)={lo_peak} "
        f"peak(E_hi)={hi_peak} ratio={ratio:.3f} > {_RESIDENCY_THRESHOLD} — the "
        f"cap is applied to a fully materialised row list, not at admission"
    )


def _checklist_full_population_body(
    result: VariantExecutionResult,
) -> List[str]:
    """The DEFECTIVE-ON-PURPOSE checklist counterfactual: render all, then slice.

    Byte-identical output to :func:`report_service._checklist_lines` for an
    unfiltered fixture, unbounded transient — every row exists before anything is
    cut, which is precisely the allocation LLR-105.1's "no intermediate
    full-population list" clause forbids.
    """
    lines = ["### Checklists", ""]
    if not result.check_results:
        lines.extend(["No checklists were executed for this variant.", ""])
        return lines
    cap = _cap()
    per_cell = _bytes_per_cell()
    admitted = 0
    for check in result.check_results:
        source = (
            f"`{report_service.md_code(check.source_path)}`"
            if check.source_path is not None
            else "(in-memory document)"
        )
        lines.extend(
            [
                f"#### Checklist: {source}",
                "",
                f"Passed: {check.aggregates.get('passed', 0)} - "
                f"Failed: {check.aggregates.get('failed', 0)} - "
                f"Uncheckable: {check.aggregates.get('uncheckable', 0)}",
                "",
            ]
        )
        saturated = admitted >= cap
        # THE DEFECT, and the only line that differs from the shipped producer.
        all_rows = [
            f"| {report_service._format_address(entry.address_start)} "
            f"| {entry.address_end - entry.address_start} "
            f"| {report_service._format_bytes(entry.expected_bytes, max_bytes=per_cell)} "
            f"| {report_service._format_bytes(entry.actual_bytes, max_bytes=per_cell)} "
            f"| {report_service.md_safe(entry.result, limit=report_service.REPORT_CELL_CHARS)} |"
            for entry in check.entries
        ]
        file_kept = len(all_rows)
        rows = all_rows[: max(0, cap - admitted)]
        admitted += len(rows)
        if not (saturated and file_kept):
            lines.extend(
                [
                    "| Address | Length | Expected | Actual | Result |",
                    "|---|---|---|---|---|",
                ]
            )
            lines.extend(rows)
        file_dropped = file_kept - len(rows)
        if file_dropped:
            lines.append(
                report_service.ROW_TRUNCATION_NOTICE_FMT.format(
                    section=f"Checklist: {source}",
                    dropped=file_dropped,
                    total=file_kept,
                    cap=cap,
                )
            )
        lines.append("")
    return lines


def test_tc546b_the_checklist_residency_oracle_discriminates() -> None:
    """TC-546b — AT-241b's gate must be exceeded by the full-population shape.

    Intent: the falsifier AT-241b needs. The counterfactual is first shown
    OUTPUT-EQUIVALENT — that is the point, because it means no output-shaped
    predicate in this file can tell the two apart — and then shown to fail the
    gate the shipped producer passes. The transcript is printed so the numbers
    are auditable.
    """
    cap = _cap()
    for count in (cap - 1, cap, cap + 1, _E_LO_MULTIPLE * cap):
        fixture = _checklist_oracle_fixture(count)
        assert _checklist_full_population_body(fixture) == (
            report_service._checklist_lines(fixture)
        ), (
            f"the counterfactual is not output-equivalent at E={count}, so it "
            f"does not demonstrate the hole it exists to demonstrate"
        )

    shipped, _, _ = _checklist_ratio(report_service._checklist_lines)
    full, _, _ = _checklist_ratio(_checklist_full_population_body)
    print(
        f"\nAT-241b checklist oracle (E: {_E_LO_MULTIPLE}·CAP -> "
        f"{_E_HI_MULTIPLE}·CAP)\n"
        f"  ADMISSION-BOUNDED (shipped) : {shipped:.3f}\n"
        f"  FULL-POPULATION-THEN-SLICE  : {full:.3f}\n"
        f"  gate                        : <= {_RESIDENCY_THRESHOLD}"
    )
    assert full > _RESIDENCY_THRESHOLD, (
        f"the full-population shape passed the gate at {full:.3f} — AT-241b "
        f"cannot detect the defect it exists to detect"
    )
    assert shipped <= _RESIDENCY_THRESHOLD
