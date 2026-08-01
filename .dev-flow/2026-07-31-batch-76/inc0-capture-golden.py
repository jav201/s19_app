"""batch-76 Inc-0 — capture the pre-flight golden from the SHIPPED producer.

WHY THIS IS ITS OWN COMMIT (C-12). ``AT-256`` is a collateral-damage PIN: it
asserts that an under-cap report is **byte-identical** before and after the
``HLR-108`` gating rewrite. A golden captured *after* the rewrite would certify
the rewrite against itself and could not fail. So this script runs against the
unmodified ``report_service.py`` at the batch base (``origin/main`` = 291bb76)
and its output is committed BEFORE any producer edit. The ordering is auditable:

    git log --diff-filter=A -- tests/goldens/batch76/

THE FIXTURE IS DELIBERATELY OVER-COVERED, NOT MINIMAL. It must traverse every
seam ``HLR-108`` touches, or the pin is vacuous in exactly the places the batch
changes — the "vacuous FIXTURE" class registered in Lane B (a correct predicate
that cannot fail because the fixture never exercises what it asserts):

  * ``V = 3`` variants          -> the per-variant reservation (LLR-108.4) and
                                   the unconditional heading (LLR-108.5) are
                                   both exercised with V > 1.
  * ``mem_map`` populated       -> ``_hexdump_section`` reaches its block loop,
                                   so BOTH the 5 ungated ``put()`` sites and the
                                   one gated ``put(block)`` at :1788 render.
  * applied + non-applied mods  -> ``_applied_regions`` returns a non-empty
                                   region list rather than short-circuiting on
                                   "No modified regions."
  * checks present              -> the ``### Checklists`` surface renders, which
                                   is the second ``Length`` site (Inc-2).

EVERYTHING IS UNDER-CAP ON PURPOSE. The report must sit far below
``REPORT_MAX_TOTAL_BYTES`` so no gate fires: the property under test is that the
bound is INVISIBLE where it does not fire. The capture prints the produced size
against the cap so that margin is a measured fact, not an assumption.

Run from the repository root:

    python .dev-flow/2026-07-31-batch-76/inc0-capture-golden.py
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from s19_app.tui.changes.model import (  # noqa: E402
    ChangeSummary,
    ChangeSummaryEntry,
    CheckRunEntry,
    CheckRunResult,
)
from s19_app.tui.models import ProjectVariantSet, VariantDescriptor  # noqa: E402
from s19_app.tui.services.report_service import (  # noqa: E402
    REPORT_MAX_TOTAL_BYTES,
    ReportOptions,
    generate_project_report,
)
from s19_app.tui.services.variant_execution_service import (  # noqa: E402
    VariantExecutionResult,
)

#: Frozen generation instant — the report header carries a timestamp, so the
#: clock is injected rather than read, or the golden could never be re-derived.
CONTROL_INSTANT = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)

#: Variant count. > 1 so the per-variant reservation (LLR-108.4) is a live
#: property of the fixture and not a degenerate V == 1 case.
VARIANTS = 3

GOLDEN = REPO_ROOT / "tests" / "goldens" / "batch76" / "document-bound-preflight.md"


def build_results() -> List[VariantExecutionResult]:
    """The pre-flight fixture. Copied VERBATIM into the Inc-1 test.

    Duplication is deliberate and follows the batch-74 precedent: the test may
    not import from ``.dev-flow/``. If the two ever drift the AT fails, which is
    the correct signal — the golden then no longer describes the fixture.
    """
    results: List[VariantExecutionResult] = []
    for v in range(VARIANTS):
        base = 0x8000_0000 + v * 0x1000
        mods = [
            ChangeSummaryEntry(
                entry_type="bytes",
                address_start=base + i * 16,
                address_end=base + i * 16 + (i % 4) + 1,
                before_bytes=tuple(range(0x10, 0x10 + (i % 4) + 1)),
                after_bytes=tuple(range(0xA0, 0xA0 + (i % 4) + 1)),
                # Two dispositions: an all-"applied" fixture would let
                # _applied_regions pass while filtering nothing.
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
        # A memory map spanning the applied regions, so _hexdump_section reaches
        # its block loop instead of short-circuiting on an absent map.
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


def variant_set() -> ProjectVariantSet:
    """The pre-flight inventory. Copied VERBATIM into the Inc-1 test."""
    return ProjectVariantSet(
        project_name="proj",
        variants=tuple(
            VariantDescriptor(
                variant_id=f"v{v}", path=Path(f"v{v}.s19"), file_type="s19"
            )
            for v in range(VARIANTS)
        ),
        active_id="v0",
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "proj"
        root.mkdir(parents=True, exist_ok=True)
        produced = generate_project_report(
            root,
            build_results(),
            ReportOptions(),
            variant_set=variant_set(),
            now_fn=lambda: CONTROL_INSTANT,
        )
        raw = produced.read_bytes()

    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_bytes(raw)

    # The margin is MEASURED and printed, never assumed: the pin only means
    # "the bound is invisible where it does not fire" if the fixture is in fact
    # nowhere near the bound.
    print(f"golden written : {GOLDEN.relative_to(REPO_ROOT)}")
    print(f"produced bytes : {len(raw)}")
    print(f"cap            : {REPORT_MAX_TOTAL_BYTES}")
    print(f"headroom       : {REPORT_MAX_TOTAL_BYTES - len(raw)} bytes "
          f"({len(raw) / REPORT_MAX_TOTAL_BYTES:.4%} of cap)")
    print(f"lines          : {raw.count(chr(10).encode()) + 1}")
    print(f"variant blocks : {raw.count(b'## Variant:')}")
    print(f"hexdump blocks : {raw.count(b'### Memory regions')}")
    print(f"checklists     : {raw.count(b'### Checklists')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
