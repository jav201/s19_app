"""Batch-103 Inc 2a - timing row R-A2L-DEF.136 (``serial_timing`` lane).

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-2/01-requirements.md``
R-A2L-DEF.136: describing every object of software_a (13,990 names) in one
call finishes within 2.0 s (median of 3 runs, cachyos-rtx, Python 3.11).
In 2a the walk holds the name, method and table maps and every field; the case
is re-run when 2b adds the span index to the same walk. The one-walk design
(not one walk per name) is what the bound separates: a per-name walk takes
minutes.

Dependencies:
    - ``s19_app.tui.a2l_definition.describe_definitions``, the app's A2L parser
"""

from __future__ import annotations

import statistics
import time
from pathlib import Path

import pytest

from s19_app.tui.a2l_definition import Definition, describe_definitions
from s19_app.tui.a2l_parse import parse_a2l_file
from tests.support.timing import report_margin, timing_bound

SOFTA = Path(__file__).resolve().parent.parent / "examples" / "case_00_public" / "software_a.a2l"
BOUND_SECONDS = 2.0


@pytest.mark.serial_timing
def test_r_a2l_def_136_1_describing_every_object_is_fast():
    """R-A2L-DEF.136/1 - 13,990 names in one call: median of 3 runs <= 2.0 s; every name gets a Definition."""
    a2l = parse_a2l_file(SOFTA)
    names = [t["name"] for t in a2l["tags"]]
    assert len(set(names)) == 13990
    runs = []
    result = {}
    for _ in range(3):
        started = time.perf_counter()
        result = describe_definitions(names, a2l)
        runs.append(time.perf_counter() - started)
    assert len(result) == 13990
    assert all(isinstance(d, Definition) for d in result.values())
    # the walk really built definitions (a constant refusal would also be fast)
    built = [d for d in result.values() if d.refusal is None]
    assert any(d.kind == "number" for d in built) and any(d.kind == "enum" for d in built)
    # Integration fix (orchestrator, 2026-11-07): the bound goes through the repo's
    # timing helpers so the R-TST-002 census sees a timing arm and QC-TM reports it.
    median = statistics.median(runs)
    assert median <= report_margin("R-A2L-DEF.136 describe 13990", median, timing_bound(BOUND_SECONDS)), runs
