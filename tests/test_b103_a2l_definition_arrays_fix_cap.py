"""Batch-103 Inc 3a - the two cap cases R-A2L-DEF.142/5 and /6 (``serial_timing`` lane).

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-3/02-test-cases.md``
rows R-A2L-DEF.142/5 and /6, which close the point-count cap coverage:

- **/5 (E3A-01, E3S3-02).** Describing 50 FIX_AXIS curves at the cap
  (1,048,576 points, a 1 MiB record) plus 50 FIX_AXIS maps of two such axes
  (element count 2^40) must finish within 1.0 s (median of 3, ``tracemalloc``
  on) with a peak under 50 MiB; every curve has no refusal and element count
  1,048,576; every map is refused ``A2L-DEF-ADDRESS`` "the object has no
  address or no length" (its record walk stops past 1 MiB, R-A2L-DEF.7.1).  The
  discriminating fact is that no point is materialised at describe: the
  FIX_AXIS parameters are kept as ``fixed_rule`` (a 3-tuple), never a 1 MiB
  point list (the round-1 rule built points at describe: 214 s, 6,007 MiB).

- **/6 (E3A-25).** A FIX_AXIS_PAR_LIST of 1,048,576 numbers (0 .. 1,048,575,
  16 per line) must describe within 5.0 s (median of 3, ``tracemalloc`` off)
  with a separate ``tracemalloc`` peak under 100 MiB, refusal ``None``, and a
  ``fixed_rule`` of ``("PAR_LIST", the 1,048,576 numbers)``.

Fixtures are synthetic INLINE3 files built by
``tests.support.b103_a2l_arrays`` (no public-corpus text).  The model is
exercised through its public names only (``describe_definitions`` /
``describe_definition``).  No child process is spawned and no in-process timer
is installed: the 60 s per-case cap is the orchestrator's, enforced outside
this file.

Dependencies:
    - ``s19_app.tui.a2l_definition`` (under test), the app's A2L parser,
      ``tests.support.b103_a2l_arrays`` (synthetic INLINE3 builders)
"""

from __future__ import annotations

import gc
import statistics
import time
import tracemalloc
from pathlib import Path

import pytest

from s19_app.tui.a2l_definition import Refusal, describe_definition, describe_definitions
from tests.support.b103_a2l_arrays import axis, curve, inline, mapchar
from tests.support.timing import report_margin, timing_bound

CAP = 1_048_576
N_CURVES = 50
N_MAPS = 50
CURVE_BASE = 0x100000
CURVE_STRIDE = 0x200000

BOUND_142_5_S = 1.0
PEAK_142_5_B = 50 * 1024 * 1024
BOUND_142_6_S = 5.0
PEAK_142_6_B = 100 * 1024 * 1024

_PER_LIST_LINE = 16


def _fix_axis_at_cap() -> str:
    """One FIX_AXIS AXIS_DESCR at the cap: max and PAR_DIST count both 1,048,576."""
    return axis("FIX_AXIS", "CM_IDENT", "1048576", "0", "255",
                "FIX_AXIS_PAR_DIST 0 1 1048576")


def _cap_fixture(tmp_path: Path) -> tuple[dict, list[str]]:
    """The /5 INLINE3 file: 50 curves ``FC000`` ... ``FC049`` at the cap and
    50 maps ``FM000`` ... ``FM049`` of two such axes, parsed; returns the
    ``a2l_data`` payload and the 100 names in file order."""
    blocks = []
    for i in range(N_CURVES):
        blocks.append(curve(f"FC{i:03d}", hex(CURVE_BASE + i * CURVE_STRIDE),
                            "RL_U8", _fix_axis_at_cap()))
    for i in range(N_MAPS):
        blocks.append(mapchar(f"FM{i:03d}", hex(CURVE_BASE + i * CURVE_STRIDE),
                              "RL_U8", _fix_axis_at_cap(), _fix_axis_at_cap()))
    a2l = inline(tmp_path, *blocks)
    names = [f"FC{i:03d}" for i in range(N_CURVES)] + [f"FM{i:03d}" for i in range(N_MAPS)]
    assert len(a2l["tags"]) == len(names)
    return a2l, names


def _par_list_axis() -> str:
    """One FIX_AXIS AXIS_DESCR whose FIX_AXIS_PAR_LIST child holds the numbers
    0 .. 1,048,575, 16 per line (the /6 fixture)."""
    body = [
        "  /begin AXIS_DESCR",
        "    FIX_AXIS NO_INPUT_QUANTITY CM_IDENT 1048576 0 255",
        "    /begin FIX_AXIS_PAR_LIST",
    ]
    for base in range(0, CAP, _PER_LIST_LINE):
        body.append("    " + " ".join(str(n) for n in range(base, base + _PER_LIST_LINE)))
    body += ["    /end FIX_AXIS_PAR_LIST", "  /end AXIS_DESCR"]
    return "\n".join(body)


def _fl_fixture(tmp_path: Path) -> dict:
    """The /6 INLINE3 file: the curve ``FL`` with the cap-sized PAR_LIST."""
    a2l = inline(tmp_path, curve("FL", "0x100", "RL_U8", _par_list_axis()))
    assert [t["name"] for t in a2l["tags"]] == ["FL"]
    return a2l


@pytest.mark.serial_timing
def test_r_a2l_def_142_5_describing_fix_axes_at_cap_builds_no_point(tmp_path):
    """R-A2L-DEF.142/5 - 50 FIX curves at the cap + 50 two-axis FIX maps: median of 3 <= 1.0 s (tracemalloc on), peak < 50 MiB, exact counts/refusals, no point built."""
    a2l, names = _cap_fixture(tmp_path)
    times: list[float] = []
    result: dict = {}
    peak = 0
    gc.collect()
    tracemalloc.start()
    try:
        for _ in range(3):
            gc.collect()
            started = time.perf_counter()
            result = describe_definitions(names, a2l)
            times.append(time.perf_counter() - started)
            _current, run_peak = tracemalloc.get_traced_memory()
            peak = max(peak, run_peak)
    finally:
        tracemalloc.stop()
    median = statistics.median(times)
    print(f"R-A2L-DEF.142/5 median {median:.3f} s, peak {peak} bytes ({peak / 1048576:.1f} MiB)")
    assert median <= report_margin(
        "R-A2L-DEF.142/5 describe 50 fix curves + 50 fix maps",
        median, timing_bound(BOUND_142_5_S)), times
    assert peak < PEAK_142_5_B, f"tracemalloc peak {peak} >= {PEAK_142_5_B}"

    assert list(result) == names and len(result) == N_CURVES + N_MAPS
    for i in range(N_CURVES):
        name = f"FC{i:03d}"
        d = result[name]
        assert d.kind == "curve" and d.refusal is None
        assert d.element_count == CAP and d.byte_length == CAP
        assert len(d.axes) == 1
        ax = d.axes[0]
        assert ax.point_count == CAP
        # the FIX parameters are kept as a 3-tuple, never a point list
        assert ax.fixed_rule == ("PAR_DIST", (0, 1, CAP))
        assert len(ax.fixed_rule[1]) == 3
    for i in range(N_MAPS):
        name = f"FM{i:03d}"
        d = result[name]
        assert d.kind == "map"
        assert d.refusal == Refusal("A2L-DEF-ADDRESS",
                                    f"{name}: the object has no address or no length")
        assert d.element_count == 2 ** 40
        assert d.byte_length is None
        assert len(d.axes) == 2
        for ax in d.axes:
            assert ax.point_count == CAP
            assert ax.fixed_rule == ("PAR_DIST", (0, 1, CAP))
            assert len(ax.fixed_rule[1]) == 3


@pytest.mark.serial_timing
def test_r_a2l_def_142_6_fix_axis_par_list_at_cap_describes_in_linear_time(tmp_path):
    """R-A2L-DEF.142/6 - a 1,048,576-number FIX_AXIS_PAR_LIST: median of 3 <= 5.0 s (tracemalloc off), separate peak < 100 MiB, refusal None, fixed_rule length/endpoints."""
    a2l = _fl_fixture(tmp_path)

    times: list[float] = []
    result = None
    for _ in range(3):
        started = time.perf_counter()
        result = describe_definition("FL", a2l)
        times.append(time.perf_counter() - started)
    median = statistics.median(times)
    print(f"R-A2L-DEF.142/6 median {median:.3f} s (tracemalloc off)")
    assert median <= report_margin(
        "R-A2L-DEF.142/6 describe FIX_AXIS_PAR_LIST at cap",
        median, timing_bound(BOUND_142_6_S)), times

    gc.collect()
    tracemalloc.start()
    try:
        result = describe_definition("FL", a2l)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    print(f"R-A2L-DEF.142/6 peak {peak} bytes ({peak / 1048576:.1f} MiB)")
    assert peak < PEAK_142_6_B, f"tracemalloc peak {peak} >= {PEAK_142_6_B}"

    assert result is not None
    assert result.refusal is None and result.kind == "curve"
    assert result.element_count == CAP and result.byte_length == CAP
    assert len(result.axes) == 1
    ax = result.axes[0]
    assert ax.point_count == CAP
    assert ax.fixed_rule is not None
    assert ax.fixed_rule[0] == "PAR_LIST"
    numbers = ax.fixed_rule[1]
    assert len(numbers) == CAP
    assert numbers[0] == 0 and numbers[-1] == CAP - 1
    for idx in (1, 2, CAP // 2, CAP // 2 + 1, CAP - 2):
        assert numbers[idx] == idx
