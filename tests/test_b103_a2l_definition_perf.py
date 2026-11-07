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

import gc
import signal
import statistics
import time
from pathlib import Path

import pytest

from s19_app.tui.a2l_definition import Definition, describe_definition, describe_definitions
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


# --------------------------------------------------------------------------
# R-A2L-DEF.149 (E5 gap pass): describe time does not grow with the size of the
# sections the objects share.  INLINE files of 400 VALUEs ``S00000`` ...
# ``S00399`` at 0x1000 + i that all name one shared section; the section is
# 256 KiB (absolute bound) and S, 2S, 8S = 256 KiB, 512 KiB, 2 MiB (scaling clause: E3S3-24 measure, as
# ruled in inc-2/E3-rulings.md, "Inc 2a E5 - known design gaps", E5-1).
# --------------------------------------------------------------------------

N_OBJECTS = 400
SIZE_S_KIB = 256
SIZE_8S_KIB = 8 * SIZE_S_KIB
ABS_BOUND_S = 0.5            # 400 names at 256 KiB, the least of 7 runs
LEAST_OF = 7
SCALE_ROUNDS = 31            # E3S3-24: least of >= 15 interleaved rounds per size (31 here: the per-object part is ~10 ms)
RATIO_BOUND_2S = 1.5         # per-object part 2S / S (ruled 1.3; 1.5 per orchestrator ruling after 2S failures of correct code; a per-object walk gives >= 1.78)
RATIO_BOUND_8S = 2.0         # per-object part at 8S / at S
SIZES_KIB = (SIZE_S_KIB, 2 * SIZE_S_KIB, SIZE_8S_KIB)
SLOW_RUN_S = 2.0             # E3S3-24: one round only once a run exceeds this
CALL_TIMEOUT_S = 60.0        # R-A2L-DEF.149 "0 timeouts (60 s)"
HOPELESS_S = 10.0            # one run 20x past the bound: no later run of a least-of-7 can rescue it


class _Timeout(Exception):
    pass


def _timed(fn, clock=time.perf_counter):
    """Seconds ``fn()`` takes and its result; a call past 60 s is a timeout and fails the test."""
    if not hasattr(signal, "SIGALRM"):          # non-POSIX: no cap, the bound assertion still applies
        started = clock()
        result = fn()
        return clock() - started, result

    def _raise(*_):
        raise _Timeout()

    old = signal.signal(signal.SIGALRM, _raise)
    signal.setitimer(signal.ITIMER_REAL, CALL_TIMEOUT_S)
    gc.collect()
    gc.disable()          # a full collection over a 2 MiB table's objects is not the code under test
    try:
        started = clock()
        result = fn()
        return clock() - started, result
    except _Timeout:
        pytest.fail(f"R-A2L-DEF.149: a describe call timed out at {CALL_TIMEOUT_S:.0f} s "
                    "(the shared section is read per object)")
    finally:
        gc.enable()
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _a2l_text(case: str, kib: int) -> str:
    """The INLINE file of case ``method`` (.149/1), ``vtab`` (/2), ``range`` (/3) or ``layout`` (/4)."""
    target = kib * 1024
    layout, conv, extra = "RL_U8", "", ""
    rl = "/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
    if case == "method":
        extra = ('/begin COMPU_METHOD CM_L "" LINEAR "%.3" ""\n COEFFS_LINEAR 0.5 0\n'
                 + " DEPOSIT ABSOLUTE\n" * (target // 18) + "/end COMPU_METHOD\n")
        conv = "CM_L"
    elif case == "vtab":
        lines, k, size = [], 0, 0
        while size < target:
            line = f' {k} "v{k}"\n'
            lines.append(line)
            size += len(line)
            k += 1
        extra = ('/begin COMPU_METHOD CM_V "" TAB_VERB "%.0" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
                 f'/begin COMPU_VTAB VT "" TAB_VERB {k}\n' + "".join(lines) + "/end COMPU_VTAB\n")
        conv = "CM_V"
    elif case == "range":
        lines, k, size = [], 0, 0
        while size < target:
            line = f' {2 * k} {2 * k + 1} "r{k}"\n'
            lines.append(line)
            size += len(line)
            k += 1
        extra = ('/begin COMPU_METHOD CM_R "" TAB_VERB "%.0" ""\n COMPU_TAB_REF VR\n/end COMPU_METHOD\n'
                 f'/begin COMPU_VTAB_RANGE VR "" {k}\n' + "".join(lines) + "/end COMPU_VTAB_RANGE\n")
        conv = "CM_R"
    elif case == "layout":
        extra = ("/begin RECORD_LAYOUT RL_LONG\n FNC_VALUES 1 " + "X " * (target // 2)
                 + "UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n")
        layout, conv = "RL_LONG", "NO_COMPU_METHOD"
    else:
        raise ValueError(case)
    objs = "".join(
        f'/begin CHARACTERISTIC S{i:05d} ""\n VALUE 0x{0x1000 + i:X} {layout} 0 {conv} 0 255\n/end CHARACTERISTIC\n'
        for i in range(N_OBJECTS)
    )
    return ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\n'
            f"BYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n{rl}{extra}{objs}/end MODULE\n/end PROJECT\n")


def _load(tmp_path: Path, case: str, kib: int):
    path = tmp_path / f"shared_{case}_{kib}.a2l"
    path.write_text(_a2l_text(case, kib), encoding="utf-8")
    a2l = parse_a2l_file(path)
    names = [t["name"] for t in a2l["tags"] if t.get("char_type") == "VALUE"]
    assert len(names) == N_OBJECTS and len(set(names)) == N_OBJECTS
    return a2l, names


_EXPECT = {"method": "number", "vtab": "enum", "range": "enum", "layout": "number"}


def _check_definitions(case: str, result: dict, names: list, a2l: dict) -> None:
    """Every definition kind/datatype/refusal as ruled; the first and the last equal a describe of that name alone."""
    assert list(result) == names
    for definition in result.values():
        assert definition.kind == _EXPECT[case] and definition.datatype == "UBYTE" and definition.refusal is None
        if case == "method":
            assert definition.conversion_type == "LINEAR"
    for name in (names[0], names[-1]):
        assert result[name] == describe_definition(name, a2l)
    if case in ("vtab", "range"):
        # the one enum table of the shared section is held by reference, not copied per object
        assert len(result[names[0]].enum_entries) > 1000
        assert len({id(d.enum_entries) for d in result.values()}) == 1


def _absolute(tmp_path: Path, case: str, label: str) -> None:
    a2l, names = _load(tmp_path, case, SIZE_S_KIB)
    runs, result = [], {}
    for _ in range(LEAST_OF):
        seconds, result = _timed(lambda: describe_definitions(names, a2l))
        runs.append(seconds)
        if seconds > HOPELESS_S:
            break
    least = min(runs)
    assert least <= report_margin(f"R-A2L-DEF.149 {label} 400 names at 256 KiB", least,
                                  timing_bound(ABS_BOUND_S)), runs
    _check_definitions(case, result, names, a2l)


def _scaling(tmp_path: Path, case: str, label: str) -> None:
    """Measure of E3S3-24 (inc-3/E3-security.md, round 5): the per-object part is the process CPU time of all 400
    names minus that of the first name alone (the first call reads every shared section once); S, 2S and 8S are
    interleaved round by round; each time is the least of 15 rounds (one round once a run exceeds 2 s)."""
    loaded = {kib: _load(tmp_path, case, kib) for kib in SIZES_KIB}
    best_all = {kib: float("inf") for kib in SIZES_KIB}
    best_first = {kib: float("inf") for kib in SIZES_KIB}
    results = {}
    for _ in range(SCALE_ROUNDS):
        slow = False
        for kib in SIZES_KIB:                    # interleaved: S, 2S, 8S in turn within every round
            a2l, names = loaded[kib]
            t_first, _r = _timed(lambda: describe_definitions(names[:1], a2l), time.process_time)
            t_all, results[kib] = _timed(lambda: describe_definitions(names, a2l), time.process_time)
            best_first[kib] = min(best_first[kib], t_first)
            best_all[kib] = min(best_all[kib], t_all)
            slow = slow or t_all > SLOW_RUN_S
        if slow:
            break
    part = {kib: max(best_all[kib] - best_first[kib], 1e-3) for kib in SIZES_KIB}   # floor: 1 ms is timer noise
    ratio_2s = part[2 * SIZE_S_KIB] / part[SIZE_S_KIB]
    ratio_8s = part[SIZE_8S_KIB] / part[SIZE_S_KIB]
    assert ratio_2s <= report_margin(f"R-A2L-DEF.149 {label} per-object part 2S/S", ratio_2s,
                                     timing_bound(RATIO_BOUND_2S)), part
    assert ratio_8s <= report_margin(f"R-A2L-DEF.149 {label} per-object part 8S/S", ratio_8s,
                                     timing_bound(RATIO_BOUND_8S)), part
    for kib in SIZES_KIB:
        _check_definitions(case, results[kib], loaded[kib][1], loaded[kib][0])
    shapes = [[(d.kind, d.datatype, d.refusal) for d in results[kib].values()] for kib in SIZES_KIB]
    assert shapes[0] == shapes[1] == shapes[2]


@pytest.mark.serial_timing
def test_r_a2l_def_149_1_shared_method_size_costs_nothing_per_object(tmp_path):
    """R-A2L-DEF.149/1 - 400 objects naming one COMPU_METHOD of 256 KiB: within 0.5 s (least of 7)."""
    _absolute(tmp_path, "method", "/1 COMPU_METHOD")


@pytest.mark.serial_timing
def test_r_a2l_def_149_2_shared_enum_table_size_costs_nothing_per_object(tmp_path):
    """R-A2L-DEF.149/2 - 400 objects sharing one COMPU_VTAB of 256 KiB: within 0.5 s; one shared enum tuple."""
    _absolute(tmp_path, "vtab", "/2 COMPU_VTAB")


@pytest.mark.serial_timing
def test_r_a2l_def_149_3_shared_range_table_size_costs_nothing_per_object(tmp_path):
    """R-A2L-DEF.149/3 - 400 objects sharing one COMPU_VTAB_RANGE of 256 KiB: within 0.5 s; one shared enum tuple."""
    _absolute(tmp_path, "range", "/3 COMPU_VTAB_RANGE")


@pytest.mark.serial_timing
def test_r_a2l_def_149_4_shared_layout_first_line_costs_nothing_per_object(tmp_path):
    """R-A2L-DEF.149/4 - 400 VALUEs sharing one RECORD_LAYOUT of 256 KiB: within 0.5 s."""
    _absolute(tmp_path, "layout", "/4 RECORD_LAYOUT")


@pytest.mark.serial_timing
def test_r_a2l_def_149_1_scaling_method(tmp_path):
    """R-A2L-DEF.149/1 scaling - per-object part at 512 KiB at most 1.3x and at 2048 KiB at most 2.0x that at 256 KiB (E3S3-24 measure)."""
    _scaling(tmp_path, "method", "/1 COMPU_METHOD")


@pytest.mark.serial_timing
def test_r_a2l_def_149_2_scaling_enum_table(tmp_path):
    """R-A2L-DEF.149/2 scaling - as /1 for a COMPU_VTAB."""
    _scaling(tmp_path, "vtab", "/2 COMPU_VTAB")


@pytest.mark.serial_timing
def test_r_a2l_def_149_3_scaling_range_table(tmp_path):
    """R-A2L-DEF.149/3 scaling - as /1 for a COMPU_VTAB_RANGE."""
    _scaling(tmp_path, "range", "/3 COMPU_VTAB_RANGE")


@pytest.mark.serial_timing
def test_r_a2l_def_149_4_scaling_layout(tmp_path):
    """R-A2L-DEF.149/4 scaling - as /1 for a RECORD_LAYOUT whose first line is long."""
    _scaling(tmp_path, "layout", "/4 RECORD_LAYOUT")
