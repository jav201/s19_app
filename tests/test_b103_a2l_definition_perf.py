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


NON_VACUITY_S = 2e-3         # E5-3: the 399 names after the first take at least 2 ms at S (a module that materialised
                             # the names before describing them would give an interval near 0)


def _steady_describe(names: list, a2l: dict) -> tuple[float, dict]:
    """E5-3 (inc-2/E5-code-review.md; inc-3 E3S3-34): CPU time of the 399 names after the first, described for the
    first time in ONE fresh walk.  ``names`` is a generator: the clock is read when the walk asks for the 2nd name
    (the 1st has reduced every shared section) and when the names run out.  Each run builds its own walk; there is
    no difference of two walks.  Returns (that interval, the walk's result)."""
    marks: list = []

    def gen():
        yield names[0]
        marks.append(time.process_time())
        yield from names[1:]
        marks.append(time.process_time())

    result = describe_definitions(gen(), a2l)
    assert len(marks) == 2 and list(result) == names          # the names were consumed once, lazily
    return marks[1] - marks[0], result


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
    """E5-3 measure (inc-2/E5-code-review.md): the per-object part is the process CPU time of the 399 names after the
    first, read inside one fresh walk (``_steady_describe``); S, 2S and 8S are interleaved round by round; each time
    is the least of 31 rounds (one round once a run exceeds 2 s)."""
    loaded = {kib: _load(tmp_path, case, kib) for kib in SIZES_KIB}
    part = {kib: float("inf") for kib in SIZES_KIB}
    results = {}
    for _ in range(SCALE_ROUNDS):
        slow = False
        for kib in SIZES_KIB:                    # interleaved: S, 2S, 8S in turn within every round
            a2l, names = loaded[kib]
            t_outer, (interval, results[kib]) = _timed(lambda: _steady_describe(names, a2l), time.process_time)
            part[kib] = min(part[kib], interval)
            slow = slow or t_outer > SLOW_RUN_S
        if slow:
            break
    assert part[SIZE_S_KIB] >= NON_VACUITY_S, part
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


# --------------------------------------------------------------------------
# E5 gap pass 2 (independent tester).  Cases R-A2L-DEF.149/6 ... /10 (a long word of a shared
# method or table, a long layout first line) and R-A2L-DEF.150/1 ... /5, /7, /8 (decode time and
# retained text do not grow with the size of the conversion table a scalar names).
# Measure of inc-2/E3-rulings.md "Inc 2a E5 - gap pass 2 rulings": process CPU time, collector
# collected and disabled for each timed call, S / 2S / 8S interleaved round by round, the least of
# >= 15 rounds, x2S <= 1.5 and x8S <= 2.0; absolute: 400 calls within 0.5 s at S (least of 7).
# --------------------------------------------------------------------------

from dataclasses import dataclass, field  # noqa: E402
from typing import Any, Callable, Optional  # noqa: E402

from s19_app.tui.a2l_definition import Decoded, Refusal, decode_definition  # noqa: E402

MESSAGE_BOUND = 1024          # R-A2L-DEF.151 / E3S3-32: every refusal message at most 1,024 characters
ECHO_LIMIT = 256              # R-A2L-DEF.151: a file word is echoed as its first 256 characters

_GP2_HEAD = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\n'
             "BYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
             "/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n")
_GP2_TAIL = "/end MODULE\n/end PROJECT\n"


def _verb_method(name: str, ref: str) -> str:
    return f'/begin COMPU_METHOD {name} "" TAB_VERB "%.0" ""\n COMPU_TAB_REF {ref}\n/end COMPU_METHOD\n'


def _gp2_objects(conv: str, layout: str = "RL_U8", kind: str = "VALUE") -> str:
    return "".join(
        f'/begin CHARACTERISTIC S{i:05d} ""\n {kind} 0x{0x1000 + i:X} {layout} 0 {conv} 0 255\n/end CHARACTERISTIC\n'
        for i in range(N_OBJECTS)
    )


def _numbered_lines(target: int, template: Callable[[int], str]) -> tuple[list, int]:
    """Lines ``template(k)`` for k = 0, 1, ... until their sizes reach ``target`` characters."""
    lines, size, k = [], 0, 0
    while size < target:
        line = template(k)
        lines.append(line)
        size += len(line)
        k += 1
    return lines, k


def _tab_lines(target: int) -> tuple[list, int, list]:
    """COMPU_TAB entries ``x_j j`` with x_j = 200 j / (k - 1) for j < k - 1, then ``300 999`` (k chosen so the
    section is about ``target`` characters).  Returns the lines, k and the entries as the parser reads them."""
    k = max(4, target // 22)
    for _ in range(4):
        xs = [f"{200.0 * j / (k - 1):.6f}" for j in range(k - 1)]
        size = sum(len(f" {x} {j}\n") for j, x in enumerate(xs)) + len(" 300 999\n")
        if abs(size - target) <= target // 50:
            break
        k = max(4, int(k * target / size))
    xs = [f"{200.0 * j / (k - 1):.6f}" for j in range(k - 1)]
    lines = [f" {x} {j}\n" for j, x in enumerate(xs)] + [" 300 999\n"]
    entries = [(float(x), float(j)) for j, x in enumerate(xs)] + [(300.0, 999.0)]
    return lines, k, entries


def _gp2_text(case: str, kib: int) -> str:
    """The INLINE file of one gap-pass-2 case at ``kib`` KiB of shared section (S = 256)."""
    n = kib * 1024
    head, tail = _GP2_HEAD, _GP2_TAIL
    if case == "fmt":                                                    # .149/6
        extra = '/begin COMPU_METHOD CM_F "" LINEAR "%' + "9" * n + '.2" ""\n COEFFS_LINEAR 0.5 0\n/end COMPU_METHOD\n'
        return head + extra + _gp2_objects("CM_F") + tail
    if case == "type":                                                   # .149/7
        extra = f'/begin COMPU_METHOD CM_T "" {"Z" * n} "%.3" ""\n/end COMPU_METHOD\n'
        return head + extra + _gp2_objects("CM_T") + tail
    if case == "tabref":                                                 # .149/8
        return head + _verb_method("CM_V", "G" * n) + _gp2_objects("CM_V") + tail
    if case == "cuboid":                                                 # .149/9
        extra = f"/begin RECORD_LAYOUT RL_LONG\n FNC_VALUES 1 {'X ' * (n // 2)}UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        return head + extra + _gp2_objects("NO_COMPU_METHOD", "RL_LONG", "CUBOID") + tail
    if case == "emptyname":                                              # .149/10
        extra = _verb_method("CM_E", "E" * n) + f'/begin COMPU_VTAB {"E" * n} "" TAB_VERB 0\n/end COMPU_VTAB\n'
        return head + extra + _gp2_objects("CM_E") + tail
    if case in ("vtab", "vtab_text", "vtab_default"):                    # .150/1, /2, /3
        if case == "vtab":
            lines, count = _numbered_lines(n, lambda j: f' {1000 + j} "v{j}"\n')
            body = "".join(lines)
        elif case == "vtab_text":
            body, count = f' 0 "{"t" * n}"\n', 1
        else:
            body, count = f' 1000 "a"\n DEFAULT_VALUE "{"d" * n}"\n', 1
        extra = _verb_method("CM_V", "VT") + f'/begin COMPU_VTAB VT "" TAB_VERB {count}\n{body}/end COMPU_VTAB\n'
        return head + extra + _gp2_objects("CM_V") + tail
    if case in ("range", "range_text"):                                  # .150/4, /5
        if case == "range":
            lines, count = _numbered_lines(n, lambda j: f' {1000 + 2 * j} {1000 + 2 * j + 1} "r{j}"\n')
            body = "".join(lines)
        else:
            body, count = f' 0 255 "{"t" * n}"\n', 1
        extra = _verb_method("CM_R", "VR") + f'/begin COMPU_VTAB_RANGE VR "" {count}\n{body}/end COMPU_VTAB_RANGE\n'
        return head + extra + _gp2_objects("CM_R") + tail
    if case == "tab_run":                                                # .150/10
        lines, cnt = _numbered_lines(n, lambda j: f" 0 {j}\n")             # one run of cnt equal x, y = 0, 1, 2, ...
        extra = (f'/begin COMPU_METHOD CM_N "" TAB_NOINTP "%.3" ""\n COMPU_TAB_REF CT\n/end COMPU_METHOD\n'
                 f'/begin COMPU_TAB CT "" TAB_NOINTP {cnt + 1}\n{"".join(lines)} 1000 5\n/end COMPU_TAB\n')
        return head + extra + _gp2_objects("CM_N") + tail
    if case in ("tab_intp", "tab_nointp"):                               # .150/7, /8
        lines, k, _entries = _tab_lines(n)
        typ = "TAB_INTP" if case == "tab_intp" else "TAB_NOINTP"
        extra = (f'/begin COMPU_METHOD CM_X "" {typ} "%.3" ""\n COMPU_TAB_REF CT\n/end COMPU_METHOD\n'
                 f'/begin COMPU_TAB CT "" {typ} {k}\n{"".join(lines)}/end COMPU_TAB\n')
        return head + extra + _gp2_objects("CM_X") + tail
    raise ValueError(case)


@dataclass
class _Loaded:
    a2l: dict
    names: list
    image: dict = field(default_factory=dict)
    defs: dict = field(default_factory=dict)


def _gp2_load(tmp_path: Path, case: str, kib: int, image_byte: Optional[int] = None) -> _Loaded:
    path = tmp_path / f"gp2_{case}_{kib}.a2l"
    path.write_text(_gp2_text(case, kib), encoding="utf-8")
    a2l = parse_a2l_file(path)
    names = [f"S{i:05d}" for i in range(N_OBJECTS)]
    assert sorted(t["name"] for t in a2l["tags"] if t["name"] in set(names)) == names
    loaded = _Loaded(a2l, names)
    if image_byte is not None:
        loaded.image = {0x1000 + i: image_byte for i in range(N_OBJECTS)}
        loaded.defs = describe_definitions(names, a2l)         # the walk is not timed in a decode case
    return loaded


def _gp2_run(tmp_path: Path, case: str, label: str, work: Callable[[_Loaded], Any],
             check: Callable[[int, _Loaded, Any], None], image_byte: Optional[int] = None,
             steady: Optional[Callable[[_Loaded], tuple]] = None) -> None:
    """Absolute bound at S (400 calls within 0.5 s, wall clock, the least of 7 runs) then the scaling bound.

    A describe case passes ``steady`` (E5-3): it returns (the CPU interval of the 399 names after the first, read
    inside one fresh walk, that walk's result) and the per-object part is the least of >= 15 interleaved rounds of
    that interval.  A decode case keeps one interval: the process CPU time of ``work`` itself."""
    loaded = {kib: _gp2_load(tmp_path, case, kib, image_byte) for kib in SIZES_KIB}
    runs, result = [], None
    for _ in range(LEAST_OF):
        seconds, result = _timed(lambda: work(loaded[SIZE_S_KIB]))
        runs.append(seconds)
        if seconds > HOPELESS_S:
            break
    least = min(runs)
    assert least <= report_margin(f"R-A2L-DEF.{label} 400 calls at 256 KiB", least, timing_bound(ABS_BOUND_S)), runs
    check(SIZE_S_KIB, loaded[SIZE_S_KIB], result)

    part = {kib: float("inf") for kib in SIZES_KIB}
    results = {}
    for _ in range(SCALE_ROUNDS):
        slow = False
        for kib in SIZES_KIB:                    # interleaved: S, 2S, 8S in turn within every round
            if steady is not None:
                t_outer, (interval, results[kib]) = _timed(lambda: steady(loaded[kib]), time.process_time)
            else:
                t_outer, results[kib] = _timed(lambda: work(loaded[kib]), time.process_time)
                interval = t_outer
            part[kib] = min(part[kib], interval)
            slow = slow or t_outer > SLOW_RUN_S
        if slow:
            break
    if steady is not None:
        assert part[SIZE_S_KIB] >= NON_VACUITY_S, part
    else:
        part = {kib: max(t, 1e-3) for kib, t in part.items()}      # floor: 1 ms is timer noise
    ratio_2s = part[2 * SIZE_S_KIB] / part[SIZE_S_KIB]
    ratio_8s = part[SIZE_8S_KIB] / part[SIZE_S_KIB]
    assert ratio_2s <= report_margin(f"R-A2L-DEF.{label} per-object part 2S/S", ratio_2s,
                                     timing_bound(RATIO_BOUND_2S)), part
    assert ratio_8s <= report_margin(f"R-A2L-DEF.{label} per-object part 8S/S", ratio_8s,
                                     timing_bound(RATIO_BOUND_8S)), part
    for kib in SIZES_KIB:
        check(kib, loaded[kib], results[kib])


def _describe_all(c: _Loaded) -> dict:
    return describe_definitions(c.names, c.a2l)


def _describe_steady(c: _Loaded) -> tuple[float, dict]:
    return _steady_describe(c.names, c.a2l)


def _decode_all(c: _Loaded) -> list:
    return [decode_definition(d, c.a2l, c.image) for d in c.defs.values()]


def _first_last_alone(c: _Loaded, result: dict) -> None:
    assert list(result) == c.names
    for name in (c.names[0], c.names[-1]):
        assert result[name] == describe_definition(name, c.a2l)


def _messages_bounded(result: dict) -> None:
    for d in result.values():
        if d.refusal is not None:
            assert len(d.refusal.message) <= MESSAGE_BOUND, len(d.refusal.message)


def _same_object(values) -> bool:
    return len({id(v) for v in values}) == 1


@pytest.mark.serial_timing
def test_r_a2l_def_149_6_long_format_word_of_a_shared_method_costs_nothing_per_object(tmp_path):
    """R-A2L-DEF.149/6 - a FORMAT word of S / 2S / 8S nines is scanned once per walk; decimals 2; one display_format object."""
    def check(kib, c, result):
        _first_last_alone(c, result)
        for d in result.values():
            assert (d.kind, d.datatype, d.conversion_type, d.decimals, d.refusal) == ("number", "UBYTE", "LINEAR", 2, None)
        assert _same_object(d.display_format for d in result.values())
        assert result[c.names[0]].display_format == "%" + "9" * (kib * 1024) + ".2"

    _gp2_run(tmp_path, "fmt", "149/6 FORMAT word", _describe_all, check, steady=_describe_steady)


@pytest.mark.serial_timing
def test_r_a2l_def_149_7_long_conversion_type_word_costs_nothing_per_object(tmp_path):
    """R-A2L-DEF.149/7 - a type word of S ... 8S of Z is echoed once at reduction: 256 characters and an ellipsis, message <= 1,024."""
    def check(kib, c, result):
        _first_last_alone(c, result)
        _messages_bounded(result)
        for name, d in result.items():
            assert (d.kind, d.datatype) == ("number", "UBYTE")
            assert d.refusal == Refusal("A2L-DEF-CONVERSION",
                                        f"{name}: the conversion type {'Z' * 256}… of CM_T is not supported")
        assert _same_object(d.conversion_type for d in result.values())

    _gp2_run(tmp_path, "type", "149/7 conversion type word", _describe_all, check, steady=_describe_steady)


@pytest.mark.serial_timing
def test_r_a2l_def_149_8_long_table_ref_word_costs_nothing_per_object(tmp_path):
    """R-A2L-DEF.149/8 - a COMPU_TAB_REF word of S ... 8S of G, declared nowhere: echoed once, found once per walk."""
    def check(kib, c, result):
        _first_last_alone(c, result)
        _messages_bounded(result)
        for name, d in result.items():
            assert (d.kind, d.datatype) == ("enum", "UBYTE")
            assert d.refusal == Refusal("A2L-DEF-TABLE",
                                        f"{name}: the table {'G' * 256}… of CM_V is not declared in the A2L")
        assert _same_object(d.enum_table for d in result.values())

    _gp2_run(tmp_path, "tabref", "149/8 COMPU_TAB_REF word", _describe_all, check, steady=_describe_steady)


@pytest.mark.serial_timing
def test_r_a2l_def_149_9_shared_layout_first_line_costs_nothing_per_cuboid(tmp_path):
    """R-A2L-DEF.149/9 - 400 CUBOIDs sharing a layout whose first line is S ... 8S: the layout step runs once per walk."""
    def check(kib, c, result):
        _first_last_alone(c, result)
        _messages_bounded(result)
        for name, d in result.items():
            assert d.datatype == "UBYTE"
            assert d.refusal == Refusal("A2L-DEF-KIND", f"{name}: the system has no definition for a CUBOID object")

    _gp2_run(tmp_path, "cuboid", "149/9 CUBOID layout", _describe_all, check, steady=_describe_steady)


@pytest.mark.serial_timing
def test_r_a2l_def_149_10_long_name_of_a_shared_empty_table_costs_nothing_per_object(tmp_path):
    """R-A2L-DEF.149/10 - a table named by a word of S ... 8S of E and holding no entries: echoed and found once per walk."""
    def check(kib, c, result):
        _first_last_alone(c, result)
        _messages_bounded(result)
        for name, d in result.items():
            assert d.kind == "enum" and d.datatype == "UBYTE"
            assert d.refusal == Refusal("A2L-DEF-TABLE-EMPTY", f"{name}: the table {'E' * 256}… has no entries")

    _gp2_run(tmp_path, "emptyname", "149/10 empty table name", _describe_all, check, steady=_describe_steady)


@pytest.mark.serial_timing
def test_r_a2l_def_150_1_shared_vtab_size_costs_nothing_per_element(tmp_path):
    """R-A2L-DEF.150/1 - decoding 400 elements that name one COMPU_VTAB of S ... 8S entries: the entries are not scanned per element."""
    def check(kib, c, result):
        assert result == [Decoded(250, None, "250 (no text)")] * N_OBJECTS

    _gp2_run(tmp_path, "vtab", "150/1 COMPU_VTAB decode", _decode_all, check, image_byte=250)


@pytest.mark.serial_timing
def test_r_a2l_def_150_2_long_matched_entry_text_is_referenced_not_copied(tmp_path):
    """R-A2L-DEF.150/2 - a matched entry text of S ... 8S characters is one string object for all 400 decodes."""
    def check(kib, c, result):
        text = "t" * (kib * 1024)
        assert all(isinstance(r, Decoded) and r.stored == 0 and r.value == text and r.text == text for r in result)
        assert _same_object(r.value for r in result) and _same_object(r.text for r in result)

    _gp2_run(tmp_path, "vtab_text", "150/2 matched entry text", _decode_all, check, image_byte=0)


@pytest.mark.serial_timing
def test_r_a2l_def_150_3_long_default_text_is_referenced_not_copied(tmp_path):
    """R-A2L-DEF.150/3 - a DEFAULT_VALUE text of S ... 8S characters is one display string for all 400 decodes."""
    def check(kib, c, result):
        text = "d" * (kib * 1024)
        assert all(isinstance(r, Decoded) and r.stored == 250 and r.value is None and r.text == text for r in result)
        assert _same_object(r.text for r in result)

    _gp2_run(tmp_path, "vtab_default", "150/3 default text", _decode_all, check, image_byte=250)


@pytest.mark.serial_timing
def test_r_a2l_def_150_4_shared_range_table_size_costs_nothing_per_element(tmp_path):
    """R-A2L-DEF.150/4 - decoding 400 elements that name one COMPU_VTAB_RANGE of S ... 8S ranges: no scan per element."""
    def check(kib, c, result):
        assert result == [Decoded(250, None, "250 (no text)")] * N_OBJECTS

    _gp2_run(tmp_path, "range", "150/4 COMPU_VTAB_RANGE decode", _decode_all, check, image_byte=250)


@pytest.mark.serial_timing
def test_r_a2l_def_150_5_long_matched_range_text_is_referenced_not_copied(tmp_path):
    """R-A2L-DEF.150/5 - a matched range text of S ... 8S characters is one string object for all 400 decodes."""
    def check(kib, c, result):
        text = "t" * (kib * 1024)
        assert all(isinstance(r, Decoded) and r.stored == 0 and r.value == text and r.text == text for r in result)
        assert _same_object(r.value for r in result) and _same_object(r.text for r in result)

    _gp2_run(tmp_path, "range_text", "150/5 matched range text", _decode_all, check, image_byte=0)


def _interp_expected_250(kib: int) -> float:
    """The TAB_INTP value at 250 on the table of ``_tab_lines``: the last interval, the arithmetic of the frozen
    lookup (``ratio = (v - lx) / (rx - lx)``; ``ly + ratio * (ry - ly)``) written out here."""
    _lines, _k, entries = _tab_lines(kib * 1024)
    (lx, ly), (rx, ry) = entries[-2], entries[-1]
    return ly + ((250.0 - lx) / (rx - lx)) * (ry - ly)


@pytest.mark.serial_timing
def test_r_a2l_def_150_7_shared_tab_intp_size_costs_nothing_per_element(tmp_path):
    """R-A2L-DEF.150/7 - TAB_INTP over a COMPU_TAB of S ... 8S: one O(log n) lookup per decode, the last interval's value."""
    def check(kib, c, result):
        expected = _interp_expected_250(kib)
        for r in result:
            assert isinstance(r, Decoded) and r.stored == 250
            assert r.value == pytest.approx(expected, rel=1e-12, abs=1e-9)

    _gp2_run(tmp_path, "tab_intp", "150/7 TAB_INTP decode", _decode_all, check, image_byte=250)


@pytest.mark.serial_timing
def test_r_a2l_def_150_8_shared_tab_nointp_size_costs_nothing_per_element(tmp_path):
    """R-A2L-DEF.150/8 - TAB_NOINTP over a COMPU_TAB of S ... 8S: one O(log n) lookup per decode; 250 is nearest to the entry 300 999."""
    def check(kib, c, result):
        for r in result:
            assert isinstance(r, Decoded) and r.stored == 250 and r.value == 999.0

    _gp2_run(tmp_path, "tab_nointp", "150/8 TAB_NOINTP decode", _decode_all, check, image_byte=250)


@pytest.mark.serial_timing
def test_r_a2l_def_150_10_a_run_of_repeated_x_below_the_stored_value_costs_nothing_per_element(tmp_path):
    """R-A2L-DEF.150/10 (CR-1 = E5S-02) - TAB_NOINTP over a COMPU_TAB that is one run of equal x (0) then 1000:
    250 is nearer the run, whose FIRST entry (y 0) is taken, as the frozen lookup takes it; one bisect, not a walk back."""
    def check(kib, c, result):
        table = c.a2l["compu_tabs_by_name"]["CT"]
        assert len(table["entries"]) > 1000 and sum(1 for x, _y in table["entries"] if x == 0) == len(table["entries"]) - 1
        frozen_value, _status, _msg = _frozen_apply(c.a2l["compu_methods_by_name"]["CM_N"], 250, c.a2l)
        assert frozen_value == 0.0                              # the oracle itself: the first entry of the run
        for r in result:
            assert isinstance(r, Decoded) and r.stored == 250
            assert r.value == frozen_value == 0.0 and r.text == "0.000", r

    _gp2_run(tmp_path, "tab_run", "150/10 TAB_NOINTP run of repeated x decode", _decode_all, check, image_byte=250)


def _frozen_apply(method: dict, raw: int, a2l: dict):
    """The frozen conversion (``s19_app.tui.a2l._apply_compu_method``) of ``raw`` by ``method``: (value, status, message)."""
    from s19_app.tui.a2l import _apply_compu_method
    return _apply_compu_method(raw, method, a2l["compu_tabs_by_name"])
