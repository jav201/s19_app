"""Batch-103 Inc 3a (G-T1) - the full serial_timing arm of R-A2L-DEF.136/arr-2,
.136/arr-3, .148/1 ... /19 and R-A2L-DEF.150/arr-1, /arr-2, /arr-3, /arr-4,
/arr-5, /arr-6, /arr-7, /arr-8, /arr-10 (arr-9 and arr-11 are functional-only
and live in ``test_b103_a2l_definition_arrays_coverage.py``).

Run apart and serially::

    ~/miniconda3/envs/s19ci/bin/python -I -B -c "import sys; \\
    sys.path.insert(0, '/tmp/b103-e4-3a-coverage/tree'); import pytest; \\
    sys.exit(pytest.main(['-p','no:cacheprovider','-m','serial_timing', \\
    'tests/test_b103_a2l_definition_arrays_scale.py']))" </dev/null

Do NOT run this while other jobs are active (E3S3-24: the measure is the least
of >= 15 runs, interleaved S / 2S / 8S run by run, each run one fresh walk,
garbage collection off).  The exact-value side of every case lives in
``test_b103_a2l_definition_arrays_coverage.py`` and runs in the ordinary lane.

Expected values are the requirement's literal texts and the frozen
``s19_app.tui.a2l`` oracle, never a value the artifact under test produced
first.
"""

from __future__ import annotations

import gc
import signal
import time
from pathlib import Path
from typing import Callable, Optional

import pytest

from s19_app.tui import a2l_definition as a2ldef
from s19_app.tui import a2l as a2l
from tests.support.b103_a2l_arrays import img
from tests.support.timing import report_margin, timing_bound
from tests.test_b103_a2l_definition_arrays_coverage import (  # noqa: F401 - shared builders
    IDENT,
    _axis,
    _axis_pts,
    _cm,
    _ctab,
    _curve,
    _parse,
    _rl,
    _valblk,
    _value,
    _vrange,
    _vtab,
    _ECHO,
    _ELLIPSIS,
)

Definition = a2ldef.Definition
DecodedValues = getattr(a2ldef, "DecodedValues", ())

S_KIB = 256
SIZES_KIB = (S_KIB, 2 * S_KIB, 8 * S_KIB)
N_OBJECTS = 400
ABS_BOUND_S = 0.5          # 400 names at 256 KiB, the least of >= 15 runs
RATIO_BOUND_2S = 1.5       # per-object part at 2S / at S
RATIO_BOUND_8S = 2.0       # per-object part at 8S / at S
LEAST_OF = 15              # the row's "least of >= 15 runs"
CALL_TIMEOUT_S = 60.0      # R-A2L-DEF.148 "0 timeouts (60 s)"
MESSAGE_BOUND = 1024       # E3S3-32: every message at most 1,024 characters


class _Timeout(Exception):
    pass


def _timed(fn, clock=time.perf_counter):
    """Seconds ``fn()`` takes and its result; a call past 60 s fails the test.
    Garbage collection is collected then disabled around the timed call, as
    ``evidence-e3/sec-r6-scale.py`` does."""
    def _raise(*_):
        raise _Timeout()

    if not hasattr(signal, "SIGALRM"):  # non-POSIX: no cap
        gc.collect()
        gc.disable()
        try:
            started = clock()
            result = fn()
            return clock() - started, result
        finally:
            gc.enable()
    old = signal.signal(signal.SIGALRM, _raise)
    signal.setitimer(signal.ITIMER_REAL, CALL_TIMEOUT_S)
    gc.collect()
    gc.disable()
    try:
        started = clock()
        result = fn()
        return clock() - started, result
    except _Timeout:
        pytest.fail(f"a call timed out at {CALL_TIMEOUT_S:.0f} s (shared content is read per object)")
    finally:
        gc.enable()
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def test_timed_runs_function_between_clock_reads():
    events = []

    def clock():
        events.append("clock")
        return float(events.count("clock") - 1)

    def work():
        events.append("work")
        return "done"

    seconds, result = _timed(work, clock)
    assert events == ["clock", "work", "clock"]
    assert seconds == 1.0 and result == "done"


def _steady_describe(names, a2l_data):
    """E5-3 / E3S3-34: process CPU time of the 399 names after the first,
    described for the first time in ONE fresh walk (the clock is read when the
    walk asks for the second name and when the names run out)."""
    marks: list = []

    def gen():
        yield names[0]
        marks.append(time.process_time())
        yield from names[1:]
        marks.append(time.process_time())

    result = a2ldef.describe_definitions(gen(), a2l_data)
    assert len(marks) == 2 and list(result) == names
    return marks[1] - marks[0], result


def _steady_decode(defs, names, a2l_data, image_of):
    """The 399 decodes after the first, timed inside one run: describe already
    happened (one fresh walk); the first decode warms the table form, then the
    399 remaining decodes are bracketed by two clock reads."""
    image_of(names[0])
    _ = a2ldef.decode_values(defs[names[0]], a2l_data, image_of(names[0]))
    t0 = time.process_time()
    for name in names[1:]:
        a2ldef.decode_values(defs[name], a2l_data, image_of(name))
    t1 = time.process_time()
    return t1 - t0


def _measure(tmp_path: Path, case_label: str, build: Callable[[Path, int], tuple[dict, list]],
             check: Callable[[int, dict], None],
             image_of: Optional[Callable[[str], dict]] = None) -> None:
    """The E3S3-24 measure for one case: absolute bound at S (least of 15 runs)
    then the interleaved least-of-15 per-object ratio at 2S and 8S."""
    loaded = {kib: build(tmp_path, kib) for kib in SIZES_KIB}
    names = loaded[S_KIB][1]

    # Absolute: 400 names at S, process CPU time (E3S3-24), least of 15 runs.
    runs = []
    for _ in range(LEAST_OF):
        seconds, _ = _timed(lambda: a2ldef.describe_definitions(names, loaded[S_KIB][0]), time.process_time)
        runs.append(seconds)
    assert min(runs) <= report_margin(f"R-A2L-DEF.148 {case_label} 400 names at 256 KiB",
                                      min(runs), timing_bound(ABS_BOUND_S)), runs
    check(S_KIB, loaded[S_KIB][0])

    part = {kib: float("inf") for kib in SIZES_KIB}
    results = {}
    for _ in range(LEAST_OF):
        for kib in SIZES_KIB:  # interleaved: S, 2S, 8S in turn within every round
            a2l_data, nms = loaded[kib]
            if image_of is None:
                t_outer, (interval, results[kib]) = _timed(lambda: _steady_describe(nms, a2l_data), time.process_time)
            else:
                defs = a2ldef.describe_definitions(nms, a2l_data)
                t_outer, interval = _timed(lambda: _steady_decode(defs, nms, a2l_data, image_of), time.process_time)
                results[kib] = defs
            part[kib] = min(part[kib], max(interval, 0.0))
    ratio_2s = part[2 * S_KIB] / part[S_KIB]
    ratio_8s = part[8 * S_KIB] / part[S_KIB]
    assert ratio_2s <= report_margin(f"R-A2L-DEF.148 {case_label} per-object part 2S/S",
                                     ratio_2s, timing_bound(RATIO_BOUND_2S)), part
    assert ratio_8s <= report_margin(f"R-A2L-DEF.148 {case_label} per-object part 8S/S",
                                     ratio_8s, timing_bound(RATIO_BOUND_8S)), part
    for kib in SIZES_KIB:
        check(kib, loaded[kib][0])


def _names(prefix: str) -> list[str]:
    return [f"{prefix}{i:05d}" for i in range(N_OBJECTS)]


def _messages_bounded(a2l_data: dict, names: list) -> None:
    defs = a2ldef.describe_definitions(names, a2l_data)
    for d in defs.values():
        if d.refusal is not None:
            assert len(d.refusal.message) <= MESSAGE_BOUND, len(d.refusal.message)
        for axis in d.axes:
            if axis.points.refusal is not None:
                assert len(axis.points.refusal.message) <= MESSAGE_BOUND


# ---------------------------------------------------------------------------
# .148 fixture builders (each returns (a2l_data, names) at ``kib`` KiB of fill)
# ---------------------------------------------------------------------------

def _b148_1(tmp_path: Path, kib: int):
    n = kib * 1024 // 17
    a2l_data = _parse(tmp_path,
                      _rl("RL", "FNC_VALUES 1 UBYTE ROW_DIR DIRECT", *("ALIGNMENT_BYTE 1",) * n),
                      *[_valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL", "NO_COMPU_METHOD", "0", "255", "NUMBER 4")
                        for i in range(N_OBJECTS)])
    return a2l_data, _names("V")


def _b148_2(tmp_path: Path, kib: int, kind: str):
    prefix = "V" if kind == "VAL_BLK" else "S"
    a2l_data = _parse(tmp_path,
                      _rl("RL_LONG", "FNC_VALUES 1 " + "X " * (kib * 1024 // 2) + "UBYTE ROW_DIR DIRECT"),
                      *[_valblk(f"{prefix}{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_LONG", "NO_COMPU_METHOD", "0", "255", "NUMBER 4")
                        for i in range(N_OBJECTS)] if kind == "VAL_BLK" else
                      [_value(f"{prefix}{i:05d}", f"0x{0x1000 + i:X}", "RL_LONG", "NO_COMPU_METHOD", "0", "255")
                       for i in range(N_OBJECTS)])
    return a2l_data, _names(prefix)


def _b148_4(tmp_path: Path, kib: int, com: bool):
    mc = ("ALIGNMENT_BYTE 1",) * (kib * 1024 // 17)
    if not com:
        body: list = []
        for i in range(N_OBJECTS):
            body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", "NO_COMPU_METHOD", "0", "255", "NUMBER 4")
        return _parse(tmp_path, body, mod_common=mc), _names("V")
    axo = _axis_pts("AXO", "0x100", "RL_AXO", "4")
    body = IDENT + _rl("RL_AXO", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT") + axo
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                       _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    return _parse(tmp_path, body, mod_common=mc), _names("C")


def _b148_6(tmp_path: Path, kib: int):
    axo = _axis_pts("AXO", "0x100", "RL_AXO", "4", "CM_IDENT", "0", "255",
                    *("DEPOSIT ABSOLUTE",) * (kib * 1024 // 17))
    body = _rl("RL_AXO", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT") + axo
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                       _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    return _parse(tmp_path, IDENT + body), _names("C")


def _b148_7(tmp_path: Path, kib: int):
    body = _cm("CM_L", 'LINEAR "%.3" ""', "COEFFS_LINEAR 0.5 0", *("DEPOSIT ABSOLUTE",) * (kib * 1024 // 17))
    body += _rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UBYTE ROW_DIR DIRECT")
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_C",
                       _axis("STD_AXIS", "CM_L", "4", "0", "255"), conv="CM_L")
    return _parse(tmp_path, body), _names("C")


def _b148_8(tmp_path: Path, kib: int, rang: bool):
    n = kib * 1024 // (18 if rang else 9)
    conv = "CM_R" if rang else "CM_V"
    body = _cm(conv, 'TAB_VERB "%.0" ""', "COMPU_TAB_REF " + ("VR" if rang else "VT"))
    if rang:
        body += _vrange("VR", str(n), *[f'{1000 + 2 * k} {1000 + 2 * k + 1} "r{k}"' for k in range(n)])
    else:
        body += _vtab("VT", str(n), *[f'{1000 + k} "v{k}"' for k in range(n)])
    body += _rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UBYTE ROW_DIR DIRECT")
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_C",
                       _axis("STD_AXIS", conv, "4", "0", "255"), conv=conv)
    return _parse(tmp_path, body), _names("C")


def _b148_10(tmp_path: Path, kib: int):
    word = "P" * (kib * 1024)
    body = _rl("RL", "FNC_VALUES 1 UBYTE ROW_DIR DIRECT", word)
    for i in range(N_OBJECTS):
        body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL", "NO_COMPU_METHOD", "0", "255", "NUMBER 1")
    return _parse(tmp_path, body), _names("V")


def _b148_11(tmp_path: Path, kib: int):
    word = "9" * (kib * 1024)
    body = [_valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", "NO_COMPU_METHOD", "0", "255", "NUMBER 4")
            for i in range(N_OBJECTS)]
    return _parse(tmp_path, *body, mod_common=(f"ALIGNMENT_BYTE {word}",)), _names("V")


def _b148_12(tmp_path: Path, kib: int):
    fmt = '"%' + "9" * (kib * 1024) + '.2"'
    body = _cm("CM_F", f'LINEAR {fmt} ""', "COEFFS_LINEAR 0.5 0")
    body += _rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UBYTE ROW_DIR DIRECT")
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_C",
                       _axis("STD_AXIS", "CM_F", "4", "0", "255"), conv="CM_F")
    return _parse(tmp_path, body), _names("C")


def _b148_13(tmp_path: Path, kib: int):
    word = "Z" * (kib * 1024)
    body = _cm("CM_T", f'{word} "%.3" ""')
    body += _rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UBYTE ROW_DIR DIRECT")
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_C",
                       _axis("STD_AXIS", "CM_T", "4", "0", "255"), conv="CM_T")
    return _parse(tmp_path, body), _names("C")


def _b148_14(tmp_path: Path, kib: int):
    word = "G" * (kib * 1024)
    body = _cm("CM_V", 'TAB_VERB "%.3" ""', f"COMPU_TAB_REF {word}")
    body += _rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UBYTE ROW_DIR DIRECT")
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_C",
                       _axis("STD_AXIS", "CM_V", "4", "0", "255"), conv="CM_V")
    return _parse(tmp_path, body), _names("C")


def _b148_15(tmp_path: Path, kib: int):
    word = "P" * (kib * 1024)
    axo = _axis_pts("AXO", "0x100", "RL_AXO", "4")
    body = IDENT + _rl("RL_AXO", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT", word) + axo
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                       _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    return _parse(tmp_path, body), _names("C")


def _b148_16(tmp_path: Path, kib: int, align: bool):
    word = "L" * (kib * 1024)
    axo = _axis_pts("AXO", "0x100", word, "4")
    lines = ("NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT")
    body = IDENT + _rl(word, *lines, *((("P",) if not align else ()))) + axo
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                       _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    return _parse(tmp_path, body, mod_common=(("ALIGNMENT_BYTE 2",) if align else ())), _names("C")


def _b148_18(tmp_path: Path, kib: int, values: bool):
    word = "E" * (kib * 1024)
    body = _cm("CM_E", 'TAB_VERB "%.3" ""', f"COMPU_TAB_REF {word}") + _vtab(word, "0")
    if values:
        for i in range(N_OBJECTS):
            body += _value(f"S{i:05d}", f"0x{0x1000 + i:X}", "RL_U8", "CM_E", "0", "255")
        return _parse(tmp_path, body), _names("S")
    body += _rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UBYTE ROW_DIR DIRECT")
    for i in range(N_OBJECTS):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_C",
                       _axis("STD_AXIS", "CM_E", "4", "0", "255"), conv="CM_E")
    return _parse(tmp_path, body), _names("C")


def _b148_19(tmp_path: Path, kib: int, values: bool):
    n = max(4, kib * 1024 // 22)
    xs = [f"{200.0 * j / (n - 1):.6f}" for j in range(n - 1)]
    pairs = [f" {x} {j}" for j, x in enumerate(xs)] + [" 300 999"]
    body: list = []
    for i in range(N_OBJECTS):
        body += _cm(f"CM{i:05d}", f'{"TAB_INTP" if values else "TAB_NOINTP"} "%.3" ""', "COMPU_TAB_REF CT")
    body += _ctab("CT", "TAB_INTP" if values else "TAB_NOINTP", *pairs)
    if values:
        for i in range(N_OBJECTS):
            body += _value(f"S{i:05d}", f"0x{0x1000 + i:X}", "RL_U8", f"CM{i:05d}", "0", "255")
        return _parse(tmp_path, body), _names("S")
    for i in range(N_OBJECTS):
        body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", f"CM{i:05d}", "0", "255", "NUMBER 1")
    return _parse(tmp_path, body), _names("V")


# ---------------------------------------------------------------------------
# .148 — the scaling row (full measure)
# ---------------------------------------------------------------------------

@pytest.mark.serial_timing
def test_r_a2l_def_148_1_shared_layout_alignment(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("V"), a2l_data)
        for d in defs.values():
            assert d.kind == "array" and d.shape == (4,) and d.refusal is None
    _measure(tmp_path, "148/1 layout ALIGNMENT", _b148_1, check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_2_shared_layout_first_line_val_blk(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("V"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-LAYOUT-PART",
                                              f"{name}: the record layout RL_LONG holds X, which the system cannot read")
    _measure(tmp_path, "148/2 layout first line VAL_BLK", lambda p, k: _b148_2(p, k, "VAL_BLK"), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_3_shared_layout_first_line_value(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("S"), a2l_data)
        for d in defs.values():
            assert d.kind == "number" and d.datatype == "UBYTE" and d.refusal is None
    _measure(tmp_path, "148/3 layout first line VALUE", lambda p, k: _b148_2(p, k, "VALUE"), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_4_mod_common_alignment_val_blk(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("V"), a2l_data)
        for d in defs.values():
            assert d.kind == "array" and d.shape == (4,) and d.refusal is None
    _measure(tmp_path, "148/4 MOD_COMMON alignment", lambda p, k: _b148_4(p, k, False), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_5_com_path_under_mod_common(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for d in defs.values():
            assert d.kind == "curve" and d.shape == (4,) and d.refusal is None
    _measure(tmp_path, "148/5 COM under MOD_COMMON", lambda p, k: _b148_4(p, k, True), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_6_shared_axis_object(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for d in defs.values():
            assert d.kind == "curve" and d.shape == (4,) and d.refusal is None
    _measure(tmp_path, "148/6 shared axis object", _b148_6, check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_7_shared_method(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for d in defs.values():
            assert d.kind == "curve" and d.shape == (4,) and d.refusal is None
    _measure(tmp_path, "148/7 shared COMPU_METHOD", _b148_7, check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_8_shared_enum_table(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        entries = [d.axes[0].points.enum_entries for d in defs.values()]
        assert all(entries) and len({id(e) for e in entries}) == 1
    _measure(tmp_path, "148/8 shared COMPU_VTAB", lambda p, k: _b148_8(p, k, False), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_9_shared_range_table(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        entries = [d.axes[0].points.enum_entries for d in defs.values()]
        assert all(entries) and len({id(e) for e in entries}) == 1
    _measure(tmp_path, "148/9 shared COMPU_VTAB_RANGE", lambda p, k: _b148_8(p, k, True), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_10_long_part_word_layout(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("V"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-LAYOUT-PART",
                                              f"{name}: the record layout RL holds {'P' * _ECHO}{_ELLIPSIS}, "
                                              "which the system cannot read")
            assert len(d.refusal.message) <= MESSAGE_BOUND
    _measure(tmp_path, "148/10 long part word layout", _b148_10, check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_11_long_alignment_word_mod_common(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("V"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-ALIGNMENT",
                                              f"{name}: the MOD_COMMON line ALIGNMENT_BYTE {'9' * _ECHO}{_ELLIPSIS} "
                                              "cannot be read")
            assert len(d.refusal.message) <= MESSAGE_BOUND
    _measure(tmp_path, "148/11 long ALIGNMENT word MOD_COMMON", _b148_11, check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_12_long_format_word(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for d in defs.values():
            assert d.decimals == 2 and d.refusal is None
            assert d.axes[0].points.decimals == 2
    _measure(tmp_path, "148/12 long FORMAT word", _b148_12, check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_13_long_type_word(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-CONVERSION",
                                              f"{name}: the conversion type {'Z' * _ECHO}{_ELLIPSIS} of CM_T is not supported")
            assert len(d.refusal.message) <= MESSAGE_BOUND
    _measure(tmp_path, "148/13 long conversion type word", _b148_13, check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_14_long_tabref_word(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-TABLE",
                                              f"{name}: the table {'G' * _ECHO}{_ELLIPSIS} of CM_V is not declared in the A2L")
            assert len(d.refusal.message) <= MESSAGE_BOUND
    _measure(tmp_path, "148/14 long COMPU_TAB_REF word", _b148_14, check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_15_long_part_word_axis_layout(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-LAYOUT-PART",
                                              f"{name}.X: the record layout RL_AXO holds {'P' * _ECHO}{_ELLIPSIS}, "
                                              "which the system cannot read")
            assert len(d.refusal.message) <= MESSAGE_BOUND
    _measure(tmp_path, "148/15 long part word axis layout", _b148_15, check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_16_long_layout_name_part(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-LAYOUT-PART",
                                              f"{name}.X: the record layout {'L' * _ECHO}{_ELLIPSIS} holds P, "
                                              "which the system cannot read")
            assert len(d.refusal.message) <= MESSAGE_BOUND
    _measure(tmp_path, "148/16 long layout name part", lambda p, k: _b148_16(p, k, False), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_17_long_layout_name_alignment(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-ALIGNMENT",
                                              f"{name}: AXIS_PTS_X of the record layout {'L' * _ECHO}{_ELLIPSIS} "
                                              "lies at offset 1, or at 2 under the MOD_COMMON alignment")
            assert len(d.refusal.message) <= MESSAGE_BOUND
    _measure(tmp_path, "148/17 long layout name alignment", lambda p, k: _b148_16(p, k, True), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_18_long_tabref_empty_curves(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-TABLE-EMPTY",
                                              f"{name}: the table {'E' * _ECHO}{_ELLIPSIS} has no entries")
            assert len(d.refusal.message) <= MESSAGE_BOUND
    _measure(tmp_path, "148/18 long COMPU_TAB_REF empty (curves)", lambda p, k: _b148_18(p, k, False), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_18_long_tabref_empty_values(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("S"), a2l_data)
        for name, d in defs.items():
            assert d.refusal == a2ldef.Refusal("A2L-DEF-TABLE-EMPTY",
                                              f"{name}: the table {'E' * _ECHO}{_ELLIPSIS} has no entries")
            assert len(d.refusal.message) <= MESSAGE_BOUND
    _measure(tmp_path, "148/18 long COMPU_TAB_REF empty (VALUEs)", lambda p, k: _b148_18(p, k, True), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_19_tab_through_own_method_val_blks(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("V"), a2l_data)
        forms = [d._table_form for d in defs.values()]
        assert all(f is not None for f in forms) and len({id(f) for f in forms}) == 1
        for d in defs.values():
            assert d.kind == "array" and d.shape == (1,) and d.refusal is None
    _measure(tmp_path, "148/19 COMPU_TAB through own methods (VAL_BLKs)", lambda p, k: _b148_19(p, k, False), check)


@pytest.mark.serial_timing
def test_r_a2l_def_148_19_tab_through_own_method_values(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("S"), a2l_data)
        forms = [d._table_form for d in defs.values()]
        assert all(f is not None for f in forms) and len({id(f) for f in forms}) == 1
        for d in defs.values():
            assert d.kind == "number" and d.refusal is None
    _measure(tmp_path, "148/19 COMPU_TAB through own methods (VALUEs)", lambda p, k: _b148_19(p, k, True), check)


# ---------------------------------------------------------------------------
# R-A2L-DEF.150 — decode per element (full measure)
# ---------------------------------------------------------------------------

def _decode_image_curve(name: str) -> dict:
    idx = int(name[-5:])
    return {0x1000 + 16 * idx + i: 250 for i in range(8)}


def _decode_image_valblk_byte(byte: int) -> Callable[[str], dict]:
    def image_of(name: str) -> dict:
        idx = int(name[-5:])
        return {0x1000 + 16 * idx + i: byte for i in range(4)}
    return image_of


_decode_image_valblk = _decode_image_valblk_byte(250)


@pytest.mark.serial_timing
def test_r_a2l_def_150_arr_1_shared_enum_table_decode(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        res = a2ldef.decode_values(defs["C00000"], a2l_data, {0x1000 + i: 250 for i in range(8)})
        assert isinstance(res, DecodedValues)
        for point in res.axes[0].points:
            assert (point.stored, point.text) == (250, "250 (no text)")
        for value in res.values:
            assert (value.stored, value.text) == (250, "250 (no text)")
    _measure(tmp_path, "150/arr-1 enum table decode", lambda p, k: _b148_8(p, k, False), check, _decode_image_curve)


def _b150_arr2(tmp_path: Path, kib: int):
    n = kib * 1024 // 9
    body = _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT") + \
        _vtab("VT", str(n), *[f'{1000 + k} "v{k}"' for k in range(n)])
    for i in range(N_OBJECTS):
        body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", "CM_V", "0", "255", "NUMBER 4")
    return _parse(tmp_path, body), _names("V")


@pytest.mark.serial_timing
def test_r_a2l_def_150_arr_2_enum_table_decode_val_blk(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("V"), a2l_data)
        res = a2ldef.decode_values(defs["V00000"], a2l_data, img(0x1000, bytes([250]) * 4))
        for value in res.values:
            assert (value.stored, value.text) == (250, "250 (no text)")
    _measure(tmp_path, "150/arr-2 enum table decode VAL_BLK", _b150_arr2, check, _decode_image_valblk)


def _b150_arr3(tmp_path: Path, kib: int):
    text = "t" * (kib * 1024)
    body = _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT") + \
        _vtab("VT", "1", f'0 "{text}"')
    for i in range(N_OBJECTS):
        body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", "CM_V", "0", "255", "NUMBER 4")
    return _parse(tmp_path, body), _names("V")


def _b150_arr4(tmp_path: Path, kib: int):
    text = "d" * (kib * 1024)
    body = _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT") + \
        _vtab("VT", "1", '1000 "a"', default=text)
    for i in range(N_OBJECTS):
        body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", "CM_V", "0", "255", "NUMBER 4")
    return _parse(tmp_path, body), _names("V")


def _check_text_shared(char: str, byte: int):
    def check(kib, a2l_data):
        text = char * (kib * 1024)
        defs = a2ldef.describe_definitions(_names("V"), a2l_data)
        texts = []
        for i in range(N_OBJECTS):
            res = a2ldef.decode_values(defs[f"V{i:05d}"], a2l_data,
                                       {0x1000 + 16 * i + j: byte for j in range(4)})
            texts += [v.text for v in res.values]
        assert all(t == text for t in texts), "an element text is not the shared entry text"
        assert len({id(t) for t in texts}) == 1, "the shared text is copied per element, not referenced"
    return check


@pytest.mark.serial_timing
def test_r_a2l_def_150_arr_3_long_matched_entry_text_referenced(tmp_path):
    _measure(tmp_path, "150/arr-3 long matched entry text referenced", _b150_arr3,
             _check_text_shared("t", 0), _decode_image_valblk_byte(0))


@pytest.mark.serial_timing
def test_r_a2l_def_150_arr_4_long_default_text_referenced(tmp_path):
    _measure(tmp_path, "150/arr-4 long default text referenced", _b150_arr4,
             _check_text_shared("d", 250), _decode_image_valblk)


@pytest.mark.serial_timing
def test_r_a2l_def_150_arr_5_range_table_decode(tmp_path):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("C"), a2l_data)
        res = a2ldef.decode_values(defs["C00000"], a2l_data, {0x1000 + i: 250 for i in range(8)})
        for point in res.axes[0].points:
            assert (point.stored, point.text) == (250, "250 (no text)")
        for value in res.values:
            assert (value.stored, value.text) == (250, "250 (no text)")
    _measure(tmp_path, "150/arr-5 range table decode", lambda p, k: _b148_8(p, k, True), check, _decode_image_curve)


def _b150_arr6(tmp_path: Path, kib: int):
    text = "t" * (kib * 1024)
    body = _cm("CM_R", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VR") + \
        _vrange("VR", "1", f'0 255 "{text}"')
    for i in range(N_OBJECTS):
        body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", "CM_R", "0", "255", "NUMBER 4")
    return _parse(tmp_path, body), _names("V")


@pytest.mark.serial_timing
def test_r_a2l_def_150_arr_6_long_matched_range_text_referenced(tmp_path):
    _measure(tmp_path, "150/arr-6 long matched range text referenced", _b150_arr6,
             _check_text_shared("t", 0), _decode_image_valblk_byte(0))


def _b150_tab(tmp_path: Path, kib: int, interp: bool):
    n = max(4, kib * 1024 // 22)
    xs = [f"{200.0 * j / (n - 1):.6f}" for j in range(n - 1)]
    pairs = [f" {x} {j}" for j, x in enumerate(xs)] + [" 300 999"]
    body = _cm("CM_I", f'{"TAB_INTP" if interp else "TAB_NOINTP"} "%.3" ""', "COMPU_TAB_REF CT")
    body += _ctab("CT", "TAB_INTP" if interp else "TAB_NOINTP", *pairs)
    for i in range(N_OBJECTS):
        body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", "CM_I", "0", "255", "NUMBER 4")
    return _parse(tmp_path, body), _names("V")


def _check_tab_value(interp: bool):
    def check(kib, a2l_data):
        defs = a2ldef.describe_definitions(_names("V"), a2l_data)
        method = a2l_data["compu_methods_by_name"]["CM_I"]
        tables = a2l_data["compu_tabs_by_name"]
        expected, _, _ = a2l._apply_compu_method(250, method, tables, (0.0, 255.0))
        res = a2ldef.decode_values(defs["V00000"], a2l_data, img(0x1000, bytes([250]) * 4))
        for value in res.values:
            assert value.stored == 250
            if interp:
                assert value.value == pytest.approx(expected, rel=1e-12, abs=1e-9)
            else:
                assert value.value == expected
    return check


@pytest.mark.serial_timing
def test_r_a2l_def_150_arr_7_tab_intp_decode(tmp_path):
    _measure(tmp_path, "150/arr-7 TAB_INTP decode", lambda p, k: _b150_tab(p, k, True), _check_tab_value(True), _decode_image_valblk)


@pytest.mark.serial_timing
def test_r_a2l_def_150_arr_8_tab_nointp_decode(tmp_path):
    _measure(tmp_path, "150/arr-8 TAB_NOINTP decode", lambda p, k: _b150_tab(p, k, False), _check_tab_value(False), _decode_image_valblk)


@pytest.mark.serial_timing
@pytest.mark.parametrize("mode", ["enum", "number"])
def test_r_a2l_def_150_arr_10_element_decode_does_not_grow_with_name(tmp_path, mode):
    """EN-1 (``enum``: TAB_INTP with an undeclared table, one refusal per element)
    and EN-2 (``number``: NO_COMPU_METHOD): the decode time per element does not
    grow with the object's name (S / 2S / 8S, interleaved, least of 15)."""
    def build(p, kib):
        name = "V" + "N" * (kib * 1024)
        if mode == "enum":
            body = _cm("CM_I", 'TAB_INTP "%.3" ""', "COMPU_TAB_REF NOT_DECLARED") + \
                _valblk(name, "0x1000", "RL_U8", "CM_I", "0", "255", "NUMBER 64")
        else:
            body = _valblk(name, "0x1000", "RL_U8", "NO_COMPU_METHOD", "0", "255", "NUMBER 64")
        return _parse(p, body), [name]

    loaded = {kib: build(tmp_path, kib) for kib in SIZES_KIB}
    part = {kib: float("inf") for kib in SIZES_KIB}
    for _ in range(LEAST_OF):
        for kib in SIZES_KIB:  # interleaved
            a2l_data, names = loaded[kib]
            defs = a2ldef.describe_definitions(names, a2l_data)
            image = img(0x1000, bytes([250]) * 64)

            def work():
                a2ldef.decode_values(defs[names[0]], a2l_data, image)

            seconds, res = _timed(work, time.process_time)
            part[kib] = min(part[kib], seconds / 64.0)
    ratio_2s = part[2 * S_KIB] / part[S_KIB]
    ratio_8s = part[8 * S_KIB] / part[S_KIB]
    assert ratio_2s <= report_margin("R-A2L-DEF.150/arr-10 per-element 2S/S", ratio_2s,
                                     timing_bound(RATIO_BOUND_2S)), part
    assert ratio_8s <= report_margin("R-A2L-DEF.150/arr-10 per-element 8S/S", ratio_8s,
                                     timing_bound(RATIO_BOUND_8S)), part
    # Exact results (the requirement's texts, not product-derived).
    a2l_data, names = loaded[S_KIB]
    defs = a2ldef.describe_definitions(names, a2l_data)
    res = a2ldef.decode_values(defs[names[0]], a2l_data, img(0x1000, bytes([250]) * 64))
    if mode == "enum":
        echo = names[0][:256] + _ELLIPSIS
        for i, element in enumerate(res.values):
            assert element.message == f"{echo}[{i}]: lookup table missing"
            assert len(element.message) <= MESSAGE_BOUND
    else:
        assert all(isinstance(v, a2ldef.Decoded) and v.stored == 250 for v in res.values)


# ---------------------------------------------------------------------------
# R-A2L-DEF.136 — read-once per walk (full budget)
# ---------------------------------------------------------------------------

@pytest.mark.serial_timing
def test_r_a2l_def_136_arr_2_shared_layout_and_mod_common(tmp_path):
    deposit = "      " + "DEPOSIT ABSOLUTE\n      " * (S_KIB * 1024 // 17)
    body = _rl("RL_BIG", "FNC_VALUES 1 UBYTE ROW_DIR DIRECT", "/*" + "c" * (S_KIB * 1024 - 4) + "*/")
    for i in range(N_OBJECTS):
        body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_BIG", "NO_COMPU_METHOD", "0", "255", "NUMBER 4")
    a2l_data = _parse(tmp_path, body, mod_common=(deposit.rstrip(),))
    names = _names("V")
    runs = []
    for _ in range(3):
        seconds, defs = _timed(lambda: a2ldef.describe_definitions(names, a2l_data))
        runs.append(seconds)
    import statistics
    assert statistics.median(runs) <= report_margin("R-A2L-DEF.136/arr-2 describe 400", statistics.median(runs),
                                                    timing_bound(2.0)), runs
    for d in defs.values():
        assert d.kind == "array" and d.shape == (4,) and d.element_count == 4 and d.byte_length == 4 and d.refusal is None


@pytest.mark.serial_timing
def test_r_a2l_def_136_arr_3_shared_axis_method_enum_range(tmp_path):
    cases = []
    axo = _axis_pts("AXO", "0x100", "RL_AXO", "4", "CM_IDENT", "0", "255", *("DEPOSIT ABSOLUTE",) * (S_KIB * 1024 // 17))
    a = IDENT + _rl("RL_AXO", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT") + axo
    for i in range(N_OBJECTS):
        a += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                    _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    cases.append(a)

    b = _cm("CM_L", 'LINEAR "%.3" ""', "COEFFS_LINEAR 0.5 0", "/*" + "c" * (S_KIB * 1024 - 4) + "*/")
    for i in range(N_OBJECTS):
        b += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                    _axis("STD_AXIS", "CM_L", "4", "0", "255"), conv="CM_L")
    cases.append(b)

    c = _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT", "/*" + "c" * (S_KIB * 1024 - 4) + "*/") + \
        _vtab("VT", "2", '0 "zero"', '1 "one"')
    for i in range(N_OBJECTS):
        c += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                    _axis("STD_AXIS", "CM_V", "4", "0", "255"), conv="CM_V")
    cases.append(c)

    d = _cm("CM_R", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VR", "/*" + "c" * (S_KIB * 1024 - 4) + "*/") + \
        _vrange("VR", "2", '0 0 "zero"', '1 255 "other"')
    for i in range(N_OBJECTS):
        d += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                    _axis("STD_AXIS", "CM_R", "4", "0", "255"), conv="CM_R")
    cases.append(d)

    import statistics
    for body in cases:
        a2l_data = _parse(tmp_path, body)
        names = _names("C")
        runs = []
        for _ in range(3):
            seconds, defs = _timed(lambda: a2ldef.describe_definitions(names, a2l_data))
            runs.append(seconds)
        assert statistics.median(runs) <= report_margin("R-A2L-DEF.136/arr-3 describe 400", statistics.median(runs),
                                                        timing_bound(2.0)), runs
        for d in defs.values():
            assert d.kind == "curve" and d.shape == (4,) and d.refusal is None
