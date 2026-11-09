"""Batch-103 Inc 3a (G-T1) — supplemental independent-tester coverage.

Exact-value (functional) side of the cases the first tester left unexecuted as
written: the read-once / immutability controls of R-A2L-DEF.136, the
definitions and per-word echo of R-A2L-DEF.148/2 … /19, the decode results of
R-A2L-DEF.150/arr-1 … /arr-11 (one-lookup decode included) and the echo caps of
R-A2L-DEF.151/arr-3 … /arr-5.  The timing arm of these rows lives in
``test_b103_a2l_definition_arrays_scale.py`` (``serial_timing``); this file
never reads a clock and never asserts a ratio, so it runs in the ordinary
functional lane.

Every expected value is the requirement's literal text, the file's own bytes,
hand arithmetic, or the frozen ``s19_app.tui.a2l`` oracle (``_apply_compu_method``
/ ``_table_lookup``) — never a value the artifact under test produced first.

Dependencies:
    - ``s19_app.tui.a2l_definition`` (under test), the app's A2L parser,
      the frozen ``s19_app.tui.a2l`` decode oracle
"""

from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import Iterable, Mapping, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

from s19_app.tui import a2l_definition as a2ldef  # noqa: E402
from s19_app.tui import a2l as a2l  # noqa: E402
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402
from tests.support.b103_a2l_arrays import img, is_refused, load  # noqa: E402

Definition = a2ldef.Definition
Decoded = a2ldef.Decoded
Refusal = a2ldef.Refusal
DecodedValues = getattr(a2ldef, "DecodedValues", ())

S = 256 * 1024  # the S size of the .148 / .150 scaling rows (256 KiB)
_ECHO = 256  # R-A2L-DEF.151: a file word is echoed as its first 256 chars + …
_ELLIPSIS = "\u2026"

# ---------------------------------------------------------------------------
# Raw INLINE3 builders (synthetic A2L text; no proprietary material).
# Each block helper returns a list of body lines, indented by the caller's
# ``_parse`` wrapper.
# ---------------------------------------------------------------------------

BASE_LAYOUTS = (
    ("RL_U8", "UBYTE"),
    ("RL_S8", "SBYTE"),
    ("RL_U16", "UWORD"),
    ("RL_S16", "SWORD"),
    ("RL_U32", "ULONG"),
    ("RL_S32", "SLONG"),
    ("RL_F16", "FLOAT16_IEEE"),
    ("RL_F32", "FLOAT32_IEEE"),
    ("RL_F64", "FLOAT64_IEEE"),
    ("RL_U64", "A_UINT64"),
    ("RL_S64", "A_INT64"),
)

_counter = [0]


@pytest.fixture(scope="module")
def v171() -> dict:
    return load("ASAP2_Demo_V171.a2l")


def _parse(tmp_path: Path, *blocks: Iterable[str], mod_common: Iterable[str] = (),
           byte_order: str = "MSB_FIRST", layouts: Iterable[tuple[str, str]] = BASE_LAYOUTS) -> dict:
    """Write and parse one INLINE3 file; each block is a list of body lines."""
    lines = ["ASAP2_VERSION 1 71", '/begin PROJECT P ""', '  /begin MODULE M ""',
             '    /begin MOD_COMMON ""', f"      BYTE_ORDER {byte_order}"]
    lines += [f"      {m}" for m in mod_common]
    lines += ["    /end MOD_COMMON"]
    for name, dt in layouts:
        lines += [f"    /begin RECORD_LAYOUT {name}",
                  f"      FNC_VALUES 1 {dt} ROW_DIR DIRECT",
                  "    /end RECORD_LAYOUT"]
    for block in blocks:
        lines += list(block)
    lines += ["  /end MODULE", "/end PROJECT"]
    _counter[0] += 1
    path = tmp_path / f"cov{_counter[0]}.a2l"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return parse_a2l_file(path)


def _rl(name: str, *component_lines: str) -> list[str]:
    return [f"/begin RECORD_LAYOUT {name}"] + [f"  {l}" for l in component_lines] + ["/end RECORD_LAYOUT"]


def _cm(name: str, type_line: str, *extra_lines: str) -> list[str]:
    return [f'/begin COMPU_METHOD {name} ""', f"  {type_line}"] + [f"  {l}" for l in extra_lines] + ["/end COMPU_METHOD"]


def _cm_std(name: str, typ: str, *coeffs: str, fmt: str = '"%.3"', unit: str = '""',
            ref: Optional[str] = None) -> list[str]:
    lines = [f"{typ} {fmt} {unit}"]
    if typ == "LINEAR" and coeffs:
        lines.append("COEFFS_LINEAR " + " ".join(coeffs))
    elif typ == "RAT_FUNC" and coeffs:
        lines.append("COEFFS " + " ".join(coeffs))
    if ref is not None:
        lines.append(f"COMPU_TAB_REF {ref}")
    return _cm(name, *lines)


def _vtab(name: str, count: str, *pairs: str, default: Optional[str] = None) -> list[str]:
    lines = [f'/begin COMPU_VTAB {name} "" TAB_VERB {count}'] + [f"  {p}" for p in pairs]
    if default is not None:
        lines.append(f'  DEFAULT_VALUE "{default}"')
    lines.append("/end COMPU_VTAB")
    return lines


def _vrange(name: str, count: str, *triples: str, default: Optional[str] = None) -> list[str]:
    lines = [f'/begin COMPU_VTAB_RANGE {name} "" {count}'] + [f"  {t}" for t in triples]
    if default is not None:
        lines.append(f'  DEFAULT_VALUE "{default}"')
    lines.append("/end COMPU_VTAB_RANGE")
    return lines


def _ctab(name: str, kind: str, *pairs: str) -> list[str]:
    return [f'/begin COMPU_TAB {name} "" {kind} {len(pairs)}'] + [f"  {p}" for p in pairs] + ["/end COMPU_TAB"]


def _axis(kind: str, method: str, maxpts: str, lo: str, hi: str, *kw: str) -> list[str]:
    return ["  /begin AXIS_DESCR", f"    {kind} NO_INPUT_QUANTITY {method} {maxpts} {lo} {hi}"] + \
           [f"    {w}" for w in kw] + ["  /end AXIS_DESCR"]


def _char(name: str, kind: str, addr: str, layout: str, conv: str, lo: str, hi: str,
          *extras: str, axes: Iterable[str] = ()) -> list[str]:
    lines = [f'/begin CHARACTERISTIC {name} ""', f"  {kind} {addr} {layout} 0 {conv} {lo} {hi}"]
    lines += [f"  {e}" for e in extras]
    lines += list(axes)
    lines.append("/end CHARACTERISTIC")
    return lines


def _valblk(name: str, addr: str, layout: str, conv: str, lo: str, hi: str, *extras: str) -> list[str]:
    return _char(name, "VAL_BLK", addr, layout, conv, lo, hi, *extras)


def _value(name: str, addr: str, layout: str, conv: str, lo: str, hi: str, *extras: str) -> list[str]:
    return _char(name, "VALUE", addr, layout, conv, lo, hi, *extras)


def _curve(name: str, addr: str, layout: str, axis_block: list[str], conv: str = "CM_IDENT",
           lo: str = "0", hi: str = "65535", *extras: str) -> list[str]:
    return _char(name, "CURVE", addr, layout, conv, lo, hi, *extras, axes=axis_block)


def _axis_pts(name: str, addr: str, layout: str, maxpts: str, conv: str = "CM_IDENT",
              lo: str = "0", hi: str = "255", *extras: str) -> list[str]:
    return [f'/begin AXIS_PTS {name} "{name} axis"', f"  {addr}", "  NO_INPUT_QUANTITY",
            f"  {layout}", "  0", f"  {conv}", f"  {maxpts}", f"  {lo} {hi}"] + \
           [f"  {e}" for e in extras] + ["/end AXIS_PTS"]


# ---------------------------------------------------------------------------
# Read-once controls
# ---------------------------------------------------------------------------

class _CountingMap:
    """A mapping wrapper that counts every by-key ``get`` / ``__getitem__``."""

    def __init__(self, inner: dict):
        self._inner = inner
        self.counts: dict[str, int] = {}

    def get(self, key, default=None):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self._inner.get(key, default)

    def __getitem__(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self._inner[key]

    def __contains__(self, key):
        return key in self._inner

    def __iter__(self):
        return iter(self._inner)

    def __len__(self):
        return len(self._inner)

    def keys(self):
        return self._inner.keys()

    def items(self):
        return self._inner.items()

    def values(self):
        return self._inner.values()


def _lookups_after_first(names: list[str], a2l_data: dict,
                         counters: Mapping[str, _CountingMap], word: str):
    """Describe ``names`` in one walk through a generator; snapshot each
    counter when the walk asks for the second name (so the first name has
    reduced every shared section).  Returns the lookups of ``word`` that the
    remaining 399 names caused, and the walk's result."""
    snapshot: dict[str, int] = {}

    def gen():
        yield names[0]
        for key, counter in counters.items():
            snapshot[key] = counter.counts.get(word, 0)
        yield from names[1:]

    result = a2ldef.describe_definitions(gen(), a2l_data)
    assert len(snapshot) == len(counters), "the generator was not consumed lazily"
    return {key: counter.counts.get(word, 0) - snapshot[key]
            for key, counter in counters.items()}, result


def _no_mutable_container(obj, path: str) -> None:
    """Walk a definition's reachable value tree; fail on any list/dict/set/
    bytearray (a read form or definition field must not hold one, E3S3-36)."""
    if isinstance(obj, (str, int, float, bool, type(None), bytes)):
        return
    if isinstance(obj, (list, dict, set, bytearray)):
        pytest.fail(f"{path} holds a mutable {type(obj).__name__}")
    if isinstance(obj, tuple):
        for i, item in enumerate(obj):
            _no_mutable_container(item, f"{path}[{i}]")
    elif hasattr(obj, "__dataclass_fields__"):
        for field in obj.__dataclass_fields__:
            _no_mutable_container(getattr(obj, field), f"{path}.{field}")
    elif isinstance(obj, Mapping):
        for key, value in obj.items():
            _no_mutable_container(value, f"{path}[{key!r}]")


# ---------------------------------------------------------------------------
# R-A2L-DEF.136 — read-once per walk
# ---------------------------------------------------------------------------

def test_r_a2l_def_136_arr_2_shared_layout_and_mod_common_read_once(tmp_path):
    # 555 KiB: MOD_COMMON with 256 KiB of DEPOSIT ABSOLUTE, one RECORD_LAYOUT
    # RL_BIG with a 256 KiB block comment, 400 VAL_BLKs sharing it.
    deposit = "      " + "DEPOSIT ABSOLUTE\n      " * (S // 17)
    body = _rl("RL_BIG", "FNC_VALUES 1 UBYTE ROW_DIR DIRECT", "/*" + "c" * (S - 4) + "*/")
    for i in range(400):
        body += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_BIG", "NO_COMPU_METHOD", "0", "255", "NUMBER 4")
    a2l_data = _parse(tmp_path, body, mod_common=(deposit.rstrip(),))
    names = [f"V{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        assert d.kind == "array", name
        assert d.shape == (4,)
        assert d.element_count == 4
        assert d.byte_length == 4
        assert d.refusal is None


def test_r_a2l_def_136_arr_3_shared_axis_method_enum_range_read_once(tmp_path):
    # (a) COM_AXIS curves sharing AXO whose body holds 256 KiB of DEPOSIT.
    axo = _axis_pts("AXO", "0x100", "RL_AXO", "4", "CM_IDENT", "0", "255",
                    *("DEPOSIT ABSOLUTE",) * (S // 17))
    blocks_a = IDENT + _rl("RL_AXO", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT") + axo
    for i in range(400):
        blocks_a += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                           _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    a2l_a = _parse(tmp_path, blocks_a)

    # (b) STD_AXIS curves whose object and axis name CM_L (LINEAR, 256 KiB comment).
    blocks_b = _cm("CM_L", 'LINEAR "%.3" ""', "COEFFS_LINEAR 0.5 0", "/*" + "c" * (S - 4) + "*/")
    for i in range(400):
        blocks_b += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                           _axis("STD_AXIS", "CM_L", "4", "0", "255"), conv="CM_L")

    # (c) the same naming CM_V -> VT (enum, 256 KiB comment).
    blocks_c = _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT", "/*" + "c" * (S - 4) + "*/") + \
        _vtab("VT", "2", '0 "zero"', '1 "one"')
    for i in range(400):
        blocks_c += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                           _axis("STD_AXIS", "CM_V", "4", "0", "255"), conv="CM_V")

    # (d) the same naming CM_R -> VR (range, 256 KiB comment).
    blocks_d = _cm("CM_R", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VR", "/*" + "c" * (S - 4) + "*/") + \
        _vrange("VR", "2", '0 0 "zero"', '1 255 "other"')
    for i in range(400):
        blocks_d += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                           _axis("STD_AXIS", "CM_R", "4", "0", "255"), conv="CM_R")

    for a2l_data in (_parse(tmp_path, blocks_b), _parse(tmp_path, blocks_c), _parse(tmp_path, blocks_d)):
        names = [f"C{i:05d}" for i in range(400)]
        defs = a2ldef.describe_definitions(names, a2l_data)
        for name in names:
            d = defs[name]
            assert d.kind == "curve", name
            assert d.shape == (4,)
            assert d.refusal is None

    names = [f"C{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_a)
    for name in names:
        assert defs[name].kind == "curve" and defs[name].shape == (4,) and defs[name].refusal is None

    # The enum table (c) and the range table (d) are held by reference, one
    # tuple for every definition's axis points (read once per walk).
    def _axis_points_enum_entries(data):
        defs = a2ldef.describe_definitions([f"C{i:05d}" for i in range(400)], data)
        return [d.axes[0].points.enum_entries for d in defs.values()]

    for data in (_parse(tmp_path, blocks_c), _parse(tmp_path, blocks_d)):
        entries = _axis_points_enum_entries(data)
        assert all(entries) and len({id(e) for e in entries}) == 1


def test_r_a2l_def_136_arr_4_read_forms_immutable_no_list_dict(v171):
    """Every stored read form is immutable (a mutation raises) and no
    definition field holds a list/dict (E3S3-19, E3S3-36)."""
    names = [t["name"] for t in v171["tags"]]
    defs = a2ldef.describe_definitions(names, v171)
    for d in defs.values():
        _no_mutable_container(d, "Definition")
    # Targeted mutation refusals on the enum read form a definition carries.
    enum_def = next(d for d in defs.values() if d.enum_entries)
    assert isinstance(enum_def.enum_entries, tuple)
    with pytest.raises((TypeError, AttributeError)):
        enum_def.enum_entries.append(a2ldef.EnumEntry(0.0, None, "x"))  # type: ignore[attr-defined]
    with pytest.raises(Exception):
        enum_def.enum_entries[0].text = "mutated"
    with pytest.raises(Exception):
        enum_def.limits.lower = 1.0
    # The frozen V171 axis curve definitions carry frozen axes.
    curve_def = next((d for d in defs.values() if d.kind == "curve" and d.axes), None)
    if curve_def is not None:
        with pytest.raises(Exception):
            curve_def.axes[0].points = None  # type: ignore[assignment]


def _one_walk_equals_fresh(a2l_data: dict) -> None:
    names = [t["name"] for t in a2l_data["tags"]]
    one = a2ldef.describe_definitions(names, a2l_data)
    one_rev = a2ldef.describe_definitions(list(reversed(names)), a2l_data)
    fresh = {n: a2ldef.describe_definition(n, a2l_data) for n in names}
    assert one == fresh and one_rev == fresh


def test_r_a2l_def_136_arr_4_k1_k3_and_poison_shapes_equal_fresh(tmp_path, v171):
    # K1: a VALUE and a VAL_BLK on one SWORD layout.
    k1 = _rl("RL_N", "FNC_VALUES 1 SWORD ROW_DIR DIRECT") + \
         _value("SA", "0x10", "RL_N", "NO_COMPU_METHOD", "0", "65535") + \
         _valblk("VA", "0x20", "RL_N", "NO_COMPU_METHOD", "0", "65535", "MATRIX_DIM 2")
    # K2: the same on a layout whose first line holds no datatype word.
    k2 = _rl("RL_N", "FNC_VALUES 1") + \
         _value("SA", "0x10", "RL_N", "NO_COMPU_METHOD", "0", "65535") + \
         _valblk("VA", "0x20", "RL_N", "NO_COMPU_METHOD", "0", "65535", "MATRIX_DIM 2")
    # K3: a VALUE and a CURVE on one layout.
    k3 = _rl("RL_N", "FNC_VALUES 1 SWORD ROW_DIR DIRECT") + \
         _value("SA", "0x10", "RL_N", "NO_COMPU_METHOD", "0", "65535") + \
         _curve("CA", "0x20", "RL_N", _axis("STD_AXIS", "NO_COMPU_METHOD", "2", "0", "255"))
    for body in (k1, k2, k3):
        _one_walk_equals_fresh(_parse(tmp_path, body))

    # P1: two VAL_BLKs sharing a refused layout (RESERVED part).
    p1 = _rl("RL_BAD", "FNC_VALUES 1 UBYTE ROW_DIR DIRECT", "RESERVED 2 BYTE") + \
         _valblk("VA", "0x100", "RL_BAD", "NO_COMPU_METHOD", "0", "255", "NUMBER 4") + \
         _valblk("VB", "0x200", "RL_BAD", "NO_COMPU_METHOD", "0", "255", "NUMBER 4")
    _one_walk_equals_fresh(_parse(tmp_path, p1, mod_common=("ALIGNMENT_WORD 2",)))

    # P2: two curves (max 8) sharing RL_C under MOD_COMMON ALIGNMENT_WORD 2.
    p2 = _rl("RL_C", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 SBYTE INDEX_INCR DIRECT",
             "FNC_VALUES 3 SWORD ROW_DIR DIRECT") + \
         _curve("CA", "0x100", "RL_C", _axis("STD_AXIS", "NO_COMPU_METHOD", "8", "0", "255")) + \
         _curve("CB", "0x200", "RL_C", _axis("STD_AXIS", "NO_COMPU_METHOD", "8", "0", "255"))
    _one_walk_equals_fresh(_parse(tmp_path, p2, mod_common=("ALIGNMENT_WORD 2",)))

    # P4: curves of max 8 and 7 share RL_C under ALIGNMENT_WORD 2 (one moved, one not).
    p4 = _rl("RL_C", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 SBYTE INDEX_INCR DIRECT",
             "FNC_VALUES 3 SWORD ROW_DIR DIRECT") + \
         _curve("CA", "0x100", "RL_C", _axis("STD_AXIS", "NO_COMPU_METHOD", "8", "0", "255")) + \
         _curve("CC", "0x200", "RL_C", _axis("STD_AXIS", "NO_COMPU_METHOD", "7", "0", "255"))
    _one_walk_equals_fresh(_parse(tmp_path, p4, mod_common=("ALIGNMENT_WORD 2",)))

    # P5: two COM curves sharing AXO under MOD_COMMON ALIGNMENT_WORD 2.
    p5 = _rl("RL_AXO", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT") + \
         _axis_pts("AXO", "0x100", "RL_AXO", "4") + \
         _curve("CR1", "0x200", "RL_U8", _axis("COM_AXIS", "NO_COMPU_METHOD", "4", "0", "255", "AXIS_PTS_REF AXO")) + \
         _curve("CR2", "0x300", "RL_U8", _axis("COM_AXIS", "NO_COMPU_METHOD", "4", "0", "255", "AXIS_PTS_REF AXO"))
    _one_walk_equals_fresh(_parse(tmp_path, p5, mod_common=("ALIGNMENT_WORD 2",)))

    # P3: CA in M1 (ALIGNMENT_WORD 2) and CB in M2 (none) share RL_C across modules.
    p3 = _parse(tmp_path, _rl("RL_C", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 SBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 3 SWORD ROW_DIR DIRECT") +
                _curve("CA", "0x100", "RL_C", _axis("STD_AXIS", "NO_COMPU_METHOD", "8", "0", "255")) +
                _curve("CB", "0x200", "RL_C", _axis("STD_AXIS", "NO_COMPU_METHOD", "8", "0", "255")),
                mod_common=("ALIGNMENT_WORD 2",))
    _one_walk_equals_fresh(p3)

    # V171: one walk == fresh, in both orders, for every name.
    _one_walk_equals_fresh(v171)


# ---------------------------------------------------------------------------
# R-A2L-DEF.148 — exact-value side of the scaling cases
# ---------------------------------------------------------------------------

def _n_valblks(conv: str, layout: str, extras: tuple[str, ...], n: int = 400) -> list[str]:
    out: list[str] = []
    for i in range(n):
        out += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", layout, conv, "0", "255", *extras)
    return out


def _n_values(conv: str, layout: str, n: int = 400) -> list[str]:
    out: list[str] = []
    for i in range(n):
        out += _value(f"S{i:05d}", f"0x{0x1000 + i:X}", layout, conv, "0", "255")
    return out


def test_r_a2l_def_148_2_shared_layout_first_line_val_blk(tmp_path):
    # The first line holds many X words, datatype word last.
    a2l_data = _parse(tmp_path,
                      _rl("RL_LONG", "FNC_VALUES 1 " + "X " * (S // 2) + "UBYTE ROW_DIR DIRECT"),
                      _n_valblks("NO_COMPU_METHOD", "RL_LONG", ("NUMBER 4",)))
    names = [f"V{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        is_refused(defs[name], "A2L-DEF-LAYOUT-PART",
                   f"{name}: the record layout RL_LONG holds X, which the system cannot read")


def test_r_a2l_def_148_3_shared_layout_first_line_value(tmp_path):
    a2l_data = _parse(tmp_path,
                      _rl("RL_LONG", "FNC_VALUES 1 " + "X " * (S // 2) + "UBYTE ROW_DIR DIRECT"),
                      _n_values("NO_COMPU_METHOD", "RL_LONG"))
    names = [f"S{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        assert d.kind == "number" and d.datatype == "UBYTE" and d.refusal is None


def test_r_a2l_def_148_4_mod_common_alignment_lines_val_blk(tmp_path):
    mc = ("ALIGNMENT_BYTE 1",) * (S // 17)
    a2l_data = _parse(tmp_path, _n_valblks("NO_COMPU_METHOD", "RL_U8", ("NUMBER 4",)), mod_common=mc)
    names = [f"V{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        assert d.kind == "array" and d.shape == (4,) and d.refusal is None


def test_r_a2l_def_148_5_com_path_under_mod_common(tmp_path):
    mc = ("ALIGNMENT_BYTE 1",) * (S // 17)
    axo = _axis_pts("AXO", "0x100", "RL_AXO", "4")
    body = IDENT + _rl("RL_AXO", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT") + axo
    for i in range(400):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                       _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    a2l_data = _parse(tmp_path, body, mod_common=mc)
    names = [f"C{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        assert d.kind == "curve" and d.shape == (4,) and d.refusal is None


IDENT = _cm("CM_IDENT", 'IDENTICAL "%.0" ""')


def _std_axis_curves(conv: str, n: int = 400) -> list[str]:
    out: list[str] = _rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UBYTE ROW_DIR DIRECT")
    for i in range(n):
        out += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_C",
                      _axis("STD_AXIS", conv, "4", "0", "255"), conv=conv)
    return out


def test_r_a2l_def_148_7_shared_method_size(tmp_path):
    a2l_data = _parse(tmp_path,
                      _cm("CM_L", 'LINEAR "%.3" ""', "COEFFS_LINEAR 0.5 0",
                          *("DEPOSIT ABSOLUTE",) * (S // 17)),
                      _std_axis_curves("CM_L"))
    names = [f"C{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        assert d.kind == "curve" and d.shape == (4,) and d.refusal is None


def test_r_a2l_def_148_8_shared_enum_table_same_tuple(tmp_path):
    a2l_data = _parse(tmp_path,
                      _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT"),
                      _vtab("VT", str(S // 9), *[f'{1000 + k} "v{k}"' for k in range(S // 9)]),
                      _std_axis_curves("CM_V"))
    names = [f"C{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    entries = [d.axes[0].points.enum_entries for d in defs.values()]
    assert all(entries) and len({id(e) for e in entries}) == 1
    for name in names:
        d = defs[name]
        assert d.kind == "curve" and d.shape == (4,) and d.refusal is None


def test_r_a2l_def_148_9_shared_range_table_same_tuple(tmp_path):
    n_entries = S // 18
    a2l_data = _parse(tmp_path,
                      _cm("CM_R", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VR"),
                      _vrange("VR", str(n_entries),
                              *[f'{1000 + 2 * k} {1000 + 2 * k + 1} "r{k}"' for k in range(n_entries)]),
                      _std_axis_curves("CM_R"))
    names = [f"C{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    entries = [d.axes[0].points.enum_entries for d in defs.values()]
    assert all(entries) and len({id(e) for e in entries}) == 1
    for name in names:
        d = defs[name]
        assert d.kind == "curve" and d.shape == (4,) and d.refusal is None


def test_r_a2l_def_148_10_long_part_word_of_shared_layout(tmp_path):
    word = "P" * S
    a2l_data = _parse(tmp_path,
                      _rl("RL", "FNC_VALUES 1 UBYTE ROW_DIR DIRECT", word),
                      _n_valblks("NO_COMPU_METHOD", "RL", ("NUMBER 1",)))
    names = [f"V{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        is_refused(d, "A2L-DEF-LAYOUT-PART",
                   f"{name}: the record layout RL holds {'P' * _ECHO}{_ELLIPSIS}, which the system cannot read")
        assert len(d.refusal.message) <= 1024


def test_r_a2l_def_148_11_long_alignment_word_of_shared_mod_common(tmp_path):
    word = "9" * S
    a2l_data = _parse(tmp_path, _n_valblks("NO_COMPU_METHOD", "RL_U8", ("NUMBER 4",)),
                      mod_common=(f"ALIGNMENT_BYTE {word}",))
    names = [f"V{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        is_refused(d, "A2L-DEF-ALIGNMENT",
                   f"{name}: the MOD_COMMON line ALIGNMENT_BYTE {'9' * _ECHO}{_ELLIPSIS} cannot be read")
        assert len(d.refusal.message) <= 1024


def test_r_a2l_def_148_12_long_format_word_decimals_once(tmp_path):
    fmt = '"%' + "9" * S + '.2"'
    a2l_data = _parse(tmp_path,
                      _cm("CM_F", f'LINEAR {fmt} ""', "COEFFS_LINEAR 0.5 0"),
                      _std_axis_curves("CM_F"))
    names = [f"C{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        assert d.decimals == 2 and d.refusal is None
        assert d.axes[0].points.decimals == 2


def test_r_a2l_def_148_13_long_conversion_type_word(tmp_path):
    word = "Z" * S
    a2l_data = _parse(tmp_path,
                      _cm("CM_T", f'{word} "%.3" ""'),
                      _std_axis_curves("CM_T"))
    names = [f"C{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        is_refused(d, "A2L-DEF-CONVERSION",
                   f"{name}: the conversion type {'Z' * _ECHO}{_ELLIPSIS} of CM_T is not supported")
        assert len(d.refusal.message) <= 1024


def test_r_a2l_def_148_14_long_tabref_word(tmp_path):
    word = "G" * S
    a2l_data = _parse(tmp_path,
                      _cm("CM_V", 'TAB_VERB "%.3" ""', f"COMPU_TAB_REF {word}"),
                      _std_axis_curves("CM_V"))
    names = [f"C{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        is_refused(d, "A2L-DEF-TABLE",
                   f"{name}: the table {'G' * _ECHO}{_ELLIPSIS} of CM_V is not declared in the A2L")
        assert len(d.refusal.message) <= 1024


def test_r_a2l_def_148_15_long_part_word_of_axis_layout(tmp_path):
    word = "P" * S
    axo = _axis_pts("AXO", "0x100", "RL_AXO", "4")
    body = IDENT + _rl("RL_AXO", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT", word) + axo
    for i in range(400):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                       _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    a2l_data = _parse(tmp_path, body)
    names = [f"C{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    for name in names:
        d = defs[name]
        is_refused(d, "A2L-DEF-LAYOUT-PART",
                   f"{name}.X: the record layout RL_AXO holds {'P' * _ECHO}{_ELLIPSIS}, which the system cannot read")
        assert len(d.refusal.message) <= 1024


def _long_name_axis_layout_curves(tmp_path, layout_word: str, *layout_lines: str):
    """400 COM curves sharing AXO whose layout word is ``layout_word``; the
    RECORD_LAYOUT of that name holds ``layout_lines``."""
    axo = _axis_pts("AXO", "0x100", layout_word, "4")
    body = IDENT + _rl(layout_word, *layout_lines) + axo
    for i in range(400):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                       _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    return _parse(tmp_path, body)


def test_r_a2l_def_148_16_long_layout_name_part_message_count(tmp_path):
    word = "L" * S
    a2l_data = _long_name_axis_layout_curves(
        tmp_path, word, "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT", "P")
    names = [f"C{i:05d}" for i in range(400)]
    # The count: 0 lookups by the shared layout word after the first name.
    counter = _CountingMap(a2l_data["record_layouts_by_name"])
    a2l_data["record_layouts_by_name"] = counter
    after, defs = _lookups_after_first(names, a2l_data, {"layouts": counter}, word)
    assert after["layouts"] == 0, after
    for name in names:
        d = defs[name]
        is_refused(d, "A2L-DEF-LAYOUT-PART",
                   f"{name}.X: the record layout {'L' * _ECHO}{_ELLIPSIS} holds P, which the system cannot read")
        assert len(d.refusal.message) <= 1024


def test_r_a2l_def_148_17_long_layout_name_alignment_message_count(tmp_path):
    word = "L" * S
    a2l_data = _long_name_axis_layout_curves(
        tmp_path, word, "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT")
    # MOD_COMMON ALIGNMENT_BYTE 2 moves AXIS_PTS_X from offset 1 to 2.
    names = [f"C{i:05d}" for i in range(400)]
    # Rebuild with the MOD_COMMON alignment.
    axo = _axis_pts("AXO", "0x100", word, "4")
    body = _rl(word, "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT") + axo
    for i in range(400):
        body += _curve(f"C{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8",
                       _axis("COM_AXIS", "CM_IDENT", "4", "0", "255", "AXIS_PTS_REF AXO"))
    a2l_data = _parse(tmp_path, IDENT + body, mod_common=("ALIGNMENT_BYTE 2",))
    counter = _CountingMap(a2l_data["record_layouts_by_name"])
    a2l_data["record_layouts_by_name"] = counter
    after, defs = _lookups_after_first(names, a2l_data, {"layouts": counter}, word)
    assert after["layouts"] == 0, after
    for name in names:
        d = defs[name]
        is_refused(d, "A2L-DEF-ALIGNMENT",
                   f"{name}: AXIS_PTS_X of the record layout {'L' * _ECHO}{_ELLIPSIS} lies at offset 1, "
                   "or at 2 under the MOD_COMMON alignment")
        assert len(d.refusal.message) <= 1024


def _long_tabref_empty_curves(tmp_path, word: str):
    return _parse(tmp_path,
                  _cm("CM_E", 'TAB_VERB "%.3" ""', f"COMPU_TAB_REF {word}"),
                  _vtab(word, "0"),
                  _std_axis_curves("CM_E"))


def test_r_a2l_def_148_18_long_tabref_empty_table_count(tmp_path):
    word = "E" * S
    a2l_data = _long_tabref_empty_curves(tmp_path, word)
    names = [f"C{i:05d}" for i in range(400)]
    # The VTAB lookup runs through the walk's local table map, so count it by
    # wrapping the resolver the model calls per name (read-once control).
    counts = {"by_word": 0}
    orig_read_enum = a2ldef._read_enum_table

    def counting_read_enum(table_name, compu_tables_by_name, reads):
        if table_name == word:
            counts["by_word"] += 1
        return orig_read_enum(table_name, compu_tables_by_name, reads)

    a2ldef._read_enum_table = counting_read_enum
    try:
        snapshots: list[int] = []

        def gen():
            yield names[0]
            snapshots.append(counts["by_word"])
            yield from names[1:]

        defs = a2ldef.describe_definitions(gen(), a2l_data)
        assert snapshots
    finally:
        a2ldef._read_enum_table = orig_read_enum
    assert counts["by_word"] - snapshots[0] == 0, (counts["by_word"], snapshots[0])
    for name in names:
        d = defs[name]
        is_refused(d, "A2L-DEF-TABLE-EMPTY",
                   f"{name}: the table {'E' * _ECHO}{_ELLIPSIS} has no entries")
        assert len(d.refusal.message) <= 1024


def test_r_a2l_def_148_19_tab_through_own_method_one_form(tmp_path):
    # CT-5: 400 VAL_BLKs, each naming its own TAB_NOINTP method on one CT.
    blocks: list[str] = []
    for i in range(400):
        blocks += _cm(f"CM{i:05d}", 'TAB_NOINTP "%.3" ""', "COMPU_TAB_REF CT")
    blocks += _ctab("CT", "TAB_NOINTP", "0 0", "10 100", "20 50", "300 999")
    for i in range(400):
        blocks += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", f"CM{i:05d}", "0", "255", "NUMBER 1")
    a2l_data = _parse(tmp_path, blocks)
    names = [f"V{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    forms = [d._table_form for d in defs.values()]
    assert all(f is not None for f in forms) and len({id(f) for f in forms}) == 1
    for name in names:
        d = defs[name]
        assert d.kind == "array" and d.shape == (1,) and d.refusal is None

    # CT-6: 400 VALUEs, each naming its own TAB_INTP method on the same CT.
    blocks = []
    for i in range(400):
        blocks += _cm(f"CM{i:05d}", 'TAB_INTP "%.3" ""', "COMPU_TAB_REF CT")
    blocks += _ctab("CT", "TAB_INTP", "0 0", "10 100", "20 50", "300 999")
    for i in range(400):
        blocks += _value(f"S{i:05d}", f"0x{0x1000 + i:X}", "RL_U8", f"CM{i:05d}", "0", "255")
    a2l_data = _parse(tmp_path, blocks)
    names = [f"S{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    forms = [d._table_form for d in defs.values()]
    assert all(f is not None for f in forms) and len({id(f) for f in forms}) == 1
    for name in names:
        d = defs[name]
        assert d.kind == "number" and d.refusal is None


# ---------------------------------------------------------------------------
# R-A2L-DEF.150 — decode side (one lookup per element)
# ---------------------------------------------------------------------------

def _decode(d: Definition, a2l_data: dict, image: Mapping[int, int]):
    return a2ldef.decode_values(d, a2l_data, image)


def test_r_a2l_def_150_arr_1_shared_enum_table_decode(tmp_path):
    n_entries = S // 9
    a2l_data = _parse(tmp_path,
                      _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT"),
                      _vtab("VT", str(n_entries), *[f'{1000 + k} "v{k}"' for k in range(n_entries)]),
                      _std_axis_curves("CM_V"))
    d = a2ldef.describe_definition("C00000", a2l_data)
    image = {0x1000 + i: 250 for i in range(16)}
    res = _decode(d, a2l_data, image)
    assert isinstance(res, DecodedValues)
    for point in res.axes[0].points:
        assert (point.stored, point.value, point.text) == (250, None, "250 (no text)")
    for value in res.values:
        assert (value.stored, value.value, value.text) == (250, None, "250 (no text)")


def test_r_a2l_def_150_arr_2_val_blk_enum_decode(tmp_path):
    a2l_data = _parse(tmp_path,
                      _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT"),
                      _vtab("VT", "2", '0 "zero"', '1 "one"'),
                      _valblk("V00000", "0x1000", "RL_U8", "CM_V", "0", "255", "NUMBER 4"))
    d = a2ldef.describe_definition("V00000", a2l_data)
    res = _decode(d, a2l_data, img(0x1000, bytes([250]) * 4))
    for value in res.values:
        assert (value.stored, value.value, value.text) == (250, None, "250 (no text)")


def test_r_a2l_def_150_arr_3_long_matched_entry_text_referenced(tmp_path):
    text = "t" * S
    a2l_data = _parse(tmp_path,
                      _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT"),
                      _vtab("VT", "1", f'0 "{text}"'),
                      _valblk("V00000", "0x1000", "RL_U8", "CM_V", "0", "255", "NUMBER 4"))
    d = a2ldef.describe_definition("V00000", a2l_data)
    res = _decode(d, a2l_data, img(0x1000, bytes([0]) * 4))
    texts = [v.text for v in res.values]
    assert all(t == text for t in texts)
    assert len({id(t) for t in texts}) == 1


def test_r_a2l_def_150_arr_4_long_default_text_referenced(tmp_path):
    text = "d" * S
    a2l_data = _parse(tmp_path,
                      _cm("CM_V", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VT"),
                      _vtab("VT", "1", '1000 "a"', default=text),
                      _valblk("V00000", "0x1000", "RL_U8", "CM_V", "0", "255", "NUMBER 4"))
    d = a2ldef.describe_definition("V00000", a2l_data)
    res = _decode(d, a2l_data, img(0x1000, bytes([250]) * 4))
    texts = [v.text for v in res.values]
    assert all(t == text for t in texts)
    assert len({id(t) for t in texts}) == 1


def test_r_a2l_def_150_arr_5_shared_range_table_decode(tmp_path):
    n_entries = S // 18
    a2l_data = _parse(tmp_path,
                      _cm("CM_R", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VR"),
                      _vrange("VR", str(n_entries),
                              *[f'{1000 + 2 * k} {1000 + 2 * k + 1} "r{k}"' for k in range(n_entries)]),
                      _std_axis_curves("CM_R"))
    d = a2ldef.describe_definition("C00000", a2l_data)
    res = _decode(d, a2l_data, {0x1000 + i: 250 for i in range(16)})
    for point in res.axes[0].points:
        assert (point.stored, point.value, point.text) == (250, None, "250 (no text)")
    for value in res.values:
        assert (value.stored, value.value, value.text) == (250, None, "250 (no text)")


def test_r_a2l_def_150_arr_6_long_matched_range_text_referenced(tmp_path):
    text = "t" * S
    a2l_data = _parse(tmp_path,
                      _cm("CM_R", 'TAB_VERB "%.0" ""', "COMPU_TAB_REF VR"),
                      _vrange("VR", "1", f'0 255 "{text}"'),
                      _valblk("V00000", "0x1000", "RL_U8", "CM_R", "0", "255", "NUMBER 4"))
    d = a2ldef.describe_definition("V00000", a2l_data)
    res = _decode(d, a2l_data, img(0x1000, bytes([0]) * 4))
    texts = [v.text for v in res.values]
    assert all(t == text for t in texts)
    assert len({id(t) for t in texts}) == 1


def _tab_intp_val_blks(tmp_path, kind: str = "TAB_INTP"):
    """400 VAL_BLKs naming one shared CM_I -> CT; CT as .150/arr-7's shape."""
    blocks = _cm("CM_I", f'{kind} "%.3" ""', "COMPU_TAB_REF CT")
    blocks += _ctab("CT", kind, "0 0", "100 100", "200 50", "300 999")
    for i in range(400):
        blocks += _valblk(f"V{i:05d}", f"0x{0x1000 + 16 * i:X}", "RL_U8", "CM_I", "0", "255", "NUMBER 4")
    return _parse(tmp_path, blocks)


def test_r_a2l_def_150_arr_7_tab_intp_frozen_value_one_lookup(tmp_path):
    a2l_data = _tab_intp_val_blks(tmp_path, "TAB_INTP")
    names = [f"V{i:05d}" for i in range(400)]
    # The count: 0 lookups by CT in the COMPU_TAB side table after the first
    # name, and none at all during the 399 decodes.
    counter = _CountingMap(a2l_data["compu_tabs_by_name"])
    a2l_data["compu_tabs_by_name"] = counter
    after, defs = _lookups_after_first(names, a2l_data, {"tabs": counter}, "CT")
    assert after["tabs"] == 0, after
    method = a2l_data["compu_methods_by_name"]["CM_I"]
    tables = a2l_data["compu_tabs_by_name"]._inner
    expected, _, _ = a2l._apply_compu_method(250, method, tables, (0.0, 255.0))
    before_decode = counter.counts.get("CT", 0)
    for i, name in enumerate(names):
        res = _decode(defs[name], a2l_data, img(0x1000 + 16 * i, bytes([250]) * 4))
        for value in res.values:
            assert value.stored == 250
            assert value.value == pytest.approx(expected, rel=1e-12, abs=1e-9)
    assert counter.counts.get("CT", 0) == before_decode


def test_r_a2l_def_150_arr_8_tab_nointp_frozen_value(tmp_path):
    a2l_data = _tab_intp_val_blks(tmp_path, "TAB_NOINTP")
    names = [f"V{i:05d}" for i in range(400)]
    defs = a2ldef.describe_definitions(names, a2l_data)
    method = a2l_data["compu_methods_by_name"]["CM_I"]
    tables = a2l_data["compu_tabs_by_name"]
    expected, _, _ = a2l._apply_compu_method(250, method, tables, (0.0, 255.0))
    for i, name in enumerate(names):
        res = _decode(defs[name], a2l_data, img(0x1000 + 16 * i, bytes([250]) * 4))
        for value in res.values:
            assert value.stored == 250
            assert value.value == expected


def _tab_form_from_entries(entries) -> a2ldef._TabForm:
    xs = tuple(e[0] for e in entries)
    ys = tuple(e[1] for e in entries)
    return a2ldef._TabForm(xs=xs, ys=ys, x_nan=any(isinstance(x, float) and math.isnan(x) for x in xs), ref_echo="")


def _probe_values(entries: list) -> list:
    """Every stored value the case names, per table with entries."""
    xs = [e[0] for e in entries]
    values: list = []
    for x in xs:
        values.append(x)
    for left, right in zip(xs, xs[1:]):
        values.append(left + (right - left) * 0.25)
    if xs:
        values += [xs[0] - 1, xs[-1] + 1]
    # Extended values (E3S3-29).
    for x in xs:
        values += [x, math.nextafter(x, math.inf), math.nextafter(x, -math.inf)]
    values += [0.0, -0.0, 1e300, -1e300, 2 ** 53 + 1, 2 ** 63, -(2 ** 63), 2 ** 64 - 1,
               float("nan"), float("inf"), float("-inf")]
    return values


def test_r_a2l_def_150_arr_9_bisect_matches_frozen_lookup(tmp_path):
    """3a's ``_table_value`` (the bisect ``_decode_stored`` runs) gives the
    frozen ``_table_lookup``'s (value, error) for every case point, on every
    table with entries the inline and fixture files declare."""
    # INLINE3 tables first (always present).
    inline_blocks = _cm("CM_I", 'TAB_INTP "%.3" ""', "COMPU_TAB_REF CTI") + \
        _cm("CM_N", 'TAB_NOINTP "%.3" ""', "COMPU_TAB_REF CTN") + \
        _ctab("CTI", "TAB_INTP", "0 0", "10 100", "20 50") + \
        _ctab("CTN", "TAB_NOINTP", "0 0", "10 100", "20 50")
    inline_data = _parse(tmp_path, inline_blocks)

    tables: list[dict] = []
    for key in ("CTI", "CTN"):
        tables.append(inline_data["compu_tabs_by_name"][key])

    # Every COMPU_TAB / COMPU_VTAB with entries in the public fixtures.
    fixtures = sorted(Path(__file__).resolve().parent.parent.glob("examples/case_00_public/*.a2l"))
    for fixture in fixtures:
        data = load(fixture.name)
        for key in ("compu_tabs_by_name",):
            for table in (data.get(key) or {}).values():
                if table.get("entries"):
                    tables.append(table)

    # The 168-file public corpus, read-only (``A2L_CORPUS_FILES``, else
    # ``~/a2l-corpus/files`` on the runner's real home).
    import os
    corpus = Path(os.environ.get("A2L_CORPUS_FILES") or Path.home() / "a2l-corpus" / "files")
    if corpus.is_dir():
        for path in sorted(corpus.glob("*.a2l")):
            data = parse_a2l_file(path)
            for table in (data.get("compu_tabs_by_name") or {}).values():
                if table.get("entries"):
                    tables.append(table)

    assert tables
    checked = 0
    for table in tables:
        entries = table.get("entries") or []
        if not entries or any(isinstance(e[0], float) and math.isnan(e[0]) for e in entries):
            continue  # the NaN-x table is refused via the verdict, tested below
        form = _tab_form_from_entries(entries)
        for interp in (False, True):
            for value in _probe_values(entries):
                got = a2ldef._table_value(form, value, interp)
                want = a2l._table_lookup(value, table, interp)
                assert got == want, (table.get("name"), interp, value, got, want)
                checked += 1
    assert checked > 0

    # The CTN table (a NaN x, a legal float word) refuses at decode, not raises.
    nan_blocks = _cm("CM_XN", 'TAB_NOINTP "%.3" ""', "COMPU_TAB_REF CTN") + \
        _cm("CM_XI", 'TAB_INTP "%.3" ""', "COMPU_TAB_REF CTN") + \
        _ctab("CTN", "TAB_NOINTP", "0 0", "nan 7", "10 100", "20 50")
    for name, conv in (("VA", "CM_XN"), ("VB", "CM_XI")):
        data = _parse(tmp_path, nan_blocks + _valblk(name, "0x10", "RL_U8", conv, "0", "255", "MATRIX_DIM 3"))
        d = a2ldef.describe_definition(name, data)
        res = _decode(d, data, img(0x10, bytes([5, 10, 15])))
        for i, element in enumerate(res.values):
            assert isinstance(element, Refusal)
            assert element.code == "A2L-DEF-DECODE"
            assert element.message == f"{name}[{i}]: the table CTN has an x that is not a number"


def test_r_a2l_def_150_arr_10_element_decode_does_not_grow_with_name(tmp_path):
    # EN-1: one VAL_BLK named V + N's, naming CM_I -> NOT_DECLARED.
    name = "V" + "N" * S
    blocks = _cm("CM_I", 'TAB_INTP "%.3" ""', "COMPU_TAB_REF NOT_DECLARED") + \
        _valblk(name, "0x1000", "RL_U8", "CM_I", "0", "255", "NUMBER 64")
    a2l_data = _parse(tmp_path, blocks)
    d = a2ldef.describe_definition(name, a2l_data)
    assert d.kind == "array" and d.shape == (64,) and d.refusal is None
    res = _decode(d, a2l_data, img(0x1000, bytes([250]) * 64))
    echo = name[:256] + _ELLIPSIS
    for i, element in enumerate(res.values):
        assert isinstance(element, Refusal)
        assert element.message == f"{echo}[{i}]: lookup table missing"
        assert len(element.message) <= 1024

    # EN-2: the same with NO_COMPU_METHOD: 64 values, no element name built.
    blocks = _valblk(name, "0x1000", "RL_U8", "NO_COMPU_METHOD", "0", "255", "NUMBER 64")
    a2l_data = _parse(tmp_path, blocks)
    d = a2ldef.describe_definition(name, a2l_data)
    res = _decode(d, a2l_data, img(0x1000, bytes([250]) * 64))
    assert all(isinstance(v, Decoded) and v.stored == 250 for v in res.values)


def test_r_a2l_def_150_arr_11_table_text_value_refused_not_raised(tmp_path):
    for kind, name, conv in (("VAL_BLK", "VA", "CM_XN"), ("VAL_BLK", "VB", "CM_XI"),
                             ("VALUE", "SC", "CM_XN"), ("VALUE", "SD", "CM_XI")):
        blocks = _cm("CM_XN", 'TAB_NOINTP "%.3" ""', "COMPU_TAB_REF VTX") + \
            _cm("CM_XI", 'TAB_INTP "%.3" ""', "COMPU_TAB_REF VTX") + \
            _vtab("VTX", "2", '0 "zero"', '1 "one"')
        if kind == "VAL_BLK":
            blocks += _valblk(name, "0x10", "RL_U8", conv, "0", "255", "MATRIX_DIM 2")
            a2l_data = _parse(tmp_path, blocks)
            d = a2ldef.describe_definition(name, a2l_data)
            res = _decode(d, a2l_data, img(0x10, bytes([1, 0])))
            for i, element in enumerate(res.values):
                assert isinstance(element, Refusal)
                assert element.message == f"{name}[{i}]: the table VTX gives a value that is not a number"
        else:
            blocks += _value(name, "0x10", "RL_U8", conv, "0", "255")
            a2l_data = _parse(tmp_path, blocks)
            d = a2ldef.describe_definition(name, a2l_data)
            res = a2ldef.decode_definition(d, a2l_data, img(0x10, bytes([1])))
            assert isinstance(res, Refusal)
            assert res.message == f"{name}: the table VTX gives a value that is not a number"


# ---------------------------------------------------------------------------
# R-A2L-DEF.151 — echo cap in the remaining message families
# ---------------------------------------------------------------------------

def test_r_a2l_def_151_arr_3_echo_cap_layout_mode(tmp_path):
    word = "M" * S
    blocks = _rl("RL_A", f"FNC_VALUES 1 UWORD {word} DIRECT") + \
        _valblk("VA", "0x10", "RL_A", "NO_COMPU_METHOD", "0", "65535", "MATRIX_DIM 2")
    a2l_data = _parse(tmp_path, blocks)
    d = a2ldef.describe_definition("VA", a2l_data)
    is_refused(d, "A2L-DEF-LAYOUT-MODE",
               f"VA: the record layout RL_A stores FNC_VALUES as {'M' * _ECHO}{_ELLIPSIS}, "
               "which the system cannot read")


def test_r_a2l_def_151_arr_4_echo_cap_layout_datatype(tmp_path):
    word = "T" * S
    blocks = _rl("RL_D", f"FNC_VALUES 1 {word} ROW_DIR DIRECT") + \
        _valblk("VD", "0x10", "RL_D", "NO_COMPU_METHOD", "0", "65535", "MATRIX_DIM 2")
    a2l_data = _parse(tmp_path, blocks)
    d = a2ldef.describe_definition("VD", a2l_data)
    is_refused(d, "A2L-DEF-LAYOUT-DATATYPE",
               f"VD: the record layout RL_D gives FNC_VALUES the datatype {'T' * _ECHO}{_ELLIPSIS}, "
               "which the system cannot read")


def test_r_a2l_def_151_arr_5_echo_cap_mod_common_alignment(tmp_path):
    word = "9" * S
    blocks = _rl("RL_CA2", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                 "FNC_VALUES 3 UWORD ROW_DIR DIRECT") + \
        _curve("CA2", "0x100", "RL_CA2", _axis("STD_AXIS", "CM_IDENT", "2", "0", "255"))
    a2l_data = _parse(tmp_path, blocks, mod_common=(f"ALIGNMENT_WORD {word}",))
    d = a2ldef.describe_definition("CA2", a2l_data)
    is_refused(d, "A2L-DEF-ALIGNMENT",
               f"CA2: the MOD_COMMON line ALIGNMENT_WORD {'9' * _ECHO}{_ELLIPSIS} cannot be read")
