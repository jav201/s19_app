"""Shared INLINE3 builders for the batch-103 Inc 3a (arrays and axes) tests.

Every fixture is synthetic (no proprietary A2L material, no public-corpus
text).  The builders produce one PROJECT / one MODULE with ``MOD_COMMON``
``BYTE_ORDER MSB_FIRST`` and no ALIGNMENT line, plus the eleven single-component
``FNC_VALUES`` record layouts Inc 2's INLINE fixture carries, then the blocks a
case names (record layouts, COMPU_METHODs, tables, objects, AXIS_DESCRs and
AXIS_PTS objects), every component line written in full.  The app's parser
ignores leading whitespace, so blocks are appended verbatim.

Dependencies:
    - ``s19_app.tui.a2l_parse.parse_a2l_file`` (the app's parser, read only)
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from s19_app.tui.a2l_parse import parse_a2l_file

FFFD = "�"

#: The single-component ``FNC_VALUES`` layouts every INLINE3 file carries.
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


def img(addr: int, data: bytes) -> dict[int, int]:
    """A byte image starting at ``addr``."""
    return {addr + i: b for i, b in enumerate(data)}


def inline(tmp_path: Path, *blocks: str, mod_common: tuple[str, ...] = (),
           byte_order: str = "MSB_FIRST", layouts=BASE_LAYOUTS) -> dict:
    """Write and parse an INLINE3 file; ``blocks`` are appended verbatim.

    The file also carries the standard INLINE3 method ``CM_IDENT`` (IDENTICAL,
    format ``%.3``) so the ``STD(n)`` / ``C(<axis>; ...)`` shorthand and every
    ``axis(..., "CM_IDENT", ...)`` resolve without a per-case declaration.
    """
    lines = ["ASAP2_VERSION 1 71", '/begin PROJECT P ""', '  /begin MODULE M ""']
    mc = [f'    /begin MOD_COMMON ""', f"      BYTE_ORDER {byte_order}"]
    mc += [f"      {e}" for e in mod_common]
    mc.append("    /end MOD_COMMON")
    lines += mc
    for rl, dt in layouts:
        lines += [f"    /begin RECORD_LAYOUT {rl}", f"      FNC_VALUES 1 {dt} ROW_DIR DIRECT", "    /end RECORD_LAYOUT"]
    lines.append(cm("CM_IDENT", "IDENTICAL"))
    lines += list(blocks)
    lines += ["  /end MODULE", "/end PROJECT"]
    _counter[0] += 1
    path = tmp_path / f"inline3_{_counter[0]}.a2l"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return parse_a2l_file(path)


def rl(name: str, *lines: str) -> str:
    """A RECORD_LAYOUT block; ``lines`` are the component / keyword lines."""
    body = [f"/begin RECORD_LAYOUT {name}"]
    body += [f"  {l}" for l in lines]
    body.append("/end RECORD_LAYOUT")
    return "\n".join(body)


def cm(name: str, typ: str | None, *coeffs: str, fmt: str = '"%.3"', unit: str = '""',
       ref: str | None = None) -> str:
    """A COMPU_METHOD; ``CM(<type> <coeffs>)`` as Inc 2's INLINE helper."""
    body = [f'/begin COMPU_METHOD {name} ""']
    if typ is not None:
        body.append(f"  {typ} {fmt} {unit}")
    if typ == "LINEAR" and coeffs:
        body.append("  COEFFS_LINEAR " + " ".join(coeffs))
    elif typ == "RAT_FUNC" and coeffs:
        body.append("  COEFFS " + " ".join(coeffs))
    if ref is not None:
        body.append(f"  COMPU_TAB_REF {ref}")
    body.append("/end COMPU_METHOD")
    return "\n".join(body)


def vtab(name: str, count: str, *pairs: str, default: str | None = None) -> str:
    """A COMPU_VTAB; each pair is the raw line text, e.g. ``0 "A"``."""
    body = [f'/begin COMPU_VTAB {name} "" TAB_VERB {count}']
    body += [f"  {p}" for p in pairs]
    if default is not None:
        body.append(f'  DEFAULT_VALUE "{default}"')
    body.append("/end COMPU_VTAB")
    return "\n".join(body)


def ctab(name: str, kind: str, *pairs: str) -> str:
    """A COMPU_TAB; each pair is the raw ``x y`` line text."""
    body = [f'/begin COMPU_TAB {name} "" {kind} {len(pairs)}']
    body += [f"  {p}" for p in pairs]
    body.append("/end COMPU_TAB")
    return "\n".join(body)


def vrange(name: str, count: str, *triples: str, default: str | None = None) -> str:
    """A COMPU_VTAB_RANGE; each triple is the raw ``min max "text"`` line."""
    body = [f'/begin COMPU_VTAB_RANGE {name} "" {count}']
    body += [f"  {t}" for t in triples]
    if default is not None:
        body.append(f'  DEFAULT_VALUE "{default}"')
    body.append("/end COMPU_VTAB_RANGE")
    return "\n".join(body)


def axis(kind: str, method: str, maxpts: str, lo: str, hi: str, *kw: str,
         on_begin: bool = False) -> str:
    """An AXIS_DESCR block (nested inside a CHARACTERISTIC).

    With ``on_begin`` the header stands on its ``/begin AXIS_DESCR`` line
    (R-A2L-DEF.92/4, H3e / CG-4); otherwise the header sits on its own line.
    """
    if on_begin:
        body = [f"  /begin AXIS_DESCR {kind} NO_INPUT_QUANTITY {method} {maxpts} {lo} {hi}"]
    else:
        body = ["  /begin AXIS_DESCR", f"    {kind} NO_INPUT_QUANTITY {method} {maxpts} {lo} {hi}"]
    body += [f"    {w}" for w in kw]
    body.append("  /end AXIS_DESCR")
    return "\n".join(body)


def _merge_extras(args: tuple[str, ...], extras) -> tuple[str, ...]:
    """Positional extras first, then keyword ``extras``; a bare string is one line."""
    if extras is None:
        return tuple(args)
    if isinstance(extras, str):
        return tuple(args) + (extras,)
    return tuple(args) + tuple(extras)


def axis_pts(name: str, addr: str, layout: str, maxpts: str, conv: str = "CM_IDENT",
             lo: str = "0", hi: str = "255", *args: str,
             input_qty: str = "NO_INPUT_QUANTITY", extras: tuple[str, ...] | str = ()) -> str:
    """An AXIS_PTS object block."""
    extras = _merge_extras(args, extras)
    body = [f'/begin AXIS_PTS {name} "{name} axis"', f"  {addr}", f"  {input_qty}", f"  {layout}",
            "  0", f"  {conv}", f"  {maxpts}", f"  {lo} {hi}"]
    body += [f"  {e}" for e in extras]
    body.append("/end AXIS_PTS")
    return "\n".join(body)


def characteristic(name: str, kind: str, addr: str, layout: str, conv: str,
                   lo: str, hi: str, *args: str, axes: tuple[str, ...] = (),
                   extras: tuple[str, ...] | str = ()) -> str:
    """A CHARACTERISTIC block; ``axes`` are pre-built AXIS_DESCR blocks."""
    extras = _merge_extras(args, extras)
    body = [f'/begin CHARACTERISTIC {name} ""', f"  {kind} {addr} {layout} 0 {conv} {lo} {hi}"]
    body += [f"  {e}" for e in extras]
    body += list(axes)
    body.append("/end CHARACTERISTIC")
    return "\n".join(body)


def valblk(name: str, addr: str, layout: str, conv: str = "NO_COMPU_METHOD",
           lo: str = "0", hi: str = "65535", *args: str,
           extras: tuple[str, ...] | str = ()) -> str:
    return characteristic(name, "VAL_BLK", addr, layout, conv, lo, hi,
                          *_merge_extras(args, extras))


def curve(name: str, addr: str, layout: str, axis_block: str, conv: str = "CM_IDENT",
          lo: str = "0", hi: str = "65535", *args: str,
          extras: tuple[str, ...] | str = ()) -> str:
    return characteristic(name, "CURVE", addr, layout, conv, lo, hi,
                          *_merge_extras(args, extras), axes=(axis_block,))


def mapchar(name: str, addr: str, layout: str, *axis_blocks: str, conv: str = "CM_IDENT",
            lo: str = "0", hi: str = "65535", extras: tuple[str, ...] | str = ()) -> str:
    return characteristic(name, "MAP", addr, layout, conv, lo, hi,
                          *_merge_extras((), extras), axes=axis_blocks)


def meas(name: str, dt: str, conv: str = "NO_COMPU_METHOD", lo: str = "0", hi: str = "65535",
         *args: str, addr: str | None = None, extras: tuple[str, ...] | str = ()) -> str:
    extras = _merge_extras(args, extras)
    body = [f'/begin MEASUREMENT {name} ""', f"  {dt} {conv} 0 0 {lo} {hi}"]
    if addr is not None:
        body.append(f"  ECU_ADDRESS {addr}")
    body += [f"  {e}" for e in extras]
    body.append("/end MEASUREMENT")
    return "\n".join(body)


def load(name: str) -> dict:
    """Parse one public example file."""
    return parse_a2l_file(Path(__file__).resolve().parents[2] / "examples" / "case_00_public" / name)


def is_refused(d, code: str, message: str) -> None:
    from s19_app.tui.a2l_definition import Refusal
    assert d.refusal == Refusal(code, message), d.refusal
