"""Inc 2 E3 round-2 architect probe (batch-103): re-measure the corrected graph's one-walk describe.

Runs on <runner> against the read-only clone at e07fb00. Imports ``s19_app`` from the clone and drives
PURE functions only (parse, tokenizer, section walk, the reused conversion); no Textual app, no display,
no clipboard. It writes only into the scratch folder given as argv[2]. It is a cost prototype of the
graph's ``describe_definitions`` walk (graph-inc2.md at 9acf0bc9), not the model.

Usage: python -I i2e3ar2-probe.py <clone root> <scratch dir>
"""
from __future__ import annotations

import math
import re
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

DEC_RE = re.compile(r"%(\d*)(?:\.(\d+))?f?\Z", re.ASCII)
MASK_RE = re.compile(r"(0x[0-9A-Fa-f]{1,16}|[0-9]{1,20})\Z", re.ASCII)
CNT_RE = re.compile(r"[0-9]{1,9}\Z", re.ASCII)
CTRL = {i: "�" for i in [*range(0x20), 0x7F, *range(0x80, 0xA0)]}
SIZES = {"UBYTE": 1, "SBYTE": 1, "UWORD": 2, "SWORD": 2, "ULONG": 4, "SLONG": 4, "A_UINT64": 8,
         "A_INT64": 8, "FLOAT16_IEEE": 2, "FLOAT32_IEEE": 4, "FLOAT64_IEEE": 8}
TYPES = {"IDENTICAL", "LINEAR", "RAT_FUNC", "TAB_INTP", "TAB_NOINTP", "TAB_VERB"}


@dataclass(frozen=True)
class Refusal:
    code: str
    message: str


@dataclass(frozen=True)
class Limits:
    lower: float | None
    upper: float | None
    lower_text: str
    upper_text: str


@dataclass(frozen=True)
class EnumEntry:
    raw: float
    raw_max: float | None
    text: str


@dataclass(frozen=True)
class Definition:
    name: str
    section: str
    char_type: str | None
    kind: str
    address: int | None
    byte_length: int | None
    datatype: str | None
    byte_order: str
    bit_mask: int | None
    bit_mask_text: str | None
    conversion_type: str | None
    method_name: str | None
    display_format: str | None
    decimals: int | None
    unit: str
    limits: Limits
    extended_limits: Limits | None
    enum_table: str | None
    enum_entries: tuple
    default_text: str | None
    coeffs_linear: tuple | None
    coeffs: tuple | None
    compu_tab_ref: str | None
    refusal: Refusal | None


def line(tag, value):
    print(f"[{tag}] {value}", flush=True)


def fnum(a2l, w):
    v = a2l._to_float(w)
    return v if v is not None and math.isfinite(v) else None


def build_maps(a2l, data):
    objects, methods, tables = {}, {}, {}
    stack = list(reversed(data["sections"]))
    while stack:
        s = stack.pop()
        n = s.get("name")
        if n in ("MEASUREMENT", "CHARACTERISTIC"):
            objects.setdefault(a2l.parse_begin_meta(s.get("meta", "") or "")[0], s)
        elif n == "COMPU_METHOD":
            methods.setdefault(a2l.parse_begin_meta(s.get("meta", "") or "")[0], s)
        elif n in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
            tables.setdefault(a2l.parse_begin_meta(s.get("meta", "") or "")[0], s)
        ch = s.get("children")
        if ch:
            stack.extend(reversed(ch))
    tags_by_name = {}
    for t in data["tags"]:
        tags_by_name.setdefault(t["name"], t)
    return tags_by_name, objects, methods, tables


def words_of(a2l, s):
    return a2l._flatten_body_tokens([s.get("meta", "") or ""] + list(s.get("lines") or []))


def read_record(a2l, mw):
    rec = {"name": mw[0] if mw else None, "long_identifier": mw[1] if len(mw) > 1 else None,
           "conversion_type": mw[2] if len(mw) > 2 else None, "format": mw[3] if len(mw) > 3 else None,
           "unit": mw[4] if len(mw) > 4 else None, "coeffs": None, "coeffs_linear": None,
           "compu_tab_ref": None, "formula": None}
    i = 5
    while i < len(mw):
        w = mw[i]
        if w == "COEFFS" and rec["coeffs"] is None:
            rec["coeffs"] = tuple(fnum(a2l, x) for x in mw[i + 1:i + 7])
            i += 7
            continue
        if w == "COEFFS_LINEAR" and rec["coeffs_linear"] is None:
            rec["coeffs_linear"] = tuple(fnum(a2l, x) for x in mw[i + 1:i + 3])
            i += 3
            continue
        if w == "COMPU_TAB_REF" and rec["compu_tab_ref"] is None and i + 1 < len(mw):
            rec["compu_tab_ref"] = mw[i + 1]
            i += 2
            continue
        i += 1
    return rec


def read_table(a2l, s):
    tw = words_of(a2l, s)
    rng = s.get("name") == "COMPU_VTAB_RANGE"
    j = 2 if rng else 3
    if len(tw) <= j or not CNT_RE.match(tw[j]):
        return (s.get("name"), (), None)
    n = int(tw[j])
    j += 1
    entries, default = [], None
    step = 3 if rng else 2
    while j < len(tw) and len(entries) < n:
        if tw[j] == "DEFAULT_VALUE":
            break
        chunk = tw[j:j + step]
        j += step
        if len(chunk) < step:
            break
        lo = fnum(a2l, chunk[0])
        hi = fnum(a2l, chunk[1]) if rng else None
        if lo is None or (rng and hi is None):
            continue
        entries.append(EnumEntry(lo, hi, chunk[-1]))
    while j < len(tw):
        if tw[j] == "DEFAULT_VALUE" and j + 1 < len(tw):
            default = tw[j + 1]
            break
        j += 1
    return (s.get("name"), tuple(entries), default)


def refuse(name, code, msg, **kw):
    return dict(name=name, code=code, message=(name + ": " + msg).translate(CTRL), **kw)


def describe_one(a2l, name, maps, layouts):
    tags_by_name, objects, methods, tables = maps
    tag = tags_by_name.get(name)
    if tag is None:
        return refuse(name, "A2L-DEF-NAME", "no tag of that name in the A2L")
    sec = objects.get(name)
    words = words_of(a2l, sec) if sec is not None else []
    section = tag.get("section") or ""
    hn = 8 if section == "MEASUREMENT" else 9
    header, rest = words[:hn], words[hn:]
    fmt = unit = mask_word = None
    ext = None
    mask_line = False
    for i, w in enumerate(rest):
        if w == "FORMAT" and fmt is None and i + 1 < len(rest):
            fmt = rest[i + 1]
        elif w == "EXTENDED_LIMITS" and ext is None and i + 2 < len(rest):
            a, b = fnum(a2l, rest[i + 1]), fnum(a2l, rest[i + 2])
            ext = Limits(a, b, rest[i + 1], rest[i + 2]) if a is not None and b is not None else False
        elif w in ("PHYS_UNIT", "UNIT") and unit is None and i + 1 < len(rest):
            unit = rest[i + 1]
        elif w == "BIT_MASK" and not mask_line:
            mask_line = True
            mask_word = rest[i + 1] if i + 1 < len(rest) else None
    t = dict(tag) if section == "MEASUREMENT" else tag
    if section == "MEASUREMENT" and len(header) >= 8:
        t.setdefault("datatype", header[2])
        if t.get("datatype") is None:
            t["datatype"] = header[2]
    datatype = t.get("datatype")
    if datatype not in SIZES:
        lay = a2l._resolve_record_layout(t.get("record_layout_name") or t.get("deposit"), layouts)
        datatype = (lay or {}).get("decode_type")
    method_name = str(t.get("conversion") or "")
    rec = None
    ctype = None
    if method_name and method_name != "NO_COMPU_METHOD":
        ms = methods.get(method_name)
        if ms is not None:
            rec = read_record(a2l, words_of(a2l, ms))
            ctype = rec["conversion_type"]
    char_type = t.get("char_type")
    kind = "text" if char_type == "ASCII" else ("enum" if ctype == "TAB_VERB" else "number")
    if section == "CHARACTERISTIC" and char_type not in ("VALUE", "ASCII"):
        kind = ""
    entries, default, table = (), None, None
    if kind == "enum" and rec is not None:
        table = rec["compu_tab_ref"]
        ts = tables.get(table or "")
        if ts is not None:
            _, entries, default = read_table(a2l, ts)
    dec = None
    if fmt:
        m = DEC_RE.match(fmt)
        if m and m.group(2) is not None:
            dec = 17 if len(m.group(2)) > 2 else min(int(m.group(2)), 17)
    lo_w = header[-2] if len(header) >= 2 else None
    hi_w = header[-1] if len(header) >= 1 else None
    lo, hi = fnum(a2l, lo_w), fnum(a2l, hi_w)
    limits = Limits(lo, hi, lo_w if lo is not None else "", hi_w if hi is not None else "")
    mask = None
    refusal = None
    addr, length = t.get("address"), t.get("length")
    if mask_line:
        if mask_word is None or not MASK_RE.match(mask_word) or kind == "text":
            refusal = Refusal("A2L-DEF-MASK", (name + ": the bit mask cannot be applied").translate(CTRL))
        else:
            mask = int(mask_word, 16) if mask_word[:2] == "0x" else int(mask_word)
    elif t.get("bit_org") is not None:
        refusal = Refusal("A2L-DEF-MASK", (name + ": the bit mask cannot be applied").translate(CTRL))
    if refusal is None:
        if kind == "":
            refusal = Refusal("A2L-DEF-KIND", (name + ": the system has no definition").translate(CTRL))
        elif addr is None or length is None:
            refusal = Refusal("A2L-DEF-ADDRESS", (name + ": no address or no length").translate(CTRL))
        elif length < 1 or length > 1048576 or addr < 0 or addr + length - 1 > 0xFFFFFFFF:
            refusal = Refusal("A2L-DEF-ADDRESS", (name + f": its span of {length} bytes").translate(CTRL))
        elif kind != "text" and datatype not in SIZES:
            refusal = Refusal("A2L-DEF-DATATYPE", (name + ": no datatype").translate(CTRL))
        elif kind != "text" and SIZES[datatype] != length:
            refusal = Refusal("A2L-DEF-LENGTH", (name + ": its length differs").translate(CTRL))
        elif method_name and method_name != "NO_COMPU_METHOD" and rec is None:
            refusal = Refusal("A2L-DEF-METHOD", (name + ": not declared").translate(CTRL))
        elif rec is not None and ctype not in TYPES:
            refusal = Refusal("A2L-DEF-CONVERSION", (name + ": not supported").translate(CTRL))
        elif kind == "enum" and not entries:
            refusal = Refusal("A2L-DEF-TABLE-EMPTY", (name + ": no entries").translate(CTRL))
    return Definition(name, section, char_type, kind, addr, length, datatype,
                      str(t.get("effective_byte_order") or "little"), mask, mask_word, ctype, method_name,
                      fmt or (rec or {}).get("format"), dec, unit or (rec or {}).get("unit") or "", limits,
                      ext or None, table, entries, default, (rec or {}).get("coeffs_linear"),
                      (rec or {}).get("coeffs"), (rec or {}).get("compu_tab_ref"), refusal)


def describe_all(a2l, names, data):
    maps = build_maps(a2l, data)
    layouts = data.get("record_layouts_by_name") or {}
    return {n: describe_one(a2l, n, maps, layouts) for n in names}


def main(argv):
    clone = Path(argv[1])
    scratch = Path(argv[2])
    sys.path.insert(0, str(clone))
    import s19_app
    from s19_app.tui import a2l
    print("s19_app.__file__ =", s19_app.__file__, flush=True)
    data = a2l.parse_a2l_file(clone / "examples" / "case_00_public" / "software_a.a2l")
    names = [t["name"] for t in data["tags"]]
    line("R0 software_a tags / distinct names", (len(names), len(set(names))))

    runs = []
    for _ in range(3):
        t0 = time.perf_counter()
        out = describe_all(a2l, names, data)
        runs.append(time.perf_counter() - t0)
    kinds = {}
    for d in out.values():
        k = d.kind if isinstance(d, Definition) else "name-refused"
        kinds[k] = kinds.get(k, 0) + 1
    line("R1 describe_definitions prototype over every name: runs s / median s", (
        [round(r, 3) for r in runs], round(statistics.median(runs), 3)))
    line("R1 kinds of the prototype's definitions", sorted(kinds.items()))
    refused = {}
    for d in out.values():
        if isinstance(d, Definition) and d.refusal is not None:
            refused[d.refusal.code] = refused.get(d.refusal.code, 0) + 1
    line("R1 refusals of the prototype (rough)", sorted(refused.items()))

    # the maps alone (the one walk + the tags pass)
    walks = []
    for _ in range(5):
        t0 = time.perf_counter()
        build_maps(a2l, data)
        walks.append(time.perf_counter() - t0)
    line("R2 the one walk + tags pass alone, median ms", round(statistics.median(walks) * 1000, 2))

    # describe_definition(name) = describe_definitions([name])[name]: the full walk per single call
    sample = names[:: max(1, len(names) // 20)][:20]
    t0 = time.perf_counter()
    for n in sample:
        describe_all(a2l, [n], data)
    line("R3 describe_definition via the full walk, ms per call", round((time.perf_counter() - t0) * 1000 / len(sample), 2))

    # the cost note's single-name variant: compare first words cheaply, parse only a match
    def first_word(meta):
        m = (meta or "").split(None, 1)
        return m[0] if m else ""
    t0 = time.perf_counter()
    for n in sample:
        stack = list(reversed(data["sections"]))
        hit = None
        while stack:
            s = stack.pop()
            if hit is None and s.get("name") in ("MEASUREMENT", "CHARACTERISTIC") and first_word(s.get("meta")) == n:
                if a2l.parse_begin_meta(s.get("meta", "") or "")[0] == n:
                    hit = s
            ch = s.get("children")
            if ch:
                stack.extend(reversed(ch))
    line("R4 one cheap first-word walk (objects only), ms per call", round((time.perf_counter() - t0) * 1000 / len(sample), 2))

    # Inc 3 facts: kinds outside Inc 2 and their per-object lookups if done as walks
    ck = {}
    for t in data["tags"]:
        if t.get("section") == "CHARACTERISTIC":
            ck[t.get("char_type")] = ck.get(t.get("char_type"), 0) + 1
    line("R5 software_a CHARACTERISTIC kinds", sorted(ck.items(), key=lambda kv: -kv[1]))
    axes = {}
    modules = 0
    stack = list(reversed(data["sections"]))
    while stack:
        s = stack.pop()
        if s.get("name") == "AXIS_DESCR":
            w = (s.get("meta") or "").split()
            k = w[0] if w else "(none)"
            axes[k] = axes.get(k, 0) + 1
        if s.get("name") == "MODULE":
            modules += 1
        ch = s.get("children")
        if ch:
            stack.extend(reversed(ch))
    line("R5 AXIS_DESCR by kind / MODULE count", (sorted(axes.items()), modules))
    t0 = time.perf_counter()
    for _ in range(10):
        a2l._collect_sections_by_name(data["sections"], "AXIS_PTS")
    line("R5 one AXIS_PTS walk (_collect_sections_by_name), ms", round((time.perf_counter() - t0) * 100, 2))

    # the corrected cases checked through the reused conversion (pure)
    a2l_text = """ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin COMPU_METHOD CM_T4 "" TAB_INTP "%.1" ""
COMPU_TAB_REF TAB_T4
/end COMPU_METHOD
/begin COMPU_TAB TAB_T4 "" TAB_INTP 2
0 0.0
10 1.0
/end COMPU_TAB
/begin COMPU_METHOD CM_L01 "" LINEAR "%.15" ""
COEFFS_LINEAR 0.1 0
/end COMPU_METHOD
/begin COMPU_METHOD CM_BIG "" LINEAR "%" ""
COEFFS_LINEAR 1 1e10
/end COMPU_METHOD
/end MODULE
/end PROJECT
"""
    p = scratch / "r2-inline.a2l"
    p.write_text(a2l_text, encoding="utf-8")
    d2 = a2l.parse_a2l_file(p)
    cms, tabs = d2.get("compu_methods_by_name") or {}, d2.get("compu_tabs_by_name") or {}
    line("R6 inline methods / tables", (sorted(cms), sorted(tabs)))

    def enc(cm, dt, x):
        tag = {"name": "X", "char_type": None, "matrix_dim": None, "datatype": dt, "length": SIZES[dt],
               "effective_byte_order": "big", "compu_method_name": cm, "lower_limit": None, "upper_limit": None}
        return a2l.encode_physical_to_raw_bytes(tag, x, {cm: cms[cm]}, tabs, None)

    r = enc("CM_T4", "UWORD", 0.55)
    raw = (r[0][0] << 8) | r[0][1] if r[0] else None
    dec = a2l._apply_compu_method(raw, cms["CM_T4"], tabs, (0.0, 0.55)) if raw is not None else None
    line("R6 .45/3 TAB_INTP 0.55 -> encode result / raw / decode", (r, raw, dec))
    if dec is not None:
        pv = dec[0]
        line("R6 .45/3 p, %.1f text, |p-0.55| <= 0.05", (pv, f"{pv:.1f}", abs(pv - 0.55) <= 0.5 * 10 ** -1))
    r = enc("CM_L01", "UWORD", 4.1)
    raw = (r[0][0] << 8) | r[0][1] if r[0] else None
    dec = a2l._apply_compu_method(raw, cms["CM_L01"], tabs, (None, None))
    line("R6 E3A-02 LINEAR 0.1 4.1 -> raw / p / %.15g / |p-x|<=0.5e-15", (raw, dec[0], "%.15g" % dec[0],
         abs(dec[0] - 4.1) <= 0.5 * 10 ** -15))
    r = enc("CM_BIG", "FLOAT64_IEEE", 1.0000001)
    import struct
    rawf = struct.unpack(">d", bytes(r[0]))[0] if r[0] else None
    dec = a2l._apply_compu_method(rawf, cms["CM_BIG"], tabs, (None, None))
    line("R6 .54/3 FLOAT64 LINEAR 1 1e10 1.0000001 -> raw / p / %.15g / %.6g", (rawf, dec[0], "%.15g" % dec[0],
         "%.6g" % dec[0]))
    big = {"name": "U", "char_type": None, "matrix_dim": None, "datatype": "A_UINT64", "length": 8,
           "effective_byte_order": "big", "compu_method_name": "NO_COMPU_METHOD", "lower_limit": None,
           "upper_limit": None}
    r = a2l.encode_physical_to_raw_bytes(big, float("9007199254740993"), {}, tabs, None)
    line("R6 .54/4 A_UINT64 9007199254740993 -> encode result", r)
    line("R6 .37 vs .38: '%.15g' of 9007199254740992 / int text", ("%.15g" % 9007199254740992.0, str(9007199254740992)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
