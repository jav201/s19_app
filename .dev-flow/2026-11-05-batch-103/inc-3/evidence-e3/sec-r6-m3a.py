"""Throwaway stdlib model of Inc 3a's describe and decode as the E3 round-5 correction states them (graph-inc3.md at
32e4db90; the echo cap of 71113bc0), for the E3 round-6 security probes. Not product code.

Base: the round-5 model `sec-r5-m3a.py` (loaded from this file's folder), which is also the negative control
MUTANT="r5" (the round-5 graph) unchanged. Changed only where 32e4db90 / 71113bc0 changed the graph:
  * `echo(word)`: R-A2L-DEF.151 at the cap of 256 -- the first 256 characters, each one outside U+0021 ... U+007E as
    U+FFFD, then "…" when the word is longer. Computed once, at reduction (graph *Lookups*).
  * `_read_record_layout` (graph :476): the owner-free stored refusal holds `<component>` / `<word>` as their .151
    echo; `<layout>` keeps .137 (`_clean`, once, at reduction: the ruling's ".151's reach"); `<name>` + stored text
    per call.
  * `_module_common` (:541): each class's first unreadable word held as its .151 echo; `_describe_array` writes it
    into the .144 message as it is. The .89 moved-component message writes `<layout>` per call with `_clean` (.137).
  * `_conversion_fields` (:361): the stored method record = the six fields + the type verdict, the type echo, the
    COMPU_TAB_REF echo and the format's decimals (Inc 2a's `_display_decimals`), computed at reduction. CONVERSION and
    TABLE messages = `<name>` + stored text; an axis's decimals from the record. TABLE-EMPTY: knob TE = "echo" (the
    general rule: the stored COMPU_TAB_REF echo) or "clean" (the node text: "messages as R-A2L-DEF.137", per call).
  * `_decode_stored` (:760): TAB_INTP / TAB_NOINTP by one bisect on the frozen parse's sorted entries, read in place
    (`table_bisect`, variant BISECT "v1" = the graph's text: exact entries, ties and ends; "v2" = v1 plus the frozen
    function's rounded-distance ties and its no-pair error), never the frozen `_table_lookup`. Scalars decode through
    the same node (3a's `decode_definition` calls `_decode_stored`).
  * Inc 2a's parts, "2a, as ruled" (the 2a gap pass is not written; modelled the way the round-5 ruling says it makes
    them):
      - the enum table reduced once per walk: each entry text and the default cleaned once; a dict raw -> the first
        entry (COMPU_VTAB); for COMPU_VTAB_RANGE a bisect over the disjoint segments of the ranges, each segment holding
        the first range in file order that covers it; `_enum_entry_text` / `_enum_text` one lookup each, returning the
        stored strings (a reference, never a copy);
      - the method record's derived values: `_display_decimals` once per format text; the record that 2a's
        `_describe_one` reads is a proxy whose unsupported type word / undeclared TAB_VERB reference are 1-character
        sentinels, so its inline steps cost O(1), and `fix_scalar` writes the CONVERSION / TABLE / TABLE-EMPTY messages
        from 3a's `_conversion_fields` (3a's `_describe_one` routes its method steps through that node) and puts the
        file's words back in the fields by reference;
      - `_resolve_datatype` per layout and the method / table reads once per walk (the round-5 model's E5 memos, kept).
Counters in `STATS`.
"""
from __future__ import annotations

import bisect
import dataclasses
import heapq
import importlib.util
import math
import operator
import pathlib
import types

_spec = importlib.util.spec_from_file_location("m3r5_base", str(pathlib.Path(__file__).with_name("sec-r5-m3a.py")))
R5 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R5)
R4, R3, B = R5.R4, R5.R3, R5.B

MP = types.MappingProxyType
A = None
D = None
MUTANT = None          # None | "r5" | "every-pair" | "rd-per-object" | "per-call"
TE = "echo"            # TABLE-EMPTY reading
BISECT = "v1"
CAP = 256
SUPPORTED = R5.SUPPORTED
SIX = R5.SIX
ORIG = {}
STATS = R5.STATS
ENUM = {}              # id(entries tuple) -> the reduced enum form (2a, as ruled); the form holds the tuple
WALK = {"on": False, "ct": {}, "dec": {}, "proxy": {}}
_KEY = operator.itemgetter(0)


def echo(word):
    """R-A2L-DEF.151: a file word in a refusal message (at most 256 characters, U+0021..U+007E kept)."""
    if word is None:
        return None
    head = word[:CAP]
    out = "".join(ch if "\x21" <= ch <= "\x7e" else "�" for ch in head)
    return out + "…" if len(word) > CAP else out


def c(text):
    return D._clean(text)


def new_walk(ct_by_name):
    return {"on": True, "ct": ct_by_name, "dec": {}, "proxy": {}}


# ------------------------------------------------------------------ binding and mutants
def bind(a2l_module, defn_module):
    global A, D
    A, D = a2l_module, defn_module
    for k, fn in (("rm", "_read_method_record"), ("rt", "_read_enum_table"), ("dd", "_display_decimals"),
                  ("eet", "_enum_entry_text"), ("et", "_enum_text")):
        ORIG.setdefault(k, getattr(D, fn))
    R5.bind(a2l_module, defn_module)            # E5 memos (method / table reads, _resolve_datatype)
    ORIG["rm4"], ORIG["rt4"] = D._read_method_record, D._read_enum_table
    D._read_method_record, D._read_enum_table = _rm6, _rt6
    D._display_decimals = _dd6
    D._enum_entry_text, D._enum_text = _eet6, _et6
    set_mutant(None)


def set_mutant(mutant):
    global MUTANT
    MUTANT = mutant
    R5.set_mutant(None if mutant in (None, "r5") else mutant)
    if mutant is None:
        R3.read_record_layout, R3.module_common = read_record_layout, module_common
    else:
        R3.read_record_layout, R3.module_common = R5.read_record_layout, R5.module_common
    R3.check_module_alignment = R5.check_module_alignment


def _r6():
    return MUTANT is None and WALK.get("on")


# ------------------------------------------------------------------ Inc 2a's parts, as ruled
def _rm6(name, by_name):
    rec = ORIG["rm4"](name, by_name)
    if rec is None or not _r6():
        return rec
    memo = WALK["proxy"]
    hit = memo.get(id(rec))
    if hit is None:
        p = dict(rec)
        t = rec.get("conversion_type")
        if t is not None and str(t).upper() not in SUPPORTED:
            p["conversion_type"] = "?"                    # the verdict, once per record
        ref = rec.get("compu_tab_ref")
        if t == "TAB_VERB" and ref is not None:
            tab = ORIG["rt"](ref, WALK["ct"]) if ref in WALK["ct"] else None
            if tab is None or not tab[1]:                 # undeclared or empty: the TABLE / TABLE-EMPTY message is
                p["compu_tab_ref"] = "?"                  # 3a's `_conversion_fields`' (stored echo), `fix_scalar`
        hit = memo[id(rec)] = (rec, p)
    return hit[1]


def _rt6(name, by_name):
    tab = ORIG["rt4"](name, by_name)
    if tab is not None and tab[1] and MUTANT is None and id(tab[1]) not in ENUM:
        ENUM[id(tab[1])] = _enum_form(*tab)
    return tab


def _dd6(fmt):
    if fmt is None or not _r6():
        return ORIG["dd"](fmt)
    memo = WALK["dec"]
    hit = memo.get(id(fmt))
    if hit is None:
        hit = memo[id(fmt)] = (fmt, ORIG["dd"](fmt))
    return hit[1]


def _range_segments(entries):
    rng = [(e.raw, e.raw_max, i) for i, e in enumerate(entries)
           if e.raw == e.raw and e.raw_max == e.raw_max and e.raw <= e.raw_max]
    pts = sorted({x for lo, hi, _ in rng for x in (lo, hi)})
    by_lo = sorted(rng, key=lambda r: r[0])
    heap, j, seg_pt, seg_iv = [], 0, [], []
    for p in pts:
        while j < len(by_lo) and by_lo[j][0] <= p:
            heapq.heappush(heap, (by_lo[j][2], by_lo[j][1]))
            j += 1
        while heap and heap[0][1] < p:
            heapq.heappop(heap)
        seg_pt.append(heap[0][0] if heap else -1)         # the point p itself
        while heap and heap[0][1] <= p:
            heapq.heappop(heap)
        seg_iv.append(heap[0][0] if heap else -1)         # the open interval (p, next point)
    return tuple(pts), tuple(seg_pt), tuple(seg_iv)


def _enum_form(kind, entries, default):
    seen = {}

    def cl(t):
        hit = seen.get(id(t))
        if hit is None:
            hit = seen[id(t)] = (t, D._clean(t))
        return hit[1]

    clean = tuple(cl(e.text) for e in entries)
    if all(e.raw_max is None for e in entries):
        idx = {}
        for i, e in enumerate(entries):
            if e.raw == e.raw:
                idx.setdefault(e.raw, i)
        look = ("dict", MP(idx))
    else:
        look = ("seg",) + _range_segments(entries)
    STATS["enum_forms"] = STATS.get("enum_forms", 0) + 1
    return MP({"entries": entries, "clean": clean, "default_raw": default,
               "default": D._clean(default) if default is not None else None, "look": look})


def _find(form, stored):
    look = form["look"]
    if look[0] == "dict":
        try:
            return look[1].get(stored, -1)
        except TypeError:
            return -1
    if stored != stored:
        return -1
    pts, sp, si = look[1], look[2], look[3]
    i = bisect.bisect_left(pts, stored)
    if i < len(pts) and pts[i] == stored:
        return sp[i]
    if 0 < i < len(pts):
        return si[i - 1]
    return -1


def _form_of(definition):
    form = ENUM.get(id(definition.enum_entries)) if MUTANT is None else None
    if form is not None and form["entries"] is definition.enum_entries:
        return form
    return None


def _eet6(definition, stored):
    form = _form_of(definition)
    if form is None:
        return ORIG["eet"](definition, stored)
    i = _find(form, stored)
    return form["entries"][i].text if i >= 0 else None


def _et6(definition, stored):
    form = _form_of(definition)
    if form is None:
        return ORIG["et"](definition, stored)
    i = _find(form, stored)
    if i >= 0:
        return form["clean"][i]
    if definition.default_text is not None:
        if definition.default_text is form["default_raw"]:
            return form["default"]
        return D._clean(definition.default_text)
    return f"{D._raw_text(stored)} (no text)"


# ------------------------------------------------------------------ _read_record_layout (round 5: words as echoes)
def _layout_read(name, rl):
    comps, align, fixed, parts, seen = [], {}, {}, [], set()
    for words in B.clean_lines(rl.get("lines")):
        if not words:
            continue
        w0 = words[0]
        if w0 in B.COMPONENTS and w0 not in seen and len(words) <= B.MAX_WORDS[w0]:
            seen.add(w0)
            comps.append(tuple(words))
        elif w0 in B.COMPONENTS and len(words) > B.MAX_WORDS[w0]:
            parts.append(words[B.MAX_WORDS[w0]])
        elif w0 in ("FIX_NO_AXIS_PTS_X", "FIX_NO_AXIS_PTS_Y") and len(words) == 2 and B.whole(words[1]) is not None:
            fixed[w0[-1]] = B.whole(words[1])
        elif w0 in B.ALIGN_WORDS and len(words) == 2 and (B.whole(words[1]) or 0) >= 1:
            align[w0] = words[1]
        elif words == ["DIRECT"]:
            pass
        else:
            parts.append(w0)
    lname = c(name)                                       # <layout>: .137, once (the ruling's reading)
    pos = [B.whole(x[1]) if len(x) > 1 else None for x in comps]
    if any(p is None for p in pos) or len(set(pos)) != len(pos):
        return ("REFUSAL", "A2L-DEF-LAYOUT-POSITION", f": the positions of the record layout {lname} do not give one order")
    if parts:
        return ("REFUSAL", "A2L-DEF-LAYOUT-PART",
                f": the record layout {lname} holds {echo(parts[0])}, which the system cannot read")
    comps = [x for _, x in sorted(zip(pos, comps))]
    for x in comps:
        modes = ("ROW_DIR", "COLUMN_DIR") if x[0] == "FNC_VALUES" else (
            ("INDEX_INCR", "INDEX_DECR") if x[0] in ("AXIS_PTS_X", "AXIS_PTS_Y") else None)
        if modes is None:
            continue
        for word, ok in ((x[3] if len(x) > 3 else None, modes), (x[4] if len(x) > 4 else None, ("DIRECT",))):
            if word not in ok:
                return ("REFUSAL", "A2L-DEF-LAYOUT-MODE", f": the record layout {lname} stores {x[0]} as "
                        f"{echo(word) if word is not None else '(none)'}, which the system cannot read")
    for x in comps:
        dt = x[2] if len(x) > 2 else None
        if dt not in B.DATATYPES or (x[0] in ("NO_AXIS_PTS_X", "NO_AXIS_PTS_Y") and dt not in B.COUNT_DATATYPES):
            return ("REFUSAL", "A2L-DEF-LAYOUT-DATATYPE", f": the record layout {lname} gives {x[0]} the datatype "
                    f"{echo(dt) if dt is not None else '(none)'}, which the system cannot read")
    return MP({"name": name, "components": tuple(comps), "alignment": tuple(align.items()), "fixed": MP(dict(fixed))})


def read_record_layout(name, a2l_data, owner, maps):
    rl = (a2l_data.get("record_layouts_by_name") or {}).get(name)
    if rl is None:
        return None
    reads = maps["reads"]
    key = id(rl)
    if key not in reads:
        maps["stats"]["layout_reads"] += 1
        reads[key] = _layout_read(name, rl)
    r = reads[key]
    if isinstance(r, tuple):
        return (r[0], r[1], c(owner) + r[2])
    return r


def module_common(section, maps):
    mc = maps["mod_common_of"].get(id(section))
    if mc is None:
        return None
    reads = maps["reads"]
    key = id(mc)
    if key not in reads:
        maps["stats"]["modc_reads"] += 1
        al = {}
        for idx, w in enumerate(B.clean_lines(mc.get("lines"))):
            if not w or w[0] not in B.ALIGN_WORDS:
                continue
            word = w[1] if len(w) > 1 else None
            bad, last = al.get(w[0], (None, None))
            n = B.whole(word) if word is not None else None
            if n is None or n < 1:
                if bad is None:
                    bad = (echo(word) if word is not None else "(none)", idx)
            else:
                last = word
            al[w[0]] = (bad, last)
        reads[key] = MP({"alignment": MP(al), "pairs": (),
                         "byte_order": A._byte_order_from_section_lines(mc.get("lines") or [])})
    return reads[key]


# ------------------------------------------------------------------ _conversion_fields (round 5: derived values)
def _method_record(method_word, cm, st):
    raw = ORIG["rm"](method_word, cm)
    rec = {k: raw[k] for k in SIX}
    for k in ("coeffs_linear", "coeffs"):
        rec[k] = None if rec[k] is None else tuple(rec[k])
    t = rec["conversion_type"]
    rec["type_ok"] = t is not None and str(t).upper() in SUPPORTED
    rec["type_echo"] = echo(str(t)) if t else None
    rec["ref_echo"] = echo(rec["compu_tab_ref"])
    rec["decimals"] = ORIG["dd"](rec["format"])
    st["method_reads"] = st.get("method_reads", 0) + 1
    return MP(rec)


def conversion_fields(name, method_word, maps, axis=False):
    st = maps["stats"]
    st["conv_calls"] = st.get("conv_calls", 0) + 1
    f = {"kind": "number", "conversion_type": None, "coeffs_linear": None, "coeffs": None, "compu_tab_ref": None,
         "record_format": None, "record_unit": None, "enum_table": None, "enum_entries": (), "default_text": None,
         "decimals": None}
    if method_word is None or method_word == "NO_COMPU_METHOD":
        return f, None
    cm = maps["cm_by_name"]
    sec = cm.get(method_word)
    if sec is None:
        return f, ("A2L-DEF-METHOD", f"{c(name)}: the conversion method {c(method_word)} is not declared in the A2L")
    reads = maps["reads"]
    if id(sec) not in reads:
        reads[id(sec)] = _method_record(method_word, cm, st)
    rec = reads[id(sec)]
    f.update(conversion_type=rec["conversion_type"], coeffs_linear=rec["coeffs_linear"], coeffs=rec["coeffs"],
             compu_tab_ref=rec["compu_tab_ref"], record_format=rec["format"], record_unit=rec["unit"])
    if axis:
        f["decimals"] = rec["decimals"]
    if not rec["type_ok"]:
        return f, ("A2L-DEF-CONVERSION", f"{c(name)}: the conversion type {rec['type_echo'] or '(none)'} of "
                                         f"{c(method_word)} is not supported")
    if rec["conversion_type"] != "TAB_VERB":
        return f, None
    f["kind"] = "enum"
    ref = rec["compu_tab_ref"]
    f["enum_table"] = ref
    if ref is None:
        return f, ("A2L-DEF-TABLE", f"{c(name)}: the table (none) of {c(method_word)} is not declared in the A2L")
    tsec = maps["ct_by_name"].get(ref)
    if tsec is None:
        return f, ("A2L-DEF-TABLE", f"{c(name)}: the table {rec['ref_echo']} of {c(method_word)} is not declared "
                                    f"in the A2L")
    if id(tsec) not in reads:
        st["table_reads"] = st.get("table_reads", 0) + 1
        reads[id(tsec)] = D._read_enum_table(ref, maps["ct_by_name"])
    tab = reads[id(tsec)]
    f["enum_entries"], f["default_text"] = tab[1], tab[2]
    if not tab[1]:
        word = rec["ref_echo"] if TE == "echo" else c(ref)
        return f, ("A2L-DEF-TABLE-EMPTY", f"{c(name)}: the table {word} has no entries")
    return f, None


def fix_scalar(d2a, tag, maps):
    """3a's `_describe_one` on a scalar kind: Inc 2a's fields (proxy record) and 3a's `_conversion_fields`."""
    if MUTANT is not None:
        return d2a
    conv, ref = conversion_fields(d2a.name, d2a.method_name, maps)   # 2a fills a MEASUREMENT's from its header
    repl = {}
    if d2a.conversion_type == "?":
        repl["conversion_type"] = conv["conversion_type"]
    if d2a.compu_tab_ref == "?":
        repl["compu_tab_ref"] = conv["compu_tab_ref"]
        if d2a.kind == "enum":
            repl.update(enum_table=conv["enum_table"], enum_entries=conv["enum_entries"],
                        default_text=conv["default_text"])
    conv_codes = ("A2L-DEF-CONVERSION", "A2L-DEF-TABLE", "A2L-DEF-TABLE-EMPTY")
    if d2a.refusal is not None and ref is not None and d2a.refusal.code in conv_codes and ref[0] in conv_codes:
        repl["refusal"] = D.Refusal(ref[0], ref[1])
    return dataclasses.replace(d2a, **repl) if repl else d2a


# ------------------------------------------------------------------ _describe_array (round 5)
def describe_array(tag, section, a2l_data, maps):
    if MUTANT is not None:
        return R5.describe_array(tag, section, a2l_data, maps)
    name = tag.get("name")
    d = {"name": name, "refusal": None, "message": None, "axes": [], "shape": (), "element_count": None,
         "byte_length": None, "values_offset": None}

    def refuse(code, msg=None):
        if d["refusal"] is None:
            d["refusal"], d["message"] = code, msg

    ct = tag.get("char_type")
    matrix = B.read_matrix_dim(section)
    header = B.flat([section.get("meta") or ""] + (section.get("lines") or [])) if section else []
    lname = header[4] if len(header) > 4 else None
    layout = read_record_layout(lname, a2l_data, name, maps)
    datatype = None
    if layout is None:
        refuse("A2L-DEF-LAYOUT", f"{c(name)}: the record layout {c(str(lname))} is not declared in the A2L")
    elif isinstance(layout, tuple):
        refuse(layout[1], layout[2])
        layout = None
    else:
        d["_layout_components"] = layout["components"]
        fnc = [x for x in layout["components"] if x[0] == "FNC_VALUES"]
        if not fnc:
            refuse("A2L-DEF-LAYOUT-VALUES")
        else:
            datatype = fnc[0][2]
    shape = None
    if ct in ("CURVE", "MAP"):
        if matrix is not None and len(matrix[0]) > 0 and matrix[1] not in ((1,), (1, 1), (1, 1, 1)):
            refuse("A2L-DEF-MATRIX")
        axes = [x for x in (section.get("children") or []) if x.get("name") == "AXIS_DESCR"]
        need = 1 if ct == "CURVE" else 2
        if len(axes) != need:
            refuse("A2L-DEF-AXES")
        elif layout is not None:
            built = []
            for letter, ax in zip("XY", axes):
                r = R3.read_axis(name, letter, ax, layout, a2l_data, maps)
                if isinstance(r, tuple):
                    refuse(r[1], r[2] if len(r) > 2 else None)
                else:
                    w = B.flat([ax.get("meta") or ""] + (ax.get("lines") or []))
                    r["_conv"] = conversion_fields(f"{name}.{letter}", w[2] if len(w) > 2 else None, maps, axis=True)
                    built.append(r)
                    d["axes"].append(r)
            if len(built) == need:
                shape = tuple(a_["point_count"] for a_ in built)
    else:
        s = B.array_shape(tag, section, datatype, matrix)
        if isinstance(s, tuple) and s and s[0] == "REFUSAL":
            refuse(s[1])
        elif s is not None:
            shape = s
    if shape is not None:
        d["shape"] = shape
        d["element_count"] = math.prod(shape)
        if layout is not None:
            placed = B.place_components(layout, shape)
            if ct in ("CURVE", "MAP"):
                d["byte_length"] = placed[1] if placed else None
            else:
                d["byte_length"] = d["element_count"] * B.SIZES[datatype] if datatype in B.SIZES else None
            if placed:
                d["values_offset"] = placed[0].get("FNC_VALUES")
                for ax in d["axes"]:
                    if ax["axis_kind"] == "STD_AXIS":
                        ax["offset"] = placed[0].get(f"AXIS_PTS_{ax['letter']}")
                        ax["count_offset"] = placed[0].get(f"NO_AXIS_PTS_{ax['letter']}")
            checks = [(layout, shape, section, lname)]
            checks += [(ax["_ap_layout"], (ax["point_count"],), ax["_ap"], ax["_ap_layout"]["name"])
                       for ax in d["axes"] if ax["axis_kind"] == "COM_AXIS"]
            for lay, counts, sec, lnm in checks:
                moved = R5.check_module_alignment(lay, counts, module_common(sec, maps), maps)
                if moved is None:
                    continue
                if len(moved) == 2:                       # .144: the stored echo, written as it is
                    refuse("A2L-DEF-ALIGNMENT", f"{c(name)}: the MOD_COMMON line {moved[0]} {moved[1]} cannot be read")
                else:                                     # .89: <layout> as .137, per call
                    refuse("A2L-DEF-ALIGNMENT", f"{c(name)}: {moved[0]} of the record layout {c(str(lnm))} lies at "
                                                f"offset {moved[1]}, or at {moved[2]} under the MOD_COMMON alignment")
    d["datatype"] = datatype
    addr = tag.get("address")
    d["address"] = addr
    bl = d["byte_length"]
    if addr is None or bl is None:
        refuse("A2L-DEF-ADDRESS")
    elif bl < 1 or bl > B.CAP or addr < 0 or addr + bl - 1 > 0xFFFFFFFF:
        refuse("A2L-DEF-ADDRESS-SPAN")
    conv, cref = conversion_fields(name, tag.get("conversion"), maps)
    d["_conv"] = conv
    if cref is not None:
        refuse(*cref)
    return d


def message_lengths(defs2a, defs3a):
    """Per definition: its message's characters, its axes' points' refusal messages included."""
    out = {}
    for nm, d in defs2a.items():
        if nm in defs3a:
            x = defs3a[nm]
            n = len(x["message"] or "")
            for ax in x["axes"]:
                r = ax.get("_conv", (None, None))[1]
                n += len(r[1]) if r else 0
            out[nm] = n
        else:
            out[nm] = len(d.refusal.message) if d.refusal is not None else 0
    return out


# ------------------------------------------------------------------ decode (round 5: one lookup per element)
def table_bisect(value, table, interpolate, variant=None):
    """3a's TAB_INTP / TAB_NOINTP lookup: bisects on the x of the frozen parse's entries, read in place."""
    variant = variant or BISECT
    entries = table.get("entries") or []
    if not entries:
        return None, "lookup table is empty"
    n = len(entries)
    i = bisect.bisect_left(entries, value, key=_KEY)
    if not interpolate:
        if i < n and entries[i][0] == value:
            return entries[i][1], ""
        lo = bisect.bisect_left(entries, entries[i - 1][0], key=_KEY) if i > 0 else None
        hi = i if i < n else None
        if lo is None:
            return entries[hi][1], ""
        if hi is None:
            best, dmin = lo, abs(entries[lo][0] - value)
        else:
            dlo, dhi = abs(entries[lo][0] - value), abs(entries[hi][0] - value)
            best, dmin = (lo, dlo) if dlo <= dhi else (hi, dhi)
        if variant == "v2" and best == lo:
            # the frozen `min` keeps the first entry of the least ROUNDED distance: the run of lower entries whose
            # distance rounds to dmin (non-increasing in x, so one more bisect)
            best = bisect.bisect_left(range(lo + 1), True, key=lambda j: abs(entries[j][0] - value) <= dmin)
        return entries[best][1], ""
    if value <= entries[0][0]:
        return entries[0][1], ""
    if value >= entries[-1][0]:
        return entries[-1][1], ""
    if variant == "v2" and not (0 < i < n):
        return None, "value outside interpolation range"
    lx, ly = entries[i - 1]
    rx, ry = entries[i]
    if variant == "v2" and not (lx <= value <= rx):
        return None, "value outside interpolation range"
    lyf, ryf = A._to_float(ly), A._to_float(ry)
    if lyf is None or ryf is None:
        return ly, ""
    if rx == lx:
        return lyf, ""
    ratio = (value - lx) / (rx - lx)
    return lyf + ratio * (ryf - lyf), ""


def decode_stored(e, data, stored):
    if e.kind == "text":
        t = D._ascii_text(stored)
        return D.Decoded(None, t, t)
    if e.kind == "enum":
        return D.Decoded(stored, D._enum_entry_text(e, stored), D._enum_text(e, stored))
    if e.method_name == "NO_COMPU_METHOD":
        value = stored
    else:
        tabs = data.get("compu_tabs_by_name") or {}
        ctype = str(e.conversion_type or "").upper()
        if ctype in ("TAB_INTP", "TAB_NOINTP"):
            table = tabs.get(e.compu_tab_ref or "")
            if table is None:
                value, status, error = None, "error", "lookup table missing"
            else:
                value, error = table_bisect(float(stored), table, ctype == "TAB_INTP")
                status = "error" if error else "ok"
        else:
            value, status, error = A._apply_compu_method(stored, {
                "conversion_type": e.conversion_type, "coeffs_linear": e.coeffs_linear, "coeffs": e.coeffs,
                "compu_tab_ref": e.compu_tab_ref}, tabs, (e.limits.lower, e.limits.upper))
        if status == "error":
            return D.Refusal("A2L-DEF-DECODE", f"{D._clean(e.name)}: {D._clean(error)}")
    return D.Decoded(stored, value, D.display_text(e, value))


def decode_element(e, data, image):
    if e.refusal is not None:
        return e.refusal
    stored = D._read_stored_value(e, image)
    if isinstance(stored, D.Refusal):
        return stored
    return decode_stored(e, data, stored)


def decode_model(d2a, d3a, data, image):
    if MUTANT is not None:
        return R5.decode_model(d2a, d3a, data, image)
    if d3a is None:
        return (decode_element(d2a, data, image),)       # 3a's decode_definition -> _decode_stored
    if d3a["refusal"] is not None:
        return ("REFUSAL", d3a["refusal"])
    addr, bl = d3a["address"], d3a["byte_length"]
    if sum(1 for o in range(bl) if addr + o not in image):
        return ("REFUSAL", "A2L-DEF-BYTES")
    out = []
    conv = d3a["_conv"]
    for ax in d3a["axes"]:
        aconv = ax["_conv"][0]
        akind = "enum" if aconv["kind"] == "enum" else "number"
        if ax["axis_kind"] == "COM_AXIS":
            lay = ax["_ap_layout"]
            base_addr = ax["axis_object_address"]
            pdt = next(x[2] for x in lay["components"] if x[0] == "AXIS_PTS_X")
            if ax["count_offset"] is not None:
                cdt = next(x[2] for x in lay["components"] if x[0] == "NO_AXIS_PTS_X")
                e, _ = R5._elem(d2a, f"{d3a['name']}.X#", "number", cdt, base_addr + ax["count_offset"], aconv)
                out.append(D._read_stored_value(e, image))
        elif ax["axis_kind"] == "STD_AXIS":
            base_addr = addr
            pdt = next((x[2] for x in (d3a.get("_layout_components") or ()) if x[0] == f"AXIS_PTS_{ax['letter']}"),
                       "UBYTE")
        else:
            continue
        if ax.get("offset") is None:
            continue
        size = B.SIZES.get(pdt, 1)
        for k in range(ax["point_count"]):
            e, _ = R5._elem(d2a, f"{d3a['name']}.{ax['letter']}[{k}]", akind, pdt,
                            base_addr + ax["offset"] + size * k, aconv)
            out.append(decode_element(e, data, image))
    kind = "enum" if conv["kind"] == "enum" else "number"
    size = B.SIZES.get(d3a["datatype"], 1)
    for i in range(d3a["element_count"]):
        e, _ = R5._elem(d2a, f"{d3a['name']}[{i}]", kind, d3a["datatype"], addr + d3a["values_offset"] + size * i,
                        conv)
        out.append(decode_element(e, data, image))
    return tuple(out)


public = R5.public


new_maps = R5.new_maps
