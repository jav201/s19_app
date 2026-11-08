"""Throwaway stdlib model of Inc 3a's describe and decode as the E3 round-6 correction states them (graph-inc3.md at
0db7c4b7, with the orchestrator's in-place rulings), for the E3 round-7 security probes. Not product code.

Base: the round-6 model `sec-r6-m3a.py` (loaded from this file's folder). It is also every negative control that names
a round-6 mutant: MUTANT="r6" is the round-6 probes' model (the round-5 correction's graph) unchanged, and "r5",
"every-pair", "rd-per-object", "per-call" are its mutants. Changed only where 0db7c4b7 changed the graph:
  * R-A2L-DEF.151 reaches every echoed word (E3S3-25). The layout read form holds `<layout>` as its .151 echo in its
    stored refusal and as `name_echo`, which the .89 message writes. The object's name is echoed once at describe and
    carried (`_name_echo`; an axis's points definition `<echo>.<letter>`). Every message writes `<name>` from it.
  * CONVERSION, TABLE and TABLE-EMPTY (E3S3-26) are `<name echo>` + a text stored in the method record, `<table>` the
    record's COMPU_TAB_REF echo.
  * Resolved references (E3S3-31). The method record keeps the COMPU_VTAB / _RANGE section its reference names
    (TAB_VERB) and, for TAB_INTP / TAB_NOINTP, its table form: (the COMPU_TAB as the frozen parse holds it, or None;
    the reference's echo; the NaN-x verdict, one pass over the x). Each AXIS_PTS entry keeps its layout section,
    resolved when the walk files it, and `_read_record_layout(..., section=)` takes it.
  * Element names on demand (E3S3-27). An element's or point's definition keeps the object's `name` by reference. A
    refusal is the carried echo + `[<i>]` + the error.
  * `_decode_stored` (E3S3-28, -29). The v2 bisect on the carried table; the NaN-x verdict gives
    `<name>: the table <ref> has an x that is not a number`; a result that is not an int or a float gives
    `<name>: the table <ref> gives a value that is not a number`.
Knobs (module globals):
  MUTANT  None (the corrected graph) | "byname" (the per-call by-name lookups of the shared reference words restored,
          E3S3-31's negative) | "named" (element names built per element, E3S3-27 (2)'s negative) | "nonum" (no number
          test, E3S3-28's) | "nonan" (no NaN-x verdict, E3S3-29's) | a round-6 mutant ("r6", "r5", ...), which runs the
          round-6 model;
  TE      "echo" | "clean" (.148/18's negative: `<table>` `_clean`ed per call);
  TF      "method" (the table form computed with each method record: the graph's text) | "table" (computed once per
          COMPU_TAB, keyed by its identity in `reads`).
Inc 2a's parts stay "2a, as ruled" as in the round-6 model; one addition: the proxy's TAB_VERB table check reads each
table once per walk, keyed by the table section's identity (Inc 2a's E3S3-13 rule), so a file of many methods naming
one table does not charge the model's shortcut to the design.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import pathlib
import types

_spec = importlib.util.spec_from_file_location("m3r6_base", str(pathlib.Path(__file__).with_name("sec-r6-m3a.py")))
R6 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R6)
R5, R4, R3, B = R6.R5, R6.R4, R6.R3, R6.B

MP = types.MappingProxyType
A = None
D = None
MUTANT = None
R7_MUTANTS = (None, "byname", "named", "nonum", "nonan")
TE = "echo"
TF = "method"
SIX = R6.SIX
SUPPORTED = R6.SUPPORTED
STATS = R6.STATS
CARRY = {}             # id(scalar definition) -> (definition, name echo, table form): the carried private fields
echo = R6.echo
_RT_RAW = None


def c(text):
    return D._clean(text)


def bind(a2l_module, defn_module):
    global A, D, _RT_RAW
    A, D = a2l_module, defn_module
    R6.bind(a2l_module, defn_module)
    _RT_RAW = R6.ORIG["rt"]
    R6.ORIG["rt"] = _rt_once
    set_mutant(None)


def _rt_once(name, by_name):
    """2a, as ruled: the proxy's table check reads each table section once per walk (by identity)."""
    w = R6.WALK
    if not w.get("on"):
        return _RT_RAW(name, by_name)
    sec = by_name.get(name)
    if sec is None:
        return _RT_RAW(name, by_name)
    memo = w.setdefault("rt_once", {})
    hit = memo.get(id(sec))
    if hit is None:
        hit = memo[id(sec)] = (sec, _RT_RAW(name, by_name))
    return hit[1]


def set_mutant(mutant):
    global MUTANT
    MUTANT = mutant
    R6.set_mutant(None if mutant in R7_MUTANTS or mutant == "r6" else mutant)


def r7():
    return MUTANT in R7_MUTANTS


# ------------------------------------------------------------------ the walk: AXIS_PTS entries with their layout
def new_maps(a2l_data):
    maps = R6.new_maps(a2l_data)
    maps["data"] = a2l_data
    maps["axo_layout"] = {}
    if r7() and MUTANT != "byname":
        rls = a2l_data.get("record_layouts_by_name") or {}
        for key, hdr in maps["axis_pts_hdr"].items():          # resolved when the walk files the AXIS_PTS
            maps["axo_layout"][key] = rls.get(hdr[4]) if len(hdr) > 4 else None
    return maps


# ------------------------------------------------------------------ _read_record_layout (round 6: <layout> echoed)
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
    lname = echo(name)                                    # <layout>: .151, once, at reduction (round 6)
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
    return MP({"name": name, "name_echo": lname, "components": tuple(comps), "alignment": tuple(align.items()),
               "fixed": MP(dict(fixed))})


def read_record_layout(name, a2l_data, owner_echo, maps, section=None):
    rl = section if section is not None else (a2l_data.get("record_layouts_by_name") or {}).get(name)
    if rl is None:
        return None
    reads = maps["reads"]
    key = id(rl)
    if key not in reads:
        maps["stats"]["layout_reads"] += 1
        reads[key] = _layout_read(name, rl)
    r = reads[key]
    if isinstance(r, tuple):
        return (r[0], r[1], owner_echo + r[2])
    return r


# ------------------------------------------------------------------ _read_axis (round 6: the resolved layout)
def read_axis(name_echo, letter, axis_section, layout, a2l_data, maps):
    words = R3.flat([axis_section.get("meta") or ""] + (axis_section.get("lines") or []))
    kind = words[0] if words else None
    out = {"letter": letter, "axis_kind": kind, "fixed_rule": None, "count_offset": None, "count_datatype": None,
           "offset": None}
    if kind not in ("STD_AXIS", "FIX_AXIS", "COM_AXIS"):
        return ("REFUSAL", "A2L-DEF-AXIS-KIND")
    ap_layout = None
    addr = None
    if kind == "COM_AXIS":
        ref = words[words.index("AXIS_PTS_REF") + 1] if "AXIS_PTS_REF" in words[:-1] else None
        ap = maps["axis_pts_by_name"].get(ref)
        if ap is None:
            return ("REFUSAL", "A2L-DEF-AXIS-REF")
        header = R3.axis_object_header(ap, maps)
        aw = header[2] if len(header) > 2 else None
        if aw is not None and len(aw) <= 20:
            try:
                addr = int(aw, 0)
            except ValueError:
                addr = None
        if addr is None:
            return ("REFUSAL", "A2L-DEF-AXIS-REF")
        lname = header[4] if len(header) > 4 else None
        if MUTANT == "byname":
            ap_layout = read_record_layout(lname, a2l_data, name_echo, maps)
        else:
            sec = maps["axo_layout"].get(id(ap))
            ap_layout = None if sec is None else read_record_layout(lname, a2l_data, name_echo, maps, section=sec)
        if isinstance(ap_layout, tuple):
            return ap_layout
        if ap_layout is None or not any(x[0] == "AXIS_PTS_X" for x in ap_layout["components"]):
            return ("REFUSAL", "A2L-DEF-AXIS-LAYOUT")
        max_word = header[7] if len(header) > 7 else None
    else:
        max_word = words[3] if len(words) > 3 else None
    pc = R3.whole(max_word)
    if pc is None or pc < 1:
        return ("REFUSAL", "A2L-DEF-AXIS-MAX")
    if pc > R3.CAP:
        return ("REFUSAL", "A2L-DEF-AXIS-MAX-N")
    out["point_count"] = pc
    if kind == "FIX_AXIS":
        fr = R3.fix_rule(words, axis_section, pc)
        if fr is None:
            return ("REFUSAL", "A2L-DEF-AXIS-FIX")
        if fr == "unreadable":
            return ("REFUSAL", "A2L-DEF-AXIS-FIX-UNREADABLE")
        if fr == "inexact":
            return ("REFUSAL", "A2L-DEF-AXIS-FIX-INEXACT")
        if isinstance(fr, int):
            return ("REFUSAL", "A2L-DEF-AXIS-FIX-COUNT")
        out["fixed_rule"] = fr
    has = any(x[0] == f"AXIS_PTS_{letter}" for x in layout["components"])
    if has and kind != "STD_AXIS":
        return ("REFUSAL", "A2L-DEF-LAYOUT-AXIS")
    out["has_points"] = has or kind != "STD_AXIS"
    fx = (ap_layout if kind == "COM_AXIS" else layout)["fixed"].get(letter if kind != "COM_AXIS" else "X")
    if fx is not None and (fx == 0 or fx > pc):
        return ("REFUSAL", "A2L-DEF-AXIS-CURRENT")
    if fx is not None and fx < pc:
        return ("REFUSAL", "A2L-DEF-AXIS-PARTIAL")
    if kind == "COM_AXIS":
        placed = R3.place_components(ap_layout, (pc,))
        if placed is None or addr < 0 or addr + placed[1] - 1 > 0xFFFFFFFF:
            return ("REFUSAL", "A2L-DEF-AXIS-REF-RECORD")
        out["axis_object_address"] = addr
        out["record_end"] = placed[1]
        out["count_offset"] = placed[0].get("NO_AXIS_PTS_X")
        out["offset"] = placed[0].get("AXIS_PTS_X")
        out["axis_object_byte_order"] = R3.axis_object_byte_order(ap, lname, a2l_data, maps)
        out["_ap"], out["_ap_layout"] = ap, ap_layout
    return out


# ------------------------------------------------------------------ _conversion_fields (round 6)
def _table_form(ref, ref_echo, maps, st):
    tabs = maps["data"].get("compu_tabs_by_name") or {}
    tab = tabs.get(ref) if ref is not None else None
    if tab is None:
        return (None, ref_echo, False)
    if TF == "table":
        key = ("table_form", id(tab))
        hit = maps["reads"].get(key)
        if hit is None:
            st["nan_passes"] = st.get("nan_passes", 0) + 1
            hit = maps["reads"][key] = (tab, any(e[0] != e[0] for e in tab.get("entries") or ()))
        return (hit[0], ref_echo, hit[1])
    st["nan_passes"] = st.get("nan_passes", 0) + 1       # the graph's text: one pass with each method record
    return (tab, ref_echo, any(e[0] != e[0] for e in tab.get("entries") or ()))


def _method_record(method_word, maps, st):
    raw = R6.ORIG["rm"](method_word, maps["cm_by_name"])
    rec = {k: raw[k] for k in SIX}
    for k in ("coeffs_linear", "coeffs"):
        rec[k] = None if rec[k] is None else tuple(rec[k])
    t = rec["conversion_type"]
    ref = rec["compu_tab_ref"]
    me = echo(method_word)
    rec["type_ok"] = t is not None and str(t).upper() in SUPPORTED
    rec["type_echo"] = echo(str(t)) if t else None
    rec["ref_echo"] = echo(ref)
    rec["decimals"] = R6.ORIG["dd"](rec["format"])
    rec["msg_conv"] = f": the conversion type {rec['type_echo'] or '(none)'} of {me} is not supported"
    rec["msg_table"] = f": the table {rec['ref_echo'] or '(none)'} of {me} is not declared in the A2L"
    rec["msg_empty"] = f": the table {rec['ref_echo']} has no entries"
    rec["table_sec"] = maps["ct_by_name"].get(ref) if t == "TAB_VERB" and ref is not None else None
    rec["table_form"] = (_table_form(ref, rec["ref_echo"], maps, st)
                         if str(t or "").upper() in ("TAB_INTP", "TAB_NOINTP") else None)
    st["method_reads"] = st.get("method_reads", 0) + 1
    return MP(rec)


def conversion_fields(name_echo, method_word, maps, axis=False):
    st = maps["stats"]
    st["conv_calls"] = st.get("conv_calls", 0) + 1
    f = {"kind": "number", "conversion_type": None, "coeffs_linear": None, "coeffs": None, "compu_tab_ref": None,
         "record_format": None, "record_unit": None, "enum_table": None, "enum_entries": (), "default_text": None,
         "decimals": None, "table_form": None}
    if method_word is None or method_word == "NO_COMPU_METHOD":
        return f, None
    sec = maps["cm_by_name"].get(method_word)             # the object's own header word
    if sec is None:
        return f, ("A2L-DEF-METHOD", f"{name_echo}: the conversion method {echo(method_word)} is not declared in the A2L")
    reads = maps["reads"]
    if id(sec) not in reads:
        reads[id(sec)] = _method_record(method_word, maps, st)
    rec = reads[id(sec)]
    f.update(conversion_type=rec["conversion_type"], coeffs_linear=rec["coeffs_linear"], coeffs=rec["coeffs"],
             compu_tab_ref=rec["compu_tab_ref"], record_format=rec["format"], record_unit=rec["unit"],
             table_form=rec["table_form"])
    if axis:
        f["decimals"] = rec["decimals"]
    if not rec["type_ok"]:
        return f, ("A2L-DEF-CONVERSION", name_echo + rec["msg_conv"])
    if rec["conversion_type"] != "TAB_VERB":
        return f, None
    f["kind"] = "enum"
    ref = rec["compu_tab_ref"]
    f["enum_table"] = ref
    if ref is None:
        return f, ("A2L-DEF-TABLE", name_echo + rec["msg_table"])
    tsec = maps["ct_by_name"].get(ref) if MUTANT == "byname" else rec["table_sec"]
    if tsec is None:
        return f, ("A2L-DEF-TABLE", name_echo + rec["msg_table"])
    if id(tsec) not in reads:
        st["table_reads"] = st.get("table_reads", 0) + 1
        reads[id(tsec)] = D._read_enum_table(ref, maps["ct_by_name"])
    tab = reads[id(tsec)]
    f["enum_entries"], f["default_text"] = tab[1], tab[2]
    if not tab[1]:
        if TE == "clean":
            return f, ("A2L-DEF-TABLE-EMPTY", f"{name_echo}: the table {c(ref)} has no entries")
        return f, ("A2L-DEF-TABLE-EMPTY", name_echo + rec["msg_empty"])
    return f, None


def fix_scalar(d2a, tag, maps):
    """3a's `_describe_one` on a scalar kind: Inc 2a's fields (proxy record) and 3a's `_conversion_fields`; the
    name's echo computed once here and carried with the table form."""
    if not r7():
        return R6.fix_scalar(d2a, tag, maps)
    ne = echo(d2a.name)
    conv, ref = conversion_fields(ne, d2a.method_name, maps)
    repl = {}
    if d2a.conversion_type == "?":
        repl["conversion_type"] = conv["conversion_type"]
    if d2a.compu_tab_ref == "?":
        repl["compu_tab_ref"] = conv["compu_tab_ref"]
        if d2a.kind == "enum":
            repl.update(enum_table=conv["enum_table"], enum_entries=conv["enum_entries"],
                        default_text=conv["default_text"])
    codes = ("A2L-DEF-CONVERSION", "A2L-DEF-TABLE", "A2L-DEF-TABLE-EMPTY")
    if d2a.refusal is not None and ref is not None and d2a.refusal.code in codes and ref[0] in codes:
        repl["refusal"] = D.Refusal(ref[0], ref[1])
    out = dataclasses.replace(d2a, **repl) if repl else d2a
    CARRY[id(out)] = (out, ne, conv["table_form"])
    return out


# ------------------------------------------------------------------ _describe_array (round 6)
def describe_array(tag, section, a2l_data, maps):
    if not r7():
        return R6.describe_array(tag, section, a2l_data, maps)
    name = tag.get("name")
    ne = echo(name)                                       # once per name, carried by the definition
    d = {"name": name, "refusal": None, "message": None, "axes": [], "shape": (), "element_count": None,
         "byte_length": None, "values_offset": None, "_name_echo": ne}

    def refuse(code, msg=None):
        if d["refusal"] is None:
            d["refusal"], d["message"] = code, msg

    ct = tag.get("char_type")
    matrix = B.read_matrix_dim(section)
    header = B.flat([section.get("meta") or ""] + (section.get("lines") or [])) if section else []
    lname = header[4] if len(header) > 4 else None
    layout = read_record_layout(lname, a2l_data, ne, maps)
    datatype = None
    if layout is None:
        refuse("A2L-DEF-LAYOUT", f"{ne}: the record layout {echo(str(lname))} is not declared in the A2L")
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
                r = read_axis(ne, letter, ax, layout, a2l_data, maps)
                if isinstance(r, tuple):
                    refuse(r[1], r[2] if len(r) > 2 else None)
                else:
                    w = B.flat([ax.get("meta") or ""] + (ax.get("lines") or []))
                    r["_name_echo"] = f"{ne}.{letter}"
                    r["_conv"] = conversion_fields(r["_name_echo"], w[2] if len(w) > 2 else None, maps, axis=True)
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
        d["element_count"] = R6.math.prod(shape)
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
            checks = [(layout, shape, section)]
            checks += [(ax["_ap_layout"], (ax["point_count"],), ax["_ap"]) for ax in d["axes"]
                       if ax["axis_kind"] == "COM_AXIS"]
            for lay, counts, sec in checks:
                moved = R5.check_module_alignment(lay, counts, R6.module_common(sec, maps), maps)
                if moved is None:
                    continue
                if len(moved) == 2:                       # .144: the stored echo, written as it is
                    refuse("A2L-DEF-ALIGNMENT", f"{ne}: the MOD_COMMON line {moved[0]} {moved[1]} cannot be read")
                else:                                     # .89: <layout> the read form's stored echo (round 6)
                    refuse("A2L-DEF-ALIGNMENT", f"{ne}: {moved[0]} of the record layout {lay['name_echo']} lies at "
                                                f"offset {moved[1]}, or at {moved[2]} under the MOD_COMMON alignment")
    d["datatype"] = datatype
    addr = tag.get("address")
    d["address"] = addr
    bl = d["byte_length"]
    if addr is None or bl is None:
        refuse("A2L-DEF-ADDRESS")
    elif bl < 1 or bl > B.CAP or addr < 0 or addr + bl - 1 > 0xFFFFFFFF:
        refuse("A2L-DEF-ADDRESS-SPAN")
    conv, cref = conversion_fields(ne, tag.get("conversion"), maps)
    d["_conv"] = conv
    d["_table_form"] = conv["table_form"]
    if cref is not None:
        refuse(*cref)
    return d


message_lengths = R6.message_lengths
public = R6.public
table_bisect = R6.table_bisect


# ------------------------------------------------------------------ decode (round 6)
def table_route(tf, value, interpolate, variant="v2"):
    """3a's TAB_INTP / TAB_NOINTP route on a carried table form: (value, error); error "" when a value is given."""
    tab, ref_echo, nan = tf if tf is not None else (None, None, False)
    if tab is None:
        return None, "lookup table missing"
    if nan and MUTANT != "nonan":
        return None, f"the table {ref_echo} has an x that is not a number"
    value, error = table_bisect(value, tab, interpolate, variant)
    if error:
        return None, error
    if MUTANT != "nonum" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        return None, f"the table {ref_echo or '(none)'} gives a value that is not a number"
    return value, ""


def decode_stored(e, data, stored, name_echo, suffix, tf):
    if e.kind == "text":
        t = D._ascii_text(stored)
        return D.Decoded(None, t, t)
    if e.kind == "enum":
        return D.Decoded(stored, D._enum_entry_text(e, stored), D._enum_text(e, stored))
    if e.method_name == "NO_COMPU_METHOD":
        value = stored
    else:
        ctype = str(e.conversion_type or "").upper()
        if ctype in ("TAB_INTP", "TAB_NOINTP"):
            if MUTANT == "byname":                        # the per-element by-name lookup restored
                tab = (data.get("compu_tabs_by_name") or {}).get(e.compu_tab_ref or "")
                tf = (tab,) + tuple((tf or (None, None, False))[1:])
            value, error = table_route(tf, float(stored), ctype == "TAB_INTP")
            if error:
                return D.Refusal("A2L-DEF-DECODE", f"{name_echo}{suffix}: {error}")
        else:
            value, status, error = A._apply_compu_method(stored, {
                "conversion_type": e.conversion_type, "coeffs_linear": e.coeffs_linear, "coeffs": e.coeffs,
                "compu_tab_ref": e.compu_tab_ref}, data.get("compu_tabs_by_name") or {}, (e.limits.lower, e.limits.upper))
            if status == "error":
                return D.Refusal("A2L-DEF-DECODE", f"{name_echo}{suffix}: {c(error)}")
            if MUTANT != "nonum" and (isinstance(value, bool) or not isinstance(value, (int, float))):
                return D.Refusal("A2L-DEF-DECODE", f"{name_echo}{suffix}: the table (none) gives a value that is not "
                                                   f"a number")
    return D.Decoded(stored, value, D.display_text(e, value))


def decode_element(e, data, image, name_echo, suffix, tf):
    if e.refusal is not None:
        return e.refusal
    stored = D._read_stored_value(e, image)
    if isinstance(stored, D.Refusal):
        return stored
    return decode_stored(e, data, stored, name_echo, suffix, tf)


def decode_model(d2a, d3a, data, image):
    if not r7():
        return R6.decode_model(d2a, d3a, data, image)
    if d3a is None:                                       # 3a's decode_definition -> _decode_stored
        hit = CARRY.get(id(d2a))
        ne, tf = (hit[1], hit[2]) if hit is not None and hit[0] is d2a else (echo(d2a.name), None)
        return (decode_element(d2a, data, image, ne, "", tf),)
    if d3a["refusal"] is not None:
        return ("REFUSAL", d3a["refusal"])
    addr, bl = d3a["address"], d3a["byte_length"]
    if sum(1 for o in range(bl) if addr + o not in image):
        return ("REFUSAL", "A2L-DEF-BYTES")
    nm = d3a["name"]
    named = MUTANT == "named"
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
                e, _ = R5._elem(d2a, f"{nm}.X#" if named else nm, "number", cdt, base_addr + ax["count_offset"], aconv)
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
            e, _ = R5._elem(d2a, f"{nm}.{ax['letter']}[{k}]" if named else nm, akind, pdt,
                            base_addr + ax["offset"] + size * k, aconv)
            out.append(decode_element(e, data, image, ax["_name_echo"], f"[{k}]", aconv["table_form"]))
    kind = "enum" if conv["kind"] == "enum" else "number"
    size = B.SIZES.get(d3a["datatype"], 1)
    ne, tf = d3a["_name_echo"], d3a["_table_form"]
    for i in range(d3a["element_count"]):
        e, _ = R5._elem(d2a, f"{nm}[{i}]" if named else nm, kind, d3a["datatype"],
                        addr + d3a["values_offset"] + size * i, conv)
        out.append(decode_element(e, data, image, ne, f"[{i}]", tf))
    return tuple(out)
