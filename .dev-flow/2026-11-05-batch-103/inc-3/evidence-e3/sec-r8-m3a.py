"""Throwaway stdlib model of Inc 3a's describe and decode as the E3 round-7 correction states them (graph-inc3.md at
25c13dec), run on Inc 2a's REAL code (a copy of the Inc 2a tree at e9bad3ca; `a2l_definition.py` md5 820a4c3a), for
the E3 round-8 security probes. Not product code.

What changed from the round-7 model (`sec-r7-m3a.py`):
  * No Inc 2a function is wrapped or replaced. The round-4 ... round-7 models patched `_read_method_record`,
    `_read_enum_table`, `_resolve_datatype`, `_display_decimals`, `_enum_entry_text` and `_enum_text` with "2a, as
    ruled" proxies; Inc 2a's gap passes have landed, so this model calls Inc 2a's real functions with the walk's one
    `reads` map: `_describe_one(..., reads)`, `_read_method_record(name, compu_methods_by_name, compu_tables_by_name,
    compu_tabs_by_name, reads)` (its record holds Inc 2a's `_TabForm` from `_build_tab_form`, or `_EnumForm` from
    `_read_enum_table`, keyed in `reads` by the identity of the table's own entry), `_table_value` (the v2 bisect),
    `_enum_entry_text` / `_enum_text` (one lookup in the `_EnumForm`), `_read_stored_value`, `display_text`.
  * 3a's `_conversion_fields` takes the record from `_read_method_record` and builds no second form (E3S3-33, -36).
  * 3a's `_decode_stored` runs on the carried `_TabForm` with Inc 2a's `_table_value`, the NaN-x verdict from the form
    (`x_nan`) and the number test.
  * 3a's own read forms (the RECORD_LAYOUT's, the MOD_COMMON's) are the round-7 model's. KEY selects how the RECORD_LAYOUT
    read form is keyed in `reads`: "bare" = `id()` of the `record_layouts_by_name` entry, as the graph writes it
    (graph-inc3.md:156, :508) -- the same key Inc 2a's `_resolve_datatype` stores its resolved datatype under
    (`a2l_definition.py:733`); "tuple" = `("RL", id(entry))`, a key no Inc 2a read uses (round 8's [K] probe).
Knobs (module globals):
  MUTANT  None (the corrected graph) | "byname" (a shared word looked up by name per call: the axis object's layout
          word per curve; the COMPU_TAB_REF word per call through `_read_enum_table` / `_build_tab_form`; the COMPU_TAB
          per element at decode -- E3S3-31's regression, E3S3-35's negative) | "named" (element names built per element)
          | "r6" (the round-5 correction's graph, as the cases' negatives name it: `<layout>` held whole, `_clean`ed, in
          the stored refusal and in the .89 message per call; each element named `<name>[<i>]` and its refusal
          `_clean`ing that name) | "nonum" | "nonan";
  TE      "echo" | "clean" (`<table>` `_clean`ed per call in TABLE-EMPTY);
  TF      "table" (Inc 2a's `_build_tab_form` as implemented: one form per COMPU_TAB per walk) | "method" (the round-6
          graph: the table form, with its NaN-x pass, built with each method record -- `_build_tab_form` given a
          throwaway map, so nothing is shared);
  KEY     "tuple" | "bare" (see above).
Counters in STATS.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import math
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
MUTANTS = (None, "byname", "named", "r6", "nonum", "nonan")
TE = "echo"
TF = "table"
KEY = "tuple"
STATS = {"btf_calls": 0, "btf_builds": 0, "scalar_msg_diff": 0, "scalar_checked": 0}
echo = R6.echo
_BTF = None


def c(text):
    return D._clean(text)


def bind(a2l_module, defn_module):
    """Bind the helpers of the earlier models to the real modules WITHOUT their bind(): those wrapped Inc 2a's
    functions with the old signatures. Only plain module globals are set here."""
    global A, D, _BTF
    A, D = a2l_module, defn_module
    R3.bind(a2l_module)                                    # B.bind(A) too
    for mod in (R4, R5, R6):
        mod.A, mod.D = a2l_module, defn_module
    R3.AXO_HEADER, R3.AXO_BYTE_ORDER = "walk", "memo"      # the AXIS_PTS header stored by the walk, byte order once
    R3.module_common = R6.module_common                    # one ALIGNMENT entry per class, .151 echo (round 5)
    R3.check_module_alignment = R5.check_module_alignment
    R4.READ_ONCE, R5.MUTANT, R6.MUTANT = True, None, None
    _BTF = D._build_tab_form
    set_knobs()


def _btf_method(ref, compu_tabs_by_name, reads):
    """TF=method: the form built with each method record, never shared (the round-6 graph's text)."""
    STATS["btf_calls"] += 1
    STATS["btf_builds"] += 1
    return _BTF(ref, compu_tabs_by_name, {})


def set_knobs(mutant=None, te="echo", tf="table", key="tuple"):
    global MUTANT, TE, TF, KEY
    assert mutant in MUTANTS, mutant
    MUTANT, TE, TF, KEY = mutant, te, tf, key
    D._build_tab_form = _BTF if tf == "table" else _btf_method
    for k in list(STATS):
        STATS[k] = 0


def restore():
    D._build_tab_form = _BTF


# ------------------------------------------------------------------ the walk (Inc 2a's maps + 3a's)
def new_maps(a2l_data, w2a):
    """3a's walk: Inc 2a's four name maps (`w2a`, the ones Inc 2a's describe_definitions builds) and 3a's
    axis_pts_by_name / mod_common_of / reads; each AXIS_PTS entry with its layout section resolved when filed."""
    maps = R6.new_maps(a2l_data)
    maps["cm_by_name"], maps["ct_by_name"] = w2a[2], w2a[3]
    maps["data"] = a2l_data
    maps["axo_layout"] = {}
    if MUTANT != "byname":
        rls = a2l_data.get("record_layouts_by_name") or {}
        for key, hdr in maps["axis_pts_hdr"].items():
            maps["axo_layout"][key] = rls.get(hdr[4]) if len(hdr) > 4 else None
    return maps


# ------------------------------------------------------------------ _read_record_layout (round 7's form)
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
    lname = c(name) if MUTANT == "r6" else echo(name)    # <layout>: .151 echo once at reduction (r6: whole, .137)
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
    key = id(rl) if KEY == "bare" else ("RL", id(rl))
    if key not in reads:
        maps["stats"]["layout_reads"] += 1
        reads[key] = _layout_read(name, rl)
    r = reads[key]
    if isinstance(r, tuple):
        return (r[0], r[1], owner_echo + r[2])
    return r


# ------------------------------------------------------------------ _read_axis (round 7)
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


# ------------------------------------------------------------------ _conversion_fields (round 7: Inc 2a's record)
def conversion_fields(name_echo, method_word, maps, axis=False):
    """3a's node on Inc 2a's `_read_method_record` (11 fields; `table_form` an `_EnumForm` / `_TabForm` or None)."""
    st = maps["stats"]
    st["conv_calls"] = st.get("conv_calls", 0) + 1
    f = {"kind": "number", "conversion_type": None, "coeffs_linear": None, "coeffs": None, "compu_tab_ref": None,
         "record_format": None, "record_unit": None, "enum_table": None, "enum_entries": (), "default_text": None,
         "decimals": None, "table_form": None}
    if method_word is None or method_word == "NO_COMPU_METHOD":
        return f, None
    data = maps["data"]
    tabs = data.get("compu_tabs_by_name") or {}
    rec = D._read_method_record(method_word, maps["cm_by_name"], maps["ct_by_name"], tabs, maps["reads"])
    if rec is None:
        return f, ("A2L-DEF-METHOD", f"{name_echo}: the conversion method {echo(method_word)} is not declared in the A2L")
    verdict = rec["type_verdict"]
    ref = rec["compu_tab_ref"]
    form = rec["table_form"]
    if MUTANT == "byname" and ref is not None:            # E3S3-31's regression: the shared word looked up per call
        if verdict == "TAB_VERB":
            form = D._read_enum_table(ref, maps["ct_by_name"], maps["reads"])
        elif verdict in ("TAB_INTP", "TAB_NOINTP"):
            form = D._build_tab_form(ref, tabs, maps["reads"])
    f.update(conversion_type=rec["conversion_type"], coeffs_linear=rec["coeffs_linear"], coeffs=rec["coeffs"],
             compu_tab_ref=ref, record_format=rec["format"], record_unit=rec["unit"])
    if axis:
        f["decimals"] = rec["decimals"]
    if verdict is None:
        return f, ("A2L-DEF-CONVERSION", f"{name_echo}: the conversion type {rec['type_echo']} of {echo(method_word)} "
                                         f"is not supported")
    if verdict in ("TAB_INTP", "TAB_NOINTP"):
        f["table_form"] = form if isinstance(form, D._TabForm) else None
        return f, None
    if verdict != "TAB_VERB":
        return f, None
    f["kind"] = "enum"
    f["enum_table"] = ref
    if ref is None or not isinstance(form, D._EnumForm):
        return f, ("A2L-DEF-TABLE", f"{name_echo}: the table {rec['table_echo']} of {echo(method_word)} is not "
                                    f"declared in the A2L")
    f["table_form"] = form
    f["enum_entries"], f["default_text"] = form.entries, form.default_text
    if not form.entries:
        if TE == "clean":
            return f, ("A2L-DEF-TABLE-EMPTY", f"{name_echo}: the table {c(ref)} has no entries")
        return f, ("A2L-DEF-TABLE-EMPTY", f"{name_echo}: the table {rec['table_echo']} has no entries")
    return f, None


CONV_CODES = ("A2L-DEF-METHOD", "A2L-DEF-CONVERSION", "A2L-DEF-TABLE", "A2L-DEF-TABLE-EMPTY")


def fix_scalar(d2a, tag, maps):
    """3a's `_describe_one` on a scalar kind: Inc 2a's real per-name code (run by the harness with the walk's `reads`)
    with its method / table steps through 3a's `_conversion_fields`; the two must agree (the graph: "the same values,
    refusals and order"), counted in STATS."""
    ne = d2a._name_echo if d2a._name_echo is not None else echo(d2a.name)
    conv, ref = conversion_fields(ne, d2a.method_name, maps)
    if d2a.refusal is not None and d2a.refusal.code in CONV_CODES:
        STATS["scalar_checked"] += 1
        if ref is None or ref[0] != d2a.refusal.code or ref[1] != d2a.refusal.message:
            STATS["scalar_msg_diff"] += 1
    if MUTANT == "byname" and conv["table_form"] is not None and conv["table_form"] is not d2a._table_form:
        return dataclasses.replace(d2a, _table_form=conv["table_form"])
    return d2a


# ------------------------------------------------------------------ _describe_array (round 7)
def describe_array(tag, section, a2l_data, maps):
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
            checks = [(layout, shape, section)]
            checks += [(ax["_ap_layout"], (ax["point_count"],), ax["_ap"]) for ax in d["axes"]
                       if ax["axis_kind"] == "COM_AXIS"]
            for lay, counts, sec in checks:
                moved = R5.check_module_alignment(lay, counts, R6.module_common(sec, maps), maps)
                if moved is None:
                    continue
                if len(moved) == 2:                       # .144: the stored echo, written as it is
                    refuse("A2L-DEF-ALIGNMENT", f"{ne}: the MOD_COMMON line {moved[0]} {moved[1]} cannot be read")
                else:                                     # .89: <layout> the read form's stored echo (r6: per call)
                    lw = c(str(lay["name"])) if MUTANT == "r6" else lay["name_echo"]
                    refuse("A2L-DEF-ALIGNMENT", f"{ne}: {moved[0]} of the record layout {lw} lies at "
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


# ------------------------------------------------------------------ decode (3a's _decode_stored on Inc 2a's forms)
def table_route(tf, stored, interpolate):
    """3a's TAB_INTP / TAB_NOINTP route on the carried `_TabForm`: (value, error); error "" when a value is given."""
    if not isinstance(tf, D._TabForm):
        return None, "lookup table missing"
    if tf.x_nan and MUTANT != "nonan":
        return None, f"the table {tf.ref_echo} has an x that is not a number"
    value, error = D._table_value(tf, stored, interpolate)
    if error:
        return None, error
    if MUTANT != "nonum" and not isinstance(value, (int, float)):
        return None, f"the table {tf.ref_echo} gives a value that is not a number"
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
            if MUTANT == "byname":                        # the COMPU_TAB looked up by name per element
                if (data.get("compu_tabs_by_name") or {}).get(e.compu_tab_ref or "") is None:
                    tf = None
            value, error = table_route(tf, stored, ctype == "TAB_INTP")
            if error:
                who = c(e.name) if MUTANT == "r6" else f"{name_echo}{suffix}"
                return D.Refusal("A2L-DEF-DECODE", f"{who}: {error}")
        else:
            value, status, error = A._apply_compu_method(stored, {
                "conversion_type": e.conversion_type, "coeffs_linear": e.coeffs_linear, "coeffs": e.coeffs,
                "compu_tab_ref": e.compu_tab_ref}, data.get("compu_tabs_by_name") or {}, (e.limits.lower, e.limits.upper))
            if status == "error":
                who = c(e.name) if MUTANT == "r6" else f"{name_echo}{suffix}"
                return D.Refusal("A2L-DEF-DECODE", f"{who}: {error}")
            if MUTANT != "nonum" and not isinstance(value, (int, float)):
                ref_echo = echo(e.compu_tab_ref) if e.compu_tab_ref is not None else "(none)"
                return D.Refusal("A2L-DEF-DECODE", f"{name_echo}{suffix}: the table {ref_echo} gives a value that is "
                                                   f"not a number")
    return D.Decoded(stored, value, D.display_text(e, value))


def decode_element(e, data, image, name_echo, suffix, tf):
    if e.refusal is not None:
        return e.refusal
    stored = D._read_stored_value(e, image)
    if isinstance(stored, D.Refusal):
        return stored
    return decode_stored(e, data, stored, name_echo, suffix, tf)


def _elem(base, name, kind, datatype, address, conv, name_echo):
    """An element / point definition: a `replace` of the object's definition, carrying the name echo and the table
    form by reference (graph *Carried values*)."""
    size = B.SIZES.get(datatype or "", 1)
    return dataclasses.replace(base, name=name, kind=kind, datatype=datatype, address=address, byte_length=size,
                               conversion_type=conv["conversion_type"], coeffs_linear=conv["coeffs_linear"],
                               coeffs=conv["coeffs"], compu_tab_ref=conv["compu_tab_ref"],
                               enum_table=conv["enum_table"], enum_entries=conv["enum_entries"],
                               default_text=conv["default_text"],
                               decimals=conv["decimals"] if conv["decimals"] is not None else base.decimals,
                               bit_mask=None, bit_mask_text=None, refusal=None,
                               _name_echo=name_echo, _table_form=conv["table_form"])


def decode_model(d2a, d3a, data, image):
    if d3a is None:                                       # 3a's decode_definition -> _decode_stored
        ne = d2a._name_echo if d2a._name_echo is not None else echo(d2a.name)
        return (decode_element(d2a, data, image, ne, "", d2a._table_form),)
    if d3a["refusal"] is not None:
        return ("REFUSAL", d3a["refusal"])
    addr, bl = d3a["address"], d3a["byte_length"]
    if sum(1 for o in range(bl) if addr + o not in image):
        return ("REFUSAL", "A2L-DEF-BYTES")
    nm = d3a["name"]
    named = MUTANT in ("named", "r6")
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
                e = _elem(d2a, f"{nm}.X#" if named else nm, "number", cdt, base_addr + ax["count_offset"], aconv,
                          ax["_name_echo"])
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
            e = _elem(d2a, f"{nm}.{ax['letter']}[{k}]" if named else nm, akind, pdt,
                      base_addr + ax["offset"] + size * k, aconv, ax["_name_echo"])
            out.append(decode_element(e, data, image, ax["_name_echo"], f"[{k}]", aconv["table_form"]))
    kind = "enum" if conv["kind"] == "enum" else "number"
    size = B.SIZES.get(d3a["datatype"], 1)
    ne, tf = d3a["_name_echo"], d3a["_table_form"]
    for i in range(d3a["element_count"]):
        e = _elem(d2a, f"{nm}[{i}]" if named else nm, kind, d3a["datatype"], addr + d3a["values_offset"] + size * i,
                  conv, ne)
        out.append(decode_element(e, data, image, ne, f"[{i}]", tf))
    return tuple(out)
