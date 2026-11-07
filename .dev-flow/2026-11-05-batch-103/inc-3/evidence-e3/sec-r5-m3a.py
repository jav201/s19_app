"""Throwaway stdlib model of Inc 3a's describe and decode as the E3 round-4 correction states them (graph-inc3.md at
cbaf970b), for the E3 round-5 security probes. Not product code.

The round-4 model `sec-r4-m3a.py` (loaded from this file's folder; it loads the round-3 and round-2 models), changed
only where cbaf970b changed the graph, and extended with the per-object work the graph's nodes name:
  * `_read_record_layout` (graph :466): the reduced read form -- at most one tuple per component, one ALIGNMENT tuple
    per class (the last number in file order), at most two FIX_NO counts. A refusal is stored owner-free, its echoed
    words already through Inc 2a's `_clean` (the most favourable reading: only `<name>` is put in per call). Texts as
    R-A2L-DEF.84 ... .87.
  * `_module_common` (:528): one ALIGNMENT entry per class -- (first unreadable word, its line index) or None, and the
    last number -- and the byte order, once per walk.
  * `_check_module_alignment` (:512): of the relevant classes, the one whose unreadable word has the lowest line index
    -> (class, word); else the layout placed with those classes' last numbers. `_describe_array` writes the .144
    message per object with Inc 2a's `_clean` ("`_describe_array` writes the message"; Messages as R-A2L-DEF.137).
  * AXIS_PTS header (:602): the walk stores its first ten words.
  * `_conversion_fields` (:355): the stored method record holds the six fields only. Messages per call through
    `_clean`, as Inc 2a's `_describe_one` writes them (METHOD; CONVERSION with Inc 2a's `str(type).upper()` test;
    TABLE; TABLE-EMPTY). For an axis, the points definition's `decimals` = Inc 2a's `_display_decimals` of the
    method's format (Interfaces: "display_format the axis FORMAT else the method's"; the axes here have no FORMAT).
  * Inc 2a's E5 (owed, ruled): `describe_e5` runs Inc 2a's REAL `describe_definitions`, its method / table reads
    memoised (round-4 model) and `_resolve_datatype` not run for VAL_BLK / CURVE / MAP and memoised per layout for
    every other kind. Inc 2a's real code stands in for 3a's `_describe_one` on the scalar kinds (same steps, texts).
  * decode (graph :650-745): `decode_model` -- `decode_values`' record check, then per element a `dataclasses.replace`
    of the object's definition (`_element_definition`) and Inc 2a's REAL `decode_definition` tail
    (`_read_stored_value`, `_apply_compu_method`, `display_text`, `_enum_entry_text`, `_enum_text`), which is what
    `_decode_stored` moves unchanged; STD axis points from the object's record, COM count and points from the axis
    object's record.
Knob MUTANT: None (the graph as corrected); "every-pair" (the round-4 graph: every ALIGNMENT pair of a layout and a
MOD_COMMON kept and walked per object); "rd-per-object" (Inc 2a's `_resolve_datatype` per object, Inc 2a as merged);
"per-call" (each section read per call: the round-2 graph). Counters in `STATS`.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import math
import pathlib
import types

_spec = importlib.util.spec_from_file_location("m3r4_base", str(pathlib.Path(__file__).with_name("sec-r4-m3a.py")))
R4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R4)
R3, B = R4.R3, R4.B

MP = types.MappingProxyType
A = None
D = None
MUTANT = None
STATS = {}
SUPPORTED = ("IDENTICAL", "LINEAR", "RAT_FUNC", "TAB_INTP", "TAB_NOINTP", "TAB_VERB")
SIX = ("conversion_type", "format", "unit", "coeffs_linear", "coeffs", "compu_tab_ref")
_RD = {"memo": None}


def bind(a2l_module, defn_module):
    global A, D
    A, D = a2l_module, defn_module
    R4.bind(a2l_module, defn_module)
    R3.read_record_layout = read_record_layout
    R3.module_common = module_common
    R3.check_module_alignment = check_module_alignment
    _install_rd()


def set_mutant(mutant):
    global MUTANT
    MUTANT = mutant
    R4.set_read_once(mutant != "per-call")


def c(text):
    return D._clean(text)


def _bump(key, n=1):
    STATS[key] = STATS.get(key, 0) + n


# ------------------------------------------------------------------ Inc 2a's E5 (owed): _resolve_datatype
def _install_rd():
    orig = D._resolve_datatype
    if getattr(orig, "_r5", False):
        return

    def rd(tag, a2l_data):
        if (MUTANT != "rd-per-object" and tag.get("section") == "CHARACTERISTIC"
                and tag.get("char_type") in ("VAL_BLK", "CURVE", "MAP")):
            return None                                   # 3a's _describe_one: not run for these kinds
        memo = _RD["memo"]
        if memo is None or MUTANT == "rd-per-object" or tag.get("datatype") in A.DATATYPE_SIZES:
            _bump("rd_scans")
            return orig(tag, a2l_data)
        layouts = a2l_data.get("record_layouts_by_name") or {}
        lname = tag.get("record_layout_name") or tag.get("deposit")
        key = ("rd", id(layouts.get(lname)) if lname else None, lname, tag.get("deposit"))
        if key not in memo:
            _bump("rd_scans")
            memo[key] = orig(tag, a2l_data)
        return memo[key]

    rd._r5 = True
    D._resolve_datatype = rd


def describe_e5(names, data):
    _RD["memo"] = {} if MUTANT != "per-call" else None
    try:
        return R4.describe_e5(names, data)
    finally:
        _RD["memo"] = None


# ------------------------------------------------------------------ _read_record_layout (reduced form)
def _layout_read(name, rl):
    comps, align, every, fixed, parts, seen = [], {}, [], {}, [], set()
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
            align[w0] = words[1]                          # last number of the class wins (a2l.py:1527)
            if MUTANT == "every-pair":
                every.append((w0, words[1]))
        elif words == ["DIRECT"]:
            pass
        else:
            parts.append(w0)                              # incl. a second line of one component
    lname = c(name)
    pos = [B.whole(x[1]) if len(x) > 1 else None for x in comps]
    if any(p is None for p in pos) or len(set(pos)) != len(pos):
        return ("REFUSAL", "A2L-DEF-LAYOUT-POSITION", f": the positions of the record layout {lname} do not give one order")
    if parts:
        return ("REFUSAL", "A2L-DEF-LAYOUT-PART",
                f": the record layout {lname} holds {c(parts[0])}, which the system cannot read")
    comps = [x for _, x in sorted(zip(pos, comps))]
    for x in comps:
        modes = ("ROW_DIR", "COLUMN_DIR") if x[0] == "FNC_VALUES" else (
            ("INDEX_INCR", "INDEX_DECR") if x[0] in ("AXIS_PTS_X", "AXIS_PTS_Y") else None)
        if modes is None:
            continue
        for word, ok in ((x[3] if len(x) > 3 else None, modes), (x[4] if len(x) > 4 else None, ("DIRECT",))):
            if word not in ok:
                return ("REFUSAL", "A2L-DEF-LAYOUT-MODE", f": the record layout {lname} stores {x[0]} as "
                        f"{c(word) if word is not None else '(none)'}, which the system cannot read")
    for x in comps:
        dt = x[2] if len(x) > 2 else None
        if dt not in B.DATATYPES or (x[0] in ("NO_AXIS_PTS_X", "NO_AXIS_PTS_Y") and dt not in B.COUNT_DATATYPES):
            return ("REFUSAL", "A2L-DEF-LAYOUT-DATATYPE", f": the record layout {lname} gives {x[0]} the datatype "
                    f"{c(dt) if dt is not None else '(none)'}, which the system cannot read")
    alignment = tuple(every) if MUTANT == "every-pair" else tuple(align.items())
    return MP({"name": name, "components": tuple(comps), "alignment": alignment, "fixed": MP(dict(fixed))})


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
        return (r[0], r[1], c(owner) + r[2])              # `<name>` put in at use
    return r


# ------------------------------------------------------------------ _module_common (reduced form)
def module_common(section, maps):
    mc = maps["mod_common_of"].get(id(section))
    if mc is None:
        return None
    reads = maps["reads"]
    key = id(mc)
    if key not in reads:
        maps["stats"]["modc_reads"] += 1
        al, pairs = {}, []
        for idx, w in enumerate(B.clean_lines(mc.get("lines"))):
            if not w or w[0] not in B.ALIGN_WORDS:
                continue
            word = w[1] if len(w) > 1 else None
            bad, last = al.get(w[0], (None, None))
            n = B.whole(word) if word is not None else None
            if n is None or n < 1:
                if bad is None:
                    bad = (word if word is not None else "(none)", idx)
            else:
                last = word
            al[w[0]] = (bad, last)
            if MUTANT == "every-pair":
                pairs.append((idx, w[0], word))
        reads[key] = MP({"alignment": MP(al), "pairs": tuple(pairs),
                         "byte_order": A._byte_order_from_section_lines(mc.get("lines") or [])})
    return reads[key]


def check_module_alignment(layout, counts, mcr, maps=None):
    if mcr is None:
        return None
    declared = {w[0] for w in layout["alignment"]}
    classes = {B.ALIGN_CLASS.get(x[2]) for x in layout["components"] if len(x) > 2}
    if MUTANT == "every-pair":                            # the round-4 graph: every pair, in file order
        extra = []
        for _idx, cls, word in mcr["pairs"]:
            if cls in declared or cls not in classes:
                continue
            n = B.whole(word) if word is not None else None
            if n is None or n < 1:
                return (cls, word if word is not None else "(none)")
            extra.append((cls, word))
    else:
        rel = [(cls, ent) for cls, ent in mcr["alignment"].items() if cls not in declared and cls in classes]
        bad = [(ent[0][1], cls, ent[0][0]) for cls, ent in rel if ent[0] is not None]
        if bad:
            _, cls, word = min(bad)
            return (cls, word)
        extra = [(cls, ent[1]) for cls, ent in rel if ent[1] is not None]
    if not extra:
        return None
    own = B.place_components(layout, counts)
    moved = B.place_components(layout, counts, extra)
    if own is None or moved is None:
        return None
    for x in layout["components"]:
        if own[0][x[0]] != moved[0][x[0]]:
            return (x[0], own[0][x[0]], moved[0][x[0]])
    return None


# ------------------------------------------------------------------ _conversion_fields (six-field record, messages)
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
        st["method_reads"] = st.get("method_reads", 0) + 1
        raw = D._read_method_record(method_word, cm)
        rec = {k: raw[k] for k in SIX}
        for k in ("coeffs_linear", "coeffs"):
            rec[k] = None if rec[k] is None else tuple(rec[k])
        reads[id(sec)] = MP(rec)
    rec = reads[id(sec)]
    f.update(conversion_type=rec["conversion_type"], coeffs_linear=rec["coeffs_linear"], coeffs=rec["coeffs"],
             compu_tab_ref=rec["compu_tab_ref"], record_format=rec["format"], record_unit=rec["unit"])
    if axis:
        f["decimals"] = D._display_decimals(rec["format"])
    t = rec["conversion_type"]
    if t is None or str(t).upper() not in SUPPORTED:
        return f, ("A2L-DEF-CONVERSION", f"{c(name)}: the conversion type {c(str(t)) if t else '(none)'} of "
                                         f"{c(method_word)} is not supported")
    if t != "TAB_VERB":
        return f, None
    f["kind"] = "enum"
    ref = rec["compu_tab_ref"]
    f["enum_table"] = ref
    if ref is None:
        return f, ("A2L-DEF-TABLE", f"{c(name)}: the table (none) of {c(method_word)} is not declared in the A2L")
    tsec = maps["ct_by_name"].get(ref)
    if tsec is None:
        return f, ("A2L-DEF-TABLE", f"{c(name)}: the table {c(ref)} of {c(method_word)} is not declared in the A2L")
    if id(tsec) not in reads:
        st["table_reads"] = st.get("table_reads", 0) + 1
        reads[id(tsec)] = D._read_enum_table(ref, maps["ct_by_name"])
    tab = reads[id(tsec)]
    f["enum_entries"], f["default_text"] = tab[1], tab[2]
    if not tab[1]:
        return f, ("A2L-DEF-TABLE-EMPTY", f"{c(name)}: the table {c(ref)} has no entries")
    return f, None


# ------------------------------------------------------------------ the walk, _describe_array, describe_definitions
def new_maps(a2l_data):
    maps = R4.new_maps(a2l_data)
    maps["axis_pts_hdr"] = {k: tuple(v[:10]) for k, v in maps.get("axis_pts_hdr", {}).items()}
    return maps


def describe_array(tag, section, a2l_data, maps):
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
                moved = check_module_alignment(lay, counts, module_common(sec, maps), maps)
                if moved is None:
                    continue
                if len(moved) == 2:                       # .144: `_describe_array` writes it, per object
                    refuse("A2L-DEF-ALIGNMENT", f"{c(name)}: the MOD_COMMON line {moved[0]} {c(moved[1])} cannot be read")
                else:
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
    conv, cref = conversion_fields(name, tag.get("conversion"), maps)     # the object's, via _describe_one
    d["_conv"] = conv
    if cref is not None:
        refuse(*cref)
    return d


def describe_all(a2l_data, order=None, maps=None):
    """3a's array part of describe_definitions: ONE walk, one `reads`; the scalar kinds are Inc 2a's (describe_e5)."""
    maps = maps or new_maps(a2l_data)
    secs = B.object_sections(a2l_data)
    tags = {}
    for t in a2l_data.get("tags") or []:
        tags.setdefault(t.get("name"), t)
    names = order or list(tags)
    out = {}
    for nm in names:
        ss = secs.get(nm) or []
        if len(ss) != 1 or nm in out or nm not in tags:
            continue
        if B.is_array_kind(tags[nm], ss[0]):
            out[nm] = describe_array(tags[nm], ss[0], a2l_data, maps)
    return out, maps


def describe(names, data):
    """The model of 3a's describe_definitions(names): Inc 2a's part (E5) + 3a's reads, one walk each."""
    defs2a = describe_e5(names, data)
    defs3a, maps = describe_all(data, list(names))
    return defs2a, defs3a, maps


def public(d2a, d3a):
    """What a consumer reads, for equality across sizes / walks: kind, refusal code, element count, shape."""
    if d3a is None:
        return ("scalar", d2a.kind, d2a.refusal.code if d2a.refusal else None)
    return ("array", d3a["refusal"], d3a["shape"], d3a["element_count"], d3a["byte_length"], d3a["values_offset"],
            d3a["datatype"], tuple((ax["axis_kind"], ax.get("point_count"), ax.get("offset"), ax.get("count_offset"))
                                   for ax in d3a["axes"]))


def message_bytes(defs2a, defs3a):
    n = sum(len(d.refusal.message) for d in defs2a.values() if d.refusal is not None)
    return n + sum(len(d["message"] or "") for d in defs3a.values())


# ------------------------------------------------------------------ decode_values (model)
def _elem(base, name, kind, datatype, address, conv):
    size = B.SIZES.get(datatype or "", 1)
    return dataclasses.replace(base, name=name, kind=kind, datatype=datatype, address=address, byte_length=size,
                               conversion_type=conv["conversion_type"], coeffs_linear=conv["coeffs_linear"],
                               coeffs=conv["coeffs"], compu_tab_ref=conv["compu_tab_ref"],
                               enum_table=conv["enum_table"], enum_entries=conv["enum_entries"],
                               default_text=conv["default_text"],
                               decimals=conv["decimals"] if conv["decimals"] is not None else base.decimals,
                               bit_mask=None, bit_mask_text=None, refusal=None), size


def decode_model(d2a, d3a, data, image):
    """decode_values: the refusal; the record's bytes; each axis; each element (Inc 2a's real decode per element)."""
    if d3a is None:
        return (D.decode_definition(d2a, data, image),)
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
                e, _ = _elem(d2a, f"{d3a['name']}.X#", "number", cdt, base_addr + ax["count_offset"], aconv)
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
            e, _ = _elem(d2a, f"{d3a['name']}.{ax['letter']}[{k}]", akind, pdt, base_addr + ax["offset"] + size * k,
                         aconv)
            out.append(D.decode_definition(e, data, image))
    kind = "enum" if conv["kind"] == "enum" else "number"
    size = B.SIZES.get(d3a["datatype"], 1)
    for i in range(d3a["element_count"]):
        e, _ = _elem(d2a, f"{d3a['name']}[{i}]", kind, d3a["datatype"], addr + d3a["values_offset"] + size * i, conv)
        out.append(D.decode_definition(e, data, image))
    return tuple(out)
