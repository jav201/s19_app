"""Throwaway stdlib model of Inc 3a's describe as the E3 round-3 correction states it (graph-inc3.md at dc1ba751),
for the E3 round-4 security probes. Not product code.

The round-3 model `sec-r3-m3a.py` (loaded from this file's folder), changed only where dc1ba751 changed the graph:
  * Interfaces *Lookups* (E3S3-13): every section an object names is read at most once per walk, keyed in
    `maps["reads"]` by id() of the section: RECORD_LAYOUT (owner-free), MOD_COMMON (ALIGNMENT pairs, byte order),
    the AXIS_PTS header (stored by the walk, as a tuple), the axis object's own byte order, the COMPU_METHOD's
    method record and the COMPU_VTAB / COMPU_VTAB_RANGE's enum table (`_conversion_fields`, once per object and
    once per axis).
  * Read forms (E3S3-14): immutable -- a layout is a MappingProxyType whose `components` / `alignment` are tuples
    of word tuples and whose `fixed` is a MappingProxyType; a MOD_COMMON form a MappingProxyType with `alignment` a
    tuple; the method record a MappingProxyType of Inc 2a's `_read_method_record` dict "whose coeffs_linear and
    coeffs are tuples" (exactly what the graph pins: the other values are left as Inc 2a gives them); the enum
    table Inc 2a's `(kind, tuple[EnumEntry], default)`. `_check_module_alignment` places a new layout.
  * Inc 2a's part: `describe_e5()` runs Inc 2a's REAL `describe_definitions` with its `_read_method_record` and
    `_read_enum_table` memoised once per call by id() of the section (the read-once map 2a's E5 owes).
Knobs: READ_ONCE (False = every call re-reads its section: the round-2 graph and Inc 2a as merged); MUTANT as in
the round-3 model.
"""
from __future__ import annotations

import importlib.util
import pathlib
import types

_spec = importlib.util.spec_from_file_location("m3r3_base", str(pathlib.Path(__file__).with_name("sec-r3-m3a.py")))
R3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R3)
B = R3.B

A = None
D = None
READ_ONCE = True
MP = types.MappingProxyType
STATS = {}
_E5 = {"memo": None}


def bind(a2l_module, defn_module):
    global A, D
    A, D = a2l_module, defn_module
    R3.bind(a2l_module)
    R3.AXO_HEADER, R3.AXO_BYTE_ORDER = "walk", "memo"
    _install_e5()


def set_read_once(flag):
    global READ_ONCE
    READ_ONCE = flag
    R3.AXO_HEADER, R3.AXO_BYTE_ORDER = ("walk", "memo") if flag else ("per-call", "per-call")


# ------------------------------------------------------------------ Inc 2a's E5 (model): method / table once per call
def _install_e5():
    orig_m, orig_t = D._read_method_record, D._read_enum_table
    if getattr(orig_m, "_r4", False):
        return

    def rm(name, by_name):
        memo = _E5["memo"]
        STATS["e5_method_calls"] = STATS.get("e5_method_calls", 0) + 1
        if memo is None:
            STATS["e5_method_reads"] = STATS.get("e5_method_reads", 0) + 1
            return orig_m(name, by_name)
        k = ("m", id(by_name.get(name)))
        if k not in memo:
            STATS["e5_method_reads"] = STATS.get("e5_method_reads", 0) + 1
            memo[k] = orig_m(name, by_name)
        return memo[k]

    def rt(name, by_name):
        memo = _E5["memo"]
        STATS["e5_table_calls"] = STATS.get("e5_table_calls", 0) + 1
        if memo is None:
            STATS["e5_table_reads"] = STATS.get("e5_table_reads", 0) + 1
            return orig_t(name, by_name)
        k = ("t", id(by_name.get(name)))
        if k not in memo:
            STATS["e5_table_reads"] = STATS.get("e5_table_reads", 0) + 1
            memo[k] = orig_t(name, by_name)
        return memo[k]

    rm._r4 = rt._r4 = True
    D._read_method_record, D._read_enum_table = rm, rt


def describe_e5(names, data):
    """Inc 2a's real describe_definitions; with READ_ONCE its method / table reads are memoised once per call."""
    _E5["memo"] = {} if READ_ONCE else None
    try:
        return D.describe_definitions(names, data)
    finally:
        _E5["memo"] = None


# ------------------------------------------------------------------ immutable read forms (E3S3-14)
class _Miss(dict):
    def __contains__(self, key):
        return False


def _freeze_layout(r):
    if isinstance(r, tuple):
        return r
    return MP({"name": r["name"], "components": tuple(tuple(c) for c in r["components"]),
               "alignment": tuple(tuple(a) for a in r["alignment"]), "fixed": MP(dict(r["fixed"]))})


def read_record_layout(name, a2l_data, owner, maps):
    rl = (a2l_data.get("record_layouts_by_name") or {}).get(name)
    if rl is None:
        return None
    reads = maps["reads"]
    key = id(rl)
    if key not in reads:
        maps["stats"]["layout_reads"] += 1
        reads[key] = _freeze_layout(R3._layout_ownerfree(name, a2l_data))
    r = reads[key]
    if isinstance(r, tuple):
        if R3.MUTANT == "owner-leak":
            if "{owner}" in r[2]:
                r = reads[key] = (r[0], r[1], r[2].replace("{owner}", owner))
            return r
        return (r[0], r[1], r[2].replace("{owner}", owner))
    return r


def module_common(section, maps):
    mc = maps["mod_common_of"].get(id(section))
    if mc is None:
        return None
    reads = maps["reads"]
    key = id(mc)
    if key not in reads:
        maps["stats"]["modc_reads"] += 1
        align = tuple(tuple(w[:2]) if len(w) > 1 else (w[0],) for w in B.clean_lines(mc.get("lines"))
                      if w and w[0] in B.ALIGN_WORDS)
        reads[key] = MP({"alignment": align, "byte_order": A._byte_order_from_section_lines(mc.get("lines") or [])})
    return reads[key]


def check_module_alignment(layout, counts, mcr, maps=None):
    """The graph's `_check_module_alignment`: a NEW layout (the stored form's ALIGNMENT pairs + MOD_COMMON's)."""
    if mcr is None:
        return None
    if R3.MUTANT == "cache-check" and maps is not None:
        ck = ("cma", id(layout), id(mcr))
        if ck in maps["reads"]:
            return maps["reads"][ck]
    declared = {w[0] for w in layout["alignment"]}
    classes = {B.ALIGN_CLASS.get(c[2]) for c in layout["components"] if len(c) > 2}
    extra = []
    res = None
    for w in mcr["alignment"]:
        if w[0] in declared or w[0] not in classes:
            continue
        n = B.whole(w[1]) if len(w) > 1 else None
        if n is None or n < 1:
            res = (w[0], w[1] if len(w) > 1 else "(none)")
            break
        extra.append(w)
    else:
        if extra:
            own = B.place_components(layout, counts)
            if R3.MUTANT == "mutate":
                layout["alignment"].extend(extra)       # the slip: raises on an immutable form
                moved = B.place_components(layout, counts)
            else:
                moved = B.place_components(layout, counts, extra)
            if own is not None and moved is not None:
                for c in layout["components"]:
                    if own[0][c[0]] != moved[0][c[0]]:
                        res = (c[0], own[0][c[0]], moved[0][c[0]])
                        break
    if R3.MUTANT == "cache-check" and maps is not None:
        maps["reads"][("cma", id(layout), id(mcr))] = res
    return res


# ------------------------------------------------------------------ _conversion_fields (E3S3-13)
def conversion_fields(name, method_word, maps):
    """Method record and enum table read once per walk, by id() of the section; the fields the graph names."""
    st = maps["stats"]
    st["conv_calls"] += 1
    if method_word is None or method_word == "NO_COMPU_METHOD":
        return ("number", None, None, None), None
    cm = maps["cm_by_name"]
    sec = cm.get(method_word)
    if sec is None:
        return ("", None, None, None), "A2L-DEF-METHOD"
    reads = maps["reads"]
    if id(sec) not in reads:
        st["method_reads"] += 1
        raw = D._read_method_record(method_word, cm)
        reads[id(sec)] = MP({**raw,
                             "coeffs_linear": None if raw["coeffs_linear"] is None else tuple(raw["coeffs_linear"]),
                             "coeffs": None if raw["coeffs"] is None else tuple(raw["coeffs"])})
    rec = reads[id(sec)]
    ctype = rec.get("conversion_type")
    if ctype not in ("IDENTICAL", "LINEAR", "RAT_FUNC", "TAB_INTP", "TAB_NOINTP", "TAB_VERB"):
        return ("", ctype, None, None), "A2L-DEF-CONVERSION"
    if ctype != "TAB_VERB":
        return ("number", ctype, rec.get("coeffs_linear"), None), None
    ref = rec.get("compu_tab_ref")
    tsec = maps["ct_by_name"].get(ref) if ref is not None else None
    if tsec is None:
        return ("enum", ctype, None, None), "A2L-DEF-TABLE"
    if id(tsec) not in reads:
        st["table_reads"] += 1
        reads[id(tsec)] = D._read_enum_table(ref, maps["ct_by_name"])
    tab = reads[id(tsec)]
    if not tab[1]:
        return ("enum", ctype, None, tab[1]), "A2L-DEF-TABLE-EMPTY"
    return ("enum", ctype, None, tab[1]), None


# ------------------------------------------------------------------ the walk and describe
def new_maps(a2l_data):
    maps = R3.new_maps(a2l_data)            # axis_pts_by_name, mod_common_of, axis_pts_hdr (walk), reads, axo_bo
    maps["axis_pts_hdr"] = {k: tuple(v) for k, v in maps.get("axis_pts_hdr", {}).items()}
    cm, ct = {}, {}
    stack = list(reversed(a2l_data.get("sections") or []))
    while stack:                             # pre-order, file order (setdefault keeps the first), as Inc 2a's walk
        node = stack.pop()
        nm = node.get("name")
        if nm == "COMPU_METHOD":
            cm.setdefault(A.parse_begin_meta(node.get("meta") or "")[0], node)
        elif nm in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
            ct.setdefault(A.parse_begin_meta(node.get("meta") or "")[0], node)
        stack.extend(reversed(node.get("children") or []))
    maps["cm_by_name"], maps["ct_by_name"] = cm, ct
    if not READ_ONCE:
        maps["reads"] = _Miss()
        maps["axo_bo"] = _Miss()
    maps["stats"].update(conv_calls=0, method_reads=0, table_reads=0)
    return maps


# the round-3 model's _read_axis and describe_array call these module names: point them at the r4 forms
R3.read_record_layout = read_record_layout
R3.module_common = module_common
R3.check_module_alignment = check_module_alignment


def describe_array(tag, section, a2l_data, maps):
    d = R3.describe_array(tag, section, a2l_data, maps)
    conv, ref = conversion_fields(tag.get("name"), tag.get("conversion"), maps)      # the object's (`_describe_one`)
    d["conversion"], d["conv_refusal"] = conv[:3], ref
    d["enum_entries"] = conv[3]
    axes_conv = []
    for ax in (section.get("children") or []):
        if ax.get("name") != "AXIS_DESCR":
            continue
        w = B.flat([ax.get("meta") or ""] + (ax.get("lines") or []))
        c, r = conversion_fields(f"{tag.get('name')}.?", w[2] if len(w) > 2 else None, maps)  # each axis (`_read_axis`)
        axes_conv.append((c[:3], r, c[3]))
    d["axes_conversion"] = axes_conv
    return d


def describe_all(a2l_data, order=None, maps=None):
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
        elif tags[nm].get("section") == "CHARACTERISTIC":     # a scalar: only its conversion (3a's _describe_one)
            conv, ref = conversion_fields(nm, tags[nm].get("conversion"), maps)
            out[nm] = {"name": nm, "conversion": conv[:3], "conv_refusal": ref, "enum_entries": conv[3]}
    return out, maps


def public(d):
    if "shape" not in d:
        return ("scalar", d["conversion"], d["conv_refusal"], d["enum_entries"])
    return R3.public(d) + (d["conversion"], d["conv_refusal"], d["enum_entries"],
                           tuple((c, r, e) for c, r, e in d["axes_conversion"]))
