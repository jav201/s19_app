"""Throwaway stdlib model of Inc 3a's build and decode rules as the E3 round-2 correction states them
(graph-inc3.md at 9ae81d2c), for the E3 round-3 security probes. Not product code.

The round-2 model `sec-r2-m3a.py` (loaded from this file's folder) changed only where the round-2 correction
changed the graph:
  * `_read_axis` FIX step (R-A2L-DEF.141, .147, .99): the words through Inc 2a's `_finite_number` (.141); for PAR the
    shift word a CTX *whole number* (1 to 9 ASCII digits) of at most 62, checked before any power; then the first
    and the last point in exact integers: each number's `as_integer_ratio()`, one power-of-two denominator D,
    `abs(A) > 2**53 * D` or `abs(A + (n - 1) * B) > 2**53 * D` -> "inexact" (.147); then n != point count (.99);
    `fixed_rule` stores each number as an int where integral.
  * `_fixed_points`: point k = (A + k*B) / D in integers, an int when D divides it, else `int / int` (correctly
    rounded). PAR_LIST: the stored numbers.
  * `maps["reads"]` (E3S3-11): each RECORD_LAYOUT read once per walk (owner-free; `<name>` put in at use) and each
    MOD_COMMON's read form (ALIGNMENT pairs, byte order) once per walk, keyed by id() of the section.
  * `_check_module_alignment` on the object's layout and on each COM axis object's layout (graph `_describe_array`
    step 5), on the MOD_COMMON read form.
Knobs (module globals, for the probes): MUTANT in {None, "owner-leak", "mutate", "cache-check"} -- implementation
slips the correction makes possible; AXO_HEADER in {"walk", "per-call"} and AXO_BYTE_ORDER in {"per-call", "memo"}
-- the two readings the graph leaves for the axis object's header and its own BYTE_ORDER line; FIX_RULE in
{"r3", "r2", "bound63", "bound61", "pow-first"} -- the .147 rule and its negative-control mutants.
"""
from __future__ import annotations

import importlib.util
import math
import pathlib

_spec = importlib.util.spec_from_file_location("m3r2_base", str(pathlib.Path(__file__).with_name("sec-r2-m3a.py")))
B = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B)

A = None
MUTANT = None
AXO_HEADER = "walk"
AXO_BYTE_ORDER = "per-call"
FIX_RULE = "r3"
CAP = B.CAP
LIM = 2 ** 53


def bind(a2l_module):
    global A
    A = a2l_module
    B.bind(a2l_module)


whole, finite, clean_lines, flat = B.whole, B.finite, B.clean_lines, B.flat
read_matrix_dim, array_shape, place_components = B.read_matrix_dim, B.array_shape, B.place_components
current_count, object_sections, is_array_kind, iwi = B.current_count, B.object_sections, B.is_array_kind, B.int_where_integral
SIZES, ALIGN_CLASS, ALIGN_WORDS = B.SIZES, B.ALIGN_CLASS, B.ALIGN_WORDS


# ---------------------------------------------------------------- FIX (.141, .147, .99) and _fixed_points
def _ratio3(o, step):
    (a, da), (b, db) = o.as_integer_ratio(), step.as_integer_ratio()
    d = max(da, db)                       # both powers of two
    return a * (d // da), b * (d // db), d


def fix_rule(words, axis_section, point_count):
    if FIX_RULE == "r2":
        return B.fix_rule(words, axis_section, point_count)
    for kw in ("FIX_AXIS_PAR", "FIX_AXIS_PAR_DIST"):
        if kw in words:
            i = words.index(kw)
            ow, xw, nw = (words[i + j] if i + j < len(words) else None for j in (1, 2, 3))
            o, x, n = finite(ow), finite(xw), whole(nw)
            if o is None or x is None or n is None:
                return "unreadable"                                   # .141
            if kw == "FIX_AXIS_PAR":
                if FIX_RULE == "pow-first":
                    _ = 2 ** int(x)                                   # mutant: the power before the shift check
                s = whole(xw)
                bound = {"bound63": 63, "bound61": 61}.get(FIX_RULE, 62)
                if s is None or s > bound:
                    return "inexact"                                  # .147 shift
                step = 2 ** s
            else:
                s, step = None, x
            a_, b_, d = _ratio3(o, step)
            if abs(a_) > LIM * d or abs(a_ + (n - 1) * b_) > LIM * d:
                return "inexact"                                      # .147 magnitude
            if n != point_count:
                return n                                              # .99
            return ("PAR", (iwi(o), s, n)) if kw == "FIX_AXIS_PAR" else ("PAR_DIST", (iwi(o), iwi(x), n))
    for child in axis_section.get("children") or []:
        if child.get("name") == "FIX_AXIS_PAR_LIST":
            nums = [finite(w) for w in flat(child.get("lines") or [])]
            if any(v is None for v in nums):
                return "unreadable"
            if len(nums) != point_count:
                return len(nums)
            return ("PAR_LIST", tuple(iwi(v) for v in nums))
    return None


def fixed_points(rule):
    form, nums = rule
    if FIX_RULE == "r2":
        return B.fixed_points(rule, "literal")
    if form == "PAR_LIST":
        return tuple(nums)
    o, x, n = nums
    step = 2 ** x if form == "PAR" else x
    a_, b_, d = _ratio3(o, step)
    if d == 1:
        return tuple(a_ + k * b_ for k in range(n))
    out = []
    for k in range(n):
        v = a_ + k * b_
        q, r = divmod(v, d)
        out.append(q if r == 0 else v / d)
    return tuple(out)


# ---------------------------------------------------------------- reads once per walk (E3S3-11)
def new_maps(a2l_data):
    maps = B.build_maps(a2l_data)
    if AXO_HEADER == "walk":    # the header stored with the section, computed once in the walk
        maps["axis_pts_hdr"] = {id(s): flat([s.get("meta") or ""] + (s.get("lines") or []))
                                for s in maps["axis_pts_by_name"].values()}
    maps["reads"] = {}
    maps["stats"] = {"layout_reads": 0, "modc_reads": 0, "axo_header_reads": 0, "axo_byte_order_reads": 0}
    maps["axo_bo"] = {}
    return maps


def _layout_ownerfree(name, a2l_data):
    r = B.read_record_layout(name, a2l_data, "")
    if isinstance(r, tuple):        # a refusal: code + a message template with the owner left out
        return ("REFUSAL", r[1], "{owner}: " + r[1] + " " + " ".join(str(w) for w in r[2:]) + f" (layout {name})")
    return r


def read_record_layout(name, a2l_data, owner, maps):
    rl = (a2l_data.get("record_layouts_by_name") or {}).get(name)
    if rl is None:
        return None
    reads = maps["reads"]
    key = id(rl)
    if key not in reads:
        maps["stats"]["layout_reads"] += 1
        reads[key] = _layout_ownerfree(name, a2l_data)
    r = reads[key]
    if isinstance(r, tuple):
        if MUTANT == "owner-leak":                    # slip: the first owner's message cached
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
        align = [tuple(w[:2]) if len(w) > 1 else (w[0],) for w in clean_lines(mc.get("lines"))
                 if w and w[0] in ALIGN_WORDS]
        reads[key] = {"alignment": align, "byte_order": A._byte_order_from_section_lines(mc.get("lines") or [])}
    return reads[key]


def check_module_alignment(layout, counts, mcr, maps=None):
    if mcr is None:
        return None
    if MUTANT == "cache-check" and maps is not None:     # slip: the verdict cached per layout, not per shape
        ck = ("cma", id(layout), id(mcr))
        if ck in maps["reads"]:
            return maps["reads"][ck]
    declared = {w[0] for w in layout["alignment"]}
    classes = {ALIGN_CLASS.get(c[2]) for c in layout["components"] if len(c) > 2}
    extra = []
    for w in mcr["alignment"]:
        if w[0] in declared or w[0] not in classes:
            continue
        n = whole(w[1]) if len(w) > 1 else None
        if n is None or n < 1:
            res = (w[0], w[1] if len(w) > 1 else "(none)")    # .144
            break
        extra.append(w)
    else:
        res = None
        if extra:
            own = place_components(layout, counts)
            if MUTANT == "mutate":                        # slip: "the layout with those lines added" in place
                layout["alignment"].extend(extra)
                moved = place_components(layout, counts)
            else:
                moved = place_components(layout, counts, extra)
            if own is not None and moved is not None:
                for c in layout["components"]:
                    if own[0][c[0]] != moved[0][c[0]]:
                        res = (c[0], own[0][c[0]], moved[0][c[0]])
                        break
    if MUTANT == "cache-check" and maps is not None:
        maps["reads"][("cma", id(layout), id(mcr))] = res
    return res


# ---------------------------------------------------------------- _read_axis (round-2 corrected)
def axis_object_header(ap, maps):
    if AXO_HEADER == "walk":
        return maps["axis_pts_hdr"][id(ap)]
    maps["stats"]["axo_header_reads"] += 1
    return flat([ap.get("meta") or ""] + (ap.get("lines") or []))


def axis_object_byte_order(ap, ap_layout_name, a2l_data, maps):
    if AXO_BYTE_ORDER == "memo" and id(ap) in maps["axo_bo"]:
        return maps["axo_bo"][id(ap)]
    maps["stats"]["axo_byte_order_reads"] += 1
    bo = A._byte_order_from_section_lines(ap.get("lines") or [])
    if bo is None:
        rl = (a2l_data.get("record_layouts_by_name") or {}).get(ap_layout_name) or {}
        bo = rl.get("byte_order")
    if bo is None:
        mcr = module_common(ap, maps)
        bo = mcr["byte_order"] if mcr else None
    bo = bo or "little"
    maps["axo_bo"][id(ap)] = bo
    return bo


def read_axis(name, letter, axis_section, layout, a2l_data, maps):
    words = flat([axis_section.get("meta") or ""] + (axis_section.get("lines") or []))
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
        header = axis_object_header(ap, maps)
        aw = header[2] if len(header) > 2 else None
        if aw is not None and len(aw) <= 20:
            try:
                addr = int(aw, 0)
            except ValueError:
                addr = None
        if addr is None:
            return ("REFUSAL", "A2L-DEF-AXIS-REF")
        lname = header[4] if len(header) > 4 else None
        ap_layout = read_record_layout(lname, a2l_data, name, maps)
        if isinstance(ap_layout, tuple):
            return ap_layout
        if ap_layout is None or not any(c[0] == "AXIS_PTS_X" for c in ap_layout["components"]):
            return ("REFUSAL", "A2L-DEF-AXIS-LAYOUT")
        max_word = header[7] if len(header) > 7 else None
    else:
        max_word = words[3] if len(words) > 3 else None
    pc = whole(max_word)
    if pc is None or pc < 1:
        return ("REFUSAL", "A2L-DEF-AXIS-MAX")
    if pc > CAP:
        return ("REFUSAL", "A2L-DEF-AXIS-MAX-N")
    out["point_count"] = pc
    if kind == "FIX_AXIS":
        fr = fix_rule(words, axis_section, pc)
        if fr is None:
            return ("REFUSAL", "A2L-DEF-AXIS-FIX")
        if fr == "unreadable":
            return ("REFUSAL", "A2L-DEF-AXIS-FIX-UNREADABLE")
        if fr == "inexact":
            return ("REFUSAL", "A2L-DEF-AXIS-FIX-INEXACT")
        if isinstance(fr, int):
            return ("REFUSAL", "A2L-DEF-AXIS-FIX-COUNT")
        out["fixed_rule"] = fr
    has = any(c[0] == f"AXIS_PTS_{letter}" for c in layout["components"])
    if has and kind != "STD_AXIS":
        return ("REFUSAL", "A2L-DEF-LAYOUT-AXIS")
    out["has_points"] = has or kind != "STD_AXIS"
    fx = (ap_layout if kind == "COM_AXIS" else layout)["fixed"].get(letter if kind != "COM_AXIS" else "X")
    if fx is not None and (fx == 0 or fx > pc):
        return ("REFUSAL", "A2L-DEF-AXIS-CURRENT")
    if fx is not None and fx < pc:
        return ("REFUSAL", "A2L-DEF-AXIS-PARTIAL")
    if kind == "COM_AXIS":
        placed = place_components(ap_layout, (pc,))
        if placed is None or addr < 0 or addr + placed[1] - 1 > 0xFFFFFFFF:
            return ("REFUSAL", "A2L-DEF-AXIS-REF-RECORD")
        out["axis_object_address"] = addr
        out["record_end"] = placed[1]
        out["count_offset"] = placed[0].get("NO_AXIS_PTS_X")
        out["offset"] = placed[0].get("AXIS_PTS_X")
        out["axis_object_byte_order"] = axis_object_byte_order(ap, lname, a2l_data, maps)
        out["_ap"], out["_ap_layout"] = ap, ap_layout
    return out


# ---------------------------------------------------------------- _describe_array (the steps the probes need)
def describe_array(tag, section, a2l_data, maps):
    name = tag.get("name")
    d = {"name": name, "refusal": None, "message": None, "axes": [], "shape": (), "element_count": None,
         "byte_length": None, "values_offset": None}

    def refuse(code, msg=None):
        if d["refusal"] is None:
            d["refusal"], d["message"] = code, msg

    ct = tag.get("char_type")
    matrix = read_matrix_dim(section)
    header = flat([section.get("meta") or ""] + (section.get("lines") or [])) if section else []
    lname = header[4] if len(header) > 4 else None
    layout = read_record_layout(lname, a2l_data, name, maps)
    datatype = None
    if layout is None:
        refuse("A2L-DEF-LAYOUT")
    elif isinstance(layout, tuple):
        refuse(layout[1], layout[2])
        layout = None
    else:
        fnc = [c for c in layout["components"] if c[0] == "FNC_VALUES"]
        if not fnc:
            refuse("A2L-DEF-LAYOUT-VALUES")
        else:
            datatype = fnc[0][2]
    shape = None
    if ct in ("CURVE", "MAP"):
        if matrix is not None and len(matrix[0]) > 0 and matrix[1] not in ((1,), (1, 1), (1, 1, 1)):
            refuse("A2L-DEF-MATRIX")
        axes = [c for c in (section.get("children") or []) if c.get("name") == "AXIS_DESCR"]
        need = 1 if ct == "CURVE" else 2
        if len(axes) != need:
            refuse("A2L-DEF-AXES")
        elif layout is not None:
            built = []
            for letter, ax in zip("XY", axes):
                r = read_axis(name, letter, ax, layout, a2l_data, maps)
                if isinstance(r, tuple):
                    refuse(r[1], r[2] if len(r) > 2 else None)
                else:
                    built.append(r)
                    d["axes"].append(r)
            if len(built) == need:
                shape = tuple(a_["point_count"] for a_ in built)
    else:
        s = array_shape(tag, section, datatype, matrix)
        if isinstance(s, tuple) and s and s[0] == "REFUSAL":
            refuse(s[1])
        elif s is not None:
            shape = s
    if shape is not None:
        d["shape"] = shape
        d["element_count"] = math.prod(shape)
        if layout is not None:
            placed = place_components(layout, shape)
            if ct in ("CURVE", "MAP"):
                d["byte_length"] = placed[1] if placed else None
            else:
                d["byte_length"] = d["element_count"] * SIZES[datatype] if datatype in SIZES else None
            if placed:
                d["values_offset"] = placed[0].get("FNC_VALUES")
                for ax in d["axes"]:
                    if ax["axis_kind"] == "STD_AXIS":
                        ax["offset"] = placed[0].get(f"AXIS_PTS_{ax['letter']}")
                        ax["count_offset"] = placed[0].get(f"NO_AXIS_PTS_{ax['letter']}")
            moved = check_module_alignment(layout, shape, module_common(section, maps), maps)
            if moved is not None:
                refuse("A2L-DEF-ALIGNMENT", f"{name}: {moved}")
            for ax in d["axes"]:
                if ax["axis_kind"] == "COM_AXIS":
                    moved = check_module_alignment(ax["_ap_layout"], (ax["point_count"],),
                                                   module_common(ax["_ap"], maps), maps)
                    if moved is not None:
                        refuse("A2L-DEF-ALIGNMENT", f"{name}: {moved}")
    d["datatype"] = datatype
    addr = tag.get("address")
    d["address"] = addr
    bl = d["byte_length"]
    if addr is None or bl is None:
        refuse("A2L-DEF-ADDRESS")
    elif bl < 1 or bl > CAP or addr < 0 or addr + bl - 1 > 0xFFFFFFFF:
        refuse("A2L-DEF-ADDRESS-SPAN")
    return d


def public(d):
    """The fields a consumer reads (no private model keys), for equality between walks."""
    axes = tuple(tuple(sorted((k, v) for k, v in ax.items() if not k.startswith("_"))) for ax in d["axes"])
    return (d["refusal"], d["message"], d["shape"], d["element_count"], d["byte_length"], d["values_offset"],
            d["datatype"], d["address"], axes)


def describe_all(a2l_data, order=None, maps=None):
    """describe_definitions: ONE walk, one `reads` map, names in `order` (tag order by default)."""
    maps = maps or new_maps(a2l_data)
    secs = object_sections(a2l_data)
    tags = {}
    for t in a2l_data.get("tags") or []:
        tags.setdefault(t.get("name"), t)
    names = order or list(tags)
    out = {}
    for nm in names:
        ss = secs.get(nm) or []
        if len(ss) != 1 or nm in out or nm not in tags:
            continue
        if is_array_kind(tags[nm], ss[0]):
            out[nm] = describe_array(tags[nm], ss[0], a2l_data, maps)
    return out, maps


def describe_one(a2l_data, nm):
    """describe_definition(name) = describe_definitions([name]): a fresh walk and a fresh `reads`."""
    out, _ = describe_all(a2l_data, [nm])
    return out.get(nm)
