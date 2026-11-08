"""Throwaway stdlib model of Inc 3a's CORRECTED build and decode rules (graph-inc3.md at 3d86eda0), for the E3
round-2 security probes. Not product code.

Round-1 model (`m3a.py`) changed only where the E3 round-1 correction changed the graph:
  * `_read_record_layout`: a NO_AXIS_PTS_X|Y component's datatype must be a *count datatype* (UBYTE, SBYTE, UWORD,
    SWORD, ULONG, SLONG, A_UINT64, A_INT64), else A2L-DEF-LAYOUT-DATATYPE (R-A2L-DEF.86, E3S3-01); a component line
    with more words than CTX *component* lists is a part (E3A-08).
  * `_read_axis` FIX: the parameters are read and checked in O(1) (first and last point in IEEE double, `2^s` only
    for s < 1024) and stored as `fixed_rule`, each number an int where integral; no point is built (E3A-01 =
    E3S3-02). The point-count cap (.142) is checked before the FIX parameters.
  * `_fixed_points(fixed_rule)`: the points, at decode only. `arith="literal"` evaluates `o + k*2^s` / `o + k*d` on
    the fixed_rule's numbers as stored (ints where integral -> exact integer arithmetic for PAR_DIST);
    `arith="float"` evaluates in IEEE double exactly as `_read_axis` checks the last point. The graph text does not
    say which; both are run.
  * `_current_count`: tested positively; anything not an int from 1 to n is CURRENT (E3S3-01, -05; E3A-13).
Where a node text leaves a branch open the model records it ("open_branch") instead of choosing.
"""
from __future__ import annotations

import math

A = None  # s19_app.tui.a2l, set by bind()

COMPONENTS = ("FNC_VALUES", "AXIS_PTS_X", "AXIS_PTS_Y", "NO_AXIS_PTS_X", "NO_AXIS_PTS_Y")
MAX_WORDS = {"FNC_VALUES": 5, "AXIS_PTS_X": 5, "AXIS_PTS_Y": 5, "NO_AXIS_PTS_X": 3, "NO_AXIS_PTS_Y": 3}
DATATYPES = ("UBYTE", "SBYTE", "UWORD", "SWORD", "ULONG", "SLONG", "A_UINT64", "A_INT64",
             "FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE")
COUNT_DATATYPES = ("UBYTE", "SBYTE", "UWORD", "SWORD", "ULONG", "SLONG", "A_UINT64", "A_INT64")
SIZES = {"UBYTE": 1, "SBYTE": 1, "UWORD": 2, "SWORD": 2, "ULONG": 4, "SLONG": 4, "A_UINT64": 8, "A_INT64": 8,
         "FLOAT16_IEEE": 2, "FLOAT32_IEEE": 4, "FLOAT64_IEEE": 8}
ALIGN_CLASS = {"UBYTE": "ALIGNMENT_BYTE", "SBYTE": "ALIGNMENT_BYTE", "UWORD": "ALIGNMENT_WORD", "SWORD": "ALIGNMENT_WORD",
               "ULONG": "ALIGNMENT_LONG", "SLONG": "ALIGNMENT_LONG", "A_UINT64": "ALIGNMENT_INT64",
               "A_INT64": "ALIGNMENT_INT64", "FLOAT16_IEEE": "ALIGNMENT_FLOAT16_IEEE",
               "FLOAT32_IEEE": "ALIGNMENT_FLOAT32_IEEE", "FLOAT64_IEEE": "ALIGNMENT_FLOAT64_IEEE"}
ALIGN_WORDS = set(ALIGN_CLASS.values())
CAP = 1_048_576
OPEN = []  # open branches met, (where, detail)


def bind(a2l_module):
    global A
    A = a2l_module


def whole(word):
    """CTX whole number: 1 to 9 ASCII digits; int() only on such a word."""
    if word is None or not 1 <= len(word) <= 9 or any(c not in "0123456789" for c in word):
        return None
    return int(word)


def finite(word):
    """Inc 2a's _finite_number: _to_float, then finite."""
    v = A._to_float(word)
    return v if (v is not None and math.isfinite(v)) else None


def int_where_integral(v):
    return int(v) if float(v).is_integer() else v


def clean_lines(lines):
    text = A._A2L_LINE_SENTINEL.join(lines or [])
    return [A._split_line_respecting_quotes(ln.strip()) for ln in A._strip_a2l_comments(text).split(A._A2L_LINE_SENTINEL)]


def flat(lines):
    return A._flatten_body_tokens(lines)


def read_matrix_dim(section):
    if section is None:
        return None
    for words in clean_lines(section.get("lines")):
        if words and words[0] == "MATRIX_DIM":
            rest = tuple(words[1:])
            nums = [whole(w) for w in rest]
            if not 1 <= len(rest) <= 3 or any(n is None or n < 1 for n in nums):
                return rest, None
            return rest, tuple(nums)
    return None


def first_line_word(section, key):
    for words in clean_lines(section.get("lines")):
        if words and words[0] == key:
            return words[1] if len(words) > 1 else None
    return None


def array_shape(tag, section, datatype, matrix):
    if matrix is not None and matrix[1] is not None:
        nums = [n for n in matrix[1] if n != 1] or [1]   # E3A-02: product above 1 -> array whatever its 1s
        shape = tuple(nums)
    else:
        shape = None
        if section is not None and tag.get("char_type") == "VAL_BLK":
            n = whole(first_line_word(section, "NUMBER") or "")
            if n is not None and n >= 1:
                shape = (n,)
        if shape is None and section is not None:
            lw = first_line_word(section, "LENGTH") or first_line_word(section, "DATA_SIZE")
            ln = whole(lw or "")
            if ln is not None and datatype in SIZES:
                if ln % SIZES[datatype]:
                    return ("REFUSAL", "A2L-DEF-SHAPE")
                shape = (ln // SIZES[datatype],)
    return shape


def read_record_layout(name, a2l_data, owner):
    rl = (a2l_data.get("record_layouts_by_name") or {}).get(name)
    if rl is None:
        return None
    comps, align, fixed, parts, seen = [], [], {}, [], set()
    for words in clean_lines(rl.get("lines")):
        if not words:
            continue
        w0 = words[0]
        if w0 in COMPONENTS and w0 not in seen and len(words) <= MAX_WORDS[w0]:
            seen.add(w0)
            comps.append(tuple(words))
        elif w0 in COMPONENTS and len(words) > MAX_WORDS[w0]:
            parts.append(words[MAX_WORDS[w0]])
        elif w0 in ("FIX_NO_AXIS_PTS_X", "FIX_NO_AXIS_PTS_Y") and len(words) == 2 and whole(words[1]) is not None:
            fixed[w0[-1]] = whole(words[1])
        elif w0 in ALIGN_WORDS and len(words) == 2 and (whole(words[1]) or 0) >= 1:
            align.append(tuple(words))
        elif words == ["DIRECT"]:
            pass
        else:
            parts.append(w0)
    pos = [whole(c[1]) if len(c) > 1 else None for c in comps]
    if any(p is None for p in pos) or len(set(pos)) != len(pos):
        return ("REFUSAL", "A2L-DEF-LAYOUT-POSITION")
    if parts:
        return ("REFUSAL", "A2L-DEF-LAYOUT-PART", parts[0])
    comps = [c for _, c in sorted(zip(pos, comps))]
    for c in comps:
        if c[0] == "FNC_VALUES":
            if (c[3] if len(c) > 3 else None) not in ("ROW_DIR", "COLUMN_DIR"):
                return ("REFUSAL", "A2L-DEF-LAYOUT-MODE")
            if (c[4] if len(c) > 4 else None) != "DIRECT":
                return ("REFUSAL", "A2L-DEF-LAYOUT-MODE")
        elif c[0] in ("AXIS_PTS_X", "AXIS_PTS_Y"):
            if (c[3] if len(c) > 3 else None) not in ("INDEX_INCR", "INDEX_DECR"):
                return ("REFUSAL", "A2L-DEF-LAYOUT-MODE")
            if (c[4] if len(c) > 4 else None) != "DIRECT":
                return ("REFUSAL", "A2L-DEF-LAYOUT-MODE")
    for c in comps:
        dt = c[2] if len(c) > 2 else None
        if dt is None:
            OPEN.append(("_read_record_layout: datatype word missing, <word> unpinned", (name, c)))
        if dt not in DATATYPES:
            return ("REFUSAL", "A2L-DEF-LAYOUT-DATATYPE", c[0], dt)
        if c[0] in ("NO_AXIS_PTS_X", "NO_AXIS_PTS_Y") and dt not in COUNT_DATATYPES:
            return ("REFUSAL", "A2L-DEF-LAYOUT-DATATYPE", c[0], dt)
    return {"name": name, "components": comps, "alignment": align, "fixed": fixed}


def place_components(layout, counts, extra_alignment=()):
    lines = [" ".join(w) for w in list(layout["alignment"]) + list(extra_alignment)]
    lines += [" ".join(c) for c in layout["components"]]
    walked = A._walk_record_layout_components({"lines": lines}, list(counts))
    if walked is None:
        return None
    return {e["component"]: e["offset"] for e in walked}, (walked[-1]["end"] if walked else 0)


def fix_rule(words, axis_section, point_count):
    """The corrected _read_axis FIX step (graph-inc3.md _read_axis): O(1) for PAR / PAR_DIST, O(list) for a list."""
    for kw in ("FIX_AXIS_PAR", "FIX_AXIS_PAR_DIST"):
        if kw in words:
            i = words.index(kw)
            o = finite(words[i + 1] if i + 1 < len(words) else None)
            x = finite(words[i + 2] if i + 2 < len(words) else None)
            n = whole(words[i + 3] if i + 3 < len(words) else None)
            if o is None or x is None or n is None:
                return "unreadable"
            if kw == "FIX_AXIS_PAR":
                if x >= 1024 and n >= 2:
                    return "unreadable"
                step = 2.0 ** x if x < 1024 else 0.0
            else:
                step = x
            last = o + (n - 1) * step          # IEEE double, as the node says
            if not (math.isfinite(o) and math.isfinite(last)):
                return "unreadable"
            if n != point_count:
                return n
            return ("PAR" if kw == "FIX_AXIS_PAR" else "PAR_DIST",
                    (int_where_integral(o), int_where_integral(x), n))
    for child in axis_section.get("children") or []:
        if child.get("name") == "FIX_AXIS_PAR_LIST":
            nums = [finite(w) for w in flat(child.get("lines") or [])]
            if any(v is None for v in nums):
                return "unreadable"
            if len(nums) != point_count:
                return len(nums)
            return ("PAR_LIST", tuple(int_where_integral(v) for v in nums))
    return None


def fixed_points(rule, arith="literal"):
    """_fixed_points at decode. literal: the fixed_rule's numbers as stored; float: IEEE double like the check."""
    form, nums = rule
    if form == "PAR_LIST":
        return tuple(nums)
    o, x, n = nums
    if arith == "float":
        o, x = float(o), float(x)
    step = 2.0 ** x if form == "PAR" else x       # 2^s in IEEE double (graph); d as stored
    out = []
    for k in range(n):
        v = o + k * step
        out.append(int_where_integral(v) if isinstance(v, float) else v)
    return tuple(out)


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
        header = flat([ap.get("meta") or ""] + (ap.get("lines") or []))
        aw = header[2] if len(header) > 2 else None
        if aw is not None and len(aw) <= 20:
            try:
                addr = int(aw, 0)
            except ValueError:
                addr = None
        if addr is None:
            return ("REFUSAL", "A2L-DEF-AXIS-REF")
        ap_layout = read_record_layout(header[4] if len(header) > 4 else None, a2l_data, name)
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
    if kind == "STD_AXIS":
        cdt = [c[2] for c in layout["components"] if c[0] == f"NO_AXIS_PTS_{letter}"]
        out["count_datatype"] = cdt[0] if cdt else None
        pdt = [c[2] for c in layout["components"] if c[0] == f"AXIS_PTS_{letter}"]
        out["point_datatype"] = pdt[0] if pdt else None
    if kind == "COM_AXIS":
        placed = place_components(ap_layout, (pc,))
        if placed is None or addr < 0 or addr + placed[1] - 1 > 0xFFFFFFFF:
            return ("REFUSAL", "A2L-DEF-AXIS-REF-RECORD")
        out["axis_object_address"] = addr
        out["record_end"] = placed[1]
        out["count_offset"] = placed[0].get("NO_AXIS_PTS_X")
        out["offset"] = placed[0].get("AXIS_PTS_X")
        cdt = [c[2] for c in ap_layout["components"] if c[0] == "NO_AXIS_PTS_X"]
        out["count_datatype"] = cdt[0] if cdt else None
        pdt = [c[2] for c in ap_layout["components"] if c[0] == "AXIS_PTS_X"]
        out["point_datatype"] = pdt[0] if pdt else None
    return out


def current_count(axis, record, byte_order):
    """The corrected _current_count: tested positively; anything else is CURRENT; never compares a non-int."""
    if axis["count_offset"] is None:
        return axis["point_count"]
    dt = axis["count_datatype"]
    size = SIZES[dt]
    c = A._decode_scalar(bytes(record[axis["count_offset"]:axis["count_offset"] + size]), dt, byte_order)
    n = axis["point_count"]
    if type(c) is int and c == n:
        return c
    if type(c) is int and 1 <= c <= n - 1:
        return ("REFUSAL", "A2L-DEF-AXIS-PARTIAL", c)
    return ("REFUSAL", "A2L-DEF-AXIS-CURRENT", c)


def build_maps(a2l_data):
    """The one walk (iterative here): AXIS_PTS by first header word, MOD_COMMON of each object by identity."""
    axis_pts, mod_of = {}, {}
    stack = [(s, None) for s in reversed(a2l_data.get("sections") or [])]
    while stack:
        node, mc = stack.pop()
        if node.get("name") == "MODULE":
            mc = next((c for c in node.get("children") or [] if c.get("name") == "MOD_COMMON"), None)
        if node.get("name") == "AXIS_PTS":
            h = flat([node.get("meta") or ""] + (node.get("lines") or []))
            if h:
                axis_pts.setdefault(h[0], node)
        if node.get("name") in ("MEASUREMENT", "CHARACTERISTIC", "AXIS_PTS"):
            mod_of[id(node)] = mc
        for c in reversed(node.get("children") or []):
            stack.append((c, mc))
    return {"axis_pts_by_name": axis_pts, "mod_common_of": mod_of}


def object_sections(a2l_data):
    out = {}
    stack = list(a2l_data.get("sections") or [])
    while stack:
        node = stack.pop()
        if node.get("name") in ("MEASUREMENT", "CHARACTERISTIC"):
            out.setdefault(A.parse_begin_meta(node.get("meta") or "")[0], []).append(node)
        stack.extend(node.get("children") or [])
    return out


def is_array_kind(tag, section):
    ct = tag.get("char_type")
    if tag.get("section") == "CHARACTERISTIC":
        return ct in ("VAL_BLK", "CURVE", "MAP")
    return False


def describe_array(tag, section, a2l_data, maps):
    name = tag.get("name")
    d = {"name": name, "refusal": None, "axes": [], "shape": (), "element_count": None, "byte_length": None}

    def refuse(code):
        if d["refusal"] is None:
            d["refusal"] = code

    ct = tag.get("char_type")
    matrix = read_matrix_dim(section)
    header = flat([section.get("meta") or ""] + (section.get("lines") or [])) if section else []
    lname = header[4] if len(header) > 4 else None
    layout = read_record_layout(lname, a2l_data, name)
    datatype = None
    if layout is None:
        refuse("A2L-DEF-LAYOUT")
    elif isinstance(layout, tuple):
        refuse(layout[1])
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
            refuse("A2L-DEF-MATRIX")                                     # .145
        axes = [c for c in (section.get("children") or []) if c.get("name") == "AXIS_DESCR"]
        need = 1 if ct == "CURVE" else 2
        if len(axes) != need:
            refuse("A2L-DEF-AXES")
        elif layout is not None:
            built = []
            for letter, ax in zip("XY", axes):
                r = read_axis(name, letter, ax, layout, a2l_data, maps)
                if isinstance(r, tuple):
                    refuse(r[1])
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
                if placed:
                    d["values_offset"] = placed[0].get("FNC_VALUES")
                    for ax in d["axes"]:
                        if ax["axis_kind"] == "STD_AXIS":
                            ax["offset"] = placed[0].get(f"AXIS_PTS_{ax['letter']}")
                            ax["count_offset"] = placed[0].get(f"NO_AXIS_PTS_{ax['letter']}")
            else:
                d["byte_length"] = d["element_count"] * SIZES[datatype] if datatype in SIZES else None
                d["values_offset"] = placed[0].get("FNC_VALUES") if placed else None
    d["datatype"] = datatype
    addr = tag.get("address")
    d["address"] = addr
    bl = d["byte_length"]
    if addr is None or bl is None:
        refuse("A2L-DEF-ADDRESS")
    elif bl < 1 or bl > CAP or addr < 0 or addr + bl - 1 > 0xFFFFFFFF:
        refuse("A2L-DEF-ADDRESS-SPAN")
    return d


def describe_all(a2l_data):
    maps = build_maps(a2l_data)
    secs = object_sections(a2l_data)
    out = {}
    for tag in a2l_data.get("tags") or []:
        nm = tag.get("name")
        ss = secs.get(nm) or []
        if len(ss) != 1 or nm in out:
            continue
        if is_array_kind(tag, ss[0]):
            out[nm] = describe_array(tag, ss[0], a2l_data, maps)
    return out
