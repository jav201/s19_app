"""E3 round-5 security probe, Inc 2 (batch-103): try to break R-A2L-DEF.138. Base parser only (clone e07fb00), read-only.

The claim under test (round-4 ruling): whatever the mask reader gets wrong, an encode can never write bytes another
object of the file owns, unless both masks were read and are disjoint.

MODEL = the records after the round-4b pass, emulated with the base parser's payload (tags + sections):
  .19       the PROP rule of sec-r4-probe.py, as now written (letters W, open per section, mid-line /begin,
            "not at all while it read one"); the mask word of the object record after the header.
  span      the tag's address (None = not declared) and the tag's length, else size x MATRIX_DIM for a MEASUREMENT
            (R-A2L-014 fill); byte order = the tag's effective_byte_order.
  index     every MEASUREMENT / CHARACTERISTIC tag with an address and a length >= 1 (graph `describe_definitions`).
  mask_of   three readings of "the bit mask this walk reads for that object (R-A2L-DEF.18) when the rules of
            R-A2L-DEF.19 give it no refusal":
              POS  the section paired with the tag by file position; a mask only for kind number/enum with a
                   datatype (what corr4/corr4b implement)
              NAME the section found by name, the first of that name (the graph: "the section is found by name";
                   `_find_tag` lost its position pairing, E3A-13)
              ANY  the mask read from the record whatever the kind (the graph's sentence without .18's kind)
              CLEAN (proposed) a mask counts only when the other object's own definition carries no refusal
  encode    step 1 the definition's refusal; step 9 shared_with -> A2L-DEF-OVERLAP; else the bits written: the bits
            its mask selects (CTX "bits an object selects"), every bit of its span when unmasked.
REF = a C-rule reader written for this probe (NOT a2ltool): comments are whitespace, /begin and /end are words matched
  by name anywhere on a line, `/include` is read, MATRIX_DIM is the product of its numbers, an object's BYTE_ORDER
  line else MOD_COMMON's, NUMBER sizes a VAL_BLK and an ASCII, BLOB / AXIS_PTS / INSTANCE own their spans, a bit mask
  applies to every element. CLOBBER = the model's encode returns bytes, and the bits it writes include a bit that REF
  says ANOTHER object owns.
"""
import collections, pathlib, re, subprocess, sys, tempfile

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app, s19_app.tui.a2l as a  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__)

def header(mod_common="BYTE_ORDER MSB_FIRST"):
    return ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\n' + mod_common +
            '\n/end MOD_COMMON\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n'
            '/begin COMPU_METHOD CM_BIT_MASK_ST "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n'
            + "".join(f'/begin RECORD_LAYOUT RL_{k}\nFNC_VALUES 1 {v} ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
                      for k, v in (("U8", "UBYTE"), ("S8", "SBYTE"), ("U16", "UWORD"), ("S16", "SWORD"), ("U32", "ULONG")))
            + '/begin RECORD_LAYOUT RL_AX16\nAXIS_PTS_X 1 UWORD INDEX_INCR DIRECT\n/end RECORD_LAYOUT\n'
            '/begin TYPEDEF_MEASUREMENT T_U16 "" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n')
TAIL = '/end MODULE\n/end PROJECT\n'
RL_DT = {"RL_U8": "UBYTE", "RL_S8": "SBYTE", "RL_U16": "UWORD", "RL_S16": "SWORD", "RL_U32": "ULONG", "RL_AX16": "UWORD"}
FULL = ' UWORD CM_ID 0 0 0 65535'; SHORT = ' UWORD CM_ID 0 0 0'
def meas(name, *body, hdr=FULL):
    return f'/begin MEASUREMENT {name} ""\n{hdr}\n' + "\n".join(body) + '\n/end MEASUREMENT'
def char(name, kind, addr, rl, *body):
    return f'/begin CHARACTERISTIC {name} ""\n {kind} {addr} {rl} 0 CM_ID 0 65535\n' + "\n".join(body) + '\n/end CHARACTERISTIC'

# ------------------------------------------------------------------------------------------------ helpers
HEX = re.compile(r"0x[0-9A-Fa-f]{1,16}", re.ASCII); DEC = re.compile(r"[0-9]{1,20}", re.ASCII)
def readable(w): return w is not None and (HEX.fullmatch(w) or DEC.fullmatch(w)) is not None
def num(w): return int(w, 16) if w[:2].lower() == "0x" else int(w)
OBJECT_SECTIONS = {"MEASUREMENT", "CHARACTERISTIC", "AXIS_PTS", "INSTANCE", "BLOB", "TYPEDEF_MEASUREMENT",
                   "TYPEDEF_CHARACTERISTIC", "TYPEDEF_AXIS", "TYPEDEF_BLOB", "TYPEDEF_STRUCTURE"}
SIGNED = {"SBYTE", "SWORD", "SLONG", "A_INT64"}; FLOATS = {"FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE"}

def walk(secs):
    for s in secs:
        yield s; yield from walk(s.get("children") or [])

def open_state(text):
    i, n, s = 0, len(text), None
    while i < n:
        c = text[i]
        if s == "quote":
            if c == '"' and text[i - 1] != "\\": s = None
            i += 1; continue
        if s == "comment":
            if c == "*" and i + 1 < n and text[i + 1] == "/": s = None; i += 2; continue
            i += 1; continue
        if c == '"': s = "quote"; i += 1; continue
        if c == "/" and i + 1 < n and text[i + 1] == "*": s = "comment"; i += 2; continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n": i += 1
            continue
        i += 1
    return s

def ref_tokens(text):
    toks, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace(): i += 1; continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0: toks.append(("ERR", "unterminated comment")); break
            i = j + 2; continue
        if text.startswith("//", i):
            j = text.find("\n", i); i = n if j < 0 else j; continue
        if c == '"':
            j = i + 1
            while j < n and not (text[j] == '"' and text[j - 1] != "\\"): j += 1
            if j >= n: toks.append(("ERR", "unterminated string")); break
            toks.append(("STR", text[i + 1:j])); i = j + 1; continue
        j = i
        while j < n and not text[j].isspace() and text[j] != '"' and not text.startswith("/*", j) and not text.startswith("//", j):
            j += 1
        toks.append(("ID", text[i:j])); i = j
    return toks

def begin_after_name_longid(meta):
    _n, rest = a._parse_first_field(meta or ""); _l, rest2 = a._parse_first_field(rest or ""); return rest2 or ""
def nonobj_desc(s):
    for c in s.get("children") or []:
        if c.get("name") in OBJECT_SECTIONS: continue
        yield c; yield from nonobj_desc(c)
def text_W(s):
    parts = [begin_after_name_longid(s["meta"])] + list(s.get("lines") or [])
    for c in nonobj_desc(s): parts += [c.get("meta", "")] + list(c.get("lines") or [])
    return "\n".join(parts)
def pieces_open(s):
    if open_state("\n".join([s["meta"]] + list(s["lines"]))): return True
    return any(open_state("\n".join([c.get("meta", "")] + list(c.get("lines") or []))) for c in nonobj_desc(s))
def midline_begin(s):
    pieces = [s["meta"]] + list(s["lines"]) + [x for c in nonobj_desc(s) for x in [c.get("meta", "")] + list(c.get("lines") or [])]
    if not any("/begin" in p.lower() for p in pieces): return False
    return any(k == "ID" and v.lower() == "/begin" for p in pieces for k, v in ref_tokens(p))

def scalar_kind(tag):
    if tag["section"] == "CHARACTERISTIC":
        return {"VALUE": "number/enum", "ASCII": "text"}.get(str(tag.get("char_type") or "").upper())
    return "number/enum" if tag.get("matrix_dim") in (None, 1) else None

def datatype(tag, sec, data):
    dt = str(tag.get("datatype") or "").upper()
    if dt in a.DATATYPE_SIZES: return dt
    if tag["section"] == "MEASUREMENT":
        w = a._flatten_body_tokens([sec["meta"]] + list(sec["lines"]))
        return w[2].upper() if len(w) > 2 and w[2].upper() in a.DATATYPE_SIZES else None
    lay = a._resolve_record_layout(tag.get("record_layout_name"), data["record_layouts_by_name"]) or {}
    dt = str(lay.get("decode_type") or "").upper()
    return dt if dt in a.DATATYPE_SIZES else None

def check_bit_mask(m, dt):
    if m <= 0 or dt in FLOATS: return False
    width = 8 * a.DATATYPE_SIZES[dt]
    if m >= 1 << width: return False
    if dt in SIGNED and (m & 1) and (m >> (width - 1)) & 1: return False
    return True

def mask_read(tag, sec, dt, kind, any_kind=False):
    """(mask or None, refused-by-.19). The rule as the records now write it (PROP of round 4)."""
    letters = text_W(sec).upper().count("BIT_MASK")
    words = a._flatten_body_tokens([sec["meta"]] + list(sec["lines"]))
    n = 8 if tag["section"] == "MEASUREMENT" else 9
    rest = words[n:]; word = None
    if "BIT_MASK" in rest:
        i = rest.index("BIT_MASK"); word = rest[i + 1] if i + 1 < len(rest) else ""
    if pieces_open(sec) or midline_begin(sec): return None, True
    if letters > 1 or (letters == 1 and word is None) or (letters == 0 and word is not None): return None, True
    if word is None: return None, False
    if kind == "text" or not readable(word): return None, True
    if not any_kind and (kind != "number/enum" or dt is None): return None, False
    m = num(word)
    if dt is not None and not check_bit_mask(m, dt): return None, True
    return m, False

def selected(address, length, order, mask):
    if mask is None: return {address + i: 0xFF for i in range(length)}
    out = {}
    for i in range(length):
        b = (mask >> (8 * i)) & 0xFF
        if b: out[address + i if order == "little" else address + length - 1 - i] = b
    return out
def meets(x, y): return any(x.get(k, 0) & v for k, v in y.items())

def model(data):
    tags = data["tags"]; secs = [s for s in walk(data["sections"]) if s["name"] in ("MEASUREMENT", "CHARACTERISTIC")]
    assert len(tags) == len(secs), (len(tags), len(secs))
    tag_count = collections.Counter(t["name"] for t in tags)
    sec_by_name = collections.defaultdict(list)
    for s in secs: sec_by_name[a.parse_begin_meta(s["meta"])[0]].append(s)
    objs = []
    for i, (t, s) in enumerate(zip(tags, secs)):
        kind = scalar_kind(t); dt = datatype(t, s, data)
        length = t.get("length")
        if length is None and t["section"] == "MEASUREMENT" and dt: length = a.DATATYPE_SIZES[dt] * (t.get("matrix_dim") or 1)
        mask, mref = mask_read(t, s, dt, kind)
        mask_any, _ = mask_read(t, s, dt, kind, any_kind=True)
        mask_name, _ = mask_read(t, sec_by_name[t["name"]][0], dt, kind)
        size = a.DATATYPE_SIZES.get(dt) if dt else None
        cm = t.get("conversion")
        if tag_count[t["name"]] > 1 or len(sec_by_name[t["name"]]) > 1: ref = "A2L-DEF-NAME(dup)"
        elif kind is None: ref = "A2L-DEF-KIND"
        elif t.get("address") is None or length is None: ref = "A2L-DEF-ADDRESS"
        elif length < 1 or length > 1 << 20 or t["address"] < 0 or t["address"] + length - 1 > 0xFFFFFFFF: ref = "A2L-DEF-ADDRESS(span)"
        elif kind == "number/enum" and dt is None: ref = "A2L-DEF-DATATYPE"
        elif kind == "number/enum" and length != size: ref = "A2L-DEF-LENGTH"
        elif cm and cm != "NO_COMPU_METHOD" and cm not in data["compu_methods_by_name"]: ref = "A2L-DEF-METHOD"
        elif mref: ref = "A2L-DEF-MASK"
        else: ref = None
        objs.append(dict(i=i, name=t["name"], sec=t["section"], addr=t.get("address"), length=length,
                         order=t.get("effective_byte_order") or "little", kind=kind, dt=dt, refusal=ref,
                         mask=mask, mask_any=mask_any, mask_name=mask_name))
    return objs

def mask_of(o, reading):
    if reading == "POS": return o["mask"]
    if reading == "NAME": return o["mask_name"]
    if reading == "ANY": return o["mask_any"]
    if reading == "CLEAN": return o["mask"] if o["refusal"] is None else None

def shared_with(objs, x, reading, self_mask=None):
    if x["addr"] is None or not x["length"]: return None
    sm = x["mask"] if self_mask is None else self_mask
    xs = selected(x["addr"], x["length"], x["order"], sm) if sm is not None else None
    for o in objs:
        if o is x or o["addr"] is None or not o["length"] or o["length"] < 1: continue
        if o["addr"] > x["addr"] + x["length"] - 1 or x["addr"] > o["addr"] + o["length"] - 1: continue
        om = mask_of(o, reading)
        if sm is not None and om is not None and not meets(xs, selected(o["addr"], o["length"], o["order"], om)): continue
        return o["name"]
    return None

def encode(objs, x, reading, lost_mask=False):
    if not lost_mask and x["refusal"]: return ("REFUSED", x["refusal"]), None
    if x["addr"] is None or not x["length"]: return ("NO-SPAN", None), None
    sm = None if lost_mask else x["mask"]
    sw = shared_with(objs, x, reading) if sm is not None else _sw_unmasked(objs, x)
    if sw: return ("OVERLAP", sw), None
    return ("BYTES", None), selected(x["addr"], x["length"], x["order"], sm)

def _sw_unmasked(objs, x):
    if x["addr"] is None or not x["length"]: return None
    for o in objs:
        if o is x or o["addr"] is None or not o["length"] or o["length"] < 1: continue
        if o["addr"] > x["addr"] + x["length"] - 1 or x["addr"] > o["addr"] + o["length"] - 1: continue
        return o["name"]
    return None

# ------------------------------------------------------------------------------------------------ REF
def ref_objects(text, includes):
    for name, body in includes.items():
        text = text.replace(f'/include "{name}"', body)
    toks = ref_tokens(text)
    if any(t[0] == "ERR" for t in toks): return None, "malformed: " + [t[1] for t in toks if t[0] == "ERR"][0]
    stack, done, mod_order, typedefs = [], [], "big", {}
    k = 0
    while k < len(toks):
        kind, v = toks[k]
        if kind == "ID" and v == "/begin":
            stack.append([toks[k + 1][1], []]); k += 2; continue
        if kind == "ID" and v == "/end":
            blk = toks[k + 1][1]
            if not stack or stack[-1][0] != blk: return None, f"malformed: /end {blk} closes {stack[-1][0] if stack else None}"
            done.append(stack.pop()); k += 2; continue
        if stack: stack[-1][1].append((kind, v))
        k += 1
    if stack: return None, "malformed: unclosed " + stack[-1][0]
    for blk, body in done:
        ids = [v for _k, v in body]
        if blk == "MOD_COMMON" and "BYTE_ORDER" in ids: mod_order = "big" if ids[ids.index("BYTE_ORDER") + 1] == "MSB_FIRST" else "little"
        if blk == "TYPEDEF_MEASUREMENT": typedefs[ids[0]] = ids[2]
    out, notes = [], []
    for blk, body in done:
        ids = [v for _k, v in body]
        def kw(name, n=1):
            if name not in ids: return None
            j = ids.index(name); return ids[j + 1: j + 1 + n]
        order = mod_order
        if kw("BYTE_ORDER"): order = "big" if kw("BYTE_ORDER")[0] == "MSB_FIRST" else "little"
        mask = num(kw("BIT_MASK")[0]) if kw("BIT_MASK") and readable(kw("BIT_MASK")[0]) else None
        def dims():
            if "MATRIX_DIM" not in ids: return 1
            j = ids.index("MATRIX_DIM") + 1; p = 1
            while j < len(ids) and DEC.fullmatch(ids[j]): p *= int(ids[j]); j += 1
            return p
        if blk == "MEASUREMENT":
            dt = ids[2]; addr = num(kw("ECU_ADDRESS")[0]) if kw("ECU_ADDRESS") else None
            el = a.DATATYPE_SIZES.get(dt); cnt = dims()
            if addr is not None and el: out.append(dict(name=ids[0], addr=addr, el=el, count=cnt, order=order, mask=mask))
        elif blk == "CHARACTERISTIC":
            ck, addr, dep = ids[2], num(ids[3]), ids[4]; el = a.DATATYPE_SIZES.get(RL_DT.get(dep, ""), None)
            if ck == "ASCII": el, cnt, mask = 1, (int(kw("NUMBER")[0]) if kw("NUMBER") else dims()), None
            elif ck == "VAL_BLK": cnt = int(kw("NUMBER")[0]) if kw("NUMBER") else dims()
            else: cnt = 1
            out.append(dict(name=ids[0], addr=addr, el=el, count=cnt, order=order, mask=mask))
        elif blk == "AXIS_PTS":
            out.append(dict(name=ids[0], addr=num(ids[2]), el=2, count=int(ids[7]), order=order, mask=None))
        elif blk == "BLOB":
            out.append(dict(name=ids[0], addr=num(ids[2]), el=1, count=int(ids[3]), order=order, mask=None))
        elif blk == "INSTANCE":
            out.append(dict(name=ids[0], addr=num(ids[3]), el=a.DATATYPE_SIZES[typedefs[ids[2]]], count=1, order=order, mask=None))
    for o in out:
        bits = {}
        for e in range(o["count"]):
            for ad, b in selected(o["addr"] + e * o["el"], o["el"], o["order"], o["mask"]).items(): bits[ad] = bits.get(ad, 0) | b
        o["bits"] = bits
    return out, None

def run_case(key, label, body, xname, readings=("POS", "NAME", "ANY", "CLEAN"), mod_common="BYTE_ORDER MSB_FIRST", includes=None,
             lost_mask=False, d=None):
    includes = includes or {}
    text = header(mod_common) + body + "\n" + TAIL
    p = pathlib.Path(d) / "x.a2l"; p.write_text(text, encoding="utf-8")
    for name, inc in includes.items(): (pathlib.Path(d) / name).write_text(inc, encoding="utf-8")
    data = a.parse_a2l_file(p)
    objs = model(data)
    refs, why = ref_objects(text, includes)
    xs = [o for o in objs if o["name"] == xname]
    x = xs[-1]
    print(f"[{key}] {label}")
    print(f"     parse errors={data['errors']}")
    print("     model objects: " + "; ".join(f"{o['name']}@{o['addr'] if o['addr'] is None else hex(o['addr'])}+{o['length']} "
                                          f"{o['order']} mask={o['mask'] if o['mask'] is None else hex(o['mask'])} "
                                          f"kind={o['kind']} ref={o['refusal']}" for o in objs))
    if refs is None: print(f"     REF: {why}")
    else: print("     REF objects:   " + "; ".join(f"{r['name']}@{hex(r['addr'])} {r['count']}x{r['el']} {r['order']} "
                                               f"mask={r['mask'] if r['mask'] is None else hex(r['mask'])} bits={ {hex(k): hex(v) for k, v in r['bits'].items()} }" for r in refs))
    for rd in readings:
        res, bits = encode(objs, x, rd, lost_mask=lost_mask)
        clob = []
        if bits is not None and refs is not None:
            for r in refs:
                if r["name"] == xname: continue
                if meets(bits, r["bits"]): clob.append(r["name"])
        own = [r for r in (refs or []) if r["name"] == xname]
        outside = bits is not None and own and any(v & ~own[0]["bits"].get(k, 0) for k, v in bits.items())
        verdict = ("CLOBBER " + ",".join(clob)) if clob else ("writes outside its own REF bits" if outside else "ok")
        print(f"     encode {xname} [{rd}]{' (lost mask)' if lost_mask else ''}: {res[0]} {res[1] or ''} "
              f"{'' if bits is None else 'writes ' + str({hex(k): hex(v) for k, v in sorted(bits.items())})} -> {verdict}")

# ------------------------------------------------------------------------------------------------ Part 1
P1_SHAPES = {   # sec-r4-probe.py SHAPES, each placed after a masked neighbour MN (UWORD 0x10, BIT_MASK 0x000F, read)
 "A": meas("SX", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10"),
 "B": meas("SX", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10", hdr=SHORT),
 "C": meas("SX", " ECU_ADDRESS 0x10", hdr=SHORT + " BIT_MASK 0x0FF0"),
 "D": meas("SX", " /* mask */ BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10", hdr=SHORT),
 "E": '/begin MEASUREMENT SX "" UWORD CM_ID 0 0 0 65535 BIT_MASK 0x0FF0\n ECU_ADDRESS 0x10\n/end MEASUREMENT',
 "F": meas("SX", " ECU_ADDRESS 0x10", hdr=FULL + "/* upper */BIT_MASK 0x0FF0"),
 "G": meas("SX", " BIT_MASK/* bits */0x0FF0", " ECU_ADDRESS 0x10"),
 "H": meas("SX", " ECU_ADDRESS 0x10", ' FORMAT "%5.0', " BIT_MASK 0x0FF0"),
 "I": meas("SX", " ECU_ADDRESS 0x10", ' FORMAT "%5.0', " /* m */ BIT_MASK 0x0FF0"),
 "J": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", " BIT_MASK 0x0FF0"),
 "J1": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK  KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " BIT_MASK 0x0FF0"),
 "K": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", " BIT_MASK 0x0FF0", " /end IF_DATA"),
 "L": meas("SX", " ECU_ADDRESS 0x10", " /* old:", " /begin IF_DATA XCP", " */", " BIT_MASK 0x0FF0"),
 "L2": meas("SX", " ECU_ADDRESS 0x10", " /* /begin IF_DATA XCP", " /end IF_DATA */", " BIT_MASK 0x0FF0"),
 "L5": meas("SX", " ECU_ADDRESS 0x10", " // /begin IF_DATA XCP", " /end IF_DATA", " BIT_MASK 0x0FF0"),
 "M": meas("SX", " ECU_ADDRESS 0x10", " /* BIT_MASK 0x0FF0 */"),
 "N": meas("SX", " BIT_MASK", " 0x0FF0", " ECU_ADDRESS 0x10"),
 "O": meas("SX", ' PHYS_UNIT "BIT_MASK"', " ECU_ADDRESS 0x10"),
 "O2": meas("SX", ' PHYS_UNIT "BIT_MASK"', " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10"),
 "P": meas("SX", " BIT_MASK 0x000F", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10"),
 "Q": meas("SX", " bit_mask 0x0FF0", " ECU_ADDRESS 0x10"),
 "R2": '/begin CHARACTERISTIC SX ""\n VALUE 0x10 RL_U16 0 CM_ID 0\n BIT_MASK 0x0FF0\n/end CHARACTERISTIC',
 "S": meas("SX", " BIT_MASK\t0x0FF0", " ECU_ADDRESS 0x10"),
 "T": meas("SX", " ECU_ADDRESS 0x10", hdr=FULL + "\x0cBIT_MASK 0x0FF0"),
 "U": meas("SX", ' FORMAT "%5.0"BIT_MASK 0x0FF0', " ECU_ADDRESS 0x10"),
 "W": meas("SX", " ECU_ADDRESS 0x10", " /begin ANNOTATION", " /begin ANNOTATION_TEXT", ' "BIT_MASK 0x0FF0"', " /end ANNOTATION_TEXT", " /end ANNOTATION"),
 "L2C": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", "  /* /begin DAQ_EVENT 1", "  /end DAQ_EVENT */", " /end IF_DATA", " BIT_MASK 0x0FF0"),
 "L2N": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", "  /begin DAQ", "   /* /begin EVENT_LIST", "   /end EVENT_LIST */", "  /end DAQ", " /end IF_DATA", " BIT_MASK 0x0FF0"),
 "L7": meas("SX", " ECU_ADDRESS 0x10", " /begin ANNOTATION", "  /begin ANNOTATION_TEXT", '   "see:', "/end ANNOTATION_TEXT", "/end ANNOTATION", '/end MEASUREMENT"', "  /end ANNOTATION_TEXT", " /end ANNOTATION", " BIT_MASK 0x0FF0"),
 "J2": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA", " /begin IF_DATA CANAPE_EXT 100 /end IF_DATA", " BIT_MASK 0x0FF0"),
 "J3": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA BIT_MASK 0x0FF0"),
 "J4": meas("SX", " ECU_ADDRESS 0x10 /begin IF_DATA XCP", "  KP_BLOB 0x10", " /end IF_DATA", " BIT_MASK 0x0FF0"),
 "J5": meas("SX", " ECU_ADDRESS 0x10 /begin IF_DATA XCP BIT_MASK 0x1 /end IF_DATA"),
 "X": meas("SX", " BIT_/* x */MASK 0x0FF0", " ECU_ADDRESS 0x10", hdr=SHORT),
 "X2": meas("SX", " BIT_/* x */MASK 0x0FF0", " ECU_ADDRESS 0x10"),
 "N2": meas("SX", " ECU_ADDRESS 0x10").replace("SX", "SIG.BIT_MASK.A"),
 "CMN": meas("SX", " ECU_ADDRESS 0x10", hdr=" UWORD CM_BIT_MASK_ST 0 0 0 65535"),
}
MN = meas("MN", " BIT_MASK 0x000F", " ECU_ADDRESS 0x10")

print("\n== Part 1: round-3/4 shapes after a masked neighbour MN (UWORD at 0x10, BIT_MASK 0x000F read) ==")
with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
    tally = collections.Counter()
    for key, body in P1_SHAPES.items():
        text = header() + MN + "\n" + body + "\n" + TAIL
        p = pathlib.Path(d) / "x.a2l"; p.write_text(text, encoding="utf-8")
        data = a.parse_a2l_file(p); objs = model(data)
        xname = "SIG.BIT_MASK.A" if key == "N2" else "SX"
        x = [o for o in objs if o["name"] == xname][-1]
        refs, why = ref_objects(text, {})
        refx = [r for r in (refs or []) if r["name"] == xname]
        ref_mask = (hex(refx[0]["mask"]) if refx and refx[0]["mask"] is not None else ("none" if refx else why))
        res, bits = encode(objs, x, "POS")
        lres, lbits = encode(objs, x, "POS", lost_mask=True)
        clob = [r["name"] for r in (refs or []) if bits is not None and r["name"] != xname and meets(bits, r["bits"])]
        lost = refx and refx[0]["mask"] is not None and x["mask"] is None
        tag = ("LOST-MASK " if lost else "") + ("refused .19" if res[0] == "REFUSED" and res[1] == "A2L-DEF-MASK" else res[0])
        tally[(bool(lost), res[0])] += 1
        print(f"[P1-{key}] model mask={x['mask'] if x['mask'] is None else hex(x['mask'])} refusal={x['refusal']} | REF mask={ref_mask} | "
              f"encode 35: {res[0]} {res[1] or ''}{'' if bits is None else ' writes ' + str({hex(k): hex(v) for k, v in sorted(bits.items())})} "
              f"| clobber={clob or 'none'} | lost-mask simulation: {lres[0]} {lres[1] or ''} | {tag}")
    print("[P1-total] (REF mask lost by the model, outcome): " + ", ".join(f"{k}: {v}" for k, v in sorted(tally.items())))

# ------------------------------------------------------------------------------------------------ Part 2
X10 = meas("X", " ECU_ADDRESS 0x10")
print("\n== Part 2: attacks on R-A2L-DEF.138 (X = the object encoded) ==")
with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
    print("\n-- A: the neighbour is not in the index --")
    run_case("A1", "N's ECU_ADDRESS word glued to a comment: `ECU_ADDRESS 0x10/* moved */`", X10 + "\n" + meas("N", " ECU_ADDRESS 0x10/* moved */"), "X", d=d)
    run_case("A2", "a comment between ECU_ADDRESS and its word: `ECU_ADDRESS /* new */ 0x10`", X10 + "\n" + meas("N", " ECU_ADDRESS /* new */ 0x10"), "X", d=d)
    run_case("A3", "N: a one-line IF_DATA (V171 style) before its ECU_ADDRESS line", X10 + "\n" + meas("N", " /begin IF_DATA ETK KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " ECU_ADDRESS 0x10"), "X", d=d)
    run_case("A4", "N CHARACTERISTIC, header address glued to a comment: `VALUE 0x10/* c */RL_U16 ...`", X10 + "\n" + '/begin CHARACTERISTIC N ""\n VALUE 0x10/* c */RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC', "X", d=d)
    run_case("A5", "N in an /include file", X10 + '\n/include "inc.a2l"', "X", includes={"inc.a2l": meas("N", " ECU_ADDRESS 0x10")}, d=d)
    run_case("A6", "N an AXIS_PTS at 0x10 (4 points; ruled to Inc 3)", X10 + '\n/begin AXIS_PTS N "" 0x10 NO_INPUT_QUANTITY RL_AX16 0 CM_ID 4 0 100\n/end AXIS_PTS', "X", d=d)
    run_case("A7", "N a BLOB at 0x10, 2 bytes", X10 + '\n/begin BLOB N "" 0x10 2\n/end BLOB', "X", d=d)
    run_case("A8", "N a VAL_BLK `NUMBER 4` at 0x10 (RL_U16: no length in the tag table); X at 0x14", meas("X", " ECU_ADDRESS 0x14") + "\n" + char("N", "VAL_BLK", "0x10", "RL_U16", " NUMBER 4"), "X", d=d)
    run_case("A9", "N an INSTANCE of a UWORD typedef at 0x10", X10 + '\n/begin INSTANCE N "" T_U16 0x10\n/end INSTANCE', "X", d=d)

    print("\n-- B: the neighbour's span is wrong --")
    run_case("B1", "N `MATRIX_DIM 1 4 1` (x = 1): the tag reads 1, a scalar of 2 bytes; X at 0x14", meas("X", " ECU_ADDRESS 0x14") + "\n" + meas("N", " ECU_ADDRESS 0x10", " MATRIX_DIM 1 4 1"), "X", d=d)
    run_case("B1n", "the same N encoded (kind number from MATRIX_DIM 1 4 1)", meas("X", " ECU_ADDRESS 0x40") + "\n" + meas("N", " ECU_ADDRESS 0x10", " MATRIX_DIM 1 4 1"), "N", d=d)
    run_case("B2", "N `MATRIX_DIM 2 2`: the tag reads 2 (4 bytes, REF 8); X at 0x16", meas("X", " ECU_ADDRESS 0x16") + "\n" + meas("N", " ECU_ADDRESS 0x10", " MATRIX_DIM 2 2"), "X", d=d)
    run_case("B3", "N: live `ECU_ADDRESS 0x20`, then an old `ECU_ADDRESS 0x10` inside a /* ... */ block; X at 0x20", meas("X", " ECU_ADDRESS 0x20") + "\n" + meas("N", " ECU_ADDRESS 0x20", " /*", " ECU_ADDRESS 0x10", " */"), "X", d=d)
    run_case("B3n", "the same N encoded (alone at its old address)", meas("X", " ECU_ADDRESS 0x40") + "\n" + meas("N", " ECU_ADDRESS 0x20", " /*", " ECU_ADDRESS 0x10", " */"), "N", d=d)
    run_case("B4", "N: live `MATRIX_DIM 4`, then `MATRIX_DIM 1` inside a /* ... */ block; X at 0x14", meas("X", " ECU_ADDRESS 0x14") + "\n" + meas("N", " ECU_ADDRESS 0x10", " MATRIX_DIM 4", " /*", " MATRIX_DIM 1", " */"), "X", d=d)
    run_case("B5", "N ASCII with `MATRIX_DIM 8` (1.7 style, no NUMBER) at 0x10; X UBYTE VALUE at 0x14", char("X", "VALUE", "0x14", "RL_U8") + "\n" + char("N", "ASCII", "0x10", "RL_U8", " MATRIX_DIM 8"), "X", d=d)

    print("\n-- C: both masks read, the exemption trusts a wrong frame or mask --")
    XU8 = char("X", "VALUE", "0x10", "RL_U8", " BIT_MASK 0x0F")
    run_case("C1", "N UWORD 0x000F: its `BYTE_ORDER MSB_LAST` line after a one-line IF_DATA (lost); X UBYTE 0x10 BIT_MASK 0x0F", XU8 + "\n" + meas("N", " ECU_ADDRESS 0x10", " BIT_MASK 0x000F", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA", " BYTE_ORDER MSB_LAST"), "X", d=d)
    run_case("C2", "N UWORD 0x000F: live `BYTE_ORDER MSB_LAST`, then `BYTE_ORDER MSB_FIRST` in a /* ... */ block (last wins)", XU8 + "\n" + meas("N", " ECU_ADDRESS 0x10", " BIT_MASK 0x000F", " BYTE_ORDER MSB_LAST", " /* alternative:", " BYTE_ORDER MSB_FIRST", " */"), "X", d=d)
    run_case("C3", "MOD_COMMON: `BYTE_ORDER MSB_LAST` inside /* ... */, then the live MSB_FIRST (first wins); X 0x000F, N 0x0F00, UWORDs at 0x10",
             meas("X", " ECU_ADDRESS 0x10", " BIT_MASK 0x000F") + "\n" + meas("N", " ECU_ADDRESS 0x10", " BIT_MASK 0x0F00"), "X",
             mod_common="/*\nBYTE_ORDER MSB_LAST\n*/\nBYTE_ORDER MSB_FIRST", d=d)
    run_case("C4", "a commented-out old copy of N (0x40, BIT_MASK 0xF000) above the live N (0x10, BIT_MASK 0x00F0); X UWORD 0x10 BIT_MASK 0x00F0",
             meas("X", " ECU_ADDRESS 0x10", " BIT_MASK 0x00F0") + "\n/* old copy\n" + meas("N", " ECU_ADDRESS 0x40", " BIT_MASK 0xF000") + "\n*/\n" + meas("N", " ECU_ADDRESS 0x10", " BIT_MASK 0x00F0"), "X", d=d)
    run_case("C5", "N `BIT_MASK 0x000F/* nibble */0` (the base glues 0x000F0); X UWORD 0x10 BIT_MASK 0x000F",
             meas("X", " ECU_ADDRESS 0x10", " BIT_MASK 0x000F") + "\n" + meas("N", " ECU_ADDRESS 0x10", " BIT_MASK 0x000F/* nibble */0"), "X", d=d)
    run_case("C6", "N a 2-element MEASUREMENT (`MATRIX_DIM 2`) with BIT_MASK 0x00FF at 0x10; X UWORD 0x10 BIT_MASK 0x00FF",
             meas("X", " ECU_ADDRESS 0x10", " BIT_MASK 0x00FF") + "\n" + meas("N", " ECU_ADDRESS 0x10", " MATRIX_DIM 2", " BIT_MASK 0x00FF"), "X", d=d)
    run_case("C7", "N `MATRIX_DIM 1 2 1` UWORD BIT_MASK 0x000F at 0x10 (kind number, span 2); X UBYTE 0x13 BIT_MASK 0x0F",
             char("X", "VALUE", "0x13", "RL_U8", " BIT_MASK 0x0F") + "\n" + meas("N", " ECU_ADDRESS 0x10", " MATRIX_DIM 1 2 1", " BIT_MASK 0x000F"), "X", d=d)

    print("\n-- D: a text object whose bytes are shared --")
    run_case("D1", "X ASCII NUMBER 4 at 0x10, N UBYTE VALUE at 0x12", char("X", "ASCII", "0x10", "RL_U8", " NUMBER 4") + "\n" + char("N", "VALUE", "0x12", "RL_U8"), "X", d=d)

# ------------------------------------------------------------------------------------------------ Part 3
print("\n== Part 3: the 35 fixture files ==")
files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True, check=True).stdout.split()
T = collections.Counter(); lost_list = []; bo_list = []; md_list = []; exempt_list = []; nolen_inside = []
for f in files:
    data = a.parse_a2l_file(repo / f)
    try: objs = model(data)
    except AssertionError as e: print(f"[FX] {f}: tag/section mismatch {e}"); continue
    secs = [s for s in walk(data["sections"]) if s["name"] in ("MEASUREMENT", "CHARACTERISTIC")]
    idx = [o for o in objs if o["addr"] is not None and o["length"] and o["length"] >= 1]
    starts = sorted(((o["addr"], o["addr"] + o["length"] - 1, o) for o in idx), key=lambda t: (t[0], t[1], t[2]["i"]))
    # (i) objects the index leaves out although their text holds an ECU_ADDRESS keyword with a readable word (C rule)
    for o, s in zip(objs, secs):
        toks = [v for k, v in ref_tokens(text_W(s)) if k == "ID"]
        decl = [toks[j + 1] for j, v in enumerate(toks[:-1]) if v == "ECU_ADDRESS" and readable(toks[j + 1])]
        if o["addr"] is None and decl:
            T["lost-address"] += 1; lost_list.append((f, o["name"], decl[:2]))
        if o["addr"] is not None and decl and num(decl[-1]) != o["addr"] and o["sec"] == "MEASUREMENT":
            T["address-differs"] += 1; lost_list.append((f, o["name"], ("tag", hex(o["addr"]), "text", decl)))
        letters = text_W(s).upper().count("BYTE_ORDER")
        if letters > 1 or (letters == 1 and not any(ln.strip().split()[:1] == ["BYTE_ORDER"] for ln in s["lines"])):
            T["byte-order-letters"] += 1; bo_list.append((f, o["name"], letters, o["mask"] is not None))
        md = [ln.split() for ln in s["lines"] if ln.split()[:1] == ["MATRIX_DIM"]]
        for parts in md:
            ns = [p for p in parts[1:] if DEC.fullmatch(p)]
            prod = 1
            for p in ns: prod *= int(p)
            if len(ns) > 1 and prod != int(ns[0]):
                T["matrix-dim-product-differs"] += 1; md_list.append((f, o["name"], parts[1:], o["addr"] is not None))
    # (ii) declared address, no length: does an indexed object that the row does NOT refuse cover its first byte?
    for o in objs:
        if o["addr"] is not None and not o["length"]:
            T["declared-no-length"] += 1
            for st, en, q in starts:
                if st <= o["addr"] <= en and q["refusal"] is None and _sw_unmasked(objs, q) is None:
                    T["declared-no-length-inside-an-unrefused-span"] += 1; nolen_inside.append((f, o["name"], q["name"])); break
    # (iii) exempt pairs and the cost of "a mask counts only for an object with no refusal" (CLEAN)
    for o in idx:
        if o["refusal"] is not None or o["mask"] is None: continue
        for q in idx:
            if q is o or q["addr"] > o["addr"] + o["length"] - 1 or o["addr"] > q["addr"] + q["length"] - 1: continue
            if q["mask"] is not None and not meets(selected(o["addr"], o["length"], o["order"], o["mask"]), selected(q["addr"], q["length"], q["order"], q["mask"])):
                exempt_list.append((f, o["name"], hex(o["mask"]), q["name"], hex(q["mask"]), q["refusal"]))
    T["files"] += 1; T["objects"] += len(objs); T["indexed"] += len(idx)
    T["pos-vs-clean-shared_with-differs"] += sum(1 for o in idx if o["refusal"] is None and shared_with(objs, o, "POS") != shared_with(objs, o, "CLEAN")) if len(idx) < 5000 else 0
print("[FX-total] " + " ".join(f"{k}={v}" for k, v in T.items()))
print("[FX-lost-address] " + repr(lost_list[:12]))
print("[FX-byte-order] " + repr(bo_list[:12]))
print("[FX-matrix-dim] " + repr(md_list[:12]))
print("[FX-declared-no-length-inside] " + repr(nolen_inside[:12]))
print("[FX-exempt] " + repr(exempt_list))
