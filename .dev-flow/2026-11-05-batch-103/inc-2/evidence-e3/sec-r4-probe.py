"""E3 round-4 security probe, Inc 2 (batch-103). Base parser only (clone e07fb00), read-only.

Q1: does the rule AS THE RECORDS WRITE IT (R-A2L-DEF.19 after the round-3 pass; CTX-A2L-DEF
    "the text of the object"; graph `_read_object_lines` / `describe_definitions`) refuse every
    round-3 shape (F, G, J1, L, L2, H, P) and keep the closed ones closed?
      letters  = the letters BIT_MASK, any case, in the text of the object: the /begin line after the
                 name and long identifier, its own lines, and the lines of each child section that is
                 not itself an object; refuse when > 1, or == 1 while no mask word was read
      open     = the object's RECORD ([meta] + own lines) ends inside an open block comment or quote
    The text of the object is emulated in two readings, because the records do not pin them:
      W = every non-object child section to any depth, each with its /begin line (meta) and lines
          (what the round-3 reference rule did, minus the name and long identifier)
      N = the direct non-object children only, their `lines` only (no /begin line)
    REF3 = the round-3 reference rule itself (sec-r3-probe.py: full meta incl. name/long id, W depth).
Q2: shapes the round-3 reference did not try (L2C, L2N, L7: a comment or quote opened in a CHILD hides
    an /end; J2, J3: two one-line IF_DATA / text after a one-line /end; J4, J5: a /begin not at line
    start; X, X2: a comment inside the keyword; N2, CMN: the letters in a name).
Q3: the 35 fixture files: refusals of each rule beyond the round-3 graph (keyword rule + bit_org
    cross-check), refusals the round-3 graph made that the new rule drops, and masks kept.
REF = the C-rule reader of round 3 (a comment separates two words; /begin and /end matched by name;
    the object's own words only). An approximation written for the probe, NOT a2ltool.
"""
import sys, pathlib, tempfile, re

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app, s19_app.tui.a2l as a
print("s19_app.__file__ =", s19_app.__file__)

# INLINE fixture of 02-test-cases.md: MOD_COMMON BYTE_ORDER MSB_FIRST
HDR = '''ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin MOD_COMMON ""
BYTE_ORDER MSB_FIRST
/end MOD_COMMON
/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""
/end COMPU_METHOD
/begin COMPU_METHOD CM_BIT_MASK_ST "" IDENTICAL "%.0" ""
/end COMPU_METHOD
/begin RECORD_LAYOUT RL_U16
FNC_VALUES 1 UWORD ROW_DIR DIRECT
/end RECORD_LAYOUT
@BODY@
/end MODULE
/end PROJECT
'''
FULL = ' UWORD CM_ID 0 0 0 65535'
SHORT = ' UWORD CM_ID 0 0 0'
def meas(name, *body):
    return f'/begin MEASUREMENT {name} ""\n' + "\n".join(body) + '\n/end MEASUREMENT'

SHAPES = {
 # round-2 / round-3 shapes (sec-r3-probe.py), unchanged
 "A": ("full header, BIT_MASK own line", meas("MA", FULL, " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "B": ("short header, BIT_MASK own line (graph .19/7 text)", meas("MB", SHORT, " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "C": ("short header, BIT_MASK same line (case .19/7)", meas("MC", SHORT + " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "D": ("short header, comment-led BIT_MASK (.19/8)", meas("MD", SHORT, " /* mask */ BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "E": ("full header on /begin line + BIT_MASK", '/begin MEASUREMENT ME "" UWORD CM_ID 0 0 0 65535 BIT_MASK 0x0FF0\n ECU_ADDRESS 0x10\n/end MEASUREMENT'),
 "F": ("comment glued left of the keyword (.19/10)", meas("MF", FULL + "/* upper */BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "G": ("comment glued between keyword and word (.19/11)", meas("MG", FULL, " BIT_MASK/* bits */0x0FF0", " ECU_ADDRESS 0x10")),
 "H": ("unterminated FORMAT quote, then BIT_MASK (.19/16)", meas("MH", FULL, " ECU_ADDRESS 0x10", ' FORMAT "%5.0', " BIT_MASK 0x0FF0")),
 "I": ("unterminated quote, then comment-led BIT_MASK", meas("MI", FULL, " ECU_ADDRESS 0x10", ' FORMAT "%5.0', " /* m */ BIT_MASK 0x0FF0")),
 "J": ("unclosed /begin IF_DATA before BIT_MASK", meas("MJ", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", " BIT_MASK 0x0FF0")),
 "J1": ("one-line IF_DATA (V171 style) before BIT_MASK (.19/12)", meas("MJ1", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA ETK  KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " BIT_MASK 0x0FF0")),
 "K": ("closed IF_DATA holding BIT_MASK (not a mask)", meas("MK", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", " BIT_MASK 0x0FF0", " /end IF_DATA")),
 "L": ("a /begin line inside a block comment (.19/15)", meas("ML", FULL, " ECU_ADDRESS 0x10", " /* old:", " /begin IF_DATA XCP", " */", " BIT_MASK 0x0FF0")),
 "L2": ("IF_DATA commented out, */ on its /end line (.19/13)", meas("ML2", FULL, " ECU_ADDRESS 0x10", " /* /begin IF_DATA XCP", " /end IF_DATA */", " BIT_MASK 0x0FF0")),
 "L5": ("// on the /begin IF_DATA line, its /end left live", meas("ML5", FULL, " ECU_ADDRESS 0x10", " // /begin IF_DATA XCP", " /end IF_DATA", " BIT_MASK 0x0FF0")),
 "M": ("keyword only in a comment (not a mask)", meas("MM", FULL, " ECU_ADDRESS 0x10", " /* BIT_MASK 0x0FF0 */")),
 "N": ("keyword and word on two lines", meas("MN", FULL, " BIT_MASK", " 0x0FF0", " ECU_ADDRESS 0x10")),
 "O": ("quoted \"BIT_MASK\", no mask", meas("MO", FULL, ' PHYS_UNIT "BIT_MASK"', " ECU_ADDRESS 0x10")),
 "O2": ("quoted \"BIT_MASK\" before a real mask", meas("MO2", FULL, ' PHYS_UNIT "BIT_MASK"', " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "P": ("two BIT_MASK lines 0x000F then 0x0FF0 (.19/14)", meas("MP", FULL, " BIT_MASK 0x000F", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "Q": ("lowercase bit_mask", meas("MQ", FULL, " bit_mask 0x0FF0", " ECU_ADDRESS 0x10")),
 "R2": ("CHARACTERISTIC .19/6 MB3, header on its own body line", '/begin CHARACTERISTIC MB3 ""\n VALUE 0x10 RL_U16 0 CM_ID 0\n BIT_MASK 0x0FF0\n/end CHARACTERISTIC'),
 "S": ("tab between keyword and word", meas("MS", FULL, " BIT_MASK\t0x0FF0", " ECU_ADDRESS 0x10")),
 "T": ("form feed before the keyword", meas("MT", FULL + "\x0cBIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "U": ("keyword glued after a closing quote", meas("MU", FULL, ' FORMAT "%5.0"BIT_MASK 0x0FF0', " ECU_ADDRESS 0x10")),
 "W": ("keyword in an ANNOTATION_TEXT child (not a mask)", meas("MW", FULL, " ECU_ADDRESS 0x10", " /begin ANNOTATION", " /begin ANNOTATION_TEXT", ' "BIT_MASK 0x0FF0"', " /end ANNOTATION_TEXT", " /end ANNOTATION")),
 # round-4 shapes
 "L2C": ("L2 one level down: inside IF_DATA a child commented out, */ on its /end line", meas("ML2C", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", "  /* /begin DAQ_EVENT 1", "  /end DAQ_EVENT */", " /end IF_DATA", " BIT_MASK 0x0FF0")),
 "L2N": ("L2 two levels down (IF_DATA > DAQ > commented EVENT_LIST)", meas("ML2N", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", "  /begin DAQ", "   /* /begin EVENT_LIST", "   /end EVENT_LIST */", "  /end DAQ", " /end IF_DATA", " BIT_MASK 0x0FF0")),
 "L7": ("a quote opened in ANNOTATION_TEXT holds /end lines", meas("ML7", FULL, " ECU_ADDRESS 0x10", " /begin ANNOTATION", "  /begin ANNOTATION_TEXT", '   "see:', "/end ANNOTATION_TEXT", "/end ANNOTATION", '/end MEASUREMENT"', "  /end ANNOTATION_TEXT", " /end ANNOTATION", " BIT_MASK 0x0FF0")),
 "J2": ("two one-line IF_DATA before BIT_MASK", meas("MJ2", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA", " /begin IF_DATA CANAPE_EXT 100 /end IF_DATA", " BIT_MASK 0x0FF0")),
 "J3": ("one-line IF_DATA, BIT_MASK after its /end on the same line", meas("MJ3", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA BIT_MASK 0x0FF0")),
 "J4": ("/begin IF_DATA not at line start, its /end on its own line", meas("MJ4", FULL, " ECU_ADDRESS 0x10 /begin IF_DATA XCP", "  KP_BLOB 0x10", " /end IF_DATA", " BIT_MASK 0x0FF0")),
 "J5": ("one-line IF_DATA not at line start, holding BIT_MASK (not a mask)", meas("MJ5", FULL, " ECU_ADDRESS 0x10 /begin IF_DATA XCP BIT_MASK 0x1 /end IF_DATA")),
 "X": ("short header, a comment inside the keyword BIT_/**/MASK", meas("MX", SHORT, " BIT_/* x */MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "X2": ("full header, a comment inside the keyword BIT_/**/MASK", meas("MX2", FULL, " BIT_/* x */MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "N2": ("the letters in the object name, no mask", meas("SIG.BIT_MASK.A", FULL, " ECU_ADDRESS 0x10")),
 "CMN": ("the letters in the conversion name, no mask", meas("MCN", " UWORD CM_BIT_MASK_ST 0 0 0 65535", " ECU_ADDRESS 0x10")),
}

HEX = re.compile(r"0x[0-9A-Fa-f]{1,16}", re.ASCII); DEC = re.compile(r"[0-9]{1,20}", re.ASCII)
def readable(w):
    return w is not None and (HEX.fullmatch(w) or DEC.fullmatch(w)) is not None

def walk_sections(secs):
    for s in secs:
        yield s
        yield from walk_sections(s.get("children") or [])

def open_state(text):
    """The state _strip_a2l_comments ends in: 'comment', 'quote' or None (same escape rule)."""
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

# --- REF: C-rule reader of round 3 (approximation, not a2ltool) ------------------------------
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

def ref_mask(text, objname):
    toks = ref_tokens(text)
    if any(t[0] == "ERR" for t in toks): return "malformed (%s)" % [t[1] for t in toks if t[0] == "ERR"][0]
    stack, own, k = [], None, 0
    while k < len(toks):
        kind, v = toks[k]
        if kind == "ID" and v == "/begin":
            blk = toks[k + 1][1]; stack.append([blk, []])
            if blk in ("MEASUREMENT", "CHARACTERISTIC") and toks[k + 2][1] == objname: own = stack[-1]
            k += 2; continue
        if kind == "ID" and v == "/end":
            blk = toks[k + 1][1]
            if not stack or stack[-1][0] != blk: return "malformed (/end %s closes %s)" % (blk, stack[-1][0] if stack else None)
            stack.pop(); k += 2; continue
        if stack: stack[-1][1].append((kind, v))
        k += 1
    if stack: return "malformed (unclosed %s)" % stack[-1][0]
    if own is None: return "object not found"
    ids = own[1]; pos = [i for i, t in enumerate(ids) if t == ("ID", "BIT_MASK")]
    if not pos: return "no mask"
    words = [ids[p + 1][1] if p + 1 < len(ids) else None for p in pos]
    return "mask " + ",".join(map(str, words))

# --- the graph after the round-2 pass (round-3 baseline: keyword rule + bit_org cross-check) ---
def model(section, sec_kind, tag, data):
    words = a._flatten_body_tokens([section["meta"]] + list(section["lines"]))
    n = 8 if sec_kind == "MEASUREMENT" else 9
    header, rest = words[:n], words[n:]
    mask_word, has_kw_rest = None, "BIT_MASK" in rest
    if has_kw_rest:
        i = rest.index("BIT_MASK")
        mask_word = rest[i + 1] if i + 1 < len(rest) else None
    keyword = ("BIT_MASK" in words[2:]) and mask_word is None
    j = words.index("BIT_MASK", 2) if "BIT_MASK" in words[2:] else None
    msg_mask = (words[j + 1] if j is not None and j + 1 < len(words) else "(none)")
    dt = tag.get("datatype")
    if sec_kind == "MEASUREMENT" and not dt and len(header) > 2: dt = header[2]   # E2-1 fill
    if sec_kind == "CHARACTERISTIC" and not dt:
        lay = a._resolve_record_layout(tag.get("record_layout_name"), data["record_layouts_by_name"]) or {}
        dt = lay.get("decode_type")
    size = a.DATATYPE_SIZES.get(str(dt or "").upper())
    length = tag.get("length") if tag.get("length") is not None else size
    if tag.get("address") is None or length is None: pre = "A2L-DEF-ADDRESS"
    elif size is None: pre = "A2L-DEF-DATATYPE"
    elif length != size: pre = "A2L-DEF-LENGTH"
    else: pre = None
    if keyword: mask = "REFUSE(keyword)"
    elif has_kw_rest and not readable(mask_word): mask = "REFUSE(unreadable %r)" % mask_word
    elif has_kw_rest: mask = "MASKED(%s)" % mask_word
    elif tag.get("bit_org"): mask = "REFUSE(bit_org)"
    else: mask = "UNMASKED"
    return dict(words=words, header=header, rest=rest, mask_word=mask_word, has_kw_rest=has_kw_rest,
                dt=dt, pre=pre, mask=mask, outcome=pre or mask, msg_mask=msg_mask)

OBJECT_SECTIONS = {"MEASUREMENT", "CHARACTERISTIC", "AXIS_PTS", "INSTANCE", "BLOB", "TYPEDEF_MEASUREMENT",
                   "TYPEDEF_CHARACTERISTIC", "TYPEDEF_AXIS", "TYPEDEF_BLOB", "TYPEDEF_STRUCTURE"}

def begin_after_name_longid(meta):
    _name, rest = a._parse_first_field(meta or "")
    _longid, rest2 = a._parse_first_field(rest or "")
    return rest2 or ""

def nonobj_desc(s, depth_all=True):
    for c in s.get("children") or []:
        if c.get("name") in OBJECT_SECTIONS: continue
        yield c
        if depth_all: yield from nonobj_desc(c, True)

def text_W(s):   # every non-object child section to any depth, with its /begin line
    parts = [begin_after_name_longid(s["meta"])] + list(s.get("lines") or [])
    for c in nonobj_desc(s, True): parts += [c.get("meta", "")] + list(c.get("lines") or [])
    return "\n".join(parts)

def text_N(s):   # direct non-object children only, their lines only
    parts = [begin_after_name_longid(s["meta"])] + list(s.get("lines") or [])
    for c in nonobj_desc(s, False): parts += list(c.get("lines") or [])
    return "\n".join(parts)

def text_REF3(s):  # sec-r3-probe.py own_text: full meta (name and long id included), W depth
    parts = [s.get("meta", "")] + list(s.get("lines") or [])
    for c in s.get("children") or []:
        if c.get("name") in OBJECT_SECTIONS: continue
        parts.append(c.get("name", "") + " " + text_REF3(c))
    return "\n".join(parts)

def record_open(s):
    return open_state("\n".join([s["meta"]] + list(s["lines"])))

def pieces_open(s):  # proposed: the record and every non-object child section, each on its own
    st = record_open(s)
    if st: return "record " + st
    for c in nonobj_desc(s, True):
        st = open_state("\n".join([c.get("meta", "")] + list(c.get("lines") or [])))
        if st: return c["name"] + " " + st
    return None

def midline_begin(s):  # proposed: a /begin word the line-based builder did not see (not at line start)
    for piece in [s["meta"]] + list(s["lines"]) + [x for c in nonobj_desc(s, True) for x in [c.get("meta", "")] + list(c.get("lines") or [])]:
        if any(k == "ID" and v.lower() == "/begin" for k, v in ref_tokens(piece)): return True
    return False

def letters_rule(m, count, opened, zero_with_mask=False):
    if opened: mask = "REFUSE(open %s)" % opened
    elif count > 1: mask = "REFUSE(letters x%d)" % count
    elif count == 1 and m["mask_word"] is None: mask = "REFUSE(letters, no mask read)"
    elif zero_with_mask and count == 0 and m["mask_word"] is not None: mask = "REFUSE(mask read, no letters)"
    elif m["has_kw_rest"] and not readable(m["mask_word"]): mask = "REFUSE(unreadable %r)" % m["mask_word"]
    elif m["has_kw_rest"]: mask = "MASKED(%s)" % m["mask_word"]
    else: mask = "UNMASKED"
    return m["pre"] or mask

def rules(s, m):
    rw = letters_rule(m, text_W(s).upper().count("BIT_MASK"), record_open(s))
    rn = letters_rule(m, text_N(s).upper().count("BIT_MASK"), record_open(s))
    r3 = letters_rule(m, text_REF3(s).upper().count("BIT_MASK"), record_open(s))
    po = pieces_open(s) or ("mid-line /begin" if midline_begin(s) else None)
    pr = letters_rule(m, text_W(s).upper().count("BIT_MASK"), po, zero_with_mask=True)
    return dict(W=rw, N=rn, REF3=r3, PROP=pr)

def enc35(tag, data):
    view = dict(tag); view["bit_org"] = None
    res = a.encode_physical_to_raw_bytes(view, 35, data["compu_methods_by_name"], data["compu_tabs_by_name"], data["record_layouts_by_name"])
    return res[0], res[1]

print("\n== Q1/Q2 shapes (INLINE header, BYTE_ORDER MSB_FIRST) ==")
with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
    for key, (label, body) in SHAPES.items():
        text = HDR.replace("@BODY@", body)
        p = pathlib.Path(d) / "x.a2l"; p.write_text(text, encoding="utf-8")
        data = a.parse_a2l_file(p)
        objname = re.search(r"/begin (?:MEASUREMENT|CHARACTERISTIC) (\S+)", body).group(1)
        sec = next(s for s in walk_sections(data["sections"]) if s["name"] in ("MEASUREMENT", "CHARACTERISTIC") and a.parse_begin_meta(s["meta"])[0] == objname)
        tag = next(t for t in data["tags"] if t["name"] == objname)
        m = model(sec, sec["name"], tag, data)
        r = rules(sec, m)
        ref = ref_mask(text, objname)
        refmask = ref.startswith("mask")
        lost = {k: (v == "UNMASKED" and refmask) for k, v in r.items()}
        print(f"[{key}] {label}")
        print(f"     tag: bit_org={tag['bit_org']!r} dt={tag['datatype']!r} addr={tag['address']!r} len={tag['length']!r} | parse errors={data['errors']}")
        print(f"     letters W={text_W(sec).upper().count('BIT_MASK')} N={text_N(sec).upper().count('BIT_MASK')} REF3={text_REF3(sec).upper().count('BIT_MASK')} | record open={record_open(sec)} pieces open={pieces_open(sec)} mid-line /begin={midline_begin(sec)} | mask word={m['mask_word']!r} <mask> in message={m['msg_mask']!r}")
        print(f"     round-3 graph: {m['outcome']} | records W: {r['W']} | records N: {r['N']} | REF3: {r['REF3']} | proposed: {r['PROP']}")
        print(f"     REF: {ref} | whole-word write with a REF mask: W={lost['W']} N={lost['N']} REF3={lost['REF3']} proposed={lost['PROP']}")
        if lost["W"] or lost["N"] or key in ("F", "J1"):
            print(f"     encode 35 on the unmasked view: {enc35(tag, data)}")

print("\n== Q3 fixtures: each rule vs the round-3 graph ==")
fixtures = sorted(set(repo.glob("examples/**/*.a2l")) | set(repo.glob("tests/fixtures/**/*.a2l")))
TOT = dict(files=0, objects=0, masked_r3=0, masked_W=0)
EXTRA = {k: 0 for k in ("W", "N", "REF3", "PROP")}; DROP = {k: 0 for k in ("W", "N", "REF3", "PROP")}
for f in fixtures:
    try:
        data = a.parse_a2l_file(f)
    except Exception as e:  # report, never hide
        print(f"[FX] {f.relative_to(repo)}: parse raised {type(e).__name__}"); continue
    TOT["files"] += 1
    tags = {}
    for t in data["tags"]: tags.setdefault(t["name"], t)
    seen, extra, drop, mr3, mw = set(), {k: [] for k in EXTRA}, {k: [] for k in DROP}, 0, 0
    for s in walk_sections(data["sections"]):
        if s["name"] not in ("MEASUREMENT", "CHARACTERISTIC"): continue
        nm = a.parse_begin_meta(s["meta"])[0]
        if nm in seen or nm not in tags: continue
        seen.add(nm); tag = tags[nm]
        m = model(s, s["name"], tag, data); r = rules(s, m)
        base = m["outcome"]
        mr3 += base.startswith("MASKED"); mw += r["W"].startswith("MASKED")
        for k, v in r.items():
            if v.startswith("REFUSE") and not base.startswith(("A2L-", "REFUSE")): extra[k].append((nm, v))
            if base.startswith("REFUSE") and not v.startswith(("A2L-", "REFUSE")): drop[k].append((nm, v))
    TOT["objects"] += len(seen); TOT["masked_r3"] += mr3; TOT["masked_W"] += mw
    for k in EXTRA: EXTRA[k] += len(extra[k]); DROP[k] += len(drop[k])
    print(f"[FX] {f.relative_to(repo)}: objects={len(seen)} masked r3/W={mr3}/{mw} errors={len(data['errors'])} | "
          + " ".join(f"{k}:+{len(extra[k])}/-{len(drop[k])}" for k in EXTRA)
          + "".join(f" {k}-extra={extra[k][:2]}" for k in EXTRA if extra[k])
          + "".join(f" {k}-drop={drop[k][:2]}" for k in DROP if drop[k]))
print(f"[FX-total] files={TOT['files']} objects={TOT['objects']} masked round-3/records-W={TOT['masked_r3']}/{TOT['masked_W']} "
      + " ".join(f"{k}: extra={EXTRA[k]} dropped={DROP[k]}" for k in EXTRA))
