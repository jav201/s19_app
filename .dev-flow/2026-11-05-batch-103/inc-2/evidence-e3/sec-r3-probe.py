"""E3 round-3 security probe, Inc 2 (batch-103). Base parser only (clone e07fb00), read-only.

Q1: after the round-2 correction (keyword rule E3S-14 + bit_org cross-check + unreadable word +
    text kind), can an A2L object whose file declares a BIT_MASK still reach the unmasked path
    (BL-I2-1, the whole-word write) with no refusal?  The corrected graph rules are emulated:
      record  = _flatten_body_tokens([meta] + lines)   (graph _read_object_lines)
      header  = first 8 words (MEASUREMENT) / 9 (CHARACTERISTIC); rest = the words after
      mask    = the word after the first BIT_MASK in rest (raw)
      keyword = 'BIT_MASK' in record[2:] and no mask word was read        (E3S-14)
      refuse  = keyword | unreadable word | tag bit_org set and no mask   (E3S-01 (1), (3))
    REF = a reference reading written for this probe (NOT a2ltool): the C rule (a comment
    separates two words; strings are tokens), /begin and /end matched by name, the object's
    own words only.  It stands for "the mask a C-rule reader of the file sees".
Q2: the proposed class fix (R': the letters BIT_MASK, any case, in the object's /begin line,
    own lines and child sections that do not open another object, comments and strings
    included, at most once and only with a mask read; E: the record ends inside an open
    comment or quote) on the shapes and on every fixture A2L: what it refuses beyond the
    graph (false-refusal cost).  A first run scanned every child section (objects included);
    it refused 26 V171 objects, because V171's one-line IF_DATA lines leave each MEASUREMENT
    open and nest the next one inside it - hence R' skips object children.
"""
import sys, pathlib, tempfile, re

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app, s19_app.tui.a2l as a
print("s19_app.__file__ =", s19_app.__file__)

HDR = '''ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin MOD_COMMON ""
BYTE_ORDER MSB_LAST
/end MOD_COMMON
/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""
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
 # round-2 shapes (sec-r2-probe.py)
 "A": ("full header, BIT_MASK own line", meas("MA", FULL, " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "B": ("short header, BIT_MASK own line", meas("MB", SHORT, " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "C": ("short header, BIT_MASK same line (.19/7)", meas("MC", SHORT + " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "D": ("short header, BIT_MASK behind a comment (.19/8)", meas("MD", SHORT, " /* mask */ BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "E": ("full header on /begin line + BIT_MASK", '/begin MEASUREMENT ME "" UWORD CM_ID 0 0 0 65535 BIT_MASK 0x0FF0\n ECU_ADDRESS 0x10\n/end MEASUREMENT'),
 # new shapes
 "F": ("comment glued left of the keyword on the header line", meas("MF", FULL + "/* upper */BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "G": ("comment glued between keyword and word", meas("MG", FULL, " BIT_MASK/* bits 4..11 */0x0FF0", " ECU_ADDRESS 0x10")),
 "H": ("unterminated FORMAT quote, then BIT_MASK own line", meas("MH", FULL, " ECU_ADDRESS 0x10", ' FORMAT "%5.0', " BIT_MASK 0x0FF0")),
 "I": ("unterminated FORMAT quote, then comment-led BIT_MASK", meas("MI", FULL, " ECU_ADDRESS 0x10", ' FORMAT "%5.0', " /* m */ BIT_MASK 0x0FF0")),
 "J": ("unclosed /begin IF_DATA before BIT_MASK", meas("MJ", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", " BIT_MASK 0x0FF0")),
 "J1": ("one-line /begin IF_DATA ... /end IF_DATA (V171's line style) before BIT_MASK", meas("MJ1", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA ETK  KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " BIT_MASK 0x0FF0")),
 "K": ("closed IF_DATA holding BIT_MASK (not a mask by the grammar)", meas("MK", FULL, " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", " BIT_MASK 0x0FF0", " /end IF_DATA")),
 "L": ("a /begin line inside a block comment", meas("ML", FULL, " ECU_ADDRESS 0x10", " /* old:", " /begin IF_DATA XCP", " */", " BIT_MASK 0x0FF0")),
 "L2": ("an IF_DATA block commented out, its */ on the /end line", meas("ML2", FULL, " ECU_ADDRESS 0x10", " /* /begin IF_DATA XCP", " /end IF_DATA */", " BIT_MASK 0x0FF0")),
 "L5": ("// on the /begin IF_DATA line, its /end left live", meas("ML5", FULL, " ECU_ADDRESS 0x10", " // /begin IF_DATA XCP", " /end IF_DATA", " BIT_MASK 0x0FF0")),
 "M": ("keyword only in a comment (not a mask)", meas("MM", FULL, " ECU_ADDRESS 0x10", " /* BIT_MASK 0x0FF0 */")),
 "N": ("keyword and word split across lines", meas("MN", FULL, " BIT_MASK", " 0x0FF0", " ECU_ADDRESS 0x10")),
 "O": ("keyword in a quoted string, no mask", meas("MO", FULL, ' PHYS_UNIT "BIT_MASK"', " ECU_ADDRESS 0x10")),
 "O2": ("quoted \"BIT_MASK\" before a real mask", meas("MO2", FULL, ' PHYS_UNIT "BIT_MASK"', " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "P": ("two BIT_MASK lines (0x000F, then 0x0FF0)", meas("MP", FULL, " BIT_MASK 0x000F", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "Q": ("lowercase bit_mask", meas("MQ", FULL, " bit_mask 0x0FF0", " ECU_ADDRESS 0x10")),
 "R": ("CHARACTERISTIC .19/6 MB3 (8 header words)", '/begin CHARACTERISTIC MB3 "" VALUE 0x10 RL_U16 0 CM_ID 0\n BIT_MASK 0x0FF0\n/end CHARACTERISTIC'),
 "R2": ("CHARACTERISTIC .19/6 with its header on body lines (MB4)", '/begin CHARACTERISTIC MB4 ""\n VALUE 0x10 RL_U16 0 CM_ID 0\n BIT_MASK 0x0FF0\n/end CHARACTERISTIC'),
 "S": ("tab between keyword and word", meas("MS", FULL, " BIT_MASK\t0x0FF0", " ECU_ADDRESS 0x10")),
 "T": ("form feed before the keyword on the header line", meas("MT", FULL + "\x0cBIT_MASK 0x0FF0", " ECU_ADDRESS 0x10")),
 "U": ("keyword glued after a closing quote", meas("MU", FULL, ' FORMAT "%5.0"BIT_MASK 0x0FF0', " ECU_ADDRESS 0x10")),
 "W": ("keyword in an ANNOTATION_TEXT child (not a mask)", meas("MW", FULL, " ECU_ADDRESS 0x10", " /begin ANNOTATION", " /begin ANNOTATION_TEXT", ' "BIT_MASK 0x0FF0"', " /end ANNOTATION_TEXT", " /end ANNOTATION")),
}

HEX = re.compile(r"0x[0-9A-Fa-f]{1,16}", re.ASCII); DEC = re.compile(r"[0-9]{1,20}", re.ASCII)
def readable(w):
    return w is not None and (HEX.fullmatch(w) or DEC.fullmatch(w)) is not None

def walk_sections(secs):
    for s in secs:
        yield s
        yield from walk_sections(s.get("children") or [])

def subtree_text(s):
    parts = [s.get("meta", "")] + list(s.get("lines") or [])
    for c in s.get("children") or []:
        parts.append(c.get("name", "") + " " + subtree_text(c))
    return "\n".join(parts)

def open_state(text):
    """The state _strip_a2l_comments ends in: 'comment', 'quote' or None."""
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

def model(section, sec_kind, tag):
    words = a._flatten_body_tokens([section["meta"]] + list(section["lines"]))
    n = 8 if sec_kind == "MEASUREMENT" else 9
    header, rest = words[:n], words[n:]
    mask_word, has_kw_rest = None, "BIT_MASK" in rest
    if has_kw_rest:
        i = rest.index("BIT_MASK")
        mask_word = rest[i + 1] if i + 1 < len(rest) else None
    keyword = ("BIT_MASK" in words[2:]) and mask_word is None
    # refusals that come before the mask (address, datatype, length)
    dt = tag.get("datatype")
    if sec_kind == "MEASUREMENT" and not dt and len(header) > 2: dt = header[2]   # E2-1 fill
    if sec_kind == "CHARACTERISTIC" and not dt:
        lay = a._resolve_record_layout(tag.get("record_layout_name"), DATA["record_layouts_by_name"]) or {}
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
    elif tag.get("bit_org"): mask = "REFUSE(bit_org cross-check)"
    else: mask = "UNMASKED"
    outcome = pre or mask
    return dict(words=words, header=header, rest=rest, mask_word=mask_word, keyword=keyword,
                dt=dt, outcome=outcome, mask=mask)

# --- REF: C-rule reader written for this probe (an approximation, not a2ltool) ---------------
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

OBJECT_SECTIONS = {"MEASUREMENT", "CHARACTERISTIC", "AXIS_PTS", "INSTANCE", "BLOB", "TYPEDEF_MEASUREMENT",
                   "TYPEDEF_CHARACTERISTIC", "TYPEDEF_AXIS", "TYPEDEF_BLOB", "TYPEDEF_STRUCTURE"}
def own_text(s):
    """The object's /begin line and own lines, plus every child section that does not open another object."""
    parts = [s.get("meta", "")] + list(s.get("lines") or [])
    for c in s.get("children") or []:
        if c.get("name") in OBJECT_SECTIONS: continue
        parts.append(c.get("name", "") + " " + own_text(c))
    return "\n".join(parts)

def proposed(section, tag, m):
    """R': letters BIT_MASK (any case) in own_text, at most once and only with a mask read; E: record ends inside a comment/quote."""
    text = own_text(section)
    count = text.upper().count("BIT_MASK")
    st = open_state("\n".join([section["meta"]] + list(section["lines"])))
    if st: return "REFUSE(E: record ends inside a %s)" % st
    if count > 1: return "REFUSE(R: BIT_MASK %d times)" % count
    if count == 1 and not m["mask"].startswith("MASKED"): return "REFUSE(R: letters, no mask read)"
    return m["outcome"]

DATA = None
print("\n== Q1/Q2 shapes ==")
with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
    for key, (label, body) in SHAPES.items():
        text = HDR.replace("@BODY@", body)
        p = pathlib.Path(d) / "x.a2l"; p.write_text(text, encoding="utf-8")
        DATA = a.parse_a2l_file(p)
        objname = re.search(r"/begin (?:MEASUREMENT|CHARACTERISTIC) (\S+)", body).group(1)
        sec = next(s for s in walk_sections(DATA["sections"]) if s["name"] in ("MEASUREMENT", "CHARACTERISTIC") and a.parse_begin_meta(s["meta"])[0] == objname)
        tag = next(t for t in DATA["tags"] if t["name"] == objname)
        m = model(sec, sec["name"], tag)
        ref = ref_mask(text, objname)
        reached = m["outcome"] == "UNMASKED" and ref.startswith("mask")
        print(f"[{key}] {label}")
        print(f"     tag: bit_org={tag['bit_org']!r} datatype={tag['datatype']!r} addr={tag['address']!r} len={tag['length']!r} | parse errors={DATA['errors']}")
        print(f"     model: header={m['header']} rest={m['rest'][:6]} mask_word={m['mask_word']!r} keyword={m['keyword']} -> {m['outcome']}")
        print(f"     REF: {ref} | BL-I2-1 reached (graph): {reached} | proposed R'+E: {proposed(sec, tag, m)}")
        if key in ("F", "J1") and m["outcome"] == "UNMASKED":
            view = dict(tag); view["bit_org"] = None
            res = a.encode_physical_to_raw_bytes(view, 35, DATA["compu_methods_by_name"], DATA["compu_tabs_by_name"], DATA["record_layouts_by_name"])
            print(f"     encode 35 on the unmasked view (what step 7 returns with no mask): {res[0]} msg={res[1]!r}")

print("\n== Q2 fixtures: the corrected graph vs the proposed R'+E rule ==")
fixtures = sorted(set(repo.glob("examples/**/*.a2l")) | set(repo.glob("tests/fixtures/**/*.a2l")))
tot = dict(objects=0, masked=0, extra=0)
for f in fixtures:
    try:
        DATA = a.parse_a2l_file(f)
    except Exception as e:  # report, never hide
        print(f"[FX] {f.relative_to(repo)}: parse raised {type(e).__name__}"); continue
    tags = {}
    for t in DATA["tags"]: tags.setdefault(t["name"], t)
    seen, counts, extra_rows, dis = set(), {"MASKED": 0, "REFUSE": 0, "UNMASKED": 0, "pre": 0}, [], []
    for s in walk_sections(DATA["sections"]):
        if s["name"] not in ("MEASUREMENT", "CHARACTERISTIC"): continue
        nm = a.parse_begin_meta(s["meta"])[0]
        if nm in seen or nm not in tags: continue
        seen.add(nm); tag = tags[nm]
        m = model(s, s["name"], tag); pr = proposed(s, tag, m)
        k = "pre" if m["outcome"].startswith("A2L-") else m["mask"].split("(")[0]
        counts[k] += 1
        if m["mask"].startswith("MASKED") and tag.get("bit_org") and tag["bit_org"] != m["mask_word"]:
            dis.append((nm, m["mask_word"], tag["bit_org"]))
        if pr != m["outcome"] and pr.startswith("REFUSE") and not m["outcome"].startswith(("A2L-", "REFUSE")):
            extra_rows.append((nm, pr))
    tot["objects"] += len(seen); tot["masked"] += counts["MASKED"]; tot["extra"] += len(extra_rows)
    print(f"[FX] {f.relative_to(repo)}: objects={len(seen)} {counts} errors={len(DATA['errors'])} "
          f"| mask word != tag bit_org: {len(dis)} {dis[:2]} | proposed R'+E refuses beyond the graph: {len(extra_rows)} {extra_rows[:3]}")
print(f"[FX-total] objects={tot['objects']} masked={tot['masked']} proposed-extra-refusals={tot['extra']}")
