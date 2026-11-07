"""Inc 11 E1 census (batch-103): the A2L reader at e07fb00 against an independent reference reading.

Run on cachyos-rtx only:  python e1-census.py <repo> <scratch> <mode>   mode = chars | fixtures | hostile | repro

REF (written for this census, NOT a2ltool, imports nothing from s19_app):
  - the file is UTF-8 with a leading BOM dropped; CRLF and a lone CR are line ends like LF;
  - word separators are the ASCII blanks space, HT, VT, FF and the line ends; every other character is a word character;
  - a block comment /* ... */ (no nesting) and a line comment // ... are word breaks; neither is read;
  - a quoted string "..." is one word without its quotes; a backslash escapes the next character (\" and \\);
    a string may span lines;
  - /begin and /end are whole words (any letter case) wherever they stand; the next word is the section keyword;
    an /end closes the innermost open section;
  - an object's own words are its words outside its child sections.
CANON(text) = the same file re-emitted from REF's token tree in the layout the e07fb00 reader handles: no comments, each
  /begin and /end on its own line, a MEASUREMENT / CHARACTERISTIC with its name and long identifier on the /begin line
  and its positional header words on one body line, each keyword of a MEASUREMENT / CHARACTERISTIC on its own line with
  its arguments, every other section's words on their original lines.
DIFF = the e07fb00 reader on the original text against the e07fb00 reader on CANON(text): a tag that differs is a tag
  the reader's tokenizer reads wrongly (the field rules stay the reader's own).
"""
import collections, difflib, json, pathlib, re, subprocess, sys, tempfile, time, unicodedata

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2]); mode = sys.argv[3]
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__)
print("python =", sys.version.split()[0], "| mode =", mode)

# ----------------------------------------------------------------------------------------------- REF lexer
WS = " \t\x0b\x0c"
_WORD = re.compile(r'(?:[^ \t\x0b\x0c\n"/]|/(?![/*]))+')

def ref_lex(text):
    """Tokens (kind, value, line, col_flag) and diagnostics. kind: ID | STR."""
    diags = []
    if text.startswith("\ufeff"):
        text = text[1:]
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    toks, i, n, line = [], 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1; i += 1; continue
        if c in WS:
            i += 1; continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                diags.append(("comment not closed", line)); break
            line += text.count("\n", i, j); i = j + 2; continue
        if text.startswith("//", i):
            j = text.find("\n", i); i = n if j < 0 else j; continue
        if c == '"':
            j, buf, start = i + 1, [], line
            while j < n:
                ch = text[j]
                if ch == "\\" and j + 1 < n:
                    buf.append(text[j:j + 2]); j += 2; continue
                if ch == '"':
                    break
                if ch == "\n":
                    line += 1
                buf.append(ch); j += 1
            if j >= n:
                diags.append(("string not closed", start)); break
            toks.append(("STR", "".join(buf), start)); i = j + 1; continue
        m = _WORD.match(text, i)
        w = m.group(0)
        if "*/" in w:
            diags.append(("stray */", line))
        toks.append(("ID", w, line)); i = m.end()
    return toks, diags

def ref_tree(toks):
    root = {"name": "ROOT", "items": [], "start": 0}
    stack, diags, k = [root], [], 0
    while k < len(toks):
        kind, v, ln = toks[k]
        if kind == "ID" and v.lower() == "/begin" and k + 1 < len(toks):
            node = {"name": toks[k + 1][1], "items": [], "start": ln, "kwline": toks[k + 1][2]}
            stack[-1]["items"].append(("child", node)); stack.append(node); k += 2; continue
        if kind == "ID" and v.lower() == "/end" and k + 1 < len(toks):
            nm = toks[k + 1][1]
            if len(stack) == 1:
                diags.append(("/end without /begin", ln))
            else:
                if stack[-1]["name"] != nm:
                    diags.append((f"/end {nm} does not close /begin {stack[-1]['name']}", ln))
                stack[-1]["end"] = ln; stack.pop()
            k += 2; continue
        stack[-1]["items"].append(("tok", toks[k])); k += 1
    if len(stack) > 1:
        diags.append(("unclosed", stack[-1]["start"]))
    return root, diags

def own(node):
    return [t for kind, t in node["items"] if kind == "tok"]

def walk_ref(node):
    for kind, x in node["items"]:
        if kind == "child":
            yield x; yield from walk_ref(x)

# keywords that start a line inside a MEASUREMENT / CHARACTERISTIC (ASAM 1.7 optional keywords + the base's extensions)
KEYWORDS = set("""ADDRESS_TYPE ARRAY_SIZE BIT_MASK BYTE_ORDER DISCRETE DISPLAY_IDENTIFIER ECU_ADDRESS ECU_ADDRESS_EXTENSION
ERROR_MASK FORMAT LAYOUT MATRIX_DIM MAX_REFRESH MODEL_LINK PHYS_UNIT READ_WRITE REF_MEMORY_SEGMENT SYMBOL_LINK
CALIBRATION_ACCESS COMPARISON_QUANTITY ENCODING EXTENDED_LIMITS GUARD_RAILS NUMBER READ_ONLY STEP_SIZE
DATA_SIZE LENGTH DATA_TYPE FUNCTION COMPU_METHOD FORMULA UNIT LOWER_LIMIT UPPER_LIMIT VIRTUAL CALIBRATABLE DEPOSIT
MONOTONY AXIS_PTS_REF FIX_AXIS_PAR FIX_AXIS_PAR_DIST CURVE_AXIS_REF MAX_GRAD READ_WRITE""".split())
HDR_N = {"MEASUREMENT": 6, "CHARACTERISTIC": 7}

def split_header(node):
    """REF header rule: the name; the long identifier when the next word is a quoted string; then up to 6 (MEASUREMENT)
    or 7 (CHARACTERISTIC) header words, stopping at the first keyword word or the first child section."""
    seq = []
    for kind, x in node["items"]:
        if kind == "child":
            break
        seq.append(x)
    head = seq[:1]
    if len(seq) > 1 and seq[1][0] == "STR":
        head = seq[:2]
    pos = []
    for t in seq[len(head):]:
        if len(pos) == HDR_N[node["name"]] or (t[0] == "ID" and t[1] in KEYWORDS):
            break
        pos.append(t)
    return head, pos, len(head) + len(pos)

def q(t):
    kind, v, _ = t
    return '"' + v + '"' if kind == "STR" else v

def emit(node, out):
    name = node["name"]
    items = node["items"]
    if name in HDR_N:
        head, pos, rest_start = split_header(node)
        out.append("/begin " + name + (" " + " ".join(q(t) for t in head) if head else ""))
        if pos:
            out.append(" " + " ".join(q(t) for t in pos))
        used, line = 0, None
        for kind, x in items:
            if kind == "tok":
                used += 1
                if used <= rest_start:
                    continue
                if x[0] == "ID" and x[1] in KEYWORDS:
                    if line:
                        out.append(" " + " ".join(line))
                    line = [q(x)]
                else:
                    line = (line or []) + [q(x)]
            else:
                if line:
                    out.append(" " + " ".join(line)); line = None
                emit(x, out)
        if line:
            out.append(" " + " ".join(line))
        out.append("/end " + name)
        return
    begin_words, lines, cur, cur_ln, started = [], [], [], None, False
    for kind, x in items:
        if kind == "tok":
            if not started and node["name"] != "ROOT" and x[2] == node["kwline"]:
                begin_words.append(q(x)); continue
            started = True
            if cur and x[2] != cur_ln:
                lines.append(("t", cur)); cur = []
            cur.append(q(x)); cur_ln = x[2]
        else:
            started = True
            if cur:
                lines.append(("t", cur)); cur = []; cur_ln = None
            lines.append(("c", x))
    if cur:
        lines.append(("t", cur))
    if node["name"] == "ROOT":
        for kind, x in lines:
            if kind == "t":
                out.append(" ".join(x))
            else:
                emit(x, out)
        return
    # the words of the /begin line stay on it
    out.append("/begin " + name + ("" if not begin_words else " " + " ".join(begin_words)))
    for kind, x in lines:
        if kind == "t":
            out.append(" " + " ".join(x))
        else:
            emit(x, out)
    out.append("/end " + name)

def canon(text):
    toks, d1 = ref_lex(text)
    root, d2 = ref_tree(toks)
    out = []
    emit(root, out)
    return "\n".join(out) + "\n", d1 + d2, root

# ----------------------------------------------------------------------------------------------- reader runs
FIELDS = ["name", "description", "address", "length", "datatype", "effective_byte_order", "endian", "bit_org", "matrix_dim",
          "char_type", "deposit", "conversion", "lower_limit", "upper_limit", "unit", "virtual", "display_identifier",
          "function_group", "access", "symbol_link", "memory_region"]
KEY6 = ["name", "address", "length", "datatype", "effective_byte_order", "bit_org"]

def read_text(text, d, fname="x.a2l", encoding="utf-8", raw=None):
    p = pathlib.Path(d) / fname
    if raw is not None:
        p.write_bytes(raw)
    else:
        p.write_bytes(text.encode(encoding))
    return a.parse_a2l_file(p)

def tag_key(t):
    return (t.get("section"), t.get("name"))

def diff_tags(orig, can):
    """Align two tag lists by (section, name); return (pairs_differing, only_orig, only_canon)."""
    ko = [tag_key(t) for t in orig]; kc = [tag_key(t) for t in can]
    diffs, only_o, only_c = [], [], []
    ops = [("equal", 0, len(ko), 0, len(kc))] if ko == kc else difflib.SequenceMatcher(a=ko, b=kc, autojunk=False).get_opcodes()
    for op, i1, i2, j1, j2 in ops:
        if op == "equal":
            for i, j in zip(range(i1, i2), range(j1, j2)):
                f = [x for x in FIELDS if orig[i].get(x) != can[j].get(x)]
                if orig[i].get("axis_meta") and can[j].get("axis_meta"):
                    mo = [m.get("max_axis_points") for m in orig[i]["axis_meta"]]
                    mc = [m.get("max_axis_points") for m in can[j]["axis_meta"]]
                    if mo != mc:
                        f.append("axis_points")
                if f:
                    diffs.append((orig[i], can[j], f))
        else:
            only_o += orig[i1:i2]; only_c += can[j1:j2]
    return diffs, only_o, only_c

def show(v):
    return hex(v) if isinstance(v, int) and not isinstance(v, bool) and v > 255 else repr(v)

# ----------------------------------------------------------------------------------------------- mode: chars
def char_census(files):
    print("== [CH] character and structure census of the 35 tracked .a2l files (counted outside comments and strings unless said) ==")
    tot = collections.Counter()
    for f in files:
        raw = (repo / f).read_bytes()
        c = collections.Counter()
        c["bytes"] = len(raw)
        c["bom_utf8"] = int(raw.startswith(b"\xef\xbb\xbf")); c["bom_utf16"] = int(raw[:2] in (b"\xff\xfe", b"\xfe\xff"))
        c["crlf"] = raw.count(b"\r\n"); c["lone_cr"] = raw.count(b"\r") - c["crlf"]; c["lf"] = raw.count(b"\n") - c["crlf"]
        c["nul"] = raw.count(b"\x00"); c["tab"] = raw.count(b"\t"); c["ff"] = raw.count(b"\x0c"); c["vt"] = raw.count(b"\x0b")
        try:
            raw.decode("utf-8"); c["invalid_utf8"] = 0
        except UnicodeDecodeError:
            c["invalid_utf8"] = len(raw.decode("utf-8", errors="replace")) - len(raw.decode("utf-8", errors="ignore"))
        text = raw.decode("utf-8", errors="replace")
        # outside comments and strings
        t = text[1:] if text.startswith("\ufeff") else text
        t = t.replace("\r\n", "\n").replace("\r", "\n")
        i, n, line = 0, len(t), 1
        outside = []
        while i < n:
            ch = t[i]
            if t.startswith("/*", i):
                j = t.find("*/", i + 2)
                inner = t[i + 2: (n if j < 0 else j)]
                if "/*" in inner: c["nested_open_in_comment"] += 1
                if re.search(r"/begin\b", inner, re.I): c["begin_in_block_comment"] += 1
                if re.search(r"/end\b", inner, re.I): c["end_in_block_comment"] += 1
                if "\n" in inner: c["multiline_block_comments"] += 1
                if j < 0: c["unclosed_comment"] += 1; break
                i = j + 2; outside.append(" "); continue
            if t.startswith("//", i):
                j = t.find("\n", i); inner = t[i:(n if j < 0 else j)]
                if re.search(r"/begin\b", inner, re.I): c["begin_in_line_comment"] += 1
                c["line_comments"] += 1
                i = n if j < 0 else j; continue
            if ch == '"':
                j = i + 1
                while j < n and t[j] != '"':
                    if t[j] == "\\": j += 1
                    j += 1
                inner = t[i + 1:j]
                if "\n" in inner: c["multiline_strings"] += 1
                if re.search(r"/(begin|end)\b", inner, re.I): c["begin_or_end_in_string"] += 1
                if "\\\\" in inner: c["escaped_backslash_in_string"] += 1
                if '\\"' in inner: c["escaped_quote_in_string"] += 1
                if j >= n: c["unclosed_string"] += 1; break
                i = j + 1; outside.append(" W "); continue
            outside.append(ch); i += 1
        o = "".join(outside)
        for ch in set(o):
            if ord(ch) > 126 or (ord(ch) < 32 and ch not in "\n\t"):
                c["nonascii_or_ctrl_outside:" + f"U+{ord(ch):04X}"] += o.count(ch)
        c["stray_close_comment"] = o.count("*/")
        for ln in o.split("\n"):
            s = ln.strip()
            ws = s.split()
            lw = [w.lower() for w in ws]
            nb, ne = lw.count("/begin"), lw.count("/end")
            if nb and ne: c["lines_begin_and_end"] += 1
            if nb and lw[0] != "/begin": c["begin_not_line_start"] += 1
            if nb > 1: c["lines_two_begins"] += 1
            if ne and lw[0] != "/end": c["end_not_line_start"] += 1
            if any(w.startswith("/begin") and w != "/begin" for w in lw): c["glued_begin_word"] += 1
            if lw and lw[0] == "/include" or "/include" in lw: c["include"] += 1
            if lw and lw[0] == "/begin" and len(ws) == 2 and ws[1] in ("MEASUREMENT", "CHARACTERISTIC", "AXIS_PTS", "INSTANCE", "BLOB"):
                c["object_name_not_on_begin_line"] += 1
        for kw in ("INSTANCE", "BLOB", "TYPEDEF_MEASUREMENT", "TYPEDEF_CHARACTERISTIC", "TYPEDEF_BLOB", "TYPEDEF_STRUCTURE",
                   "TYPEDEF_AXIS", "STRUCTURE_COMPONENT", "AXIS_PTS", "MEASUREMENT", "CHARACTERISTIC", "IF_DATA"):
            c["sec:" + kw] = len(re.findall(r"/begin\s+" + kw + r"\b", o))
        print(f"[CH] {f}: " + " ".join(f"{k}={v}" for k, v in sorted(c.items()) if v))
        tot.update(c)
    print("[CH-total] " + " ".join(f"{k}={v}" for k, v in sorted(tot.items()) if v))

# ----------------------------------------------------------------------------------------------- mode: fixtures
def fixtures(files):
    print("== [FX] e07fb00 reader on each tracked file against the same reader on CANON(file) ==")
    T = collections.Counter(); defect_rows = []; fieldc = collections.Counter(); per_file = {}; other_rows = []; extra_rows = []
    with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
        for f in files:
            t0 = time.perf_counter()
            text = (repo / f).read_bytes().decode("utf-8", errors="replace")
            data_o = a.parse_a2l_file(repo / f)
            ctext, rdiag, root = canon(text)
            data_c = read_text(ctext, d)
            diffs, only_o, only_c = diff_tags(data_o["tags"], data_c["tags"])
            key6 = [x for x in diffs if set(x[2]) & set(KEY6 + ["axis_points"])]
            other = [x for x in diffs if not set(x[2]) & set(KEY6 + ["axis_points"])]
            for o, c_, fl in diffs:
                for x in fl:
                    fieldc[(f, x)] += 1
            for o, c_, fl in other:
                other_rows.append((f, o["section"], o["name"], {x: (show(o.get(x)), show(c_.get(x))) for x in fl}))
            extra_counts(f, root, data_o, T, extra_rows)
            for o, c_, fl in key6:
                defect_rows.append((f, o["section"], o["name"], {x: (show(o.get(x)), show(c_.get(x))) for x in fl if x in KEY6 + ["axis_points", "matrix_dim", "char_type", "deposit"]}))
            for o in only_o:
                defect_rows.append((f, o["section"], o["name"], {"only_in_reader": (show(o.get("address")), "absent in REF")}))
            for c_ in only_c:
                defect_rows.append((f, c_["section"], c_["name"], {"missing_in_reader": ("absent", show(c_.get("address")))}))
            per_file[f] = dict(tags=len(data_o["tags"]), canon_tags=len(data_c["tags"]), key6=len(key6), other=len(other),
                               only_reader=len(only_o), only_ref=len(only_c), errors=data_o["errors"][:3], canon_errors=data_c["errors"][:3],
                               ref_diags=rdiag[:3], seconds=round(time.perf_counter() - t0, 2))
            print(f"[FX] {f}: tags={len(data_o['tags'])} canon={len(data_c['tags'])} key6_diff={len(key6)} other_field_diff={len(other)} "
                  f"phantom(only reader)={len(only_o)} missing(only canon)={len(only_c)} errors={data_o['errors'][:2]} canon_errors={data_c['errors'][:2]} "
                  f"ref_diags={rdiag[:2]} t={per_file[f]['seconds']}s")
            T["files"] += 1; T["tags"] += len(data_o["tags"]); T["key6"] += len(key6); T["other"] += len(other)
            T["phantom"] += len(only_o); T["missing"] += len(only_c)
            # INSTANCE / BLOB / TYPEDEF census from REF
            for node in walk_ref(root):
                if node["name"] in ("INSTANCE", "BLOB"):
                    T["ref_" + node["name"]] += 1
                    o_ = own(node)
                    if node["name"] == "INSTANCE" and len(o_) >= 3:
                        T["instance_typedef_ref"] += 1
    print("[FX-total] " + " ".join(f"{k}={v}" for k, v in T.items()))
    print("[FX-fields] " + " ".join(f"{f.split('/')[-2]}/{f.split('/')[-1]}:{x}={v}" for (f, x), v in sorted(fieldc.items())))
    lst = scratch / "fx-defects.jsonl"
    with lst.open("w") as h:
        for r in defect_rows:
            h.write(json.dumps(r) + "\n")
    print(f"[FX-list] {len(defect_rows)} defect rows written to fx-defects.jsonl; first 40:")
    for r in defect_rows[:40]:
        print("   ", r)
    by = collections.Counter((r[0], tuple(sorted(r[3]))) for r in defect_rows)
    print("[FX-classes] " + "; ".join(f"{k[0].split('/')[-1]} {list(k[1])}: {v}" for k, v in sorted(by.items())))
    with (scratch / "fx-other-fields.jsonl").open("w") as h:
        for r in other_rows:
            h.write(json.dumps(r) + "\n")
    byo = collections.Counter((r[0], tuple(sorted(r[3]))) for r in other_rows)
    print(f"[FX-other] {len(other_rows)} rows (fields outside name/address/length/datatype/byte order/mask) in fx-other-fields.jsonl: "
          + "; ".join(f"{k[0].split('/')[-1]} {list(k[1])}: {v}" for k, v in sorted(byo.items())))
    for r in other_rows[:6]:
        print("   ", json.dumps(r)[:300])
    with (scratch / "fx-extra.jsonl").open("w") as h:
        for r in extra_rows:
            h.write(json.dumps(r) + "\n")
    bye = collections.Counter(r[1] for r in extra_rows)
    print(f"[FX-extra] {len(extra_rows)} rows in fx-extra.jsonl: " + "; ".join(f"{k}: {v}" for k, v in sorted(bye.items())))
    seen = collections.Counter()
    for r in extra_rows:
        if seen[r[1]] < 4:
            print("   ", json.dumps(r)[:300]); seen[r[1]] += 1

# keyword arities at a MEASUREMENT / CHARACTERISTIC's own level (ASAM MCD-2 MC 1.7 + the base's extensions); -1 = 1..3 numbers
ARITY = {"ADDRESS_TYPE": 1, "ARRAY_SIZE": 1, "BIT_MASK": 1, "BYTE_ORDER": 1, "DISCRETE": 0, "DISPLAY_IDENTIFIER": 1,
         "ECU_ADDRESS": 1, "ECU_ADDRESS_EXTENSION": 1, "ERROR_MASK": 1, "FORMAT": 1, "LAYOUT": 1, "MATRIX_DIM": -1,
         "MAX_REFRESH": 2, "MODEL_LINK": 1, "PHYS_UNIT": 1, "READ_WRITE": 0, "REF_MEMORY_SEGMENT": 1, "SYMBOL_LINK": 2,
         "CALIBRATION_ACCESS": 1, "COMPARISON_QUANTITY": 1, "ENCODING": 1, "EXTENDED_LIMITS": 2, "GUARD_RAILS": 0,
         "NUMBER": 1, "READ_ONLY": 0, "STEP_SIZE": 1, "DATA_SIZE": 1, "LENGTH": 1, "DATA_TYPE": 1, "FUNCTION": 1,
         "COMPU_METHOD": 1, "FORMULA": 1, "UNIT": 1, "LOWER_LIMIT": 1, "UPPER_LIMIT": 1, "VIRTUAL": 0, "CALIBRATABLE": 0,
         "DEPOSIT": 1}
NUMW = re.compile(r"-?(0[xX][0-9A-Fa-f]+|[0-9]+(\.[0-9]*)?([eE][-+]?[0-9]+)?)")
SPLITLINE_CHARS = "\x0b\x0c\x1c\x1d\x1e\x85  "

def extra_counts(f, root, data, T, rows):
    """Counts REF can give that the differential cannot: duplicate keywords, short headers, stray number words,
    MATRIX_DIM products, INSTANCE / BLOB / TYPEDEF sizing inputs, lengths and addresses out of bounds."""
    typedefs = {}
    for node in walk_ref(root):
        if node["name"].startswith("TYPEDEF_"):
            o = own(node)
            if o: typedefs[o[0][1]] = (node["name"], [t[1] for t in o])
    for node in walk_ref(root):
        nm = node["name"]
        o = own(node)
        if nm in HDR_N:
            head, pos, k = split_header(node)
            name = head[0][1] if head else "?"
            if 0 < len(pos) < HDR_N[nm]:
                T["short_header"] += 1; rows.append((f, "short_header", nm, name, len(pos)))
            if len(head) < 2:
                T["no_long_identifier"] += 1
            rest = [t for t in o[k:]]
            ids = [t[1] if t[0] == "ID" else None for t in rest]
            cnt = collections.Counter(w for w in ids if w in ARITY)
            for w, c in cnt.items():
                if c > 1:
                    T["dup_keyword:" + w] += 1; rows.append((f, "dup_keyword", nm, name, w, c))
            j = 0
            while j < len(rest):
                t = rest[j]
                if t[0] == "ID" and t[1] in ARITY:
                    ar = ARITY[t[1]]
                    if ar == -1:
                        j += 1; n = 0
                        while j < len(rest) and rest[j][0] == "ID" and re.fullmatch(r"[0-9]+", rest[j][1]) and n < 3:
                            j += 1; n += 1
                        nums = [int(x[1]) for x in rest[j - n:j]]
                        p = 1
                        for x in nums: p *= x
                        if n > 1 and p != nums[0]:
                            T["matrix_dim_product_differs"] += 1; rows.append((f, "matrix_dim_product", nm, name, nums))
                        continue
                    j += 1 + ar; continue
                if t[0] == "ID" and NUMW.fullmatch(t[1]):
                    T["stray_number_word"] += 1; rows.append((f, "stray_number_word", nm, name, t[1], t[2]))
                elif t[0] == "ID" and t[1] not in KEYWORDS:
                    T["unknown_word"] += 1
                    if T["unknown_word"] <= 30: rows.append((f, "unknown_word", nm, name, t[1], t[2]))
                j += 1
        if nm in ("INSTANCE", "BLOB"):
            ids = [t[1] for t in o]
            if nm == "BLOB":
                T["blob"] += 1; rows.append((f, "blob", ids[:4]))
            else:
                td = typedefs.get(ids[2]) if len(ids) > 2 else None
                T["instance_of:" + (td[0] if td else "UNKNOWN_TYPEDEF")] += 1
                if T["instance_rows"] < 12:
                    T["instance_rows"] += 1; rows.append((f, "instance", ids[:4], td[0] if td else None, (td[1][:6] if td else None)))
    for t in data["tags"]:
        ln, ad = t.get("length"), t.get("address")
        if isinstance(ln, int) and (ln < 1 or ln > a.MAX_A2L_DECODE_BYTES):
            T["length_out_of_bounds"] += 1; rows.append((f, "length_out_of_bounds", t["name"], ln))
        if isinstance(ad, int) and (ad < 0 or ad > 0xFFFFFFFF or (isinstance(ln, int) and ln > 0 and ad + ln - 1 > 0xFFFFFFFF)):
            T["address_out_of_bounds"] += 1; rows.append((f, "address_out_of_bounds", t["name"], ad, ln))
    def secwalk(secs):
        for s in secs:
            yield s; yield from secwalk(s.get("children") or [])
    for s in secwalk(data["sections"]):
        if any(ch in (s.get("meta") or "") for ch in SPLITLINE_CHARS):
            T["meta_with_splitline_char"] += 1; rows.append((f, "meta_with_splitline_char", s["name"], s["start_line"]))
        if "/*" in (s.get("meta") or "") or "//" in (s.get("meta") or ""):
            T["meta_with_comment"] += 1
            if T["meta_with_comment"] <= 8: rows.append((f, "meta_with_comment", s["name"], s["start_line"], (s.get("meta") or "")[:80]))

# ----------------------------------------------------------------------------------------------- object helpers for shapes
def header(mod_common="BYTE_ORDER MSB_FIRST", nl="\n"):
    h = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\n' + mod_common +
         '\n/end MOD_COMMON\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n'
         + "".join(f'/begin RECORD_LAYOUT RL_{k}\nFNC_VALUES 1 {v} ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
                   for k, v in (("U8", "UBYTE"), ("U16", "UWORD"), ("U32", "ULONG")))
         + '/begin TYPEDEF_MEASUREMENT T_U16 "" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n')
    return h.replace("\n", nl)
TAIL = '/end MODULE\n/end PROJECT\n'
FULL = ' UWORD CM_ID 0 0 0 65535'
def meas(name, *body, hdr=FULL, longid='""'):
    return f'/begin MEASUREMENT {name} {longid}\n{hdr}\n' + "\n".join(body) + '\n/end MEASUREMENT'
def char(name, kind, addr, rl, *body):
    return f'/begin CHARACTERISTIC {name} ""\n {kind} {addr} {rl} 0 CM_ID 0 65535\n' + "\n".join(body) + '\n/end CHARACTERISTIC'

SHORT = ' UWORD CM_ID 0 0 0'
P1_SHAPES = {   # copied from inc-2/evidence-e3/sec-r5-probe.py (round-3/4 shapes)
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
 "C5": meas("SX", " ECU_ADDRESS 0x10", " BIT_MASK 0x000F/* nibble */0"),
 "B3": meas("SX", " ECU_ADDRESS 0x20", " /*", " ECU_ADDRESS 0x10", " */"),
 "A1": meas("SX", " ECU_ADDRESS 0x10/* moved */"),
 "A2": meas("SX", " ECU_ADDRESS /* new */ 0x10"),
 "A3": meas("SX", " /begin IF_DATA ETK KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " ECU_ADDRESS 0x10"),
 "A4": '/begin CHARACTERISTIC SX ""\n VALUE 0x10/* c */RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC',
 "C2": meas("SX", " ECU_ADDRESS 0x10", " BYTE_ORDER MSB_LAST", " /* alternative:", " BYTE_ORDER MSB_FIRST", " */"),
 "C1": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA", " BYTE_ORDER MSB_LAST"),
 "B1": meas("SX", " ECU_ADDRESS 0x10", " MATRIX_DIM 1 4 1"),
 "H1": char("SX", "ASCII", "0x10", "RL_U8", " NUMBER 1000000000000"),
 "H3": meas("SX", " ECU_ADDRESS 0x10", " LENGTH 99999999999"),
}

def ctrl_chars(s):
    return sorted({f"U+{ord(ch):04X}" for ch in s if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Zs") and ch not in " "})

def views(data):
    """The A2L summary lines (as the Workspace pane gets them), the 16 tag-table cells and the detail card, as plain text."""
    from s19_app.tui.services.a2l_service import enrich_tags_and_render
    from s19_app.tui import app as app_mod
    merged, summary = enrich_tags_and_render(data, None)
    rows = []
    for tag in merged:
        cells = app_mod.S19TuiApp._build_a2l_table_cells(None, tag)
        card = app_mod._a2l_detail_card_text(tag)
        rows.append((tag.get("name"), [c.plain for c in cells], card.plain))
    return summary, rows

def ref_fields(text, xname):
    """REF's own reading of an object's key words (independent of the reader)."""
    toks, d1 = ref_lex(text); root, d2 = ref_tree(toks)
    hits = []
    num = lambda w: (int(w, 16) if re.fullmatch(r"0[xX][0-9A-Fa-f]+", w) else int(w) if re.fullmatch(r"[0-9]+", w) else None) if w else None
    for node in walk_ref(root):
        if node["name"] not in HDR_N: continue
        o = own(node)
        if not o or o[0][1] != xname: continue
        head, pos, k = split_header(node)
        ids = [t[1] for t in o[k:]]
        def kw(key, n=1):
            if key not in ids: return None
            j = ids.index(key); return ids[j + 1:j + 1 + n]
        if node["name"] == "MEASUREMENT":
            addr = num((kw("ECU_ADDRESS") or [None])[0]); dt = pos[0][1] if pos else None
        else:
            addr = num(pos[1][1]) if len(pos) > 1 else None; dt = None
            if kw("ECU_ADDRESS"): addr = num(kw("ECU_ADDRESS")[0])
        md = None
        if "MATRIX_DIM" in ids:
            j = ids.index("MATRIX_DIM") + 1; md = 1
            while j < len(ids) and re.fullmatch(r"[0-9]+", ids[j]): md *= int(ids[j]); j += 1
        hits.append(dict(name=head[0][1], longid=head[1][1] if len(head) > 1 else None, address=addr, datatype=dt,
                         byte_order=(kw("BYTE_ORDER") or [None])[0], bit_mask=(kw("BIT_MASK") or [None])[0], matrix_dim=md))
    return hits, d1 + d2

def run_shape(key, label, text, xname, d, raw=None, expect=None):
    data = read_text(text, d, raw=raw)
    xs = [t for t in data["tags"] if t.get("name") == xname]
    try:
        ctext, rdiag, _ = canon(text)
        cdata = read_text(ctext, d, fname="c.a2l")
        cx = [t for t in cdata["tags"] if t.get("name") == xname]
    except Exception as exc:  # REF must never raise; report it
        cx, rdiag = [], [("REF raised " + type(exc).__name__, 0)]
    refx, _ = ref_fields(text, xname)
    got = [{k: show(t.get(k)) for k in ("address", "length", "datatype", "effective_byte_order", "bit_org", "matrix_dim", "description")} for t in xs]
    want = [{k: show(t.get(k)) for k in ("address", "length", "datatype", "effective_byte_order", "bit_org", "matrix_dim", "description")} for t in cx]
    if expect is not None:
        want = expect
    verdict = "OK" if got == want else ("PHANTOM" if len(xs) > len(cx) else "LOST" if len(xs) < len(cx) else "WRONG")
    # REF's own words, independent of the reader's field rules: the address, the datatype word and the long identifier
    if verdict == "OK" and len(refx) == 1 and len(xs) == 1:
        r, t = refx[0], xs[0]
        mism = []
        if r["address"] != t.get("address"): mism.append(("address", show(t.get("address")), show(r["address"])))
        if r["datatype"] and r["datatype"] != t.get("datatype"): mism.append(("datatype", t.get("datatype"), r["datatype"]))
        if (r["longid"] or None) != (t.get("description") or None): mism.append(("description", t.get("description"), r["longid"]))
        if mism:
            verdict = "WRONG(ref)"; want = [dict(ref_mismatch=mism)]
    summary, rows = views(data)
    xlines = [ln for ln in summary if xname in ln]
    adj = []
    for nm, cells, card in rows:
        if nm != xname: continue
        for c in cells + card.split(chr(10)):
            cc = ctrl_chars(c)
            if cc: adj.append((c[:60], cc))
    broken = [ln for ln in summary if ln and not re.match(r"^(\s*- |A2L |\.\.\. |No A2L)", ln)]
    print(f"[{key}] {verdict} | {label}")
    print(f"      reader: {got} errors={data['errors'][:2]}")
    print(f"      REF:    {want} ref_diags={rdiag[:2]} ref_words={refx}")
    print(f"      views:  summary lines naming it={xlines[:3]} broken summary lines={broken[:3]} ctrl chars in cells/card={adj[:3]}")
    return verdict, bool(adj or broken)

# ----------------------------------------------------------------------------------------------- mode: repro
def repro():
    print("== [RP] reproduction matrix: line ends, blanks, encodings, comment adjacency (X = the object checked) ==")
    tally = collections.Counter(); classes = collections.defaultdict(list)
    base_objs = (meas("XM", " ECU_ADDRESS 0x00001234", " BYTE_ORDER MSB_LAST") + "\n" +
                 char("XC", "VALUE", "0x00002000", "RL_U16") + "\n" +
                 '/begin CHARACTERISTIC XH "one-line header" VALUE 0x00003000 RL_U32 0 CM_ID 0 100\n/end CHARACTERISTIC\n' +
                 meas("XA", " ECU_ADDRESS 0x00004000", " MATRIX_DIM 4"))
    lf = header() + base_objs + "\n" + TAIL
    with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
        base = read_text(lf, d)
        basev = {t["name"]: {k: t.get(k) for k in FIELDS} for t in base["tags"]}
        print("[RP-base] LF reading: " + "; ".join(f"{n} addr={show(v['address'])} len={v['length']} dt={v['datatype']} bo={v['effective_byte_order']} desc={v['description']!r}" for n, v in basev.items()))
        print(f"[RP-base] errors={base['errors']}")
        def same_as_lf(key, label, text, raw=None):
            data = read_text(text, d, raw=raw)
            got = {t["name"]: {k: t.get(k) for k in FIELDS} for t in data["tags"]}
            diffs = {n: [k for k in FIELDS if got.get(n, {}).get(k) != basev[n].get(k)] for n in basev}
            diffs = {n: v for n, v in diffs.items() if v}
            extra = sorted(set(got) - set(basev))
            summary, rows = views(data)
            adj = sorted({(nm, tuple(ctrl_chars(c))) for nm, cells, card in rows for c in cells + card.split(chr(10)) if ctrl_chars(c)})
            broken = [ln for ln in summary if ln and not re.match(r"^(\s*- |A2L |\.\.\. |No A2L)", ln)]
            v = "SAME-AS-LF" if not diffs and not extra and data["errors"] == base["errors"] else "DIFFERS"
            tally[v] += 1
            print(f"[{key}] {v} | {label} | diffs={ {n: {k: (show(got.get(n, {}).get(k)), show(basev[n].get(k))) for k in fl} for n, fl in diffs.items()} } "
                  f"extra={extra} errors={data['errors'][:2]} view ctrl chars={adj[:4]} broken summary lines={broken[:2]}")
            if v == "DIFFERS" or adj or broken:
                classes["line-end/encoding"].append(key)
        print("-- A: the same file with other line ends and encodings (expected: identical to LF) --")
        same_as_lf("RP-A1", "CRLF everywhere", lf.replace("\n", "\r\n"))
        same_as_lf("RP-A2", "lone CR everywhere (classic Mac)", lf.replace("\n", "\r"))
        mixed = "".join(ln + ("\r\n" if i % 3 == 0 else "\r" if i % 3 == 1 else "\n") for i, ln in enumerate(lf.split("\n")))
        same_as_lf("RP-A3", "mixed CRLF / CR / LF", mixed)
        same_as_lf("RP-A4", "CR CR LF (a CRLF file converted twice)", lf.replace("\n", "\r\r\n"))
        same_as_lf("RP-A5", "a trailing CR on the ECU_ADDRESS line only (CRLF there, LF elsewhere)", lf.replace("ECU_ADDRESS 0x00001234\n", "ECU_ADDRESS 0x00001234\r\n"))
        same_as_lf("RP-A6", "trailing blanks and tabs after every word line", lf.replace("\n", " \t \n"))
        same_as_lf("RP-A7", "tabs as separators everywhere", lf.replace(" ", "\t"))
        same_as_lf("RP-A8", "UTF-8 BOM, first line ASAP2_VERSION", "\ufeff" + lf)
        same_as_lf("RP-A9", "UTF-8 BOM, file starts with /begin PROJECT (no ASAP2_VERSION line)", "\ufeff" + lf.split("\n", 1)[1])
        same_as_lf("RP-A10", "UTF-16 LE with BOM (Windows 'Unicode' save)", lf, raw=b"\xff\xfe" + lf.encode("utf-16-le"))
        same_as_lf("RP-A11", "UTF-16 LE with BOM and CRLF", lf, raw=b"\xff\xfe" + lf.replace("\n", "\r\n").encode("utf-16-le"))
        same_as_lf("RP-A12", "form feed between objects (page break line)", lf.replace("/begin CHARACTERISTIC XC", "\x0c\n/begin CHARACTERISTIC XC"))
        same_as_lf("RP-A13", "form feed as the separator before the address word", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS\x0c0x00001234"))
        same_as_lf("RP-A14", "NBSP U+00A0 (UTF-8) as the separator before the address word", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS\u00a00x00001234"))
        same_as_lf("RP-A15", "cp1252 NBSP byte 0xA0 after the address word (ANSI file)", lf, raw=lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS 0x00001234\u00a0").encode("cp1252"))
        same_as_lf("RP-A16", "NUL after the address word", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS 0x00001234\x00"))
        same_as_lf("RP-A17", "NUL padding at the end of the file (a truncated copy)", lf + "\x00" * 64)
        same_as_lf("RP-A18", "U+2028 LINE SEPARATOR after the address word", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS 0x00001234\u2028"))
        same_as_lf("RP-A19", "U+0085 NEL inside the one-line CHARACTERISTIC header", lf.replace("VALUE 0x00003000 RL_U32", "VALUE 0x00003000\u0085RL_U32"))
        same_as_lf("RP-A20", "VT U+000B inside the one-line CHARACTERISTIC header", lf.replace("VALUE 0x00003000 RL_U32", "VALUE 0x00003000\x0bRL_U32"))
        same_as_lf("RP-A21", "U+001E (record separator) inside the long identifier of XH", lf.replace('"one-line header"', '"one-line\x1eheader"'))
        same_as_lf("RP-A22", "U+FEFF (zero-width no-break space) after the address word", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS 0x00001234\ufeff"))
        same_as_lf("RP-A23", "ESC sequence in the long identifier of XC", lf.replace('/begin CHARACTERISTIC XC ""', '/begin CHARACTERISTIC XC "a\x1b[2Jb"'))
        HV = "VALUE 0x00003000 RL_U32"
        for key, label, sep in [("RP-A24", "FF U+000C", chr(0x0C)), ("RP-A25", "U+2028", chr(0x2028)), ("RP-A26", "U+001C", chr(0x1C)),
                                ("RP-A26b", "VT U+000B", chr(0x0B)), ("RP-A26c", "NEL U+0085", chr(0x85))]:
            same_as_lf(key, sep_label := label + " as the separator after the address word of the one-line CHARACTERISTIC header",
                       lf.replace(HV, "VALUE 0x00003000" + sep + "RL_U32"))
        same_as_lf("RP-A27", "a comment glued after the address word of the one-line CHARACTERISTIC header", lf.replace(HV, "VALUE 0x00003000/*old 0x1000*/ RL_U32"))
        same_as_lf("RP-A28", "a CRLF file whose one-line header holds a lone CR after the address word",
                   lf.replace(chr(10), chr(13) + chr(10)).replace(HV, "VALUE 0x00003000" + chr(13) + "RL_U32"))
        same_as_lf("RP-A29", "DISPLAY_IDENTIFIER with a trailing comment on XM",
                   lf.replace(" BYTE_ORDER MSB_LAST", " BYTE_ORDER MSB_LAST" + chr(10) + " DISPLAY_IDENTIFIER XM_disp /* shown name */"))

        print("-- B: comment and line adjacency (expected: REF's reading) --")
        cases = [
            ("RP-B1", "ECU_ADDRESS 0x1234/*c*/ (comment glued after the address)", meas("X", " ECU_ADDRESS 0x1234/*c*/")),
            ("RP-B2", "ECU_ADDRESS 0x1234//c (line comment glued)", meas("X", " ECU_ADDRESS 0x1234//c")),
            ("RP-B3", "ECU_ADDRESS /*c*/ 0x1234", meas("X", " ECU_ADDRESS /*c*/ 0x1234")),
            ("RP-B4", "ECU_ADDRESS/*c*/0x1234 (glued both sides)", meas("X", " ECU_ADDRESS/*c*/0x1234")),
            ("RP-B5", "address on the next line: ECU_ADDRESS / 0x1234", meas("X", " ECU_ADDRESS", " 0x1234")),
            ("RP-B6", "address two lines down, a comment line between", meas("X", " ECU_ADDRESS", " /* moved */", " 0x1234")),
            ("RP-B7", "a live ECU_ADDRESS, then an old one inside /* ... */", meas("X", " ECU_ADDRESS 0x1234", " /*", " ECU_ADDRESS 0x9999", " */")),
            ("RP-B8", "an old ECU_ADDRESS behind //", meas("X", " ECU_ADDRESS 0x1234", " // ECU_ADDRESS 0x9999")),
            ("RP-B9", "an old ECU_ADDRESS behind /* ... */ on one line, first", meas("X", " /* ECU_ADDRESS 0x9999 */ ECU_ADDRESS 0x1234")),
            ("RP-B10", "a comment inside the address word: 0x12/*c*/34", meas("X", " ECU_ADDRESS 0x12/*c*/34")),
            ("RP-B11", "a line break inside the address word (CR): 0x12<CR>34", meas("X", " ECU_ADDRESS 0x12\r34")),
            ("RP-B12", "two keywords on one line: ECU_ADDRESS 0x1234 BYTE_ORDER MSB_LAST", meas("X", " ECU_ADDRESS 0x1234 BYTE_ORDER MSB_LAST")),
            ("RP-B13", "a one-line IF_DATA before the ECU_ADDRESS line (V171 style)", meas("X", " /begin IF_DATA ETK KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " ECU_ADDRESS 0x1234")),
            ("RP-B14", "the MEASUREMENT header on the /begin line", '/begin MEASUREMENT X "" UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
            ("RP-B15", "the MEASUREMENT header spread over lines with comments (BalanceTube style)", '/begin MEASUREMENT X ""\n UWORD /* type */\n CM_ID /* conv */\n 0 /* res */\n 0 /* acc */\n 0 /* low */\n 65535 /* high */\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
            ("RP-B16", "the name on the line after /begin MEASUREMENT", '/begin MEASUREMENT\n X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
            ("RP-B17", "the long identifier on the line after the name", '/begin MEASUREMENT X\n "long id"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
            ("RP-B18", "a comment glued to the name: X/*c*/", '/begin MEASUREMENT X/*c*/ ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
            ("RP-B19", "a comment between /begin MEASUREMENT and the name", '/begin MEASUREMENT /* c */ X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
            ("RP-B20", "the long identifier glued to the name: X\"long\"", '/begin MEASUREMENT X"long"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
            ("RP-B21", "CHARACTERISTIC header address glued to a comment: VALUE 0x2000/*c*/RL_U16", '/begin CHARACTERISTIC X ""\n VALUE 0x2000/*c*/RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC'),
            ("RP-B22", "CHARACTERISTIC header address, block comment to the next line, glued", '/begin CHARACTERISTIC X ""\n VALUE 0x2000/* old 0x1000\n */RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC'),
            ("RP-B23", "CHARACTERISTIC header on the /begin line", '/begin CHARACTERISTIC X "d" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC'),
            ("RP-B24", "CHARACTERISTIC long identifier with an escaped backslash at its end: \"C:\\\\\"", '/begin CHARACTERISTIC X "C:\\\\"\n VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC'),
            ("RP-B25", "LENGTH glued to a comment: DATA_SIZE 0x10/*c*/", meas("X", " ECU_ADDRESS 0x1234", " DATA_SIZE 0x10/*c*/")),
            ("RP-B26", "MATRIX_DIM 2 2 (two numbers)", meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 2 2")),
            ("RP-B27", "a live MATRIX_DIM 4, then MATRIX_DIM 1 inside a comment block", meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 4", " /*", " MATRIX_DIM 1", " */")),
            ("RP-B28", "a commented-out old copy of X above the live X", "/*\n" + meas("X", " ECU_ADDRESS 0x9999") + "\n*/\n" + meas("X", " ECU_ADDRESS 0x1234")),
            ("RP-B29", "a commented-out X with no live copy", "/*\n" + meas("X", " ECU_ADDRESS 0x9999") + "\n*/"),
            ("RP-B30", "a commented-out X behind // on every line", "\n".join("// " + ln for ln in meas("X", " ECU_ADDRESS 0x9999").split("\n"))),
            ("RP-B31", "glued keyword /beginMEASUREMENT", '/beginMEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
            ("RP-B32", "address word 010 (leading zero)", meas("X", " ECU_ADDRESS 010")),
            ("RP-B33", "address word 0x12_34 (underscore)", meas("X", " ECU_ADDRESS 0x12_34")),
            ("RP-B34", "address word with fullwidth digits", meas("X", " ECU_ADDRESS \uff11\uff12")),
            ("RP-B35", "address word -0x10", meas("X", " ECU_ADDRESS -0x10")),
            ("RP-B36", "address word 0X1234 (capital X)", meas("X", " ECU_ADDRESS 0X1234")),
            ("RP-B37", "BYTE_ORDER inside a comment block after the live one", meas("X", " ECU_ADDRESS 0x1234", " BYTE_ORDER MSB_LAST", " /*", " BYTE_ORDER MSB_FIRST", " */")),
            ("RP-B38", "BIT_MASK glued to a comment: BIT_MASK 0x0FF0/*c*/", meas("X", " ECU_ADDRESS 0x1234", " BIT_MASK 0x0FF0/*c*/")),
            ("RP-B39", "an unterminated quote in a body line before ECU_ADDRESS", meas("X", ' FORMAT "%5.0', " ECU_ADDRESS 0x1234")),
            ("RP-B40", "a nested comment: /* a /* b */ c */ before the address", meas("X", " /* a /* b */ c */", " ECU_ADDRESS 0x1234")),
        ]
        for key, label, body in cases:
            text = header() + body + "\n" + TAIL
            v, adj = run_shape(key, label, text, "X", d)
            tally[v] += 1
            if v != "OK" or adj:
                classes[v].append(key)

        print("-- C: the Inc 2 E3 security shapes (sec-r5-probe.py P1, after a masked neighbour MN) --")
        MN = meas("MN", " BIT_MASK 0x000F", " ECU_ADDRESS 0x10")
        for key, body in P1_SHAPES.items():
            xname = "SIG.BIT_MASK.A" if key == "N2" else "SX"
            text = header() + MN + "\n" + body + "\n" + TAIL
            v, adj = run_shape("RP-C-" + key, "Inc 2 E3 shape " + key, text, xname, d)
            tally[v] += 1
            if v != "OK" or adj:
                classes[v].append("C-" + key)

        print("-- D: INSTANCE and BLOB (the reader lists no span for either) --")
        for key, label, body in [
            ("RP-D1", "BLOB at 0x10, 2 bytes", '/begin BLOB B1 "" 0x10 2\n/end BLOB'),
            ("RP-D2", "INSTANCE of TYPEDEF_MEASUREMENT T_U16 at 0x10", '/begin INSTANCE I1 "" T_U16 0x10\n/end INSTANCE'),
            ("RP-D3", "INSTANCE with MATRIX_DIM 5", '/begin INSTANCE I2 "" T_U16 0x20\n MATRIX_DIM 5\n/end INSTANCE'),
            ("RP-D4", "a commented-out BLOB", '/* /begin BLOB B9 "" 0x90 2\n/end BLOB */'),
        ]:
            text = header() + body + "\n" + TAIL
            data = read_text(text, d)
            toks, _ = ref_lex(text); root, _ = ref_tree(toks)
            spans = [(n["name"], [t[1] for t in own(n)]) for n in walk_ref(root) if n["name"] in ("INSTANCE", "BLOB")]
            secs = [s["name"] for s in a._collect_sections_by_name(data["sections"], "BLOB") + a._collect_sections_by_name(data["sections"], "INSTANCE")]
            print(f"[{key}] {label} | reader: tags={[t['name'] for t in data['tags']]} BLOB/INSTANCE sections in tree={secs} "
                  f"payload keys={sorted(data)} | REF spans={spans}")
    print("[RP-total] " + " ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    print("[RP-classes] " + "; ".join(f"{k}: {v}" for k, v in classes.items()))

if mode in ("chars", "fixtures"):
    files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True, check=True).stdout.split()
    print("files =", len(files))
    (char_census if mode == "chars" else fixtures)(files)
elif mode == "repro":
    repro()
else:
    raise SystemExit("mode?")
