"""A2L field corpus census (batch-103, feeds Inc 11 / Inc 2-3).  stdlib + read-only s19_app clone.

usage: python3 -I census.py <clone_root> <files_dir> <manifest.tsv|-> <out_dir>
A census lexer (comment/string aware, ASAP2-spec whitespace only) is run beside the current reader
(s19_app.tui.a2l.parse_a2l_file) and the two are compared (differential oracle).
Writes nothing but under <out_dir>.  Never executes anything from the files.
"""
import collections, json, pathlib, re, sys, time, tracemalloc, traceback

clone = pathlib.Path(sys.argv[1]); fdir = pathlib.Path(sys.argv[2]); man_path = sys.argv[3]; out = pathlib.Path(sys.argv[4])
sys.path.insert(0, str(clone))
import s19_app.tui.a2l as A  # noqa: E402
print("reader module:", A.__file__, "python", sys.version.split()[0])
out.mkdir(parents=True, exist_ok=True)

TOKEN = re.compile(
    r'(?P<nl>\r\n|\r|\n)|(?P<ws>[ \t\f\v]+)|(?P<bc>/\*.*?(?:\*/|\Z))|(?P<lc>//[^\r\n]*)'
    r'|(?P<str>"(?:\\.|""|[^"\\])*")|(?P<ustr>".*\Z)|(?P<w>(?:(?!/\*|//)[^ \t\r\n\f\v"])+)', re.S)
NLRE = re.compile(r'\r\n|\r|\n')
UPPER = re.compile(r'[A-Z][A-Z0-9_]*\Z')
HEXW = re.compile(r'0[xX][0-9A-Fa-f]+\Z'); DECW = re.compile(r'[0-9]+\Z')
SPEC_WS = ' \t\r\n\f\v'

KW = """CHARACTERISTIC MEASUREMENT AXIS_PTS AXIS_DESCR RECORD_LAYOUT COMPU_METHOD COMPU_TAB COMPU_VTAB COMPU_VTAB_RANGE
FIX_AXIS_PAR FIX_AXIS_PAR_DIST FIX_AXIS_PAR_LIST BIT_MASK BYTE_ORDER MATRIX_DIM NUMBER EXTENDED_LIMITS ECU_ADDRESS
ECU_ADDRESS_EXTENSION IF_DATA INSTANCE TYPEDEF_STRUCTURE TYPEDEF_MEASUREMENT TYPEDEF_CHARACTERISTIC TYPEDEF_AXIS TYPEDEF_BLOB
BLOB MOD_COMMON MOD_PAR MODULE PROJECT HEADER FUNCTION GROUP FRAME VARIANT_CODING USER_RIGHTS UNIT ANNOTATION
READ_ONLY READ_WRITE DISPLAY_IDENTIFIER SYMBOL_LINK FORMAT PHYS_UNIT LAYOUT VIRTUAL CALIBRATION_ACCESS DEFAULT_VALUE
STEP_SIZE MAX_REFRESH DEPENDENT_CHARACTERISTIC VIRTUAL_CHARACTERISTIC MAP_LIST FUNCTION_LIST STATIC_RECORD_LAYOUT
AXIS_PTS_REF CURVE_AXIS_REF RESERVED COEFFS COEFFS_LINEAR FORMULA FORMULA_INV COMPU_TAB_REF REF_UNIT MEMORY_SEGMENT
MEMORY_LAYOUT SYSTEM_CONSTANT ALIGNMENT_BYTE ALIGNMENT_WORD ALIGNMENT_LONG ALIGNMENT_INT64 ALIGNMENT_FLOAT16_IEEE
ALIGNMENT_FLOAT32_IEEE ALIGNMENT_FLOAT64_IEEE FNC_VALUES IDENTIFICATION
AXIS_PTS_X AXIS_PTS_Y AXIS_PTS_Z AXIS_PTS_4 AXIS_PTS_5 AXIS_RESCALE_X AXIS_RESCALE_Y AXIS_RESCALE_Z AXIS_RESCALE_4 AXIS_RESCALE_5
NO_AXIS_PTS_X NO_AXIS_PTS_Y NO_AXIS_PTS_Z NO_AXIS_PTS_4 NO_AXIS_PTS_5 NO_RESCALE_X NO_RESCALE_Y NO_RESCALE_Z NO_RESCALE_4 NO_RESCALE_5
FIX_NO_AXIS_PTS_X FIX_NO_AXIS_PTS_Y FIX_NO_AXIS_PTS_Z FIX_NO_AXIS_PTS_4 FIX_NO_AXIS_PTS_5 OFFSET_X OFFSET_Y OFFSET_Z OFFSET_4 OFFSET_5
DIST_OP_X DIST_OP_Y DIST_OP_Z DIST_OP_4 DIST_OP_5 SHIFT_OP_X SHIFT_OP_Y SHIFT_OP_Z SHIFT_OP_4 SHIFT_OP_5 SRC_ADDR_X SRC_ADDR_Y
SRC_ADDR_Z SRC_ADDR_4 SRC_ADDR_5 RIP_ADDR_W RIP_ADDR_X RIP_ADDR_Y RIP_ADDR_Z RIP_ADDR_4 RIP_ADDR_5
CHECKSUM MODEL_LINK ECU_CALIBRATION_OFFSET SUB_FUNCTION IN_MEASUREMENT OUT_MEASUREMENT LOC_MEASUREMENT DEF_CHARACTERISTIC
REF_CHARACTERISTIC REF_MEASUREMENT SUB_GROUP ROOT VAR_CHARACTERISTIC TRANSFORMER ASAP2_VERSION A2ML_VERSION CUSTOMER_NO ECU
CPU_TYPE EPK VERSION PROJECT_NO SUPPLIER ADDR_EPK NO_OF_INTERFACES CALIBRATION_METHOD CALIBRATION_HANDLE OVERWRITE GUARD_RAILS
DISCRETE ERROR_MASK COMPARISON_QUANTITY BIT_OPERATION LEFT_SHIFT RIGHT_SHIFT SIGN_EXTEND MONOTONY ADDRESS_TYPE
SYNCHRONOUS_BYTE_ORDER ARRAY_SIZE""".split()
KWSET = set(KW)
OPTIONAL_HDR = KWSET - {"CHARACTERISTIC", "MEASUREMENT", "AXIS_PTS", "FUNCTION", "UNIT", "VERSION", "ROOT", "ECU", "FRAME", "PROJECT"}
HDR_N = {"CHARACTERISTIC": 9, "MEASUREMENT": 8, "AXIS_PTS": 10, "COMPU_METHOD": 5}
MEAS_TYPES = {"UBYTE", "SBYTE", "UWORD", "SWORD", "ULONG", "SLONG", "A_UINT64", "A_INT64", "FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE"}
EXOTIC_SEPS = {0x85, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0x180E, 0x200B, 0x1C, 0x1D, 0x1E, 0x1F, *range(0x2000, 0x200B)}


def a2l_number(w):
    if w is None:
        return None
    if HEXW.match(w):
        return int(w, 16)
    if DECW.match(w):
        return int(w, 10)
    return None


def lex(text):
    toks = []; comments = []; strings = 0; unterminated = 0; line = 1; code_on_line = False; cmt = False
    for m in TOKEN.finditer(text):
        k = m.lastgroup; s = m.group()
        if k == 'nl':
            line += 1; code_on_line = False; cmt = False
        elif k == 'ws':
            pass
        elif k in ('bc', 'lc'):
            nl = len(NLRE.findall(s)) if k == 'bc' else 0
            comments.append({"kind": "block" if k == 'bc' else "line", "line": line, "end": line + nl, "inline": code_on_line,
                             "has_begin": "/begin" in s or "/end" in s, "unterm": k == 'bc' and not s.endswith('*/')})
            cmt = True
            if nl:
                line += nl; code_on_line = False; cmt = False
        elif k in ('str', 'ustr'):
            nl = len(NLRE.findall(s)); strings += 1
            if k == 'ustr':
                unterminated += 1
            toks.append(("S", s, line, code_on_line, cmt)); line += nl; code_on_line = True; cmt = False if nl else cmt
        else:
            toks.append(("W", s, line, code_on_line, cmt)); code_on_line = True
    return toks, comments, strings, unterminated


def structure(toks):
    stack = []; secs = []; top = []; mism = 0; begins_off = 0; ends_off = 0; ends_unmatched = 0
    i = 0; n = len(toks)
    while i < n:
        t = toks[i]
        if t[0] == "W" and t[1] == "/begin" and i + 1 < n:
            nm = toks[i + 1]
            s = {"name": nm[1], "line": t[2], "inline": t[3], "name_line": nm[2], "direct": [], "end_line": None}
            if t[3]:
                begins_off += 1
            secs.append(s); stack.append(s); i += 2; continue
        if t[0] == "W" and t[1] == "/end":
            if t[3]:
                ends_off += 1
            if stack:
                s = stack.pop(); s["end_line"] = t[2]
                if i + 1 < n and toks[i + 1][1] != s["name"]:
                    mism += 1
            else:
                ends_unmatched += 1
            i += 2; continue
        (stack[-1]["direct"] if stack else top).append(t); i += 1
    return secs, top, {"unclosed": len(stack), "end_name_mismatch": mism, "begin_not_line_start": begins_off,
                       "end_not_line_start": ends_off, "end_unmatched": ends_unmatched}


def census_text(path):
    raw = path.read_bytes(); R = {"bytes": len(raw)}
    R["bom"] = "utf8" if raw.startswith(b"\xef\xbb\xbf") else "utf16le" if raw.startswith(b"\xff\xfe") else "utf16be" if raw.startswith(b"\xfe\xff") else "none"
    try:
        raw.decode("utf-8"); utf8ok = True
    except UnicodeDecodeError:
        utf8ok = False
    ascii_only = raw.isascii()
    R["encoding"] = "ascii" if ascii_only else ("utf-8" if utf8ok else "not-utf8(latin-1?)")
    crlf = raw.count(b"\r\n"); lf = raw.count(b"\n") - crlf; cr = raw.count(b"\r") - crlf
    R.update(crlf=crlf, lf_only=lf, cr_only=cr)
    R["eol"] = "+".join(k for k, v in (("CRLF", crlf), ("LF", lf), ("CR", cr)) if v) or "none"
    R["mixed_eol"] = sum(1 for v in (crlf, lf, cr) if v) > 1
    R["tabs"] = raw.count(b"\t"); R["formfeeds"] = raw.count(b"\x0c"); R["nul"] = raw.count(b"\x00"); R["vt"] = raw.count(b"\x0b")
    R["final_newline"] = raw.endswith((b"\n", b"\r"))
    text = raw.decode("utf-8", errors="replace")   # same decode the reader uses
    R["replacement_chars"] = text.count("\ufffd")
    R["nbsp"] = text.count("\u00a0") + (raw.count(b"\xa0") if not utf8ok else 0)
    R["other_separators"] = dict(collections.Counter(f"U+{ord(c):04X}" for c in text if ord(c) in EXOTIC_SEPS))
    R["py_ws_nonspec"] = sum(1 for c in text if c.isspace() and c not in SPEC_WS)
    if text.startswith("\ufeff"):
        text = text[1:]
    return text, R


def census(path):
    text, R = census_text(path)
    toks, comments, nstr, unterm = lex(text)
    secs, top, sst = structure(toks)
    R.update(sst); R["strings"] = nstr; R["unterminated_strings"] = unterm
    R["comments_block"] = sum(1 for c in comments if c["kind"] == "block"); R["comments_line"] = sum(1 for c in comments if c["kind"] == "line")
    R["comments_inline"] = sum(1 for c in comments if c["inline"]); R["comments_spanning"] = sum(1 for c in comments if c["end"] > c["line"])
    R["comments_unterminated"] = sum(1 for c in comments if c["unterm"])
    R["comments_with_begin_end"] = sum(1 for c in comments if c["has_begin"])
    kw = collections.Counter(t[1] for t in toks if t[0] == "W" and t[1] in KWSET)
    unknown = collections.Counter(t[1] for t in toks if t[0] == "W" and UPPER.match(t[1]) and t[1] not in KWSET)
    F = collections.Counter()
    for k, v in kw.items():
        F["kw:" + k] = v
    for i, t in enumerate(top):
        if t[1] == "ASAP2_VERSION" and i + 2 < len(top):
            R["asap2_version"] = f"{top[i+1][1]}.{top[i+2][1]}"
    R.setdefault("asap2_version", "none")
    for k, v in collections.Counter(s["name"] for s in secs).items():
        F["begin:" + k] = v
    F["directive:/include"] = sum(1 for t in toks if t[0] == "W" and t[1] in ("/include", "/INCLUDE"))
    if not F["directive:/include"]:
        del F["directive:/include"]
    anomalies = []
    layouts = {}
    for s in secs:
        d = s["direct"]; nm = s["name"]
        if nm == "RECORD_LAYOUT" and d:
            layouts[d[0][1]] = {"fnc": any(t[1] == "FNC_VALUES" for t in d)}
            for t in d[1:]:
                if t[0] == "W" and t[1] in KWSET:
                    F["rl:" + t[1]] += 1
        if nm == "CHARACTERISTIC" and len(d) > 2:
            F["char_kind:" + d[2][1]] += 1
        if nm == "AXIS_DESCR" and d:
            F["axis_kind:" + d[0][1]] += 1
        if nm == "COMPU_METHOD" and len(d) > 2:
            F["compu_type:" + d[2][1]] += 1
        if nm in ("COMPU_VTAB", "COMPU_VTAB_RANGE") and len(d) > 2:
            F["vtab_type:" + nm + ":" + d[2][1]] += 1
        if nm == "IF_DATA":
            F["if_data:one_line" if s["end_line"] == s["line"] else "if_data:multi_line"] += 1
        if nm in HDR_N:
            need = HDR_N[nm]; cnt = 0
            for t in d:
                if t[0] == "W" and t[1] in OPTIONAL_HDR and cnt >= 1:
                    break
                cnt += 1
            cnt = min(cnt, need)
            if cnt < need:
                F["hdr:short_" + nm] += 1
                anomalies.append(("HDR_SHORT", s["line"], f"{nm} header has {cnt} positional words, standard {need}"))
            if len(d) >= need and len({t[2] for t in d[:need]} | {s["name_line"]}) > 1:
                F["hdr:split_" + nm] += 1
        for j, t in enumerate(d):
            if t[0] == "W" and t[1] == "MATRIX_DIM":
                k = 0
                while j + 1 + k < len(d) and DECW.match(d[j + 1 + k][1]):
                    k += 1
                F[f"matrix_dim:{k}_numbers"] += 1
            if t[0] == "W" and t[1] in ("ECU_ADDRESS", "BIT_MASK", "BYTE_ORDER", "MATRIX_DIM", "NUMBER", "EXTENDED_LIMITS",
                                        "ECU_ADDRESS_EXTENSION", "DISPLAY_IDENTIFIER", "SYMBOL_LINK") and t[3]:
                F["kw_not_line_start:" + t[1]] += 1
                if t[1] in ("ECU_ADDRESS", "BIT_MASK", "BYTE_ORDER", "MATRIX_DIM", "ECU_ADDRESS_EXTENSION"):
                    anomalies.append(("KW_NOT_LINE_START", t[2], f"{t[1]} is not the first word on its line (current reader keys on the line-first word)"))
    for s in secs:
        if s["inline"] and s["name"] in ("MEASUREMENT", "CHARACTERISTIC", "AXIS_PTS", "COMPU_METHOD", "INSTANCE", "BLOB"):
            anomalies.append(("BEGIN_NOT_LINE_START", s["line"], f"/begin {s['name']} follows other code on its line"))
        if s["name_line"] != s["line"]:
            F["begin_name_next_line"] += 1
            anomalies.append(("BEGIN_NAME_NEXT_LINE", s["line"], f"/begin {s['name']} - name token on a later line"))
    R["_secs"] = secs; R["_layouts"] = layouts
    for f, v in R["other_separators"].items():
        F["sep:" + f] = v
    R["unknown_upper_words_top"] = unknown.most_common(12)
    return R, F, anomalies


def declared_objects(secs):
    objs = []
    for s in secs:
        if s["name"] not in ("CHARACTERISTIC", "MEASUREMENT"):
            continue
        d = s["direct"]
        o = {"section": s["name"], "line": s["line"], "addr": None, "addr_word": None, "ecu_addr_word": None, "ecu_n": 0,
             "kind": None, "datatype": None, "layout": None, "ecu_not_first": False, "ecu_after_comment": False,
             "begin_words": sum(1 for t in d if t[2] == s["line"]), "name": d[0][1] if d else None, "name_line": s["name_line"]}
        if s["name"] == "CHARACTERISTIC":
            if len(d) > 2:
                o["kind"] = d[2][1]
            if len(d) > 3:
                o["addr_word"] = d[3][1]; o["addr"] = a2l_number(d[3][1])
            if len(d) > 4:
                o["layout"] = d[4][1]
        elif len(d) > 2:
            o["datatype"] = d[2][1]
        for j, t in enumerate(d):
            if t[0] == "W" and t[1] == "ECU_ADDRESS" and j + 1 < len(d):
                o["ecu_n"] += 1; o["ecu_addr_word"] = d[j + 1][1]
                if t[3]:
                    o["ecu_not_first"] = True
                if t[4]:
                    o["ecu_after_comment"] = True
        if o["ecu_addr_word"] is not None:
            o["addr"] = a2l_number(o["ecu_addr_word"])
        objs.append(o)
    return objs


def compare(R, objs, data, anomalies):
    C = collections.Counter()
    rsecs = []

    def walk(lst):
        for s in lst:
            if s.get("name") in ("CHARACTERISTIC", "MEASUREMENT"):
                rsecs.append(s)
            walk(s.get("children") or [])
    walk(data["sections"]); tags = data["tags"]
    if len(rsecs) != len(tags):
        C["reader_sections_vs_tags_len_differ"] += 1
    mine = {(o["section"], o["line"]): o for o in objs}
    reader_keys = set()
    for rs, tag in zip(rsecs, tags):
        key = (rs["name"], rs["start_line"]); reader_keys.add(key)
        o = mine.get(key)
        if o is None:
            C["READER_TAG_NOT_IN_CODE"] += 1
            anomalies.append(("READER_TAG_NOT_IN_CODE", rs["start_line"], f"reader built a {rs['name']} tag from a /begin the census places in a comment or string"))
            continue
        ra, ma = tag.get("address"), o["addr"]
        if o["section"] == "CHARACTERISTIC" and o["addr_word"] and HEXW.match(o["addr_word"]) and len(o["addr_word"]) - 2 > 8:
            C["ADDR_WORD_GT8_DIGITS"] += 1
            anomalies.append(("ADDR_WORD_GT8_DIGITS", o["line"], f"CHARACTERISTIC header address word has {len(o['addr_word'])-2} hex digits"))
        if o["ecu_addr_word"] and HEXW.match(o["ecu_addr_word"]) and len(o["ecu_addr_word"]) - 2 > 8:
            C["ECU_WORD_GT8_DIGITS"] += 1
            anomalies.append(("ECU_WORD_GT8_DIGITS", o["line"], f"ECU_ADDRESS word has {len(o['ecu_addr_word'])-2} hex digits"))
        if isinstance(ra, int) and ra > 0xFFFFFFFF:
            C["READER_ADDR_GT_FFFFFFFF"] += 1
            anomalies.append(("READER_ADDR_GT_FFFFFFFF", o["line"], f"reader address has {len(f'{ra:X}')} hex digits on a {o['section']}"))
        if ra != ma:
            cls = "ADDR_READER_NONE_ORACLE_HAS" if ra is None else "ADDR_ORACLE_NONE_READER_HAS" if ma is None else "ADDR_DIFFERENT"
            C[cls] += 1
            w = o["ecu_addr_word"] or o["addr_word"] or ""
            why = ("leading-zero decimal word" if DECW.match(w) and w.startswith("0") and len(w) > 1 else
                   "ECU_ADDRESS keyword/value split across lines" if o["ecu_addr_word"] is None and False else
                   "header words on the /begin line" if o["begin_words"] > 2 else
                   "ECU_ADDRESS preceded by a comment on its line" if o["ecu_after_comment"] and not o["ecu_not_first"] else
                   "ECU_ADDRESS not line-first" if o["ecu_not_first"] else "unclassified")
            C["addrwhy:" + why] += 1
            anomalies.append((cls, o["line"], f"{o['section']} reader address {'None' if ra is None else hex(ra)} vs census {'None' if ma is None else hex(ma)} ({why})"))
        if tag.get("name") != o["name"]:
            cls = "NAME_UNKNOWN_FROM_EMPTY_BEGIN_META" if tag.get("name") == "UNKNOWN" else "NAME_DIFFERENT"
            C[cls] += 1
            anomalies.append((cls, o["line"], f"{o['section']} reader name is {'UNKNOWN' if tag.get('name') == 'UNKNOWN' else 'different'}; census name token is on line {o['name_line']} ({o['begin_words']} words on the /begin line)"))
        if o["section"] == "CHARACTERISTIC" and tag.get("char_type") != o["kind"]:
            C["CHAR_KIND_DIFFERENT"] += 1
            C["charkind_why:" + ("header words on the /begin line" if o["begin_words"] > 2 else "other")] += 1
            anomalies.append(("CHAR_KIND_DIFFERENT", o["line"], f"CHARACTERISTIC kind read as {tag.get('char_type')} vs census {o['kind']} ({o['begin_words']} words on the /begin line)"))
        if o["section"] == "MEASUREMENT" and tag.get("datatype") != o["datatype"]:
            C["MEAS_DATATYPE_DIFFERENT"] += 1
            C["measdt_why:" + ("header words on the /begin line" if o["begin_words"] > 2 else "other")] += 1
            anomalies.append(("MEAS_DATATYPE_DIFFERENT", o["line"], f"MEASUREMENT datatype read as {tag.get('datatype')} vs census {o['datatype']} ({o['begin_words']} words on the /begin line)"))
        if o["begin_words"] > 2:
            C["objects_with_header_on_begin_line"] += 1
        if o["ecu_n"] > 1:
            C["MULTIPLE_ECU_ADDRESS"] += 1
        if tag.get("length") is None:
            if o["section"] == "MEASUREMENT" and o["datatype"] in MEAS_TYPES:
                C["LEN_NONE_MEAS_DATATYPE_DECLARED"] += 1
                C["lennone_meas_why:" + ("header words on the /begin line" if o["begin_words"] > 2 else "other")] += 1
                anomalies.append(("LEN_NONE_MEAS_DATATYPE_DECLARED", o["line"], f"MEASUREMENT datatype {o['datatype']} declared but reader length None"))
            elif o["section"] == "CHARACTERISTIC":
                lay = R["_layouts"].get(o["layout"])
                C["LEN_NONE_CHAR_" + str(o["kind"])] += 1
                if lay and lay["fnc"] and o["kind"] in ("VALUE", "VAL_BLK", "ASCII"):
                    C["LEN_NONE_CHAR_RESOLVABLE_LAYOUT"] += 1
                    anomalies.append(("LEN_NONE_CHAR_RESOLVABLE_LAYOUT", o["line"], f"CHARACTERISTIC {o['kind']} with a record layout in the file but reader length None"))
        C["tags_" + str(tag.get("section"))] += 1
    for (sec, line) in mine:
        if (sec, line) not in reader_keys:
            C["CENSUS_OBJECT_NOT_READ"] += 1
            anomalies.append(("CENSUS_OBJECT_NOT_READ", line, f"{sec} /begin in code but no reader section starts on that line"))
    cnt = collections.Counter((t.get("section"), t.get("name")) for t in tags)
    dups = {k for k, v in cnt.items() if v > 1}
    if dups:
        C["DUPLICATE_NAMES"] += len(dups); C["DUPLICATE_NAME_EXTRA_TAGS"] += sum(cnt[k] - 1 for k in dups)
        pos = {}
        for rs, tag in zip(rsecs, tags):
            k = (tag.get("section"), tag.get("name"))
            if k in dups:
                pos.setdefault(k, []).append(rs["start_line"])
        for k, ls in list(pos.items())[:50]:
            anomalies.append(("DUPLICATE_NAME", ls[1], f"{k[0]} name occurs {len(ls)} times (first at line {ls[0]})"))
    for _ in data["errors"]:
        C["reader_errors"] += 1
    D = collections.Counter()
    for tag in tags:
        if tag.get("section") == "CHARACTERISTIC" and tag.get("char_type") in ("MAP", "CURVE"):
            k = tag["char_type"]; D[k + ":objects"] += 1
            a, l = tag.get("address"), tag.get("length")
            at = f"0x{a:08X}" if isinstance(a, int) else "n/a"; lt = str(l) if isinstance(l, int) else "n/a"
            if lt == "n/a":
                D[k + ":length_n/a"] += 1; continue
            D[k + ":len_digits_%d%s" % (min(len(lt), 5), "+" if len(lt) >= 5 else "")] += 1
            if at != "n/a":
                D[k + ":concat_reads_as_one_hex_literal"] += 1
                if len(lt) == 4:
                    D[k + ":concat_adds_exactly_4_digits"] += 1
                if len(at) - 2 > 8:
                    D[k + ":addr_text_gt8_digits"] += 1
    return C, D


def main():
    files = sorted(fdir.glob("*.a2l"), key=lambda p: (int(p.stem) if p.stem.isdigit() else 10**9, p.name))
    perfile = []; total_F = collections.Counter(); files_with = collections.Counter(); total_C = collections.Counter(); total_D = collections.Counter()
    all_anoms = []; big = []
    shas = {}
    if man_path != "-" and fdir.name == "files":
        for l in open(man_path).read().splitlines()[1:]:
            q = l.split("	"); shas[q[0]] = q[6]
    seen = {}; dups = []
    for p in files:
        n = p.stem; row = {"n": n, "file": p.name}
        sh = shas.get(n)
        if sh and sh in seen:
            dups.append((n, seen[sh])); continue
        if sh:
            seen[sh] = n
        try:
            R, F, an = census(p)
            objs = declared_objects(R["_secs"])
            row.update({k: v for k, v in R.items() if not k.startswith("_")}); row["objects"] = len(objs)
        except Exception as e:
            row["census_exception"] = repr(e)[:200]; perfile.append(row); print(n, "CENSUS EXC", e); traceback.print_exc(); continue
        try:
            data, dt = (lambda t0: (A.parse_a2l_file(p), time.perf_counter() - t0))(time.perf_counter())
            row["parse_seconds"] = round(dt, 3); row["tags"] = len(data["tags"]); row["reader_errors"] = data["errors"][:3]
            C, D = compare(R, objs, data, an)
            row["compare"] = dict(C); row["display"] = dict(D)
            total_C.update(C); total_D.update(D); big.append((R["bytes"], p))
        except Exception as e:
            row["parse_exception"] = repr(e)[:200]; an.append(("PARSE_EXCEPTION", 0, "reader raised " + type(e).__name__)); total_C["PARSE_EXCEPTION"] += 1
            print(n, "PARSE EXC", repr(e)[:120])
        row["features"] = dict(F); total_F.update(F)
        for k in F:
            files_with[k] += 1
        per = collections.Counter()
        for cls, line, desc in an:
            per[cls] += 1
            if per[cls] <= 8:
                all_anoms.append((cls, n, line, desc))
        for cls, c in per.items():
            if c > 8:
                all_anoms.append((cls, n, 0, f"(+{c-8} more of this class in this file; {c} in total)"))
        row["anomaly_counts"] = dict(per)
        perfile.append(row)
        print(f"{n}\t{R['bytes']}\t{R['encoding']}\t{R['eol']}\tv{R['asap2_version']}\tobjs={len(objs)}\tparse={row.get('parse_seconds')}s", flush=True)
    mem = []
    for sz, p in sorted(big, reverse=True)[:5]:
        tracemalloc.start(); t0 = time.perf_counter(); A.parse_a2l_file(p); dt = time.perf_counter() - t0
        cur, peak = tracemalloc.get_traced_memory(); tracemalloc.stop(); mem.append((p.name, sz, round(dt, 2), peak))
    json.dump({"per_file": perfile, "features_total": total_F, "features_files": files_with, "compare_total": total_C,
               "display_total": total_D, "memory_top5": mem}, open(out / "census.json", "w"), indent=1, default=str)
    json.dump(all_anoms, open(out / "anomalies.json", "w"))
    L = []; nf = len(perfile); ok = [r for r in perfile if "bytes" in r]
    L.append("identical-content duplicates skipped (n, same as n): " + str(dups))
    L.append(f"# census summary: {nf} files, {sum(r.get('objects',0) for r in ok)} MEASUREMENT/CHARACTERISTIC objects")
    for key in ("encoding", "bom", "eol", "asap2_version"):
        L.append(key + ": " + ", ".join(f"{k}={v}" for k, v in collections.Counter(r.get(key) for r in ok).most_common()))
    L.append("files with: mixed_eol=%d tabs=%d formfeeds=%d nbsp=%d nul=%d other_separators=%d non-spec-python-whitespace=%d replacement_chars=%d no_final_newline=%d" % (
        *(sum(1 for r in ok if r.get(k)) for k in ("mixed_eol", "tabs", "formfeeds", "nbsp", "nul", "other_separators", "py_ws_nonspec", "replacement_chars")),
        sum(1 for r in ok if not r.get("final_newline"))))
    sizes = sorted(r["bytes"] for r in ok)
    L.append("size bytes: min=%d median=%d max=%d total=%d" % (sizes[0], sizes[len(sizes) // 2], sizes[-1], sum(sizes)))
    L.append("parse seconds max=%s ; largest-5 (name, bytes, seconds, tracemalloc peak bytes): %s" % (max(r.get("parse_seconds", 0) for r in perfile), mem))
    L.append("\n## reader/oracle comparison totals (counts of objects)")
    L += [f"{k}\t{v}" for k, v in sorted(total_C.items())]
    L.append("\n## display check, MAP/CURVE (address text 0x%08X, length text decimal)")
    L += [f"{k}\t{v}" for k, v in sorted(total_D.items())]
    L.append("\n## feature table: key, files_with, total_occurrences")
    for k in sorted(total_F):
        L.append(f"{k}\t{files_with[k]}\t{total_F[k]}")
    (out / "summary.txt").write_text("\n".join(L) + "\n")
    print("\n".join(L[:12]))


main()
