"""Inc 11 E3 architect round 2 (batch-103): does the named-kind rule (R-A2L-READ.54, DE-3 as revised) give the
e07fb00 line readers the name AND the content of a section whose /begin stands alone? Run on <runner> only.

    python -I e3a2-named.py <repo> <files_dir> <manifest.tsv> <scratch>

Model (not product code, no stub): E1's REF lexer and tree (evidence-e1/e1-census.py ref_lex / ref_tree / emit,
copied; imports nothing from s19_app) re-emit each file in the layout the e07fb00 reader handles:
  CANON1 = E1's emit: a non-tag section keeps its keyword-line words on its /begin line, every later run on its own line
           (the graph's DE-3 before the E3 correction);
  CANON2 = the same, plus DE-3 as revised: for a named kind whose keyword line holds no own word, its first run that
           holds own words goes to the /begin line (meta) and leaves the body; when that run is the name alone and the
           next run starts with a quoted word, that run joins it.
The e07fb00 readers (build_section_tree, extract_compu_methods, extract_compu_tables, extract_record_layouts,
_resolve_record_layout, _apply_compu_method, extract_memory_segments, parse_a2l_file) then read CANON1 and CANON2.
Truth = REF's own words of each section (independent of both). Prints counts only: no file text, no object names.
Corpus files are sha256-checked against the manifest, read only; derived temp files live under <scratch> and are
deleted after each read.
"""
import collections, hashlib, os, pathlib, re, subprocess, sys

repo = pathlib.Path(sys.argv[1]); fdir = pathlib.Path(sys.argv[2]); manifest = pathlib.Path(sys.argv[3])
scratch = pathlib.Path(sys.argv[4]); scratch.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(repo))
import logging  # noqa: E402
logging.disable(logging.CRITICAL)
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__, "| python", sys.version.split()[0])

WS = " \t\x0b\x0c"
_WORD = re.compile(r'(?:[^ \t\x0b\x0c\n"/]|/(?![/*]))+')


def ref_lex(text):
    if text.startswith("﻿"):
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
                break
            line += text.count("\n", i, j); i = j + 2; continue
        if text.startswith("//", i):
            j = text.find("\n", i); i = n if j < 0 else j; continue
        if c == '"':
            j, buf, start = i + 1, [], line
            while j < n:
                ch = text[j]
                if ch == "\\" and j + 1 < n and text[j + 1] != "\n":
                    buf.append(text[j:j + 2]); j += 2; continue
                if ch == '"':
                    break
                if ch == "\n":
                    line += 1
                buf.append(ch); j += 1
            if j >= n:
                break
            toks.append(("STR", "".join(buf), start)); i = j + 1; continue
        m = _WORD.match(text, i)
        toks.append(("ID", m.group(0), line)); i = m.end()
    return toks


def ref_tree(toks):
    root = {"name": "ROOT", "items": [], "start": 0, "kwline": -1}
    stack, k = [root], 0
    while k < len(toks):
        kind, v, ln = toks[k]
        if kind == "ID" and v.lower() == "/begin" and k + 1 < len(toks):
            node = {"name": toks[k + 1][1], "items": [], "start": ln, "kwline": toks[k + 1][2]}
            stack[-1]["items"].append(("child", node)); stack.append(node); k += 2; continue
        if kind == "ID" and v.lower() == "/end" and k + 1 < len(toks):
            if len(stack) > 1:
                stack[-1]["end"] = ln; stack.pop()
            k += 2; continue
        stack[-1]["items"].append(("tok", toks[k])); k += 1
    return root


def walk(node):
    for kind, x in node["items"]:
        if kind == "child":
            yield x
            yield from walk(x)


KEYWORDS = set("""ADDRESS_TYPE ARRAY_SIZE BIT_MASK BYTE_ORDER DISCRETE DISPLAY_IDENTIFIER ECU_ADDRESS ECU_ADDRESS_EXTENSION
ERROR_MASK FORMAT LAYOUT MATRIX_DIM MAX_REFRESH MODEL_LINK PHYS_UNIT READ_WRITE REF_MEMORY_SEGMENT SYMBOL_LINK
CALIBRATION_ACCESS COMPARISON_QUANTITY ENCODING EXTENDED_LIMITS GUARD_RAILS NUMBER READ_ONLY STEP_SIZE
DATA_SIZE LENGTH DATA_TYPE FUNCTION COMPU_METHOD FORMULA UNIT LOWER_LIMIT UPPER_LIMIT VIRTUAL CALIBRATABLE DEPOSIT
MONOTONY AXIS_PTS_REF FIX_AXIS_PAR FIX_AXIS_PAR_DIST CURVE_AXIS_REF MAX_GRAD READ_WRITE""".split())
HDR_N = {"MEASUREMENT": 6, "CHARACTERISTIC": 7}
NAMED = {"AXIS_PTS", "BLOB", "CHARACTERISTIC", "COMPU_METHOD", "COMPU_TAB", "COMPU_VTAB", "COMPU_VTAB_RANGE", "FRAME",
         "FUNCTION", "GROUP", "INSTANCE", "MEASUREMENT", "MEMORY_SEGMENT", "MODULE", "PROJECT", "RECORD_LAYOUT",
         "TRANSFORMER", "UNIT"}
STATS = collections.Counter()


def is_named(k):
    return k in NAMED or k.startswith("TYPEDEF_")


def q(t):
    kind, v, _ = t
    return '"' + v + '"' if kind == "STR" else v


def split_header(node):
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


def emit(node, out, rule):
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
                emit(x, out, rule)
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
                emit(x, out, rule)
        return
    if rule and is_named(name) and not begin_words:
        j = next((i for i, (k, _) in enumerate(lines) if k == "t"), None)
        if j is not None:
            if any(k == "c" for k, _ in lines[:j]):
                STATS["named_first_run_after_a_child"] += 1
            begin_words = lines.pop(j)[1]
            if len(begin_words) == 1 and j < len(lines) and lines[j][0] == "t" and lines[j][1][0].startswith('"'):
                begin_words = begin_words + lines.pop(j)[1]
    out.append("/begin " + name + ("" if not begin_words else " " + " ".join(begin_words)))
    for kind, x in lines:
        if kind == "t":
            out.append(" " + " ".join(x))
        else:
            emit(x, out, rule)
    out.append("/end " + name)


def canon(root, rule):
    out = []
    emit(root, out, rule)
    return "\n".join(out) + "\n"


def base_walk(secs, kinds):
    stack = list(reversed(secs))
    while stack:
        s = stack.pop()
        if s.get("name") in kinds:
            yield s
        stack.extend(reversed(s.get("children") or []))


def own_toks(node):
    return [x for k, x in node["items"] if k == "tok"]


def fnum(w):
    try:
        return float(w)
    except (TypeError, ValueError):
        return None


def ref_method(node):
    """Truth of one COMPU_METHOD from REF's own words: name, conversion type, coefficients, table reference."""
    s = own_toks(node)
    if not s:
        return None
    name = s[0][1]
    i = 1
    if i < len(s) and s[i][0] == "STR":
        i += 1
    conv = s[i][1] if i < len(s) and s[i][0] == "ID" else None
    t = {"name": name, "conversion_type": conv, "coeffs_linear": None, "coeffs": None, "compu_tab_ref": None}
    vals = [x[1] for x in s]
    for k, w in enumerate(vals):
        if w == "COEFFS_LINEAR" and k + 2 < len(vals):
            t["coeffs_linear"] = [fnum(vals[k + 1]), fnum(vals[k + 2])]
        elif w == "COEFFS" and k + 6 < len(vals):
            t["coeffs"] = [fnum(vals[k + j]) for j in range(1, 7)]
        elif w == "COMPU_TAB_REF" and k + 1 < len(vals):
            t["compu_tab_ref"] = vals[k + 1]
    return t


def ref_table_pairs(node):
    s = own_toks(node)
    if len(s) < 4:
        return None
    i = 1 + (1 if len(s) > 1 and s[1][0] == "STR" else 0)
    i += 1  # conversion type
    n = fnum(s[i][1]) if i < len(s) else None
    return int(n) if n is not None else None


def ref_layout_dt(node):
    s = [x[1] for x in own_toks(node)]
    for k, w in enumerate(s):
        if w == "FNC_VALUES" and k + 2 < len(s):
            return s[k + 2]
    return None


def shape(node):
    runs = collections.Counter(x[2] for x in own_toks(node))
    return "one-word-per-line" if runs and max(runs.values()) == 1 else "several-words-per-line"


KIND_LIST = ("COMPU_METHOD", "COMPU_VTAB", "COMPU_TAB", "RECORD_LAYOUT", "AXIS_PTS", "FUNCTION", "GROUP",
             "MEMORY_SEGMENT", "INSTANCE", "UNIT", "MODULE", "PROJECT")


def read_tree(text, tag):
    p = scratch / f"tmp-{os.getpid()}-{tag}.a2l"
    p.write_text(text, encoding="utf-8")
    try:
        secs, errs = a.build_section_tree(p)
    finally:
        p.unlink()
    return secs


def methods_status(methods, tabs, tm):
    m = methods.get(tm["name"])
    if m is None:
        return "missing", None
    phys, status, _ = a._apply_compu_method(5.0, m, tabs)
    return status, phys


def scan(path, C, label):
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    root = ref_tree(ref_lex(text))
    nodes = {k: [n for n in walk(root) if n["name"] == k] for k in KIND_LIST}
    trees = {r: read_tree(canon(root, r), f"c{int(r)}") for r in (False, True)}
    for r, secs in trees.items():
        tagr = "CANON2" if r else "CANON1"
        bsecs = {k: list(base_walk(secs, {k})) for k in KIND_LIST}
        for k in KIND_LIST:
            if len(bsecs[k]) != len(nodes[k]):
                C[f"{label}:{tagr}:{k}:section_count_mismatch"] += 1
                continue
            for n, b in zip(nodes[k], bsecs[k]):
                s = own_toks(n)
                if not s:
                    continue
                later = s[0][2] != n["kwline"]
                grp = "later" if later else "begin"
                nm = a.parse_begin_meta(b.get("meta") or "")[0]
                C[f"{label}:{tagr}:{k}:{grp}:all"] += 1
                C[f"{label}:{tagr}:{k}:{grp}:named_right"] += int(nm == s[0][1])
                if later and r:
                    C[f"{label}:shape:{k}:{shape(n)}"] += 1
        methods = a.extract_compu_methods(secs)
        tabs = a.extract_compu_tables(secs)
        layouts = a.extract_record_layouts(secs)
        for n in nodes["COMPU_METHOD"]:
            tm = ref_method(n)
            if tm is None:
                continue
            later = own_toks(n)[0][2] != n["kwline"]
            grp = "later" if later else "begin"
            sh = shape(n)
            bm = methods.get(tm["name"])
            fields_ok = bm is not None and all(
                (bm.get(f) == tm[f]) for f in ("coeffs_linear", "coeffs", "compu_tab_ref")) and (
                tm["conversion_type"] not in a.COMPU_CONVERSION_KEYWORDS or bm.get("conversion_type") == tm["conversion_type"])
            C[f"{label}:{tagr}:CM:{grp}:{sh}:all"] += 1
            C[f"{label}:{tagr}:CM:{grp}:{sh}:fields_equal_REF"] += int(fields_ok)
            got_status, got = methods_status(methods, tabs, tm)
            want, want_status, _ = a._apply_compu_method(5.0, dict(tm, format=None, unit=None), tabs)
            same = (got_status == want_status and (got == want or (isinstance(got, float) and isinstance(want, float)
                                                                    and abs(got - want) < 1e-9)))
            C[f"{label}:{tagr}:CM:{grp}:{sh}:decode5_equals_REF"] += int(same)
            if not same:
                C[f"{label}:{tagr}:CM:{grp}:decode5_wrong:{tm['conversion_type']}:got={got_status}:want={want_status}"] += 1
        for k in ("COMPU_VTAB", "COMPU_TAB"):
            for n in nodes[k]:
                s = own_toks(n)
                if not s:
                    continue
                later = s[0][2] != n["kwline"]
                grp = "later" if later else "begin"
                want = ref_table_pairs(n)
                bt = tabs.get(s[0][1])
                got = len(bt["entries"]) if bt else None
                C[f"{label}:{tagr}:{k}:{grp}:{shape(n)}:all"] += 1
                C[f"{label}:{tagr}:{k}:{grp}:{shape(n)}:entries_equal_REF"] += int(got == want)
        for n in nodes["RECORD_LAYOUT"]:
            s = own_toks(n)
            if not s:
                continue
            later = s[0][2] != n["kwline"]
            grp = "later" if later else "begin"
            want = ref_layout_dt(n)
            got = (a._resolve_record_layout(s[0][1], layouts) or {}).get("decode_type")
            C[f"{label}:{tagr}:RL:{grp}:{shape(n)}:all"] += 1
            C[f"{label}:{tagr}:RL:{grp}:{shape(n)}:fnc_datatype_equal_REF"] += int(got == want)
        # tags: does the conversion name resolve to a method that decodes as REF says?
        for n in walk(root):
            if n["name"] not in HDR_N:
                continue
            head, pos, _ = split_header(n)
            if not head or len(pos) != HDR_N[n["name"]]:
                continue
            conv = pos[1][1] if n["name"] == "MEASUREMENT" else pos[4][1]
            if conv == "NO_COMPU_METHOD":
                continue
            C[f"{label}:{tagr}:TAG:with_method"] += 1
            bm = methods.get(conv)
            if bm is None:
                C[f"{label}:{tagr}:TAG:method_not_found(identity_fallback)"] += 1
        sm = a.extract_memory_segments(secs)
        C[f"{label}:{tagr}:memseg_digest"] += 0
        trees[r] = (secs, sm)
    if trees[False][1] != trees[True][1]:
        C[f"{label}:memory_segments_CANON1_ne_CANON2_files"] += 1


def tags6(data):
    return [tuple(t.get(k) for k in ("name", "address", "length", "datatype", "effective_byte_order", "bit_org"))
            for t in data["tags"]]


C = collections.Counter()
seen = set()
nfiles = 0
for ln in manifest.read_text(encoding="utf-8").splitlines()[1:]:
    parts = ln.split("\t")
    n, sha = parts[0], parts[6]
    p = fdir / f"{n}.a2l"
    if not p.exists():
        continue
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    if h != sha:
        print(f"[skip] n={n} sha256 mismatch")
        continue
    if h in seen:
        continue
    seen.add(h)
    nfiles += 1
    scan(p, C, "corpus")
print(f"[corpus] files={nfiles}")

tracked = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True,
                         check=True).stdout.split()
diff1 = diff2 = d12 = total = 0
for f in tracked:
    p = repo / f
    scan(p, C, "tracked")
    text = p.read_bytes().decode("utf-8", errors="replace")
    root = ref_tree(ref_lex(text))
    out = {}
    for r in (False, True):
        q2 = scratch / f"tmp-{os.getpid()}-t{int(r)}.a2l"
        q2.write_text(canon(root, r), encoding="utf-8")
        try:
            out[r] = tags6(a.parse_a2l_file(q2))
        finally:
            q2.unlink()
    base = tags6(a.parse_a2l_file(p))
    total += len(base)
    if len(base) == len(out[False]) == len(out[True]):
        diff1 += sum(x != y for x, y in zip(base, out[False]))
        diff2 += sum(x != y for x, y in zip(base, out[True]))
        d12 += sum(x != y for x, y in zip(out[False], out[True]))
    else:
        C["tracked:tag_count_mismatch_files"] += 1
print(f"[tracked] files={len(tracked)} tags={total}; six fields: e07fb00(raw) vs e07fb00(CANON1) differ {diff1}; "
      f"e07fb00(raw) vs e07fb00(CANON2) differ {diff2}; CANON1 vs CANON2 differ {d12}")
for k in sorted(C):
    print(f"{k} = {C[k]}")
for k in sorted(STATS):
    print(f"[stats] {k} = {STATS[k]}")
