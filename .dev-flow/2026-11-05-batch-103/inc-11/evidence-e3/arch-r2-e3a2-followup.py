"""Inc 11 E3 architect round 2 (batch-103), follow-up of e3a2-named.py. Run on <runner> only.

    python -I e3a2-followup.py <repo> <files_dir> <manifest.tsv>

(1) Corpus: the RECORD_LAYOUTs named on a later line whose FNC_VALUES datatype the e07fb00 layout reader
    (_resolve_record_layout: the first datatype word of the FIRST body line) does not give on CANON2 -- is that the
    base first-line rule (the first component is not FNC_VALUES), or the named-kind rule moving component words into
    meta (the name's run holds more than the name)? The same split for layouts named on their /begin line, as control.
(2) Tracked files (35): an independent count, from REF's own words, of the tags on which a rule the E3 correction
    added would fire -- a keyword with fewer arguments than its arity because the next word is a keyword (READ.58), an
    argument of a number keyword that is not a number word (READ.63), a keyword twice with different arguments
    (READ.32/.60), two address words that differ (READ.59/.60), sizes that do not agree under CTX *sizes* (READ.59/.61),
    MATRIX_DIM with 0 or more than 3 words; and the counts of the size classes the correction lists (ARRAY_SIZE,
    DATA_SIZE with MATRIX_DIM). Counts only; no file text, no names. Imports s19_app only for the e07fb00 tag length.
"""
import collections, hashlib, pathlib, re, subprocess, sys

repo = pathlib.Path(sys.argv[1]); fdir = pathlib.Path(sys.argv[2]); manifest = pathlib.Path(sys.argv[3])
WS = " \t\x0b\x0c"
_WORD = re.compile(r'(?:[^ \t\x0b\x0c\n"/]|/(?![/*]))+')
NUMW = re.compile(r"(0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,20})\Z")


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
    root = {"name": "ROOT", "items": [], "kwline": -1}
    stack, k = [root], 0
    while k < len(toks):
        kind, v, ln = toks[k]
        if kind == "ID" and v.lower() == "/begin" and k + 1 < len(toks):
            node = {"name": toks[k + 1][1], "items": [], "kwline": toks[k + 1][2]}
            stack[-1]["items"].append(("child", node)); stack.append(node); k += 2; continue
        if kind == "ID" and v.lower() == "/end" and k + 1 < len(toks):
            if len(stack) > 1:
                stack.pop()
            k += 2; continue
        stack[-1]["items"].append(("tok", toks[k])); k += 1
    return root


def walk(node):
    for kind, x in node["items"]:
        if kind == "child":
            yield x
            yield from walk(x)


def own(node):
    return [x for k, x in node["items"] if k == "tok"]


DTS = {"UBYTE": 1, "SBYTE": 1, "UWORD": 2, "SWORD": 2, "ULONG": 4, "SLONG": 4, "A_UINT64": 8, "A_INT64": 8,
       "FLOAT16_IEEE": 2, "FLOAT32_IEEE": 4, "FLOAT64_IEEE": 8}
LAYOUT_COMPONENTS = {"FNC_VALUES", "AXIS_PTS_X", "AXIS_PTS_Y", "AXIS_PTS_Z", "NO_AXIS_PTS_X", "NO_AXIS_PTS_Y",
                     "NO_AXIS_PTS_Z", "SRC_ADDR_X", "SRC_ADDR_Y", "RIP_ADDR_X", "RIP_ADDR_Y", "RIP_ADDR_W",
                     "AXIS_RESCALE_X", "NO_RESCALE_X", "IDENTIFICATION", "RESERVED", "ALIGNMENT_BYTE",
                     "ALIGNMENT_WORD", "ALIGNMENT_LONG", "ALIGNMENT_FLOAT32_IEEE", "ALIGNMENT_FLOAT64_IEEE",
                     "FIX_NO_AXIS_PTS_X", "FIX_NO_AXIS_PTS_Y", "STATIC_RECORD_LAYOUT", "DIST_OP_X", "OFFSET_X",
                     "SHIFT_OP_X", "STATIC_ADDRESS_OFFSETS", "ALIGNMENT_INT64"}


def rl_reason(node):
    s = own(node)
    name_line = s[0][2]
    name_run = [t for t in s if t[2] == name_line]
    first_comp = next((t[1] for t in s[1:] if t[1] in LAYOUT_COMPONENTS), None)
    if len(name_run) > 1 and any(t[1] in LAYOUT_COMPONENTS for t in name_run[1:]):
        return "component words on the name's line (moved into meta by the named-kind rule)"
    if first_comp != "FNC_VALUES":
        return f"first component {first_comp} (base first-line rule)"
    return "other"


def rl_dt(node):
    s = [t[1] for t in own(node)]
    for k, w in enumerate(s):
        if w == "FNC_VALUES" and k + 2 < len(s):
            return s[k + 2]
    return None


def base_first_line_dt(node, rule):
    """What _resolve_record_layout sees on CANON1/CANON2: the first body line's first datatype word."""
    s = own(node)
    later = s[0][2] != node["kwline"]
    runs = collections.OrderedDict()
    for t in s:
        if t[2] == node["kwline"]:
            continue
        runs.setdefault(t[2], []).append(t[1])
    body = list(runs.values())
    if rule and later and body:
        first = body.pop(0)
        if len(first) == 1 and body and body[0] and body[0][0].startswith('"'):
            body.pop(0)
    first_line = body[0] if body else []
    return next((w for w in first_line if w in DTS), None)


C = collections.Counter()
seen = set()
for ln in manifest.read_text(encoding="utf-8").splitlines()[1:]:
    parts = ln.split("\t")
    n, sha = parts[0], parts[6]
    p = fdir / f"{n}.a2l"
    if not p.exists():
        continue
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    if h != sha or h in seen:
        continue
    seen.add(h)
    root = ref_tree(ref_lex(p.read_bytes().decode("utf-8", errors="replace")))
    for node in walk(root):
        if node["name"] != "RECORD_LAYOUT" or not own(node):
            continue
        later = own(node)[0][2] != node["kwline"]
        grp = "later" if later else "begin"
        want = rl_dt(node)
        got = base_first_line_dt(node, True)
        C[f"[RL {grp}] all"] += 1
        if got == want:
            C[f"[RL {grp}] FNC datatype read"] += 1
        else:
            C[f"[RL {grp}] not read: {rl_reason(node)}"] += 1
print("[corpus] files", len(seen))

ARITY = {"ADDRESS_TYPE": 1, "ARRAY_SIZE": 1, "BIT_MASK": 1, "BYTE_ORDER": 1, "DISCRETE": 0, "DISPLAY_IDENTIFIER": 1,
         "ECU_ADDRESS": 1, "ECU_ADDRESS_EXTENSION": 1, "ERROR_MASK": 1, "FORMAT": 1, "LAYOUT": 1, "MATRIX_DIM": -1,
         "MAX_REFRESH": 2, "MODEL_LINK": 1, "PHYS_UNIT": 1, "READ_WRITE": 0, "REF_MEMORY_SEGMENT": 1, "SYMBOL_LINK": 2,
         "CALIBRATION_ACCESS": 1, "COMPARISON_QUANTITY": 1, "ENCODING": 1, "EXTENDED_LIMITS": 2, "GUARD_RAILS": 0,
         "NUMBER": 1, "READ_ONLY": 0, "STEP_SIZE": 1, "DATA_SIZE": 1, "LENGTH": 1, "DATA_TYPE": 1, "FUNCTION": 1,
         "COMPU_METHOD": 1, "FORMULA": 1, "UNIT": 1, "LOWER_LIMIT": 1, "UPPER_LIMIT": 1, "VIRTUAL": 0,
         "CALIBRATABLE": 0, "DEPOSIT": 1}
NUMKW = {"ECU_ADDRESS", "DATA_SIZE", "LENGTH", "NUMBER", "MATRIX_DIM", "ARRAY_SIZE"}
HDR = {"MEASUREMENT": 6, "CHARACTERISTIC": 7}
T = collections.Counter()
tracked = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True,
                         check=True).stdout.split()
for f in tracked:
    root = ref_tree(ref_lex((repo / f).read_bytes().decode("utf-8", errors="replace")))
    fnc = {}
    for node in walk(root):
        if node["name"] == "RECORD_LAYOUT" and own(node):
            dt = rl_dt(node)
            if dt:
                fnc[own(node)[0][1]] = dt
    for node in walk(root):
        kind = node["name"]
        if kind not in HDR:
            continue
        seq = []
        for k, x in node["items"]:
            seq.append(("MARK", "", 0) if k == "child" else x)
        if not seq or seq[0][0] == "MARK":
            continue
        T["tags"] += 1
        pos = 2 if len(seq) > 1 and seq[1][0] == "STR" else 1
        header = []
        while pos < len(seq) and len(header) < HDR[kind]:
            t = seq[pos]
            if t[0] == "MARK" or (t[0] == "ID" and t[1] in ARITY):
                break
            header.append(t[1]); pos += 1
        fired = set()
        addrs, sizes, seen_kw = [], [], {}
        md = None
        if kind == "CHARACTERISTIC" and len(header) == 7:
            if NUMW.match(header[1]):
                addrs.append(int(header[1], 0) if header[1][:2].lower() == "0x" else int(header[1], 10))
            else:
                fired.add("READ.63 header address not a number")
        while pos < len(seq):
            t = seq[pos]
            if t[0] != "ID" or t[1] not in ARITY:
                pos += 1; continue
            kw, ar = t[1], ARITY[t[1]]
            j, args = pos + 1, []
            while j < len(seq) and (ar < 0 or len(args) < ar):
                x = seq[j]
                if x[0] == "MARK" or (x[0] == "ID" and x[1] in ARITY):
                    break
                args.append(x); j += 1
            if (ar >= 0 and len(args) < ar) or (ar < 0 and not 1 <= len(args) <= 3):
                fired.add(f"READ.58 {kw} arguments")
            argv = tuple(a[1] for a in args)
            if kw in seen_kw and seen_kw[kw] != argv:
                fired.add(f"READ.32/.60 {kw} twice, different")
            elif kw in seen_kw:
                fired.add(f"READ.32 {kw} twice, same")
            seen_kw[kw] = argv
            if kw in NUMKW:
                vals = []
                for a in args:
                    if a[0] != "ID" or not NUMW.match(a[1]):
                        fired.add(f"READ.63 {kw} not a number"); vals = None; break
                    vals.append(int(a[1], 16) if a[1][:2].lower() == "0x" else int(a[1], 10))
                if vals:
                    if kw == "ECU_ADDRESS":
                        addrs.append(vals[0])
                    elif kw == "MATRIX_DIM":
                        p = 1
                        for v in vals:
                            p *= v
                        md = p
                    else:
                        sizes.append((kw, vals[0]))
            pos = j
        if len(set(addrs)) > 1:
            fired.add("READ.59/.60 address words differ")
        el = None
        if kind == "MEASUREMENT" and header:
            el = DTS.get(header[0])
        elif len(header) == 7:
            dep = header[2]
            el = DTS.get(fnc.get(dep, ""))
        has_len = any(k in ("DATA_SIZE", "LENGTH") for k, _ in sizes)
        if el is not None:
            b = [v if k in ("DATA_SIZE", "LENGTH") else v * el for k, v in sizes]
            if md is not None:
                b.append(md * el)
            if has_len:
                b.append(el * (md or 1))
        else:
            b = [v for k, v in sizes if k not in ("DATA_SIZE", "LENGTH")] + ([md] if md is not None else [])
        if len(set(b)) > 1:
            fired.add("READ.59/.61 sizes disagree")
        if "ARRAY_SIZE" in seen_kw:
            T[f"class: ARRAY_SIZE on {kind}" + (" with MATRIX_DIM" if md is not None else "")] += 1
        if "DATA_SIZE" in seen_kw and md is not None:
            T["class: DATA_SIZE with MATRIX_DIM (R-A2L-013 changed)"] += 1
        if has_len and el is not None and len(header) and (kind == "MEASUREMENT" or header[0] in ("VALUE", "VAL_BLK", "ASCII")):
            T["class: DATA_SIZE/LENGTH with a known element size"] += 1
        for x in fired:
            T[f"fires: {x}"] += 1
        if any(not x.startswith("READ.32 ") or "different" in x for x in fired):
            T["tags on which a fail-closed rule fires"] += 1
for k in sorted(C):
    print(f"{k} = {C[k]}")
print(f"[tracked] files {len(tracked)}")
for k in sorted(T):
    print(f"[tracked] {k} = {T[k]}")
