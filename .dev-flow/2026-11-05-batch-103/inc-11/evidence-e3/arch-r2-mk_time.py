import pathlib

HERE = pathlib.Path(__file__).resolve().parent
src = (HERE.parent / "e3a11" / "e3a-time.py").read_text(encoding="utf-8")
doc_end = src.index('"""', 3) + 3
doc = '''"""Inc 11 E3 architect round 2 (batch-103): R-A2L-READ.52 with the E3 correction's rules, re-measured.

Round 1's model (e3a-time.py, unchanged in its modes) plus two modes for what the correction adds:
  cand3       pilot3.build: the candidate tree with the correction's per-line and per-section rules (printable-ASCII
              tier 1, the NUL test on every other line, the named-kind rule, the nesting cap, capped errors);
  candFront2  candFront plus the correction's tag rules: a keyword is never an argument (DE-9), the arity shortfall
              test (READ.58), duplicate keywords (READ.32) kept per tag, the address words compared (READ.60), the sizes
              of CTX *sizes* collected and compared (_tag_sizes, READ.59/.61), every size/address argument through the
              number word (READ.63), and the quoted-name character test (READ.4).
Model: new parse = cand3 + (baseFull - baseTree) - baseFront + candFront2. Not product code, not a stub; the candidate
path imports nothing from s19_app.

Usage: python -I e3a2-time.py drive <repo> <runs> <file> [<file> ...]
       python -I e3a2-time.py <mode> <repo> <file>
"""'''
body = src[doc_end:]


def sub(old, new):
    global body
    assert body.count(old) >= 1, old[:80]
    body = body.replace(old, new, 1)


sub('''_spec = importlib.util.spec_from_file_location("pilot2", _HERE / "pilot2.py")
pilot2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pilot2)''', '''_spec = importlib.util.spec_from_file_location("pilot2", _HERE / "pilot2.py")
pilot2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pilot2)
_spec3 = importlib.util.spec_from_file_location("pilot3", _HERE / "pilot3.py")
pilot3 = importlib.util.module_from_spec(_spec3)
_spec3.loader.exec_module(pilot3)
DTS = {"UBYTE": 1, "SBYTE": 1, "UWORD": 2, "SWORD": 2, "ULONG": 4, "SLONG": 4, "A_UINT64": 8, "A_INT64": 8,
       "FLOAT16_IEEE": 2, "FLOAT32_IEEE": 4, "FLOAT64_IEEE": 8}
SIZE_KW = ("DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE")''')

sub('''def base_front(a, secs):''', '''def keyword_lines2(words, start, errors):
    """DE-9: a keyword's arguments end at the next unquoted keyword or a place mark; READ.58's shortfall test."""
    out = []
    i = start
    n = len(words)
    while i < n:
        w = words[i][0]
        if w and w[:1] != '"' and w in ARITY:
            k = ARITY[w]
            j = i + 1
            args = []
            lim = 4 if k < 0 else k
            while j < n and len(args) < lim:
                x = words[j][0]
                if x == "" or (x[:1] != '"' and x in ARITY):
                    break
                args.append(x)
                j += 1
            if (k < 0 and not (1 <= len(args) <= 3)) or (k >= 0 and len(args) < k):
                errors.append(f"Line {words[i][1]}: {w} has {len(args)} of its {k} arguments")
            out.append((" ".join([w] + args), words[i][1]))
            i = j
        else:
            i += 1
    return out


def tag_rules(kind, header, kws, name_word, errors):
    """The correction's per-tag checks: duplicates, address words, sizes, number words, quoted-name characters."""
    seen = {}
    addrs = []
    sizes = []
    no_number = False
    if kind == "CHARACTERISTIC" and len(header) == 7:
        v = number_word(header[1])
        if v is None:
            errors.append(f"Line 0: address {header[1]} is not a number")
        else:
            addrs.append(v)
    el = DTS.get(header[0]) if kind == "MEASUREMENT" and header else None
    md = None
    has_len = False
    for text, ln in kws:
        parts = text.split(" ")
        kw = parts[0]
        if kw in seen:
            errors.append(f"Line {ln}: {kw} is declared twice")
        seen[kw] = parts[1:]
        if kw == "ECU_ADDRESS" or kw in SIZE_KW or kw == "MATRIX_DIM":
            vals = [number_word(p) for p in parts[1:]]
            if not vals or any(v is None for v in vals):
                no_number = True
                errors.append(f"Line {ln}: {kw} is not a number")
                continue
            if kw == "ECU_ADDRESS":
                addrs.append(vals[0])
            elif kw == "MATRIX_DIM":
                p = 1
                for v in vals:
                    p *= v
                md = p
            else:
                has_len = has_len or kw in ("DATA_SIZE", "LENGTH")
                sizes.append((kw, vals[0]))
    if el is not None:
        b = [v if k in ("DATA_SIZE", "LENGTH") else v * el for k, v in sizes]
        if md is not None:
            b.append(md * el)
        if has_len:
            b.append(el * (md or 1))
    else:
        b = [v for k, v in sizes if k not in ("DATA_SIZE", "LENGTH")] + ([md] if md is not None else [])
    agree = len(set(b)) <= 1
    if not agree:
        errors.append(f"Line 0: declares the sizes {min(b)} and {max(b)}")
    if len(set(addrs)) > 1:
        errors.append(f"Line 0: declares the addresses {min(addrs)} and {max(addrs)}")
    if name_word[:1] == '"' and not (name_word.isascii() and name_word.isprintable()):
        errors.append("Line 0: unexpected character")
    return agree, no_number


def cand_front2(secs):
    count = 0
    errors = pilot3.Capped()
    for sec in objects(secs):
        kind = sec["name"]
        words = section_words(sec)
        name, lid, header, rest = tag_header(kind, words)
        tag = {"name": name, "description": lid}
        if kind == "MEASUREMENT":
            parts = " ".join(header).split(" ")
            tag["datatype"] = parts[0] if parts and parts[0] else None
        elif len(header) == 7:
            tag["char_type"] = header[0]
            tag["address"] = number_word(header[1])
        kws = keyword_lines2(words, rest, errors)
        field_loop([t for t, _ in kws], tag)
        tag["_agree"] = tag_rules(kind, header, kws, words[0][0] if words else "", errors)
        for ch in sec["children"]:
            if ch["name"] == "AXIS_DESCR":
                errs: list = []
                toks = [w for _, c in pilot3.lex_lines("\\n".join([ch["meta"]] + ch["lines"]), errs)
                        for w in pilot3.line_words(c)]
                tag.setdefault("axis", []).append(toks[3] if len(toks) > 3 else None)
        count += 1
    return count, len(errors), errors.dropped


def base_front(a, secs):''')

sub('''    if mode in ("baseTree", "baseFull", "cand"):
        res = pilot2.one(mode, repo, f)
        res.pop("file", None)
        return res''', '''    if mode in ("baseTree", "baseFull", "cand"):
        res = pilot2.one(mode, repo, f)
        res.pop("file", None)
        return res
    if mode == "cand3":
        t0 = time.perf_counter()
        secs, errs = pilot3.build(f)
        dt = time.perf_counter() - t0
        objs, total = pilot3.count(secs)
        res = {"mode": mode, "s": round(dt, 3), "objects": objs, "sections": total, "errors": list(errs)[:2],
               "named_meta_filled": sum(1 for s in _all(secs) if s.get("meta_line") is not None)}
        res["maxrss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
        return res
    if mode == "candFront2":
        secs, _ = pilot3.build(f)
        t0 = time.perf_counter()
        n, ne, nd = cand_front2(secs)
        dt = time.perf_counter() - t0
        res = {"mode": mode, "front_s": round(dt, 3), "objects": n, "tag_errors_kept": ne, "tag_errors_dropped": nd}
        res["maxrss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
        return res''')

sub('''def drive(repo: Path, runs: int, files: list) -> int:
    modes = ("baseTree", "baseFull", "cand", "baseFront", "candFront")''', '''def _all(secs):
    stack = list(secs)
    while stack:
        s = stack.pop()
        yield s
        stack.extend(s["children"])


def drive(repo: Path, runs: int, files: list) -> int:
    modes = ("baseTree", "baseFull", "cand", "cand3", "baseFront", "candFront", "candFront2")''')

sub('''        med = {m: statistics.median(x["s"] for x in rows[m]) for m in ("baseTree", "baseFull", "cand")}
        fr = {m: statistics.median(x["front_s"] for x in rows[m]) for m in ("baseFront", "candFront")}''', '''        med = {m: statistics.median(x["s"] for x in rows[m]) for m in ("baseTree", "baseFull", "cand", "cand3")}
        fr = {m: statistics.median(x["front_s"] for x in rows[m]) for m in ("baseFront", "candFront", "candFront2")}
        rss = {m: statistics.median(x["maxrss_mb"] for x in rows[m]) for m in modes}''')

sub('''        print(f"[E3 model] {f.name}: E2 projection - baseFront + candFront = {model:.3f} s = "
              f"{model / med['baseFull']:.2f} x base parse (bound 1.50; bound time {1.5 * med['baseFull']:.3f} s)")''', '''        print(f"[E3 model] {f.name}: E2 projection - baseFront + candFront = {model:.3f} s = "
              f"{model / med['baseFull']:.2f} x base parse (bound 1.50; bound time {1.5 * med['baseFull']:.3f} s)")
        model2 = med["cand3"] + rest - fr["baseFront"] + fr["candFront2"]
        print(f"[E3 round-2 model] {f.name}: cand3 {med['cand3']} (cand {med['cand']}, +{med['cand3'] - med['cand']:.3f}); "
              f"candFront2 {fr['candFront2']} (candFront {fr['candFront']}, +{fr['candFront2'] - fr['candFront']:.3f}); "
              f"cand3 + (baseFull - baseTree) - baseFront + candFront2 = {model2:.3f} s = "
              f"{model2 / med['baseFull']:.2f} x base parse (bound 1.50; bound time {1.5 * med['baseFull']:.3f} s)")
        print(f"[maxrss median MB] {f.name}: " + ", ".join(f"{m} {rss[m]}" for m in modes))''')

(HERE / "e3a2-time.py").write_text(doc + body, encoding="utf-8")
print("ok")
