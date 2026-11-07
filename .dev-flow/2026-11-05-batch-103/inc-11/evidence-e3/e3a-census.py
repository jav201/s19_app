"""Inc 11 E3 architect (batch-103): two read-only censuses of the 35 tracked A2L files, run on <runner> only.

    python -I e3a-census.py <repo> <scratch> sizes     the size keywords of every MEASUREMENT / CHARACTERISTIC
    python -I e3a-census.py <repo> <scratch> issues    the Issues screen's A2L codes, e07fb00 vs projected

Both read the files through the E1 census's own reference reading (evidence-e1/e1-census.py, copied beside this script
as e1census.py and loaded without its mode dispatch): ref_lex / ref_tree / split_header / canon. Nothing is written to
the repo; temporary files go to <scratch>.

sizes:  for each object, the size keywords among its own words after its header (LENGTH, DATA_SIZE, MATRIX_DIM with 1
  to 3 number words, NUMBER, ARRAY_SIZE), each turned into bytes: LENGTH / DATA_SIZE as written; MATRIX_DIM, NUMBER and
  ARRAY_SIZE x the element size (MEASUREMENT: its header datatype; CHARACTERISTIC: the FNC_VALUES datatype of its record
  layout, else the datatype its deposit name spells as __<DT>_Z). Counts the objects with 2 or more size keywords, those
  whose sizes disagree, and the e07fb00 length of each such tag (the orchestrator's E1-addendum ruling: disagreeing size
  keywords give no length). Also every object with ARRAY_SIZE (R-A2L-014 reads MATRIX_DIM only).
issues: the e07fb00 reader on the file and on CANON(file) (E1's projection of the fixed tree), each through
  validate_a2l_internal_issues; the code counts and the messages that appear or go.
"""
import collections, pathlib, re, subprocess, sys

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2]); MODE = sys.argv[3]
scratch.mkdir(parents=True, exist_ok=True)
src = (pathlib.Path(__file__).resolve().parent / "e1census.py").read_text(encoding="utf-8")
src = src[: src.index('if mode in ("chars", "fixtures"):')]
ns = {"__name__": "e1census"}
sys.argv = [sys.argv[0], str(repo), str(scratch), "lib"]
exec(compile(src, "e1census.py", "exec"), ns)
a = ns["a"]
ref_lex, ref_tree, own, walk_ref, split_header, canon, read_text = (
    ns[k] for k in ("ref_lex", "ref_tree", "own", "walk_ref", "split_header", "canon", "read_text"))
SIZES = a.DATATYPE_SIZES
NUM = re.compile(r"0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,20}")


def num(w):
    return (int(w, 16) if w[:2] in ("0x", "0X") else int(w, 10)) if w.isascii() and NUM.fullmatch(w) else None


files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True,
                       check=True).stdout.split()
if MODE == "sizes-corpus":
    # the public corpus (untrusted, read-only): <scratch>/../corpus.lst holds "<sha256> <path>" per line, checked here
    import hashlib
    files = []
    for ln in (pathlib.Path(sys.argv[4]) if len(sys.argv) > 4 else scratch / "corpus.lst").read_text().splitlines():
        sha, path = ln.split(" ", 1)
        if hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() == sha:
            files.append(path)
        else:
            print("[skip] sha256 mismatch", pathlib.Path(path).name)
    repo_files = files
print("mode =", MODE, "| files =", len(files))


def layouts_of(root):
    out = {}
    for n in walk_ref(root):
        if n["name"] == "RECORD_LAYOUT":
            t = [x[1] for x in own(n)]
            if not t:
                continue
            dt = None
            for i, w in enumerate(t):
                if w == "FNC_VALUES" and i + 2 < len(t):
                    dt = t[i + 2]
                    break
            out.setdefault(t[0], dt)
    return out


def elem_size(node, pos, layouts):
    if node["name"] == "MEASUREMENT":
        return SIZES.get(pos[0]) if pos else None
    if len(pos) < 3:
        return None
    dep = pos[2]
    dt = layouts.get(dep)
    if dt in SIZES:
        return SIZES[dt]
    up = dep.upper()
    for d in SIZES:
        if f"__{d}_Z" in up:
            return SIZES[d]
    return None


def sizes_mode():
    tot = collections.Counter()
    shown = 0
    for f in files:
        p = repo / f
        text = p.read_bytes().decode("utf-8", errors="replace")
        toks, _ = ref_lex(text)
        root, _ = ref_tree(toks)
        layouts = layouts_of(root)
        base = {}
        if MODE == "sizes" or p.stat().st_size < 4_000_000:
            for t in a.parse_a2l_file(p)["tags"]:
                base.setdefault((t["section"], t["name"]), t)
        if MODE != "sizes":
            f = p.name
        fc = collections.Counter()
        for n in walk_ref(root):
            if n["name"] not in ("MEASUREMENT", "CHARACTERISTIC"):
                continue
            head, pos, rest = split_header(n)
            words = [x for x in own(n)][rest:]
            kws = {}
            i = 0
            while i < len(words):
                kind, w, _ = words[i]
                if kind == "ID" and w == "MATRIX_DIM":
                    args = []
                    j = i + 1
                    while j < len(words) and len(args) < 3 and num(words[j][1]) is not None:
                        args.append(num(words[j][1])); j += 1
                    kws["MATRIX_DIM"] = args
                    i = j; continue
                if kind == "ID" and w in ("LENGTH", "DATA_SIZE", "NUMBER", "ARRAY_SIZE") and i + 1 < len(words):
                    kws[w] = num(words[i + 1][1]); i += 2; continue
                i += 1
            name = head[0][1] if head else "?"
            kind_c = pos[0][1] if (n["name"] == "CHARACTERISTIC" and pos) else n["name"]
            es = elem_size(n, [x[1] for x in pos], layouts)
            sz = {}
            for k, v in kws.items():
                if k in ("LENGTH", "DATA_SIZE"):
                    sz[k] = v
                elif k == "MATRIX_DIM":
                    prod = 1
                    for x in v:
                        prod *= x
                    sz[k] = prod * es if (v and es) else None
                else:
                    sz[k] = v * es if (v is not None and es) else None
            bt = base.get((n["name"], name))
            blen = bt.get("length") if bt else "no-tag"
            if "ARRAY_SIZE" in kws:
                fc["array_size"] += 1
                if "MATRIX_DIM" not in kws:
                    fc["array_size_without_matrix_dim"] += 1
                if shown < 40 and MODE == "sizes":
                    print(f"[AS] {f} {n['name']} {kind_c} {name}: ARRAY_SIZE {kws['ARRAY_SIZE']} elem {es} -> {sz.get('ARRAY_SIZE')}; "
                          f"MATRIX_DIM {kws.get('MATRIX_DIM')}; e07fb00 length {blen}"); shown += 1
            if len(kws) >= 2:
                fc["multi"] += 1
                vals = set(sz.values())
                key = "+".join(sorted(kws))
                fc["multi:" + kind_c + ":" + key] += 1
                if len(vals) > 1 or None in vals:
                    fc["disagree_or_unknown"] += 1
                    fc["disagree:" + kind_c + ":" + key] += 1
                    if blen not in (None, "no-tag"):
                        fc["disagree_with_base_length"] += 1
                    if shown < 25:
                        print(f"[DIS] {f} {n['name']} {kind_c} {name}: {kws} -> bytes {sz}; e07fb00 length {blen}"); shown += 1
        if fc:
            print(f"[file] {f}: " + ", ".join(f"{k}={v}" for k, v in sorted(fc.items())))
        tot.update(fc)
    print("[total] " + ", ".join(f"{k}={v}" for k, v in sorted(tot.items())))


def issues_mode():
    tot_b, tot_p = collections.Counter(), collections.Counter()
    for f in files:
        p = repo / f
        text = p.read_bytes().decode("utf-8", errors="replace")
        raw = a.parse_a2l_file(p)
        can_text, diags, _ = canon(text)
        can = read_text(can_text, scratch, fname="canon.a2l")
        ib = a.validate_a2l_internal_issues(raw)
        ip = a.validate_a2l_internal_issues(can)
        cb = collections.Counter(i.code for i in ib)
        cp = collections.Counter(i.code for i in ip)
        tot_b.update(cb); tot_p.update(cp)
        if cb != cp or diags:
            mb = collections.Counter((i.code, i.message) for i in ib)
            mp = collections.Counter((i.code, i.message) for i in ip)
            gone = list((mb - mp).elements()); came = list((mp - mb).elements())
            print(f"[file] {f}: e07fb00 {dict(sorted(cb.items()))} | projected {dict(sorted(cp.items()))} | REF diags {diags[:3]}")
            for c, m in gone[:6]:
                print(f"    gone  {c}: {m[:110]}")
            if len(gone) > 6:
                print(f"    gone  … {len(gone) - 6} more")
            for c, m in came[:6]:
                print(f"    came  {c}: {m[:110]}")
            if len(came) > 6:
                print(f"    came  … {len(came) - 6} more")
    print(f"[total] e07fb00 {dict(sorted(tot_b.items()))}")
    print(f"[total] projected {dict(sorted(tot_p.items()))}")


(sizes_mode if MODE.startswith("sizes") else issues_mode)()
