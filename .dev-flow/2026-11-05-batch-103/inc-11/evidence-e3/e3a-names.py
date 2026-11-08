"""Inc 11 E3 architect (batch-103): where do section names stand? Run on <runner> only.

    python -I e3a-names.py <repo> <files_dir> <manifest.tsv>

For every file of the public corpus manifest (sha256 checked first; files untrusted and read-only; nothing copied) and
for the 35 tracked fixtures, the e07fb00 section tree (build_section_tree) is walked and, per section kind, the sections
whose /begin line holds no own word are counted: the base `meta` with its comments removed (the e07fb00
_strip_a2l_comments, which keeps no word break, is enough to tell empty from not empty) is empty. After Inc 11 the
graph's canonical `meta` is the same words (DE-3), so every reader that names a section by parse_begin_meta(meta)
(extract_record_layouts, extract_compu_methods, extract_compu_tables, the AXIS_DESCR capture, Inc 2a's walk) still
names these sections UNKNOWN, while the tag reader (_tag_header) names MEASUREMENT and CHARACTERISTIC by their first
own word. Prints counts only (kind, files, sections); no file text, no names.
"""
import collections, hashlib, pathlib, subprocess, sys

repo = pathlib.Path(sys.argv[1]); fdir = pathlib.Path(sys.argv[2]); manifest = pathlib.Path(sys.argv[3])
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__)
KINDS = ("MEASUREMENT", "CHARACTERISTIC", "AXIS_PTS", "RECORD_LAYOUT", "COMPU_METHOD", "COMPU_TAB", "COMPU_VTAB",
         "COMPU_VTAB_RANGE", "FUNCTION", "GROUP", "TYPEDEF_MEASUREMENT", "TYPEDEF_CHARACTERISTIC", "INSTANCE", "BLOB",
         "MEMORY_SEGMENT", "UNIT")


def scan(path):
    secs, _ = a.build_section_tree(path)
    c = collections.Counter()
    stack = list(secs)
    while stack:
        s = stack.pop()
        k = s.get("name")
        if k in KINDS:
            c[k + ":all"] += 1
            if not a._strip_a2l_comments(s.get("meta") or "").strip():
                c[k + ":empty_meta"] += 1
        stack.extend(s.get("children") or [])
    return c


def report(label, rows):
    tot = collections.Counter()
    files_with = collections.Counter()
    for _, c in rows:
        tot.update(c)
        for k, v in c.items():
            if k.endswith(":empty_meta") and v:
                files_with[k] += 1
    print(f"[{label}] files={len(rows)}")
    for k in KINDS:
        al, em = tot[k + ":all"], tot[k + ":empty_meta"]
        if al:
            print(f"[{label}] {k}: sections {al}, name not on the /begin line {em} ({100.0 * em / al:.1f} %), "
                  f"in {files_with[k + ':empty_meta']} files")
    both = sum(1 for _, c in rows if (c["MEASUREMENT:empty_meta"] + c["CHARACTERISTIC:empty_meta"])
               and (c["RECORD_LAYOUT:empty_meta"] + c["COMPU_METHOD:empty_meta"]))
    print(f"[{label}] files with an object AND a RECORD_LAYOUT or COMPU_METHOD named on a later line: {both}")


rows = []
seen = set()
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
    rows.append((n, scan(p)))
report("corpus", rows)
tracked = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True,
                         check=True).stdout.split()
report("tracked", [(f, scan(repo / f)) for f in tracked])
