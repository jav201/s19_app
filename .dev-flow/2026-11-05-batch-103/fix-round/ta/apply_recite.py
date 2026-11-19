#!/usr/bin/env python
"""Apply recite-map.tsv (U1-recite): rewrite dead test citations to canon rows (docstrings/comments only; stdlib)."""
import argparse
import ast
import csv
import os
import re
import sys
from collections import Counter

CANON_RE = re.compile(r"^\| ((?:R|US)-[^ |]+) \|")
QUOTE_RE = re.compile(r"""(?:[rR])?(?:\"\"\"|''')""")
TRACES = "Traces:"

def fail(code, msg):
    sys.stderr.write("recite: " + msg + "\n")
    sys.exit(code)

def token_re(id_):
    return re.compile(
        r"(?<![A-Za-z0-9_.-])" + re.escape(id_) + r"(?![A-Za-z0-9_]|[.-][A-Za-z0-9]|/)"
    )

def case_re(id_):
    return re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(id_) + r"(?=/)")

def split_ids(cell):
    return [p.strip() for p in cell.split(";") if p.strip()]

def canon_set(repo):
    lines = open(os.path.join(repo, "REQUIREMENTS.md"), encoding="utf-8", newline="").read().split("\n")
    s02 = next(i for i, l in enumerate(lines) if l.startswith("#### S0.2 "))
    nxt = next(i for i in range(s02 + 1, len(lines)) if lines[i].startswith("#### "))
    ids = set()
    for i, l in enumerate(lines):
        if not (s02 <= i < nxt):
            m = CANON_RE.match(l)
            if m:
                ids.add(m.group(1))
    return ids

def find_func(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None

def docstring_of(node):
    b = node.body
    if b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant) \
       and isinstance(b[0].value.value, str):
        return b[0].value
    return None

def strip_docstrings(tree):
    for node in list(ast.walk(tree)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            b = node.body
            if b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant) \
               and isinstance(b[0].value.value, str):
                b.pop(0)
    return tree

def anchor_of(node):
    return node.decorator_list[0].lineno if node.decorator_list else node.lineno

def comment_block_start(lines, anchor):
    i = anchor - 1
    while i >= 1 and lines[i - 1].strip().startswith("#"):
        i -= 1
    return i + 1

def quote_style(lines, doc):
    m = QUOTE_RE.match(lines[doc.lineno - 1][doc.col_offset:])
    if not m:
        fail(2, "docstring quote not recognised")
    return m.group(0)[-3:]

def traces_text(ids):
    return TRACES + " " + ", ".join(ids) + "."

def doc_case(node, lines):
    first = node.body[0]
    if isinstance(first, ast.Expr):
        v = first.value
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            if v.lineno == v.end_lineno:
                return ("c", v, None)
            if lines[v.end_lineno - 1].strip() in ('"""', "'''"):
                return ("a", v, None)
            return ("b", v, None)
        if isinstance(v, ast.JoinedStr) or (isinstance(v, ast.Constant) and isinstance(v.value, bytes)):
            fail(2, "non-plain-str docstring (f-string or bytes)")
    return ("d", None, first)

def read_file(repo, path):
    text = open(os.path.join(repo, path), encoding="utf-8", newline="").read()
    if "\r" in text:
        fail(2, path + ": holds CR bytes")
    if text.startswith("\ufeff"):
        fail(2, path + ": holds BOM")
    lines = text.split("\n")
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        fail(2, path + ": does not parse: " + str(exc))
    return text, lines, tree

def comment_location_ok(lines, anchor, node, where, line_no, line, mstart):
    ok = (anchor - line_no) <= 30 if where == "banner" \
        else comment_block_start(lines, anchor) <= line_no <= node.end_lineno
    h = line.find("#")
    return ok and h != -1 and h <= mstart

def region_text(lines, node, where):
    if where == "doc":
        ds = docstring_of(node)
        return "" if ds is None else "\n".join(lines[ds.lineno - 1:ds.end_lineno])
    anchor = anchor_of(node)
    if where == "banner":
        return "\n".join(lines[max(0, anchor - 31):anchor - 1])
    return "\n".join(lines[comment_block_start(lines, anchor) - 1:node.end_lineno])

def replace_rows(tree, lines, frows, path):
    content, results = [], {}
    for r in frows:
        if r["action"] != "REPLACE":
            continue
        seq = r["seq"]
        name = r["test"].split("[", 1)[0]
        node = find_func(tree, name)
        if node is None:
            fail(2, f"{seq}: function {name} not in {path}")
        line_no = int(r["edit_at"].rsplit(":", 1)[1])
        line = lines[line_no - 1]
        old = r["old_id"]
        new_ids = split_ids(r["new_ids"])
        tmatch = token_re(old)
        region = region_text(lines, node, r["old_where"])
        if case_re(old).search(region):
            fail(2, f"{seq}: {old} is a case id at {path}:{line_no}")
        matches = list(tmatch.finditer(line))
        if not matches:
            if tmatch.search(region):
                fail(2, f"{seq}: token moved (edit_at stale) for {old} at {path}:{line_no}")
            if all(token_re(n).search(region) for n in new_ids):
                results[seq] = ("already", f"{path}:{line_no}")
                continue
            fail(2, f"{seq}: no token match for {old} at {path}:{line_no}")
        if r["old_where"] == "doc":
            ds = docstring_of(node)
            if ds is None or not (ds.lineno <= line_no <= ds.end_lineno):
                fail(2, f"{seq}: line {line_no} not in docstring of {name}")
        elif not comment_location_ok(lines, anchor_of(node), node, r["old_where"],
                                     line_no, line, matches[0].start()):
            fail(2, f"{seq}: line {line_no} not a comment of {name}")
        if not line.strip().startswith(r["line_excerpt"][:40]):
            fail(2, f"{seq}: drift at {path}:{line_no}")
        content.append((line_no - 1, tmatch.sub(", ".join(new_ids), line)))
        results[seq] = ("applied", f"{path}:{line_no}")
    return content, results

def add_one(lines, node, case, ds, first_body, planned):
    if case == "a":
        last_idx = ds.end_lineno - 1
        closing = lines[last_idx]
        indent = closing[: len(closing) - len(closing.lstrip())]
        ins = [] if lines[last_idx - 1].strip() == "" else [""]
        ins.append(indent + planned)
        return [], (last_idx, ins, len(ins) - 1)
    if case in ("b", "c"):
        last_idx = ds.end_lineno - 1
        quote = quote_style(lines, ds)
        content = (last_idx, lines[last_idx][: ds.end_col_offset - len(quote)])
        indent = " " * ds.col_offset
        return [content], (last_idx + 1, ["", indent + planned, indent + quote], 1)
    if first_body.lineno == node.lineno:
        fail(2, f"add {node.name}: first body statement on the def line")
    c = first_body.col_offset
    return [], (first_body.lineno - 1, [" " * c + '"""' + planned + '"""'], 0)

def add_rows(tree, lines, add_groups, path):
    content, insert, results = [], [], {}
    for tname, grp in add_groups.items():
        name = tname.split("[", 1)[0]
        node = find_func(tree, name)
        if node is None:
            fail(2, f"add: function {name} not in {path}")
        ids = []
        for r in grp:
            for nid in split_ids(r["new_ids"]):
                if nid not in ids:
                    ids.append(nid)
        planned = traces_text(ids)
        doc = ast.get_docstring(node, clean=True)
        if doc is not None:
            tlines = [l.strip() for l in doc.splitlines() if l.strip().startswith(TRACES)]
            if tlines:
                if tlines != [planned]:
                    fail(2, f"add {name}: docstring already has a Traces: line")
                for r in grp:
                    results[r["seq"]] = ("already", f"{path}:{node.lineno}")
                continue
        case, ds, first_body = doc_case(node, lines)
        c_extra, entry = add_one(lines, node, case, ds, first_body, planned)
        content += c_extra
        insert.append(entry)
        idx, ins, off = entry
        for r in grp:
            results[r["seq"]] = ("applied", f"{path}:{idx + off + 1}")
    return content, insert, results

def build_plan(repo, rows):
    canon = canon_set(repo)
    bad = [(r["seq"], nid) for r in rows if r["action"] != "NEEDS-RULING"
           for nid in split_ids(r["new_ids"]) if nid not in canon]
    if bad:
        fail(2, "non-canon new_ids: " + "; ".join(f"{s}={i}" for s, i in bad))
    by_file = {}
    for r in rows:
        by_file.setdefault(r["file"], []).append(r)
    plans, results = {}, {}
    for path, frows in by_file.items():
        text, lines, tree = read_file(repo, path)
        content, res = replace_rows(tree, lines, frows, path)
        results.update(res)
        groups = {}
        for r in frows:
            if r["action"] == "ADD":
                groups.setdefault(r["test"], []).append(r)
        c2, ins, res2 = add_rows(tree, lines, groups, path)
        results.update(res2)
        content += c2
        if content or ins:
            plans[path] = {"lines": lines, "content": content, "insert": ins}
    return plans, results

def render(plans):
    out = {}
    for path, plan in plans.items():
        lines = list(plan["lines"])
        for idx, new in plan["content"]:
            lines[idx] = new
        for idx, ins, _off in sorted(plan["insert"], key=lambda t: t[0], reverse=True):
            lines[idx:idx] = ins
        out[path] = "\n".join(lines)
    return out

def verify(plans, rendered, repo):
    for path in plans:
        with open(os.path.join(repo, path), encoding="utf-8", newline="") as fh:
            before = fh.read()
        after = rendered[path]
        try:
            compile(after, path, "exec")
        except SyntaxError as exc:
            fail(3, path + ": result does not compile: " + str(exc))
        if ast.dump(strip_docstrings(ast.parse(before))) != ast.dump(strip_docstrings(ast.parse(after))):
            fail(3, path + ": code changed (stripped ast differs)")

def report(rows, results, nfiles):
    act = Counter(r["action"] for r in rows)
    by_act = {k: Counter() for k in ("REPLACE", "ADD", "NEEDS-RULING")}
    for r in rows:
        by_act[r["action"]][results.get(r["seq"], ("skipped",))[0]] += 1
    print(f"REPLACE rows: {act['REPLACE']} (applied={by_act['REPLACE']['applied']}, already={by_act['REPLACE']['already']})")
    print(f"ADD rows: {act['ADD']} (applied={by_act['ADD']['applied']}, already={by_act['ADD']['already']})")
    print(f"NEEDS-RULING rows: {act.get('NEEDS-RULING', 0)} (skipped={by_act['NEEDS-RULING']['skipped']})")
    print(f"files: {nfiles}")

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--map", default="../in/recite-map.tsv")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--result", default="../scratch/recite-result.tsv")
    a = ap.parse_args(argv)
    with open(a.map, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE))
    if not rows:
        fail(2, "empty map")
    plans, results = build_plan(a.repo, rows)
    rendered = render(plans)
    verify(plans, rendered, a.repo)
    if a.apply:
        for path, text in rendered.items():
            with open(os.path.join(a.repo, path), "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
        outdir = os.path.dirname(a.result) or "."
        os.makedirs(outdir, exist_ok=True)
        with open(a.result, "w", encoding="utf-8", newline="") as fh:
            fh.write("seq\tstatus\tfile:line_after\n")
            for r in rows:
                st, la = results.get(r["seq"], ("skipped", r["edit_at"]))
                fh.write(f"{r['seq']}\t{st}\t{la}\n")
    report(rows, results, len(plans))

if __name__ == "__main__":
    main()
