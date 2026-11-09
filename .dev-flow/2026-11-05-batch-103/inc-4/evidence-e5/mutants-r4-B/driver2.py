#!/usr/bin/env python3
"""E5 mutant unit B (round 4) driver v2 — runs on <runner> only.

Same mutants as driver.py, but edits ONE working copy in place (on the root
fs, which has room) instead of copytree-per-mutant (which filled the 16 GiB
/tmp tmpfs). BASE stays pristine/read-only in /tmp; per mutant the single
label_match.py is restored from BASE, edited, the row's tests run, and the
unified diff + pytest tail saved to OUT. Resumable: skips non-empty evidence.
"""
import os
import shutil
import subprocess

BASE = "/tmp/b103-e5-4-mutr4B/base"
WORK = "/home/<user>/mutr4B-work"
OUT = "/tmp/b103-e5-4-mutr4B/out"
PY = os.path.expanduser("~/miniconda3/envs/s19ci/bin/python")
ISO = "/home/<user>/mutr4B-iso"
LABEL = "s19_app/tui/services/label_match.py"
BEH = "tests/test_b103_label_match.py"
PERF = "tests/test_b103_label_match_perf.py"


def env():
    e = dict(os.environ)
    e["HOME"] = ISO
    e["XDG_CACHE_HOME"] = ISO + "/.cache"
    e["XDG_CONFIG_HOME"] = ISO + "/.config"
    e["XDG_DATA_HOME"] = ISO + "/.local/share"
    e["LOCALAPPDATA"] = ISO + "/.local"
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    return e


MUTANTS = [
    # --- behaviour rows .21 .. .43 ---
    ("M-21", BEH, "R-A2L-MATCH.21", False, [
        ("""        key = 1
        name_folded = folded[i]
        p = name_folded.find(text)
        while p >= 0:
            if _at_boundary(names[i], p):
                key = 0
                break
            p = name_folded.find(text, p + 1)
        add_group(MatchRule.SUBSTRING, key, i)""",
         """        key = 1
        add_group(MatchRule.SUBSTRING, key, i)"""),
    ]),
    ("M-22", BEH, "R-A2L-MATCH.22", False, [
        ("add_group(MatchRule.FUZZY, total, name_id)",
         "add_group(MatchRule.FUZZY, 0, name_id)"),
    ]),
    ("M-23", BEH, "R-A2L-MATCH.23 or rows_23", False, [
        ("    return (_RULE_RANK[rule], key, len(name), 0 if case_exact else 1, name)",
         "    return (_RULE_RANK[rule], key, 0, 0 if case_exact else 1, name)"),
    ]),
    ("M-23b", BEH, "R-A2L-MATCH.23 or rows_23", False, [
        ("    return (_RULE_RANK[rule], key, len(name), 0 if case_exact else 1, name)",
         "    return (_RULE_RANK[rule], key, 0 if case_exact else 1, len(name), name)"),
        ("_order_key(rule, key, index.names[name_id], False)[:3]",
         "_order_key(rule, key, index.names[name_id], False)[:2]"),
        ("_order_key(rule, group_key[1], name, case_exact)[3:]",
         "_order_key(rule, group_key[1], name, case_exact)[2:]"),
    ]),
    ("M-24", BEH, "R-A2L-MATCH.24 or rows_24", False, [
        ("""            if rule is MatchRule.EXACT:
                case_exact = name == raw
            elif rule is MatchRule.PREFIX:
                case_exact = name.startswith(raw)
            elif rule is MatchRule.SUBSTRING:
                case_exact = raw in name
            else:
                case_exact = False""",
         """            case_exact = False"""),
    ]),
    ("M-24b", BEH, "R-A2L-MATCH.24 or rows_24", False, [
        ("""            elif rule is MatchRule.SUBSTRING:
                case_exact = raw in name""",
         """            elif rule is MatchRule.SUBSTRING:
                p = name.find(raw)
                case_exact = p >= 0 and _at_boundary(name, p)"""),
    ]),
    ("M-25", BEH, "R-A2L-MATCH.25 or rows_25", False, [
        ("    return (_RULE_RANK[rule], key, len(name), 0 if case_exact else 1, name)",
         "    return (_RULE_RANK[rule], key, len(name), 0 if case_exact else 1)"),
    ]),
    ("M-26", BEH, "rows_26", False, [
        ("    if rule is MatchRule.EXACT:\n        return ((0, len(name)),)",
         "    if rule is MatchRule.EXACT:\n        return ()"),
    ]),
    ("M-27", BEH, "rows_27", False, [
        ("    if rule is MatchRule.PREFIX:\n        return ((0, len(text)),)",
         "    if rule is MatchRule.PREFIX:\n        return ((0, len(name)),)"),
    ]),
    ("M-28", BEH, "R-A2L-MATCH.28 or rows_28", False, [
        ("""        span = (p, p + len(text))
        cursor = p
        while cursor >= 0:
            if _at_boundary(name, cursor):
                span = (cursor, cursor + len(text))
                break
            cursor = folded.find(text, cursor + 1)
        return (span,)""",
         """        return ((p, p + len(text)),)"""),
    ]),
    ("M-29", BEH, "rows_29", False, [
        ("""        span = (p, p + len(text))
        cursor = p
        while cursor >= 0:
            if _at_boundary(name, cursor):
                span = (cursor, cursor + len(text))
                break
            cursor = folded.find(text, cursor + 1)
        return (span,)""",
         """        cursor = p
        while cursor >= 0:
            if _at_boundary(name, cursor):
                return ((cursor, cursor + len(text)),)
            cursor = folded.find(text, cursor + 1)
        return ()"""),
    ]),
    ("M-30", BEH, "rows_30", False, [
        ("match_span = (start, start + len(query_token))",
         "match_span = (start, end)"),
    ]),
    ("M-31", BEH, "rows_31", False, [
        ("        found = text.find(ch, pos)",
         "        found = text.rfind(ch, pos)"),
    ]),
    ("M-32", BEH, "R-A2L-MATCH.32 or rows_32", False, [
        ("            fuzzy_spans.append(name_spans[best_pos])",
         "            fuzzy_spans.append(\n                (name_spans[best_pos][0], name_spans[best_pos][0] + len(query_token))\n            )"),
    ]),
    ("M-33", BEH, "R-A2L-MATCH.33 or rows_33", False, [
        ("                    edits=group_key[1] if rule is MatchRule.FUZZY else 0,",
         "                    edits=0,"),
    ]),
    ("M-33b", BEH, "R-A2L-MATCH.33 or rows_33", False, [
        ("""                name_id: totals.get(name_id, 0)
                + sum(weight * counter[name_id] for weight, counter in weights.items())""",
         """                name_id: max(
                    totals.get(name_id, 0),
                    sum(weight * counter[name_id] for weight, counter in weights.items()),
                )"""),
    ]),
    ("M-34", BEH, "R-A2L-MATCH.34 or rows_34", False, [
        ("    ordered = sorted(spans)", "    ordered = list(spans)"),
    ]),
    ("M-34b", BEH, "R-A2L-MATCH.34 or rows_34", False, [
        ("        if start <= prev_end:", "        if start < prev_end:"),
    ]),
    ("M-38", BEH, "R-A2L-MATCH.38", False, [
        ("    if len(raw) > 256:", "    if len(raw) > 10**9:"),
    ]),
    ("M-39", BEH, "R-A2L-MATCH.39", False, [
        ("        if len(name) > 1024 or not name.isascii():",
         "        if len(name) > 10**9 or not name.isascii():"),
    ]),
    ("M-41", BEH, "R-A2L-MATCH.41 or a2l_match_41", False, [
        ("    if len(counts) > _FUZZY_TOKEN_CAP:\n        return {}, {}\n", ""),
    ]),
    ("M-41b", BEH, "R-A2L-MATCH.41 or a2l_match_41", False, [
        ("    if len(counts) > _FUZZY_TOKEN_CAP:", "    if len(query.tokens) > _FUZZY_TOKEN_CAP:"),
    ]),
    ("M-43", BEH, "R-A2L-MATCH.43 or rows_43", False, [
        ("        if len(name) > 1024 or not name.isascii():",
         "        if len(name) > 1024:"),
    ]),
    # --- perf rows .35 / .36 / .37 / .40 / .42 ---
    ("M-35", PERF, "a2l_match_35", True, [
        ("""    tokens = tuple(sorted(distinct))
    del distinct
    find = bisect_left""",
         """    tokens = tuple(sorted(distinct))
    del distinct
    _sub = tokens[:6000]
    for _a in _sub:
        for _b in _sub:
            _prefix_distance(_a, _b, 2)
    find = bisect_left"""),
    ]),
    ("M-36a", PERF, "a2l_match_36", True, [
        ("""    if limit < 1:
        return []
    raw = query.strip(_WHITESPACE)""",
         """    if limit < 1:
        return []
    index = build_label_index(index.names)
    raw = query.strip(_WHITESPACE)"""),
    ]),
    ("M-36b", PERF, "a2l_match_36", True, [
        ("""    if allowed == 0:
        lo, hi = _token_range(index._tokens, query_token)
        return ([(lo, hi, 0)] if lo < hi else []), 0""",
         """    if True:
        out = []
        for _tid, _tok in enumerate(index._tokens):
            _d = _prefix_distance(query_token, _tok, allowed)
            if _d <= allowed:
                out.append((_tid, _tid + 1, _d))
        return out, len(index._tokens)"""),
    ]),
    ("M-36d", PERF, "a2l_match_36", True, [
        ("_FUZZY_SWITCH_CAP = 512", "_FUZZY_SWITCH_CAP = -1"),
    ]),
    ("M-37", PERF, "a2l_match_37", True, [
        ("    del span_start, span_end\n", """    del span_start, span_end

    _trie = {}
    for _tok in tokens:
        _node = _trie
        for _ch in _tok:
            _node = _node.setdefault(_ch, {})
    _per_name_tokens = tuple(
        tuple(tokens[tid] for tid in name_token_ids[name_token_starts[i]:name_token_starts[i + 1]])
        for i in range(count)
    )
"""),
    ]),
    ("M-37b", PERF, "a2l_match_37", True, [
        ("""    tokens = tuple(sorted(distinct))
    del distinct
    find = bisect_left
    name_token_ids = array("I", [0]) * len(span_start)
    for i in range(count):
        text = folded[i]
        for j in range(name_token_starts[i], name_token_starts[i + 1]):
            name_token_ids[j] = find(tokens, text[span_start[j]:span_end[j]])
    del span_start, span_end""",
         """    tokens = tuple(sorted(distinct))
    del distinct
    token_to_id = {tok: tid for tid, tok in enumerate(tokens)}
    name_token_ids = array("I", [0]) * len(span_start)
    for i in range(count):
        text = folded[i]
        for j in range(name_token_starts[i], name_token_starts[i + 1]):
            name_token_ids[j] = token_to_id[text[span_start[j]:span_end[j]]]
    del span_start, span_end"""),
    ]),
    ("M-40a", PERF, "a2l_match_40", True, [
        ("""        if (
            not switched
            and candidates is not None
            and len(candidates) <= _FUZZY_SWITCH_CAP
            and sum(starts[n + 1] - starts[n] for n in candidates)
            <= _FUZZY_SWITCH_CAP
        ):
            switched = True""",
         """        if (
            not switched
            and candidates is not None
            and len(candidates) <= _FUZZY_SWITCH_CAP
        ):
            switched = True"""),
    ]),
    ("M-40b", PERF, "a2l_match_40", True, [
        ("_FUZZY_NODE_BUDGET = 400_000", "_FUZZY_NODE_BUDGET = 10**12"),
    ]),
    ("M-42", PERF, "a2l_match_42", True, [
        ("_FUZZY_NODE_BUDGET = 400_000", "_FUZZY_NODE_BUDGET = 10**12"),
    ]),
]


def restore_and_edit(edits):
    shutil.copyfile(os.path.join(BASE, LABEL), os.path.join(WORK, LABEL))
    path = os.path.join(WORK, LABEL)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for old, new in edits:
        n = text.count(old)
        if n != 1:
            raise RuntimeError(f"edit not unique/absent (count={n}): {old[:80]!r}")
        text = text.replace(old, new)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def run_one(mid, test_file, kexpr, perf, edits):
    out_path = os.path.join(OUT, mid + ".txt")
    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        print(f"skip {mid} (exists)", flush=True)
        return
    restore_and_edit(edits)

    modfile = subprocess.run(
        [PY, "-c", "import s19_app, os; print(os.path.abspath(s19_app.__file__))"],
        cwd=WORK, env=env(), capture_output=True, text=True, timeout=120,
    ).stdout.strip() or "s19_app.__file__: ?"

    diff = subprocess.run(
        ["diff", "-u", os.path.join(BASE, LABEL), os.path.join(WORK, LABEL)],
        capture_output=True, text=True,
    ).stdout or "(no diff)"

    parts = [f"=== s19_app.__file__ ===\n{modfile}\n", f"=== DIFF base -> {mid} ({LABEL}) ===\n{diff}"]

    cmd = [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_file, "-k", kexpr]
    up = []
    if perf:
        up.append(("uptime before", subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()))
    proc = subprocess.run(cmd, cwd=WORK, env=env(), capture_output=True, text=True, timeout=7200)
    if perf:
        up.append(("uptime after", subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()))
    for label, line in up:
        parts.append(f"=== {label} ===\n{line}\n")

    tail = "\n".join((proc.stdout or "").splitlines()[-160:])
    if proc.stderr:
        tail += "\n--- stderr ---\n" + "\n".join(proc.stderr.splitlines()[-40:])
    parts.append(f"=== PYTEST (tail, rc={proc.returncode}) ===\n{tail}\n")

    os.makedirs(OUT, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    print(f"done {mid} rc={proc.returncode}", flush=True)


def main():
    os.makedirs(ISO, exist_ok=True)
    for mid, test_file, kexpr, perf, edits in MUTANTS:
        try:
            run_one(mid, test_file, kexpr, perf, edits)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR {mid}: {exc}", flush=True)
            os.makedirs(OUT, exist_ok=True)
            with open(os.path.join(OUT, mid + ".txt"), "w", encoding="utf-8") as f:
                f.write(f"ERROR: {exc}\n")
    print("ALL DONE", flush=True)


if __name__ == "__main__":
    main()
