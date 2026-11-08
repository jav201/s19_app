#!/usr/bin/env python3
"""Build the round-2 E5 mutant-B files for rows R-A2L-MATCH.21..40.

Text-only: reads the base label_match.py, applies one small edit per mutant and
writes mutants/<id>.py plus manifest.txt. Never imports s19_app.
"""
import os
import sys

BASE = "/tmp/b103-e5-4-mutr2B/base/s19_app/tui/services/label_match.py"
OUT = "/tmp/b103-e5-4-mutr2B/mutants"

# Each mutant: id -> list of (old_text, new_text); every old_text must occur
# exactly once in the base.
MUTANTS = {
    # --- .21 key left out (length first) -----------------------------------
    "M-21": [(
        """    for i in subs:
        key = 1
        name_folded = folded[i]
        p = name_folded.find(text)
        while p >= 0:
            if _at_boundary(names[i], p):
                key = 0
                break
            p = name_folded.find(text, p + 1)
        add_group(MatchRule.SUBSTRING, key, i)
        taken.add(i)""",
        """    for i in subs:
        add_group(MatchRule.SUBSTRING, 1, i)
        taken.add(i)""",
    )],
    # --- .22 edits left out (length first) ----------------------------------
    "M-22": [(
        """        for name_id, total in fuzzy.items():
            add_group(MatchRule.FUZZY, total, name_id)""",
        """        for name_id, total in fuzzy.items():
            add_group(MatchRule.FUZZY, 0, name_id)""",
    )],
    # --- .23 length left out ------------------------------------------------
    "M-23": [(
        """    return (_RULE_RANK[rule], key, len(name), 0 if case_exact else 1, name)""",
        """    return (_RULE_RANK[rule], key, 0, 0 if case_exact else 1, name)""",
    )],
    # --- .23b case-exactness before length ----------------------------------
    "M-23b": [
        ("""        groups.setdefault(
            _order_key(rule, key, index.names[name_id], False)[:3], []
        ).append(name_id)""",
         """        groups.setdefault(
            _order_key(rule, key, index.names[name_id], False)[:2], []
        ).append(name_id)"""),
        ("""            keyed.append((_order_key(rule, group_key[1], name, case_exact)[3:], name_id))""",
         """            keyed.append((_order_key(rule, group_key[1], name, case_exact)[2:], name_id))"""),
        ("""    return (_RULE_RANK[rule], key, len(name), 0 if case_exact else 1, name)""",
         """    return (_RULE_RANK[rule], key, 0 if case_exact else 1, len(name), name)"""),
    ],
    # --- .24 case-exactness left out ----------------------------------------
    "M-24": [(
        """            if rule is MatchRule.EXACT:
                case_exact = name == raw
            elif rule is MatchRule.PREFIX:
                case_exact = name.startswith(raw)
            elif rule is MatchRule.SUBSTRING:
                case_exact = raw in name
            else:
                case_exact = False""",
        """            case_exact = False""",
    )],
    # --- .24b substring case-exact only at a boundary offset -----------------
    "M-24b": [(
        """            elif rule is MatchRule.SUBSTRING:
                case_exact = raw in name""",
        """            elif rule is MatchRule.SUBSTRING:
                case_exact = False
                pp = name.find(raw)
                while pp >= 0:
                    if _at_boundary(name, pp):
                        case_exact = True
                        break
                    pp = name.find(raw, pp + 1)""",
    )],
    # --- .25 input order kept (no name key) ---------------------------------
    "M-25": [(
        """    return (_RULE_RANK[rule], key, len(name), 0 if case_exact else 1, name)""",
        """    return (_RULE_RANK[rule], key, len(name), 0 if case_exact else 1)""",
    )],
    # --- .26 no span -> [] ---------------------------------------------------
    "M-26": [(
        """    if rule is MatchRule.EXACT:
        return ((0, len(name)),)""",
        """    if rule is MatchRule.EXACT:
        return ()""",
    )],
    # --- .27 span over the whole name ----------------------------------------
    "M-27": [(
        """    if rule is MatchRule.PREFIX:
        return ((0, len(text)),)""",
        """    if rule is MatchRule.PREFIX:
        return ((0, len(name)),)""",
    )],
    # --- .28 leftmost occurrence regardless of boundaries ---------------------
    "M-28": [(
        """    if rule is MatchRule.SUBSTRING:
        p = folded.find(text)
        if p < 0:
            raise ValueError(f"substring: {name!r} does not meet its tier")
        span = (p, p + len(text))
        cursor = p
        while cursor >= 0:
            if _at_boundary(name, cursor):
                span = (cursor, cursor + len(text))
                break
            cursor = folded.find(text, cursor + 1)
        return (span,)""",
        """    if rule is MatchRule.SUBSTRING:
        p = folded.find(text)
        if p < 0:
            raise ValueError(f"substring: {name!r} does not meet its tier")
        return ((p, p + len(text)),)""",
    )],
    # --- .29 no span when no boundary occurrence ------------------------------
    "M-29": [(
        """    if rule is MatchRule.SUBSTRING:
        p = folded.find(text)
        if p < 0:
            raise ValueError(f"substring: {name!r} does not meet its tier")
        span = (p, p + len(text))
        cursor = p
        while cursor >= 0:
            if _at_boundary(name, cursor):
                span = (cursor, cursor + len(text))
                break
            cursor = folded.find(text, cursor + 1)
        return (span,)""",
        """    if rule is MatchRule.SUBSTRING:
        p = folded.find(text)
        if p < 0:
            raise ValueError(f"substring: {name!r} does not meet its tier")
        span = None
        cursor = p
        while cursor >= 0:
            if _at_boundary(name, cursor):
                span = (cursor, cursor + len(text))
                break
            cursor = folded.find(text, cursor + 1)
        if span is None:
            return ()
        return (span,)""",
    )],
    # --- .30 span over the whole name token -----------------------------------
    "M-30": [(
        """            for start, end in name_spans:
                if folded[start:end].startswith(query_token):
                    match_span = (start, start + len(query_token))
                    break""",
        """            for start, end in name_spans:
                if folded[start:end].startswith(query_token):
                    match_span = (start, end)
                    break""",
    )],
    # --- .31 each key character at its rightmost offset ------------------------
    "M-31": [(
        """    offsets: list[int] = []
    pos = 0
    for ch in keys:
        found = text.find(ch, pos)
        if found < 0:
            return None
        offsets.append(found)
        pos = found + 1
    return tuple(offsets)""",
        """    offsets: list[int] = []
    for ch in keys:
        found = text.rfind(ch)
        if found < 0:
            return None
        offsets.append(found)
    return tuple(offsets)""",
    )],
    # --- .32 span as long as the query token ----------------------------------
    "M-32": [(
        """            for (start, end), token_id in zip(name_spans, token_ids):
                value = table.get(token_id)
                if value is not None and (best is None or value < best):
                    best = value
                    best_span = (start, end)""",
        """            for (start, end), token_id in zip(name_spans, token_ids):
                value = table.get(token_id)
                if value is not None and (best is None or value < best):
                    best = value
                    best_span = (start, start + len(query_token))""",
    )],
    # --- .33 total edits always 0 --------------------------------------------
    "M-33": [(
        """                    edits=group_key[1] if rule is MatchRule.FUZZY else 0,""",
        """                    edits=0,""",
    )],
    # --- .33b the largest edit instead of the sum -----------------------------
    "M-33b": [
        ("""                    totals[name_id] = totals.get(name_id, 0) + best * count""",
         """                    totals[name_id] = max(totals.get(name_id, 0), best * count)"""),
        ("""                totals[name_id] = totals.get(name_id, 0) + d * count""",
         """                totals[name_id] = max(totals.get(name_id, 0), d * count)"""),
    ],
    # --- .34 spans in query-token order ---------------------------------------
    "M-34": [(
        """    ordered = sorted(spans)""",
        """    ordered = list(spans)""",
    )],
    # --- .34b touching spans not joined ---------------------------------------
    "M-34b": [(
        """        if start <= prev_end:""",
        """        if start < prev_end:""",
    )],
    # --- .35 quadratic preparation -------------------------------------------
    "M-35": [(
        """    trie_chars, trie_depth, trie_first, trie_end = _build_trie(tokens)

    return LabelIndex(""",
        """    trie_chars, trie_depth, trie_first, trie_end = _build_trie(tokens)

    # M-35 negative control: quadratic fuzzy distances of every name-token pair
    _ts = tokens[:6000]
    for _i in range(len(_ts)):
        for _j in range(_i + 1, len(_ts)):
            _prefix_distance(_ts[_i], _ts[_j], 2)

    return LabelIndex(""",
    )],
    # --- .36a no preparation (re-read the names) ------------------------------
    "M-36a": [(
        """    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError(f"limit must be int, got {type(limit).__name__}")
    if limit < 1:""",
        """    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError(f"limit must be int, got {type(limit).__name__}")
    index = build_label_index(index.names)
    if limit < 1:""",
    )],
    # --- .36b fuzzy step scans every distinct token per query token -------------
    "M-36b": [(
        """    if allowed == 0:
        lo, hi = _token_range(index._tokens, query_token)
        return {token_id: 0 for token_id in range(lo, hi)}

    chars = index._trie_chars""",
        """    if allowed == 0:
        lo, hi = _token_range(index._tokens, query_token)
        return {token_id: 0 for token_id in range(lo, hi)}

    # M-36b negative control: scan every distinct token per query token
    _scanned: dict[int, int] = {}
    for _tid, _tok in enumerate(index._tokens):
        _d = _prefix_distance(query_token, _tok, allowed)
        if _d <= allowed:
            _scanned[_tid] = _d
    return _scanned

    chars = index._trie_chars""",
    )],
    # --- .36d a map for every query token (no switch, variant A) ---------------
    "M-36d": [(
        """        if (
            not switched
            and candidates is not None
            and len(candidates) <= _FUZZY_SWITCH_CAP
            and sum(starts[n + 1] - starts[n] for n in candidates)
            <= _FUZZY_SWITCH_CAP
        ):
            switched = True""",
        """        # M-36d negative control: switch removed (walk every distinct query
        # token, the E2 tier's eager maps = C5 variant A)
        if False:
            switched = True""",
    )],
    # --- .37 nested-dict trie + per-name token strings -------------------------
    "M-37": [(
        """    trie_chars, trie_depth, trie_first, trie_end = _build_trie(tokens)

    return LabelIndex(""",
        """    trie_chars, trie_depth, trie_first, trie_end = _build_trie(tokens)

    # M-37 negative control: nested-dict trie + per-name token strings
    _trie2: dict = {}
    for _tok in tokens:
        _node = _trie2
        for _ch in _tok:
            _node = _node.setdefault(_ch, {})
    _per_name = tuple(tuple(folded[i][s:e] for s, e in _tokens(uniq[i])) for i in range(count))

    return LabelIndex(""",
    )],
    # --- .38 query cap removed ------------------------------------------------
    "M-38": [(
        """    raw = query.strip(_WHITESPACE)
    if len(raw) > 256:
        return []
    parsed = _parse_query(raw)""",
        """    raw = query.strip(_WHITESPACE)
    parsed = _parse_query(raw)""",
    )],
    # --- .39 name cap removed --------------------------------------------------
    "M-39": [(
        """        if len(name) > 1024:
            continue
        if name not in seen:""",
        """        if name not in seen:""",
    )],
    # --- .40a no collapse of duplicate query tokens ----------------------------
    "M-40a": [
        ("""    counts: dict[str, int] = {}
    for token in query.tokens:
        counts[token] = counts.get(token, 0) + 1
    distinct = sorted(counts, key=_allowed_edits)""",
         """    distinct = list(query.tokens)"""),
        ("""        allowed = _allowed_edits(token)
        count = counts[token]""",
         """        allowed = _allowed_edits(token)
        count = 1"""),
    ],
    # --- .40b per-candidate check restored (E3 step 4, switch at 300) ----------
    "M-40b": [(
        """        if (
            not switched
            and candidates is not None
            and len(candidates) <= _FUZZY_SWITCH_CAP
            and sum(starts[n + 1] - starts[n] for n in candidates)
            <= _FUZZY_SWITCH_CAP
        ):
            switched = True""",
        """        if not switched and candidates is not None and len(candidates) <= 300:
            switched = True""",
    )],
    # --- .40c _prefix_distance without the band --------------------------------
    "M-40c": [(
        """        lo = j - cap if j - cap > 1 else 1
        hi = j + cap if j + cap < m else m""",
        """        lo = 1
        hi = m""",
    )],
}

MANIFEST = [
    ("M-21", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.21"),
    ("M-22", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.22"),
    ("M-23", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.23 or rows_23_1"),
    ("M-23b", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.23 or rows_23_1"),
    ("M-24", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.24 or rows_24_1 or rows_24_3"),
    ("M-24b", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.24 or rows_24_1 or rows_24_3"),
    ("M-25", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.25 or rows_25_1 or rows_25_2"),
    ("M-26", "b", "tests/test_b103_label_match.py", "rows_26"),
    ("M-27", "b", "tests/test_b103_label_match.py", "rows_27"),
    ("M-28", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.28 or rows_28"),
    ("M-29", "b", "tests/test_b103_label_match.py", "rows_29"),
    ("M-30", "b", "tests/test_b103_label_match.py", "rows_30"),
    ("M-31", "b", "tests/test_b103_label_match.py", "rows_31"),
    ("M-32", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.32 or rows_32"),
    ("M-33", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.33 or rows_33"),
    ("M-33b", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.33 or rows_33"),
    ("M-34", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.34 or rows_34"),
    ("M-34b", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.34 or rows_34"),
    ("M-35", "p", "tests/test_b103_label_match_perf.py", "a2l_match_35"),
    ("M-36a", "p", "tests/test_b103_label_match_perf.py", "a2l_match_36"),
    ("M-36b", "p", "tests/test_b103_label_match_perf.py", "a2l_match_36"),
    ("M-36d", "p", "tests/test_b103_label_match_perf.py", "a2l_match_36"),
    ("M-37", "p", "tests/test_b103_label_match_perf.py", "a2l_match_37"),
    ("M-38", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.38"),
    ("M-39", "b", "tests/test_b103_label_match.py", "R-A2L-MATCH.39"),
    ("M-40a", "p", "tests/test_b103_label_match_perf.py", "a2l_match_40"),
    ("M-40b", "p", "tests/test_b103_label_match_perf.py", "a2l_match_40"),
    ("M-40c", "p", "tests/test_b103_label_match_perf.py", "a2l_match_40"),
]


def main() -> int:
    with open(BASE, "r", encoding="utf-8", newline="") as f:
        base = f.read()
    os.makedirs(OUT, exist_ok=True)

    for mid in sorted(MUTANTS):
        text = base
        for old, new in MUTANTS[mid]:
            n = text.count(old)
            if n != 1:
                print(f"FAIL {mid}: old text occurs {n} times (want 1): {old[:60]!r}")
                return 1
            text = text.replace(old, new, 1)
        path = os.path.join(OUT, mid + ".py")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    with open(os.path.join(OUT, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        for mid, kind, mod, k in MANIFEST:
            f.write(f"{mid}\t{kind}\t{mod}\t{k}\n")

    print(f"built {len(MUTANTS)} mutant files + manifest into {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
