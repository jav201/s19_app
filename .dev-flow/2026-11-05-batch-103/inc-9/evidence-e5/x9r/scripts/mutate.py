"""X9r mutants (HT-09: applied to copies only). mutate.py <tree> <id>; each replaces exactly one occurrence."""
import sys
from pathlib import Path

M = {
    # FX9c O-C: drop the "past the end of before" term of the changed count.
    "oc1": ("s19_app/tui/screens_directionb/shared.py",
            "changed_count = sum(map(ne, before, after)) + max(0, span - len(before))",
            "changed_count = sum(map(ne, before, after))"),
    # FX9c O-C: one span cell short of the painted rows.
    "oc2": ("s19_app/tui/screens_directionb/shared.py",
            "for i in range(min(span, max(0, painted - len(lead))))",
            "for i in range(min(span, max(0, painted - len(lead) - 1)))"),
    # FX9c O-D: the worker's cached max |delta| is wrong.
    "od1": ("s19_app/tui/definition_bench.py",
            "return values, staged, _max_staged_delta(values, staged)",
            "return values, staged, 0.0"),
    # FX9c O-D: the cache is used without the identity check (a stale pair paints).
    "od2": ("s19_app/tui/definition_bench.py",
            "if cached is not None and cached[0] is state.values and cached[1] is state.staged:",
            "if cached is not None:"),
    # FX9c O-D: a deselected LARGE row keeps the cache (and with it its values) alive.
    "od3": ("s19_app/tui/screens_directionb/patch_editor/bench_sheet.py",
            "lo=0.0, hi=0.0, strip=None, labels=None, staged_delta=None,",
            "lo=0.0, hi=0.0, strip=None, labels=None,"),
}

tree, mid = sys.argv[1], sys.argv[2]
rel, old, new = M[mid]
p = Path(tree) / rel
src = p.read_text(encoding="utf-8")
assert src.count(old) == 1, (mid, src.count(old))
p.write_text(src.replace(old, new), encoding="utf-8")
print(f"{mid}: applied to {rel}")
