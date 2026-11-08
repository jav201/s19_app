"""batch-103 Inc 4 E5 round-3 DESIGN pilot (d3): the two round-3 rulings as monkeypatches of label_match's private
functions. THROWAWAY EVIDENCE, NOT PRODUCT CODE. Imported by d3-probe.py and by the pytest plugin d3-plugin.py.

- R-A2L-MATCH.42 (E5S-10): a per-ranking budget of trie node visits shared by the fuzzy walks of one ranking, in the
  order rank step 4 takes the distinct query tokens. The walk loop stops before the node after the budget-th; the
  walk returns the runs it emitted so far ("the fuzzy rule lists what it found so far"); a walk started with the
  budget spent emits nothing (step 4 then stops: an empty table). Deterministic: a count, not a clock. The walk is the
  shipped _fuzzy_token_distances (its own source) with three lines added at the top of its loop; the reviewer's pilot
  (sec-r3-probe.py fixb) raised there instead (no fuzzy name at all).
- R-A2L-MATCH.43 (E5S-11): a name holding a character above U+007F (not str.isascii()) is left out of the prepared
  name list, after the shipped type checks (a non-str element still raises).
"""
from __future__ import annotations

import inspect

LOOP = "    while j < node_count:\n"
GUARD = LOOP + "        if _D3_USED[0] >= _D3_LIMIT[0]:\n            break\n        _D3_USED[0] += 1\n"
BUDGET = 400_000


class Pilot:
    def __init__(self, lm):
        self.lm = lm
        src = inspect.getsource(lm._fuzzy_token_distances)
        assert src.count(LOOP) == 1, "walk loop not found"
        self.used, self.limit = [0], [0]
        ns = dict(lm.__dict__)
        ns.update(_D3_USED=self.used, _D3_LIMIT=self.limit)
        exec(compile("from __future__ import annotations\n" + src.replace(LOOP, GUARD, 1), "<d3 budgeted walk>", "exec"), ns)
        self.walk = ns["_fuzzy_token_distances"]
        self.orig = (lm._fuzzy_token_distances, lm._fuzzy_tier, lm.build_label_index)
        self.last_nodes = 0
        self.state = "shipped"

    def install(self, budget=None, ascii_only=False):
        self.uninstall()
        lm = self.lm
        walk0, tier0, build0 = self.orig
        if budget is not None:
            self.limit[0] = budget

            def tier(query, index, taken):
                self.used[0] = 0
                try:
                    return tier0(query, index, taken)
                finally:
                    self.last_nodes = self.used[0]

            lm._fuzzy_token_distances, lm._fuzzy_tier = self.walk, tier
        if ascii_only:
            def build(names):
                if isinstance(names, (str, bytes)):
                    return build0(names)  # the shipped TypeError
                return build0([n for n in names if not (isinstance(n, str) and not n.isascii())])

            lm.build_label_index = build
        self.state = f"budget={budget} ascii_only={ascii_only}"

    def uninstall(self):
        self.lm._fuzzy_token_distances, self.lm._fuzzy_tier, self.lm.build_label_index = self.orig
        self.state = "shipped"
