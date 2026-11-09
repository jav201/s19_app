"""Inc 4 E5 corrective 3 (tester): R-A2L-MATCH.42's timing control. THROWAWAY EVIDENCE, NOT A TEST.
Runs on <runner> only, in a /tmp copy of the integrated tree whose label_match.py has NO node budget
(or the budget removed). Times R-A2L-MATCH.42/2 (W40, 6 tokens) with the test module's own builders:
median of 3 > 2.0 s means the control is RED."""
import statistics
import sys
import time

sys.path.insert(0, ".")
import s19_app
from s19_app.tui.services.label_match import build_label_index, rank
from tests import test_b103_label_match_perf as T

print("s19_app.__file__ =", s19_app.__file__)
ix = build_label_index(T.w40_names())
q = T.runs_query(range(40, 34, -1))
times = []
for _ in range(3):
    t0 = time.perf_counter()
    got = rank(q, ix, 20)
    times.append(time.perf_counter() - t0)
m = statistics.median(times)
print(f"R-A2L-MATCH.42/2 W40 6 tokens ({len(q)} chars): times {[round(t * 1000, 1) for t in times]} ms; median of 3 {m * 1000:.1f} ms;"
      f" bound 2000 ms -> {'RED (> 2.0 s)' if m > 2.0 else 'NOT RED'}")
print("rules:", sorted({r.rule.value for r in got}), "edits:", sorted({r.edits for r in got}), "list sha256", T._sha_list(got))
