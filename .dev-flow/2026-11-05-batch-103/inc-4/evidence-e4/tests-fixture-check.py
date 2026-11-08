import ast, sys
sys.path.insert(0, ".")
import tests.test_b103_label_match_perf as P
from collections import defaultdict
want = defaultdict(list)
for line in open("/tmp/b103-e4-4-tests/.dev-flow/2026-11-05-batch-103/inc-4/evidence-e3/addenda-pset.txt", encoding="utf-8"):
    if line.startswith("#") or not line.strip():
        continue
    lst, label, rep = line.rstrip("\n").split("\t")
    want[lst].append(ast.literal_eval(rep))
swa = P._read_names(P.SWA_PATH)
ref = (swa + [n + "_1" for n in swa] + [n + "_2" for n in swa] + [n + "_3" for n in swa])[:50000]
got = {"REF": [q for _, q in P.pset_ref()], "REF6": [q for _, q in P.pset_ref6(swa)], "LONG": [q for _, q in P.LONG_QUERIES]}
for k in got:
    print(k, "mine", len(got[k]), "file", len(want[k]), "equal:", got[k] == want[k])
    if got[k] != want[k]:
        for i, (a, b) in enumerate(zip(got[k], want[k])):
            if a != b: print("  differs at", i, repr(a[:60]), repr(b[:60]))
q = P.qset33(swa, ref)
print("QSET 33:", len(q), "shapes 5,6 vs file REF6 shapes:", q[-4] == want["REF6"][-4], q[-3] == want["REF6"][-3], "longest:", q[-2] == want["REF6"][-2], q[-1] == want["REF6"][-1])
print("longest REF name by independent count:")
import re
def toks(n):
    return re.findall(r"[0-9]+|[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z])|[^\x00-\x7f]+", n)
best = sorted(ref, key=lambda n: (-len(toks(n)), n))[0]
print(len(toks(best)), len(best), best == P.LONGEST_REF_NAME)
