import json, sys
t = json.load(open(sys.argv[1], encoding="utf-8"))
for n, calls in t.items():
    if n == "_skipped":
        print("_skipped", calls); continue
    if len(sys.argv) > 2 and n not in sys.argv[2:]:
        continue
    for c in calls[:2]:
        s = json.dumps({k: c.get(k) for k in ("test", "in", "out", "after")}, ensure_ascii=False)
        print(f"== {n} ({len(calls)}): {s[:700]}")
