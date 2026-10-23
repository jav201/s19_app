import sys, json
p, spec = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8", newline="").read()
for a, b in json.load(open(spec, encoding="utf-8")):
    n = s.count(a)
    assert n == 1, (n, a[:80])
    s = s.replace(a, b)
open(p, "w", encoding="utf-8", newline="").write(s)
print("ok")
