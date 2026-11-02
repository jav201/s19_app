import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path, encoding="utf-8").read()
assert s.count(old) == 1, (path, s.count(old))
open(path, "w", encoding="utf-8", newline="\n").write(s.replace(old, new))
print("mutated", path)
