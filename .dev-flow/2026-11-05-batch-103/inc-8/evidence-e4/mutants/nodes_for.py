"""nodes_for.py <nodes.json> <id|--by-file> [unit|at]: print the node ids of a requirement, or the baseline groups."""
import json
import sys

sys.dont_write_bytecode = True
data = json.load(open(sys.argv[1], encoding="utf-8"))
if sys.argv[2] == "--by-file":
    groups = {}
    for entry in data.values():
        for kind in ("unit", "at"):
            for node in entry[kind]:
                groups.setdefault(node.split("::")[0], set()).add(node)
    for path in sorted(groups):
        print(path + "\t" + " ".join(sorted(groups[path])))
else:
    print("\n".join(data[sys.argv[2]][sys.argv[3]]))
