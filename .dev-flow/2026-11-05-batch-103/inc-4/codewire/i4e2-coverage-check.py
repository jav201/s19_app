import re
import sys

tc_path, graph_path = sys.argv[1], sys.argv[2]
tc = open(tc_path, encoding="utf-8").read()
cases = re.findall(r"^\| (R-A2L-MATCH\.\d+/\d+|AT-B103-I4-\d) \|", tc, re.M)
graph = open(graph_path, encoding="utf-8").read()
nodes_part = graph.split("## Nodes", 1)[1].split("## Entities", 1)[0]
covered = set()
for line in nodes_part.splitlines():
    if not line.startswith("examples: ("):
        continue
    src = line[len("examples: ("):].split(")", 1)[0]
    for m in re.finditer(r"AT-B103-I4-\d", src):
        covered.add(m.group(0))
    row = None
    last_k = None
    toks = re.findall(r"R-A2L-MATCH\.(\d+)(?:/(\d+))?|\.(\d+)/(\d+)|(…|–)\s*/(\d+)|/(\d+)", src)
    for full_n, full_k, dot_n, dot_k, rng, rng_k, bare_k in toks:
        if full_n:
            row, last_k = int(full_n), (int(full_k) if full_k else None)
            if last_k:
                covered.add(f"R-A2L-MATCH.{row}/{last_k}")
        elif dot_n:
            row, last_k = int(dot_n), int(dot_k)
            covered.add(f"R-A2L-MATCH.{row}/{last_k}")
        elif rng:
            k2 = int(rng_k)
            for k in range((last_k or 1), k2 + 1):
                covered.add(f"R-A2L-MATCH.{row}/{k}")
            last_k = k2
        elif bare_k and row is not None:
            last_k = int(bare_k)
            covered.add(f"R-A2L-MATCH.{row}/{last_k}")
missing = [c for c in cases if c not in covered]
rows = sorted({int(c.split(".")[1].split("/")[0]) for c in cases if c.startswith("R-")})
rows_cov = sorted({int(c.split(".")[1].split("/")[0]) for c in covered if c.startswith("R-")})
print(f"cases in 02-test-cases.md: {len(cases)}; covered by an example line: {len(cases) - len(missing)}; missing: {missing}")
print(f"rows with cases: {len(rows)}; rows with at least one example: {len([r for r in rows if r in rows_cov])}")
extra = sorted(c for c in covered if c not in cases)
print(f"ids in examples that are no case: {extra}")
