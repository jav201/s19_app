"""Inc 7 E2 coverage check (records tool): every active requirement of 01-requirements.md has a row in the
graph's coverage table, is named on some node's req: line, and has at least one example line whose source
is one of its cases (`(<id>/<k>`). Run from the inc-7 folder: python -I -B codewire/i7e2-coverage-check.py"""
import io
import re

req = io.open("01-requirements.md", encoding="utf-8").read()
graph = io.open("codewire/graph-inc7.md", encoding="utf-8").read()
active = [m.group(1) for m in re.finditer(r"^\| (R-[A-Za-z0-9.-]+) \| [A-Za-z]+ \| (.*?) \|", req, re.M)
          if "Withdrawn" not in m.group(2)]
cov = graph.split("### Coverage", 1)[1].split("### E4 notes", 1)[0]
reqlines = " ".join(re.findall(r"^req: (.*)$", graph, re.M))
examples = re.findall(r"^examples: \(([^)]*)\)", graph, re.M)
bad = 0
for r in active:
    short = "." + r.split(".", 1)[1] if r.startswith("R-A2L-LIST.") else r
    in_cov = re.search(r"^\| " + re.escape(r) + r" \|", cov, re.M) is not None
    in_req = re.search(r"(?<![\w.-])" + re.escape(r) + r"(?![\w-]|\.\d)", reqlines) is not None
    has_ex = any(re.search(r"(?<![\w.-])" + re.escape(r) + r"/\d", e) for e in examples)
    if not (in_cov and in_req and has_ex):
        bad += 1
        print(f"GAP {r}: coverage={in_cov} req={in_req} example={has_ex}")
print(f"{len(active)} active requirements, {len(examples)} example lines, {bad} gap(s)")
