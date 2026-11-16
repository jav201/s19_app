"""build_nodes.py <repo-root>: requirement id -> {unit: [file::test], at: [file::test]} (writes nodes.json).

unit = the tests the case files name for the requirement plus every test_b103_inc8_* test whose name
starts with the requirement's normalised id; at = the named acceptance nodes (test_b103_inc8_at*.py).
"""
import glob
import json
import os
import re
import sys

sys.dont_write_bytecode = True
repo = sys.argv[1]
inc = os.path.join(repo, ".dev-flow", "2026-11-05-batch-103", "inc-8")
here = os.path.dirname(os.path.abspath(__file__))
ids = [line.split("\t")[0] for line in open(os.path.join(here, "controls.txt"), encoding="utf-8")]
defs = {}
for path in glob.glob(os.path.join(repo, "tests", "*.py")):
    text = open(path, encoding="utf-8").read()
    for match in re.finditer(r"^\s*(?:async )?def (test_\w+)", text, re.M):
        defs.setdefault(match.group(1), set()).add(os.path.basename(path))
listed = {}
for case_file in ["02-test-cases.md"] + [os.path.basename(p) for p in sorted(glob.glob(os.path.join(inc, "02-test-cases-*.md")))]:
    for line in open(os.path.join(inc, case_file), encoding="utf-8"):
        if not line.startswith("| R-"):
            continue
        rid = line.split("|")[1].strip().split("/")[0]
        for name in re.findall(r"(test_\w+)", line):
            if name in defs:
                listed.setdefault(rid, set()).add(name)
out = {}
for rid in ids:
    prefix = "test_" + re.sub(r"[.\-]", "_", rid.lower()) + "_"
    names = set(listed.get(rid, ()))
    for name, files in defs.items():
        if name.startswith(prefix) and any(f.startswith("test_b103_inc8") for f in files):
            names.add(name)
    unit, at = [], []
    for name in sorted(names):
        for f in sorted(defs[name]):
            if not f.startswith("test_b103_inc8"):
                continue
            (at if "_at" in f.split("inc8")[1] and f.split("inc8_")[1].startswith("at") else unit).append(f"tests/{f}::{name}")
    out[rid] = {"unit": unit, "at": at}
json.dump(out, open(os.path.join(here, "nodes.json"), "w", encoding="utf-8"), indent=1)
print({k: (len(v["unit"]), len(v["at"])) for k, v in out.items() if not v["unit"]})
print(sum(len(v["unit"]) for v in out.values()), sum(len(v["at"]) for v in out.values()))
