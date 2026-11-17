from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

out = Path(sys.argv[1])
prior = Path(sys.argv[2])
nodes = out.joinpath("nodes.txt").read_text(encoding="utf-8").splitlines()
control_nodes = out.joinpath("control-nodes.txt").read_text(encoding="utf-8").splitlines()
ansi = re.compile(r"(?:\x1b|#x1B)\[[0-9;]*m")


def nodeid(case):
    return case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"]


def read_junit(path):
    if not path.exists():
        return {}, {}
    root = ET.parse(path).getroot()
    rows = {}
    for case in root.iter("testcase"):
        outcome = "passed"
        detail = None
        for kind in ("failure", "error", "skipped"):
            found = case.find(kind)
            if found is not None:
                outcome = {"failure": "failed", "error": "error", "skipped": "skipped"}[kind]
                detail = found
                break
        signature = ""
        if detail is not None:
            signature = ansi.sub("", detail.attrib.get("message", "").splitlines()[0])
        qc = [p.attrib["value"] for p in case.findall("./properties/property") if p.attrib.get("name") == "qc_tm"]
        rows[nodeid(case)] = {
            "status": outcome,
            "time": float(case.attrib.get("time", "0")),
            "signature": signature,
            "qc_tm": qc,
        }
    suite = next(root.iter("testsuite"), None)
    return rows, dict(suite.attrib) if suite is not None else {}


def clean(value):
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")


data = {}
attrs = {}
for tree in ("head", "base", "control"):
    data[tree], attrs[tree] = read_junit(out / tree / "junit.xml")

with out.joinpath("results.tsv").open("w", encoding="utf-8", newline="") as stream:
    stream.write("tree\tnodeid\tstatus\ttime_s\tsignature\tqc_tm\n")
    for tree in ("head", "base", "control"):
        for node in nodes:
            row = data[tree].get(node)
            if row is None:
                continue
            fields = [tree, node, row["status"], f'{row["time"]:.3f}', row["signature"], "; ".join(row["qc_tm"])]
            stream.write("\t".join(clean(value) for value in fields) + "\n")

with out.joinpath("comparison.tsv").open("w", encoding="utf-8", newline="") as stream:
    stream.write("nodeid\thead_status\treference_tree\treference_status\thead_signature\treference_signature\n")
    for node in nodes:
        head = data["head"].get(node, {})
        reference_tree = "control" if node in control_nodes else "base"
        reference = data[reference_tree].get(node, {})
        fields = [node, head.get("status", "missing"), reference_tree, reference.get("status", "missing"), head.get("signature", ""), reference.get("signature", "")]
        stream.write("\t".join(clean(value) for value in fields) + "\n")

with out.joinpath("prior-results.tsv").open("w", encoding="utf-8", newline="") as stream:
    stream.write("nodeid\tlane\tstatus\ttime_s\tsignature\tqc_tm\n")
    for lane, filename in (("main", "main-junit.xml"), ("serial", "serial-junit.xml")):
        rows, _ = read_junit(prior / filename)
        for node in nodes:
            row = rows.get(node)
            if row is None:
                continue
            fields = [node, lane, row["status"], f'{row["time"]:.3f}', row["signature"], "; ".join(row["qc_tm"])]
            stream.write("\t".join(clean(value) for value in fields) + "\n")

summary = {"trees": {}, "nodes": len(nodes)}
for tree in ("head", "base", "control"):
    counts = {key: 0 for key in ("passed", "failed", "error", "skipped")}
    for row in data[tree].values():
        counts[row["status"]] += 1
    summary["trees"][tree] = {
        "suite": attrs[tree],
        "counts": counts,
        "records": len(data[tree]),
        "qc_tm_records": sum(len(row["qc_tm"]) for row in data[tree].values()),
        "qc_tm_low_margin_records": sum(float(value.rsplit("|", 1)[1]) < 20.0 for row in data[tree].values() for value in row["qc_tm"]),
        "qc_tm_over_bound_records": sum(float(value.rsplit("|", 1)[1]) < 0.0 for row in data[tree].values() for value in row["qc_tm"]),
    }
out.joinpath("summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

with out.joinpath("sha256.txt").open("w", encoding="utf-8", newline="") as stream:
    for path in sorted(out.rglob("*")):
        if not path.is_file() or path.name == "sha256.txt" or any(part in {"t", "tmp", "home", "appdata", "localappdata", "xdg-cache", "xdg-config", "xdg-data", "xdg-state"} for part in path.parts):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        stream.write(f"{digest}  {path.relative_to(out).as_posix()}\n")

print(json.dumps(summary, indent=2, ensure_ascii=False))
