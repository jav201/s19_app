"""build_report.py <res-dir> <out-dir>: parse the runner's result files into table.md and results.txt (paths redacted)."""
import json
import os
import re
import sys

sys.dont_write_bytecode = True
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
from mutants import M  # noqa: E402

res, out = sys.argv[1], sys.argv[2]
nodes = json.load(open(os.path.join(here, "nodes.json"), encoding="utf-8"))
ctrl = dict(line.rstrip("\n").split("\t", 1) for line in open(os.path.join(here, "controls.txt"), encoding="utf-8"))
HOME = re.compile(r"/home/[^/\s]+/work/zq-e4-8-mut/(w\d|pristine)/tree/")


def clean(text):
    text = HOME.sub("<tree>/", text)
    return re.sub(r"/home/[^/\s]+", "<runner-home>", text)


def parse(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    rcs = re.findall(r"^RC (\w+) (\d+)", text, re.M)
    evid = [l for l in text.splitlines() if re.search(r"\.py:\d+:|^FAILED|^ERROR", l)]
    loads = [float(x) for x in re.findall(r"^LOAD_(?:BEFORE|AFTER) ([\d.]+)", text, re.M)]
    return text, rcs, evid, loads


rows, killed, survived, timeouts, results = [], 0, 0, 0, []
for key in M:
    safe = key.replace("#", "_")
    text, rcs, evid, loads = parse(os.path.join(res, safe + ".txt"))
    extra = "EXTRA" in M[key][0]
    verdict = "survived"
    for kind, rc in rcs:
        if rc == "0":
            continue
        if rc == "124":
            verdict = f"timeout ({kind}, 300 s)"
        elif any(l.startswith("FAILED") for l in evid) or rc == "1":
            verdict = f"killed ({kind})"
        else:
            verdict = f"inconclusive rc{rc}"
        break
    wider = ""
    wpath = os.path.join(res, "wider-" + safe + ".txt")
    if verdict == "survived" and os.path.exists(wpath):
        wtext, _, wevid, wloads = parse(wpath)
        wv = re.search(r"^VERDICT \S+ (\S+)", wtext, re.M).group(1)
        wider = wv
        evid = evid or wevid
        loads += wloads
    base = key.split("#")[0]
    n_unit, n_at = len(nodes[base]["unit"]), len(nodes[base]["at"])
    first = clean(next((l for l in evid if ".py:" in l), evid[0] if evid else "—")).strip()
    rows.append((key, base, M[key][0], n_unit, n_at, verdict, wider, first, (min(loads), max(loads)) if loads else (0, 0), extra))
    if not extra:
        killed += verdict.startswith("killed")
        survived += verdict == "survived"
        timeouts += verdict.startswith("timeout")
    results.append(clean(text))
total = sum(1 for r in rows if not r[9])
lines = ["| Row | Control (requirement text) | Mutation as applied | Nodes (unit+AT) | Result | Evidence line | Load |", "|---|---|---|---|---|---|---|"]
for key, base, desc, nu, na, verdict, wider, first, (lo, hi), extra in rows:
    res_txt = verdict + (f"; wider run: {wider}" if wider else "")
    if extra:
        res_txt = "extra, not scored: " + res_txt
    lines.append(f"| {key} | {ctrl[base].replace('|', '/')} | {desc} | {nu}+{na} | {res_txt} | `{first[:170].replace('|', '/')}` | {lo:.2f}-{hi:.2f} |")
open(os.path.join(out, "table.md"), "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
open(os.path.join(out, "results.txt"), "w", encoding="utf-8", newline="\n").write("\n\n".join(results))
print(f"scored={total} killed={killed} survived={survived} timeouts={timeouts}")
print("loads", min(r[8][0] for r in rows), max(r[8][1] for r in rows))
