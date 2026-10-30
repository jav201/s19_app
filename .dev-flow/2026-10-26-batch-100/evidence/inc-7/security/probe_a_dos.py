"""A: reader / project-check cost for capped manifests whose entries need
filesystem calls (the SEC6-5 arm uses '../' entries, decided on text)."""
import json, shutil, sys, time
from common import *
from s19_app.tui.services.variant_execution_service import read_project_manifest, MANIFEST_SIZE_CAP_BYTES
from s19_app.tui.services.manifest_writer import check_project_files
CASE01 = WT / "examples" / "case_01_basic_valid"

def project(tag):
    p = wa(fresh(tag)) / "P"
    p.mkdir(parents=True)
    shutil.copy(CASE01 / "firmware.s19", p / "firmware.s19")
    return p

def run(tag, payload, setup=None):
    p = project(tag)
    if setup: setup(p)
    text = json.dumps(payload, separators=(",", ":"))
    (p / "project.json").write_text(text, encoding="utf-8")
    t = time.perf_counter(); m = read_project_manifest(p); tr = time.perf_counter() - t
    t = time.perf_counter(); probs = check_project_files(p, m); tc = time.perf_counter() - t
    codes = {}
    for i in m.issues: codes[i.code] = codes.get(i.code, 0) + 1
    entries = len(m.batch) + sum(len(v) for v in m.assignments.values()) + sum(len(v) for v in m.gathered.values())
    print(f"[{tag}] bytes={len(text)} read={tr:.2f}s check={tc:.2f}s issues={codes} kept_entries={entries} problems={len(probs)}")
    return p

which = sys.argv[1:] or ["A1", "A2", "A3", "A4"]
if "A1" in which:
    # 5 arrays x 1000 entries, each ~50 nested components, nonexistent (accepted; no issue)
    seg = "sub/" * 36
    run("A1-nested-5x1000", {"schema_version": 1,
        "batch": [f"{seg}b{i}.json" for i in range(1000)],
        "assignments": {"firmware": [f"{seg}a{i}.json" for i in range(1000)]},
        "gathered": {"patches": [f"{seg}g{i}.json" for i in range(1000)]},
        "files": {f"{seg}f{i}.s19": {"size": 1, "sha256": "0"*64} for i in range(1000)},
        "derived_from": {f"{seg}d{i}.s19": {"base": "firmware.s19", "sha256": "0"*64, "differ": 1} for i in range(1000)}})
if "A2" in which:
    # few very deep entries, total just under 1 MiB, each under 32 767 chars
    deep = "a/" * 16300
    n = (MANIFEST_SIZE_CAP_BYTES - 200) // (len(deep) + 12)
    run(f"A2-deep-{n}x{len(deep)}", {"schema_version": 1, "batch": [f"{deep}x{i}.json" for i in range(n)]})
if "A3" in which:
    def loop(p):
        junction(p / "loop", p / "loop")
    p = run("A3-junction-loop-5x1000", {"schema_version": 1,
        "batch": [f"loop/b{i}.json" for i in range(1000)],
        "assignments": {"firmware": [f"loop/a{i}.json" for i in range(1000)]},
        "gathered": {"patches": [f"loop/g{i}.json" for i in range(1000)]},
        "files": {f"loop/f{i}.s19": {"size": 1, "sha256": "0"*64} for i in range(1000)},
        "derived_from": {f"loop/d{i}.s19": {"base": "firmware.s19", "sha256": "0"*64, "differ": 1} for i in range(1000)}}, setup=loop)
    rm_junction(p / "loop")
if "A4" in which:
    # deep entries through a junction to a sibling dir inside the project: the reparse walk
    def inner(p):
        (p / "real").mkdir()
        junction(p / "j", p / "real")
    seg = "j/" + "sub/" * 45
    p = run("A4-through-junction-3x1000", {"schema_version": 1,
        "batch": [f"{seg}b{i}.json" for i in range(1000)],
        "assignments": {"firmware": [f"{seg}a{i}.json" for i in range(1000)]},
        "gathered": {"patches": [f"{seg}g{i}.json" for i in range(1000)]}}, setup=inner)
    rm_junction(p / "j")
