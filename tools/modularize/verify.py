"""Identity verifier for the mechanical modularization (spec-verify.md Part A).

python -I tools/modularize/verify.py --repo <tree> --base-rev <sha> --map <module-map.json>
       [--json <out>] [--py <interpreter>] [--state <dir>]

Checks V1-V19. Everything that imports `s19_app` runs in a subprocess (`--py`, isolated env).
Exit 0 iff no check fails. Independent of move.py.
"""
from __future__ import annotations

import argparse
import ast
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.setrecursionlimit(20000)

import verify_check as vc  # noqa: E402
import verify_names as vn  # noqa: E402
import verify_runtime as vr  # noqa: E402
import verify_static as vs  # noqa: E402
import verify_units as vu  # noqa: E402

PKGS = ("app", "screens_directionb")


def analyse(tree: Path, rev: str, mapd: dict, pkg: str, run: vr.Runner) -> dict:
    old, old_text = vu.inventory_old(tree, rev, pkg)
    loaded = vc.load_new(tree, pkg, mapd)
    d1 = set(mapd[pkg]["d1_names"])
    fails: list[vc.Fail] = [("V3", f"{e}") for e in loaded.errors + loaded.extras]
    pairs, f = vc.match_units(old, loaded.units)
    fails += f
    f, cnt = vc.compare_bodies(pairs, d1)
    fails += f
    fails += [("V8", m) for m in vs.check_placement(pairs, vs.placement_index(mapd, pkg))]
    stats = {"d1_new": 0, "d1_old": 0, "bare": 0, "pins": (0, 0), "reexp": 0, "fresh": (0, 0)}
    present = bool(loaded.parsed)
    missing_deps: set[str] = set()
    if present:
        f, stats["d1_new"], stats["d1_old"], stats["bare"] = vc.d1_checks(old_text, loaded, d1)
        fails += f
        f, missing_deps = names_part(pkg, old_text, loaded)
        fails += f
        fails += [("V14", m) for m in vs.check_graph(pkg, loaded.parsed)]
        fails += [("V15", m) for m in vs.check_caps(pkg, loaded.texts, loaded.parsed)]
        if pkg == "app":
            core = vu.find_core_class(loaded.parsed["core"]) if "core" in loaded.parsed else None
            fails += [("V10", m) for m in vs.check_header(core, mapd)]
        fails += runtime_part(run, tree, mapd, pkg, loaded, old_text, stats, missing_deps)
    else:
        fails.append(("V13", f"{pkg}: package directory {vu.NEW_DIRS[pkg]}/ is missing; runtime checks skipped"))
    return {"pkg": pkg, "units_old": len(old), "units_new": len(loaded.units), "fails": fails,
            "relimport": cnt.relimport, "css": cnt.css, "stats": stats}


def names_part(pkg: str, old_text: str, loaded: vc.Loaded) -> tuple[list[vc.Fail], set[str]]:
    """V18 (static half) and V19 for one package."""
    fails, missing = vn.names_checks(pkg, old_text, loaded.texts, loaded.parsed)
    fails += vn.type_checking_shape(f"{pkg} (old)", ast.parse(old_text))
    for stem, mod in sorted(loaded.parsed.items()):
        fails += vn.type_checking_shape(f"{pkg}/{stem}.py", mod)
    return fails, missing


def runtime_part(run: vr.Runner, tree: Path, mapd: dict, pkg: str, loaded: vc.Loaded, old_text: str,
                 stats: dict, missing_deps: set[str]) -> list[vc.Fail]:
    fails, rt = vr.runtime_checks(run, mapd, pkg)
    stats["pins"] = (rt["pins_ok"], rt["pins_total"])
    stats["reexp"] = rt["reexports_missing"]
    f, ok = vr.fresh_import_checks(run, vr.dotted_modules(pkg, sorted(loaded.parsed)))
    stats["fresh"] = (ok, len(loaded.parsed))
    spec = vn.runtime_spec(pkg, old_text, loaded.parsed, set(mapd[pkg]["d1_names"]), missing_deps)
    return fails + f + vr.equivalence_checks(run, tree, pkg, old_text, loaded.parsed, spec)


def summarize(rev: str, results: list[dict], old_present: list[str]) -> tuple[list[str], dict, list[vc.Fail]]:
    fails = [x for r in results for x in r["fails"]]
    fails += [("V12", f"{f} still exists") for f in old_present]
    n = Counter(c for c, _ in fails)
    st = [r["stats"] for r in results]
    s = {
        "units_old": sum(r["units_old"] for r in results), "units_new": sum(r["units_new"] for r in results),
        "missing": n["V1"], "duplicate": n["V2"], "extra": n["V3"], "body_diff": n["V4"],
        "unlisted_rewrite": n["V5"], "d1_new": sum(x["d1_new"] for x in st), "d1_old": sum(x["d1_old"] for x in st),
        "relimports": sum(r["relimport"] for r in results), "css": sum(r["css"] for r in results),
        "bare_d1": n["V6"], "pins_ok": sum(x["pins"][0] for x in st), "pins_total": sum(x["pins"][1] for x in st),
        "reexports_missing": n["V11"], "fresh_ok": sum(x["fresh"][0] for x in st),
        "fresh_total": sum(x["fresh"][1] for x in st), "cycles": n["V14"], "caps_over": n["V15"],
        "old_files": n["V12"], "placement": n["V8"], "header": n["V10"], "css_fail": n["V16"], "equiv": n["V17"],
        "names": n["V18"], "tc_shape": n["V19"],
    }
    lines = [
        f"VERIFY base={rev} units_old={s['units_old']} units_new={s['units_new']} missing={s['missing']} "
        f"duplicate={s['duplicate']} extra={s['extra']} body_diff={s['body_diff']} unlisted_rewrite={s['unlisted_rewrite']}",
        f"VERIFY d1_sites={s['d1_new']}/{s['d1_old']} relimports={s['relimports']} css={s['css']} "
        f"bare_d1={s['bare_d1']} pins={s['pins_ok']}/{s['pins_total']} reexports_missing={s['reexports_missing']} "
        f"fresh_imports={s['fresh_ok']}/{s['fresh_total']} cycles={s['cycles']} caps_over={s['caps_over']} "
        f"old_files={s['old_files']} placement={s['placement']} header={s['header']} css_fail={s['css_fail']} "
        f"imports_equiv={s['equiv']} names={s['names']} tc_shape={s['tc_shape']}",
    ]
    return lines, s, fails


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="verify.py")
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--base-rev", required=True)
    ap.add_argument("--map", required=True, type=Path, dest="map_path")
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--py", default=sys.executable, help="interpreter for the subprocess (runtime) checks")
    ap.add_argument("--state", type=Path, default=None, help="scratch HOME/XDG/TMPDIR root for subprocesses")
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    a = parse_args(argv)
    tree = a.repo.resolve()
    mapd = json.loads(a.map_path.read_text(encoding="utf-8"))
    own_state = a.state is None
    state = vr.default_state() if own_state else a.state
    try:
        run = vr.Runner(a.py, tree, state)
        results = [analyse(tree, a.base_rev, mapd, p, run) for p in PKGS]
    finally:
        if own_state:
            shutil.rmtree(state, ignore_errors=True)
    lines, stats, fails = summarize(a.base_rev, results, vs.old_files_present(tree))
    out = list(lines) + [f"VERIFY FAIL {c}: {m}" for c, m in sorted(fails, key=lambda x: int(x[0][1:]))]
    out.append("VERIFY FAIL" if fails else "VERIFY OK")
    print("\n".join(out))
    if a.json:
        a.json.write_text(json.dumps({"base": a.base_rev, "stats": stats, "failures":
                                      [{"check": c, "detail": m} for c, m in fails]}, indent=1), encoding="utf-8")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
