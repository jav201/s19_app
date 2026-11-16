"""Runtime checks V9/V10/V11/V13/V16/V17: every one runs `verify_probe.py` in a SUBPROCESS (RU-12).

The verifier never imports `s19_app` itself. Each subprocess gets an isolated environment
(env -i style), stdin from the null device, and the interpreter given by `--py`.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from verify_units import NEW_DIRS

PROBE = Path(__file__).resolve().parent / "verify_probe.py"
PINS = ["on_button_pressed", "on_flow_execution_panel_external_step_confirmed", "__init__", "compose",
        "on_mount", "check_action", "on_event", "action_show_help_panel", "watch_current_file",
        "copy_to_clipboard", "action_help_quit", "action_quit"]


class Runner:
    def __init__(self, py: str, tree: Path, state: Path, timeout: int = 900) -> None:
        self.py, self.tree, self.state, self.timeout = py, tree, state, timeout
        for d in ("zq_iso_user", "x/c", "x/d", "x/k", "x/s", "tmp"):
            (state / d).mkdir(parents=True, exist_ok=True)

    def env(self) -> dict[str, str]:
        s = str(self.state)
        return {"PATH": "/usr/bin:/bin", "HOME": f"{s}/zq_iso_user", "XDG_CONFIG_HOME": f"{s}/x/c",
                "XDG_DATA_HOME": f"{s}/x/d", "XDG_CACHE_HOME": f"{s}/x/k", "XDG_STATE_HOME": f"{s}/x/s",
                "TMPDIR": f"{s}/tmp", "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8",
                "PYTHONIOENCODING": "utf-8", "TERM": "xterm-256color"}

    def probe(self, mode: str, spec: dict, tag: str) -> dict:
        spec_file = self.state / "tmp" / f"spec_{tag}.json"
        spec_file.write_text(json.dumps({**spec, "tree": str(self.tree)}), encoding="utf-8")
        try:
            r = subprocess.run([self.py, "-I", str(PROBE), mode, str(spec_file)], cwd=self.tree, env=self.env(),
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return {"errors": [f"timeout after {self.timeout}s"]}
        finally:
            spec_file.unlink(missing_ok=True)
        lines = [ln for ln in r.stdout.splitlines() if ln.startswith("PROBE:")]
        if not lines:
            tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
            return {"errors": [f"no probe result (rc={r.returncode}): {' | '.join(tail)[:300]}"]}
        return json.loads(lines[-1][6:])


def homes(mapd: dict, pkg: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for t in mapd[pkg]["top"]:
        if t["module"] in ("imports", "__init__"):
            continue
        for n in t["names"] or [t["key"]]:
            out[n] = t["module"]
    return out


def runtime_checks(run: Runner, mapd: dict, pkg: str) -> tuple[list[tuple[str, str]], dict]:
    """[(check id, message)] failures and a stats dict for one package."""
    dotted = f"s19_app.tui.{pkg}"
    h = homes(mapd, pkg)
    spec = {"pkg": dotted, "class_checks": pkg == "app", "pins": PINS,
            "reexports": [{"name": n, "home": h.get(n)} for n in mapd[pkg]["reexports"]]}
    res = run.probe("runtime", spec, f"rt_{pkg}")
    fails: list[tuple[str, str]] = [("V11" if pkg != "app" else "V9", f"{pkg}: {e}") for e in res.get("errors", [])]
    stats = {"pins_ok": 0, "pins_total": 0, "reexports_missing": 0}
    if pkg == "app":
        fails += _class_fails(res, mapd, stats)
    miss, notsame = res.get("reexport_missing", []), res.get("reexport_notsame", [])
    stats["reexports_missing"] = len(miss) + len(notsame)
    fails += [("V11", f"{pkg}: re-export {n} is missing") for n in miss]
    fails += [("V11", f"{pkg}: re-export {n} is not the home module's object") for n in notsame]
    return fails, stats


def _class_fails(res: dict, mapd: dict, stats: dict) -> list[tuple[str, str]]:
    from verify_static import header_bases

    out: list[tuple[str, str]] = []
    if "pins_missing" in res:
        stats["pins_total"] = res["pins_total"]
        stats["pins_ok"] = res["pins_total"] - len(res["pins_missing"])
        out += [("V9", f"S19TuiApp.__dict__ has no {n}") for n in res["pins_missing"]]
    if "bases" in res:
        want = header_bases(mapd)
        if res["bases"] != want:
            out.append(("V10", f"S19TuiApp.__bases__ {res['bases']} != {want}"))
        out += [("V10", f"mixin bases: {m}") for m in res["mixin_bases_bad"]]
        out += [("V10", f"name {n} defined in {', '.join(o)}") for n, o in res["dup_names"].items()]
    if "css" in res and not res["css"]["ok"]:
        out.append(("V16", f"CSS resolves to {res['css']['got']}, expected {res['css']['want']} (existing file)"))
    return out


def fresh_import_checks(run: Runner, modules: list[str]) -> tuple[list[tuple[str, str]], int]:
    def one(m: str) -> tuple[str, list[str]]:
        return m, run.probe("import", {"module": m}, "imp_" + m.replace(".", "_")).get("errors", [])

    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(one, modules))
    fails = [("V13", f"{m}: {e}") for m, errs in results for e in errs]
    return fails, sum(1 for _, errs in results if not errs)


def external_import_names(pkg: str, stem: str, mod: ast.Module) -> list[str]:
    """Names bound by top-level imports that reach OUTSIDE the package."""
    dotted = f"s19_app.tui.{pkg}"
    names: list[str] = []
    for n in mod.body:
        if isinstance(n, ast.Import):
            names += [(a.asname or a.name).split(".")[0] for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            inside = n.level == 1 or (n.level == 0 and (n.module or "").startswith(dotted))
            if not inside and n.module != "__future__":
                names += [a.asname or a.name for a in n.names if a.name != "*"]
    return names


def equivalence_checks(run: Runner, tree: Path, pkg: str, old_text: str, parsed: dict[str, ast.Module],
                       names_spec: dict) -> list[tuple[str, str]]:
    """V17 (imports bind the old objects) and the runtime half of V18 (`names_spec`: deps_module/deps_attrs/imported_d1)."""
    old_name = f"_verify_old_{pkg}"
    old_file = tree / "s19_app" / "tui" / f"{old_name}.py"
    dotted = f"s19_app.tui.{pkg}"
    mods = []
    for stem, mod in sorted(parsed.items()):
        names = external_import_names(pkg, stem, mod)
        if names:
            mods.append({"module": dotted if stem == "__init__" else f"{dotted}.{stem}", "names": names})
    try:
        old_file.write_text(old_text, encoding="utf-8", newline="\n")
        res = run.probe("equiv", {"old_mod": f"s19_app.tui.{old_name}", "modules": mods, **names_spec}, f"eq_{pkg}")
    finally:
        old_file.unlink(missing_ok=True)
        for pyc in (tree / "s19_app" / "tui" / "__pycache__").glob(f"{old_name}*"):
            pyc.unlink(missing_ok=True)
    out = [("V17", f"{pkg}: {e}") for e in res.get("errors", [])] + [("V17", m) for m in res.get("mismatch", [])]
    out += [("V18", f"{pkg}: runtime: deps.{x} does not exist on the deps module") for x in res.get("deps_missing", [])]
    return out + [("V18", f"{pkg}: runtime: deps.{x} is not the object the old module binds")
                  for x in res.get("deps_different", [])]


def package_exists(tree: Path, pkg: str) -> bool:
    return (tree / NEW_DIRS[pkg] / "__init__.py").is_file()


def dotted_modules(pkg: str, stems: list[str]) -> list[str]:
    base = f"s19_app.tui.{pkg}"
    return [base if s == "__init__" else f"{base}.{s}" for s in stems]


def default_state() -> Path:
    import tempfile

    return Path(tempfile.mkdtemp(prefix="verify_state_", dir=os.environ.get("TMPDIR")))
