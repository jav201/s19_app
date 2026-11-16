"""Runs INSIDE a verifier subprocess (python -I <this> <mode> <spec.json>); never imported by verify.py.

Modes: `import` (fresh import of one module), `runtime` (V9/V10/V11/V16), `equiv` (V17).
Prints one line `PROBE:<json>`.
"""
from __future__ import annotations

import importlib
import inspect
import json
import sys
from pathlib import Path

AUTO = {"__module__", "__qualname__", "__doc__", "__dict__", "__weakref__", "__firstlineno__",
        "__static_attributes__", "__annotations__", "__annotate__", "__annotate_func__", "__classdictcell__",
        "__annotations_cache__", "__annotate_cache__"}


def setup(tree: str) -> None:
    sys.path.insert(0, tree)
    import s19_app

    if not Path(s19_app.__file__).resolve().is_relative_to(Path(tree).resolve()):
        raise RuntimeError(f"s19_app imported from outside the tree: {s19_app.__file__}")


def mode_import(spec: dict) -> dict:
    mod = importlib.import_module(spec["module"])
    if not Path(mod.__file__).resolve().is_relative_to(Path(spec["tree"]).resolve()):
        return {"errors": [f"{spec['module']} resolved outside the tree: {mod.__file__}"]}
    return {"errors": []}


def _rt_pins(pkg, spec: dict, out: dict) -> None:
    cls = pkg.S19TuiApp
    out["pins_missing"] = [n for n in spec["pins"] if n not in vars(cls)]
    out["pins_total"] = len(spec["pins"])


def _rt_header(pkg, spec: dict, out: dict) -> None:
    cls = pkg.S19TuiApp
    out["bases"] = [b.__name__ for b in cls.__bases__]
    mixins = [b for b in cls.__bases__ if b.__name__.endswith("Mixin")]
    out["mixin_bases_bad"] = [f"{m.__name__}: {[b.__name__ for b in m.__bases__]}" for m in mixins
                              if m.__bases__ != (object,)]
    owners: dict[str, list[str]] = {}
    for c in [cls] + mixins:
        for name in vars(c):
            if name not in AUTO:
                owners.setdefault(name, []).append(c.__name__)
    out["dup_names"] = {n: o for n, o in sorted(owners.items()) if len(o) > 1}


def _rt_reexports(pkg, spec: dict, out: dict) -> None:
    missing, notsame = [], []
    for item in spec["reexports"]:
        name, home = item["name"], item.get("home")
        if not hasattr(pkg, name):
            missing.append(name)
        elif home:
            hm = importlib.import_module(f"{spec['pkg']}.{home}")
            if getattr(pkg, name) is not getattr(hm, name, object()):
                notsame.append(f"{name} (home {home})")
    out["reexport_missing"], out["reexport_notsame"] = missing, notsame


def _rt_css(pkg, spec: dict, out: dict) -> None:
    cls = pkg.S19TuiApp
    got = (Path(inspect.getfile(cls)).parent / cls.CSS_PATH).resolve()
    want = (Path(spec["tree"]) / "s19_app/tui/styles.tcss").resolve()
    out["css"] = {"got": str(got), "want": str(want), "ok": got == want and got.exists()}


def mode_runtime(spec: dict) -> dict:
    out: dict = {"errors": []}
    pkg = importlib.import_module(spec["pkg"])
    steps = [("pins", _rt_pins), ("header", _rt_header), ("css", _rt_css)] if spec["class_checks"] else []
    steps.append(("reexports", _rt_reexports))
    for label, fn in steps:
        try:
            fn(pkg, spec, out)
        except Exception as e:  # noqa: BLE001 - report, keep going
            out["errors"].append(f"{label}: {type(e).__name__}: {e}")
    return out


def mode_equiv(spec: dict) -> dict:
    old = importlib.import_module(spec["old_mod"])
    bad = []
    for item in spec["modules"]:
        new = importlib.import_module(item["module"])
        for name in item["names"]:
            if not hasattr(old, name):
                bad.append(f"{item['module']}.{name}: the old module binds no such name")
            elif getattr(new, name, object()) is not getattr(old, name):
                bad.append(f"{item['module']}.{name}: bound to a different object than the old module's")
    return {"errors": [], "mismatch": bad, **_deps_names(spec, old)}


def _deps_names(spec: dict, old) -> dict:
    """V18 runtime: every `deps.X` used in the package exists; imported D1 names are the old module's objects."""
    if not spec.get("deps_module"):
        return {"deps_missing": [], "deps_different": []}
    dm = importlib.import_module(spec["deps_module"])
    gone, other = object(), object()
    return {"deps_missing": [x for x in spec["deps_attrs"] if not hasattr(dm, x)],
            "deps_different": [x for x in spec["imported_d1"] if getattr(dm, x, gone) is not getattr(old, x, other)]}


def main() -> int:
    mode, spec_path = sys.argv[1], sys.argv[2]
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    try:
        setup(spec["tree"])
        res = {"import": mode_import, "runtime": mode_runtime, "equiv": mode_equiv}[mode](spec)
    except BaseException as e:  # noqa: BLE001
        res = {"errors": [f"{type(e).__name__}: {e}"]}
    print("PROBE:" + json.dumps(res))
    return 0 if not res["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
