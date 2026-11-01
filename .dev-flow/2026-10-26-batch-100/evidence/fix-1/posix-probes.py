"""Fix round 1 posix probes (no Linux host): pure code paths driven with posix inputs."""
import ntpath, posixpath, os
from s19_app.tui.workspace import _recent_entry_ok, _placed_name_candidates

print("== CI9b-3: store entry check (LLR-172.2e, host-neutral regex) ==")
for p in ["/tmp/pytest-of-runner/pytest-0/x/src/here.s19",
          "/tmp/pytest-of-runner/pytest-0/x/missing/gone.s19",
          r"Q:\nowhere\fw.s19", r"C:\src\here.s19", r"C:\missing\gone.s19"]:
    print(f"{p!r:60} kept={_recent_entry_ok({'path': p, 'kind': 's19'}) is not None}")

print("== CI11-3: the planner's free-name walk fold (project_gather_service.py:1707-1712) ==")
for mod in (ntpath, posixpath):
    folded = {mod.normcase("Changes.json")}
    name = next(c for c in _placed_name_candidates("changes.json") if mod.normcase(c) not in folded)
    print(f"{mod.__name__:10} normcase -> landing {name}")

print("== CI11-1: the save-as tail's two path forms for P/../elsewhere/x.json ==")
from pathlib import PurePosixPath, PureWindowsPath
for mod, pure in ((posixpath, PurePosixPath), (ntpath, PureWindowsPath)):
    root = "/w/.s19tool/workarea" if mod is posixpath else r"C:\w\.s19tool\workarea"
    P = pure(root) / "P"
    doc = P / ".." / "elsewhere" / "x.json"
    rel = doc.relative_to(P).as_posix()
    print(f"{mod.__name__:10} relative_to(P)={rel!r} has '..'={'..' in PurePosixPath(rel).parts}; abspath collapses to {mod.normpath(str(doc))!r}")
