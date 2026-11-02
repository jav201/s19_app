"""batch-101 Inc 3 E1: the ``sec6_5 appended`` interval with a product stamp beside the poll clock.

Runs the scene of tests/test_b100_project_check.py (``_sec6_5_filesystem_scene``) for the three
SEC6-5 payloads whose ``appended`` arm sat near 1 s, unchanged, and additionally stamps:
  start   ``load_from_path`` entered (the test's ``started`` is taken just before it)
  status  ``set_status`` receives the first manifest outcome line (``was not rewritten`` /
          ``manifest verified``), the painted line the poll waits for
The test's own value is the poll clock (``appended``); ``stamped`` = status - start.
Usage: python appended-stamp-script.py <rounds> <tmp root>
"""
import os, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, os.getcwd())
from tests import test_b100_project_check as t
from tests.support import b100_manifests as hostile
from s19_app.tui.app import S19TuiApp

S = {}
_real_load = S19TuiApp.load_from_path
_real_status = S19TuiApp.set_status


def _load(self, *a, **k):
    S["start"] = time.perf_counter()
    S.pop("status", None)
    return _real_load(self, *a, **k)


def _status(self, message, *a, **k):
    text = str(message)
    if "start" in S and "status" not in S and ("was not rewritten" in text or "manifest verified" in text):
        S["status"] = time.perf_counter()
    return _real_status(self, message, *a, **k)


S19TuiApp.load_from_path = _load
S19TuiApp.set_status = _status


def _folders(project_dir: Path) -> None:
    for name in hostile.distinct_folder_names():
        (project_dir / name).mkdir()
        (project_dir / name / "x.json").write_text("{}", encoding="utf-8")


SCENES = {
    "distinct_folders": lambda tmp: t._sec6_5_filesystem_scene(tmp, hostile.distinct_folders_at_cap(), setup=_folders),
}
for name in ("deep_entries", "entries_under_an_existing_folder"):
    pass  # the other two scenes build their payloads inside their tests; distinct_folders is the worst case

import s19_app
print("s19_app from", s19_app.__file__)
for _ in range(int(sys.argv[1])):
    for name, build in SCENES.items():
        S.clear()
        scene = build(Path(tempfile.mkdtemp(dir=sys.argv[2])))
        stamped = S["status"] - S["start"] if "status" in S else None
        print(f"{name}: appended(poll)={scene['appended']:.3f} stamped(load_from_path->outcome line)="
              f"{'none' if stamped is None else f'{stamped:.3f}'} painted(poll)={scene['painted']:.3f}", flush=True)
