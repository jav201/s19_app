"""batch-101 Inc 3 E1: where the ``sec6_5 appended`` interval goes (distinct-folders scene).

Marks, seconds after ``load_from_path`` is entered: the variant-append sync
(``_sync_loaded_file_to_project``, main thread, posted by the file-load worker) entered and left,
and the outcome line painted. With env APPEND_PROFILE=<path>, the sync is profiled once and dumped.
Usage: python appended-split-script.py <rounds> <tmp root>
"""
import cProfile, os, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, os.getcwd())
from tests import test_b100_project_check as t
from tests.support import b100_manifests as hostile
from s19_app.tui.app import S19TuiApp

S = {}
PROF = cProfile.Profile() if os.environ.get("APPEND_PROFILE") else None
_real_load = S19TuiApp.load_from_path
_real_status = S19TuiApp.set_status
_real_sync = S19TuiApp._sync_loaded_file_to_project


def _load(self, *a, **k):
    S.clear()
    S["start"] = time.perf_counter()
    return _real_load(self, *a, **k)


def _status(self, message, *a, **k):
    text = str(message)
    if "start" in S and "status" not in S and ("was not rewritten" in text or "manifest verified" in text):
        S["status"] = time.perf_counter()
    return _real_status(self, message, *a, **k)


def _sync(self, *a, **k):
    if "start" in S:
        S["sync_start"] = time.perf_counter()
        if PROF:
            PROF.enable()
    try:
        return _real_sync(self, *a, **k)
    finally:
        if "start" in S:
            if PROF:
                PROF.disable()
            S["sync_end"] = time.perf_counter()


S19TuiApp.load_from_path = _load
S19TuiApp.set_status = _status
S19TuiApp._sync_loaded_file_to_project = _sync


def _folders(project_dir: Path) -> None:
    for name in hostile.distinct_folder_names():
        (project_dir / name).mkdir()
        (project_dir / name / "x.json").write_text("{}", encoding="utf-8")


import s19_app
print("s19_app from", s19_app.__file__)
for _ in range(int(sys.argv[1])):
    t._sec6_5_filesystem_scene(Path(tempfile.mkdtemp(dir=sys.argv[2])), hostile.distinct_folders_at_cap(), setup=_folders)
    print({k: round(v - S["start"], 3) for k, v in sorted(S.items(), key=lambda kv: kv[1])}, flush=True)
if PROF:
    PROF.dump_stats(os.environ["APPEND_PROFILE"])
