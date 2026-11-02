"""Fix round 2 R-1 diagnosis: where the save-project arm of TC-B100-20 spends its time."""
import asyncio, json, sys, tempfile, time
from pathlib import Path
import os
sys.path.insert(0, os.environ["DBG_ROOT"])
from tests import test_b100_active_variant as t
from tests.support import b100_projects as projects
from s19_app.tui.app import S19TuiApp, SaveProjectPayload

async def drive(tmp: Path, sleepy: bool, noprog: bool = False):
    base = tmp / "app"
    project_dir = projects.seed_project_with_every_key(t._workarea(base))
    names = projects.real_files_under_a_chain(project_dir)
    m = projects.read_manifest(project_dir)
    m.update(batch=names, assignments={"firmware": names}, gathered={"patches": names})
    (project_dir / "project.json").write_text(json.dumps(m, separators=(",", ":")), encoding="utf-8")
    app = S19TuiApp(base_dir=base)
    marks = {}
    statuses = []
    real_set = app.set_status
    def cap(msg, *a, **k):
        statuses.append(str(msg))
        if any(o in str(msg) for o in t.WRITER_OUTCOMES) and "status" not in marks:
            marks["status"] = time.perf_counter()
        return real_set(msg, *a, **k)
    app.set_status = cap
    global BASE
    BASE = not hasattr(app, "_save_project_files")
    if BASE:
        app._save_project_files = lambda req: None
        app._on_project_saved = lambda o: None
    real_files = app._save_project_files
    def files(req):
        marks["worker_start"] = time.perf_counter()
        try:
            return real_files(req)
        finally:
            marks["worker_end"] = time.perf_counter()
    app._save_project_files = files
    real_saved = app._on_project_saved
    def saved(outcome):
        marks["commit_start"] = time.perf_counter()
        try:
            return real_saved(outcome)
        finally:
            marks["commit_end"] = time.perf_counter()
    app._on_project_saved = saved
    if noprog:
        app._progress_forwarder = lambda *a: (lambda done, total: None)
        app.call_from_thread = (lambda real: (lambda fn, *a, **k: None if getattr(fn, "__name__", "") == "step_busy" else real(fn, *a, **k)))(app.call_from_thread)
    async with app.run_test() as pilot:
        await pilot.pause()
        await t._open_seeded_project(pilot, app)
        statuses.clear()
        t0 = time.perf_counter()
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P",
            batch=tuple(names), assignments={"firmware": tuple(names)}))
        marks["handler_return"] = time.perf_counter()
        for _ in range(4000):
            if "status" in marks and ("commit_end" in marks or BASE):
                break
            await pilot.pause()
            if sleepy:
                await asyncio.sleep(0.01)
        marks["noticed"] = time.perf_counter()
    import s19_app; print(s19_app.__file__); print(("noprog " if noprog else "") + ("sleepy " if sleepy else "bare   "), {k: round(v - t0, 3) for k, v in sorted(marks.items(), key=lambda kv: kv[1])})

for sleepy, noprog in ((True, False), (True, True), (True, False), (True, True), (True, False), (True, True)):
    d = Path(tempfile.mkdtemp(dir=r"<HOME>/AppData/Local/Temp/s19f2"))
    asyncio.run(drive(d, sleepy, noprog))
