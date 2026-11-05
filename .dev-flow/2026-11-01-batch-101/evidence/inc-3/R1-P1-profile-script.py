"""batch-101 Inc 3 E1: where Save project at the TC-B100-20 composition spends its time.

Same scene as tests/test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_
finish_under_one_second[save-project] (1 000 real files at the end of a 31-folder chain recorded in
batch / assignments / gathered; re-save of the open project P). Marks are taken from t0 = just before
``_handle_save_dialog``. Mode ``marks`` runs N times without a profiler; mode ``profile`` runs once
with cProfile enabled inside the worker step (its own thread) and once around the handler and the
main-thread commit, and prints the top functions by cumulative time.
Usage: python R1-P1-profile-script.py <marks N | profile> <tmp root>

Experiments (env R1P1_EXP, comma-separated; runtime wrappers only, no source edit), to size the
candidate optimisations before E1 fixes a target:
  gather - the worker hands ``gather_project_artifacts`` each composition name once (order kept);
  memo   - one manifest read / serialize resolves each distinct entry text once: a clean result
           (a path returned, no finding appended) is reused for the same (walk, entry, mode).
"""
import asyncio, cProfile, io, json, os, pstats, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, os.getcwd())
from tests import test_b100_active_variant as t
from tests.support import b100_projects as projects
from s19_app.tui.app import S19TuiApp, SaveProjectPayload
import s19_app.tui.app as app_module
from s19_app.tui.services import manifest_writer as mw
from s19_app.tui.services import variant_execution_service as ves

EXP = {e for e in os.environ.get("R1P1_EXP", "").split(",") if e}
if "gather" in EXP:
    _real_gather = app_module.gather_project_artifacts

    def _gather_once(project_dir, *, composition_names=(), **kw):
        return _real_gather(project_dir, composition_names=list(dict.fromkeys(composition_names)), **kw)

    app_module.gather_project_artifacts = _gather_once
if "memo" in EXP:
    _real_resolve = ves._resolve_manifest_entry
    _memo = {}

    def _resolve_once(project_root, raw_entry, context, issues, mode=ves.ENTRY_MODE_DEFAULT, walk=None):
        key = (id(walk), raw_entry, mode) if walk is not None and isinstance(raw_entry, str) else None
        if key is not None and key in _memo and _memo[key][0] is walk:
            return _memo[key][1]
        before = len(issues)
        result = _real_resolve(project_root, raw_entry, context, issues, mode, walk)
        if key is not None and result is not None and len(issues) == before:
            _memo[key] = (walk, result)
        return result

    ves._resolve_manifest_entry = _resolve_once
    mw._resolve_manifest_entry = _resolve_once


async def drive(tmp: Path, profile: bool):
    base = tmp / "app"
    project_dir = projects.seed_project_with_every_key(t._workarea(base))
    names = projects.real_files_under_a_chain(project_dir)
    m = projects.read_manifest(project_dir)
    m.update(batch=names, assignments={"firmware": names}, gathered={"patches": names})
    (project_dir / "project.json").write_text(json.dumps(m, separators=(",", ":")), encoding="utf-8")
    app = S19TuiApp(base_dir=base)
    marks, statuses = {}, []
    profs = {"worker": cProfile.Profile(), "main": cProfile.Profile()}
    real_set = app.set_status

    def cap(msg, *a, **k):
        statuses.append(str(msg))
        if any(o in str(msg) for o in t.WRITER_OUTCOMES) and "status" not in marks:
            marks["status"] = time.perf_counter()
        return real_set(msg, *a, **k)

    app.set_status = cap
    real_files = app._save_project_files

    def files(req):
        marks["worker_start"] = time.perf_counter()
        if profile:
            profs["worker"].enable()
        try:
            return real_files(req)
        finally:
            if profile:
                profs["worker"].disable()
            marks["worker_end"] = time.perf_counter()

    app._save_project_files = files
    real_saved = app._on_project_saved

    def saved(outcome):
        marks["commit_start"] = time.perf_counter()
        if profile:
            profs["main"].enable()
        try:
            return real_saved(outcome)
        finally:
            if profile:
                profs["main"].disable()
            marks["commit_end"] = time.perf_counter()

    app._on_project_saved = saved
    async with app.run_test() as pilot:
        await pilot.pause()
        await t._open_seeded_project(pilot, app)
        statuses.clear()
        t0 = time.perf_counter()
        if profile:
            profs["main"].enable()
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P",
            batch=tuple(names), assignments={"firmware": tuple(names)}))
        if profile:
            profs["main"].disable()
        marks["handler_return"] = time.perf_counter()
        for _ in range(4000):
            if "status" in marks and "commit_end" in marks:
                break
            if os.environ.get("R1P1_QUIET"):
                # quiet waiter: the test side does not wake the app's loop while the worker runs
                await asyncio.sleep(0.25)
            else:
                await pilot.pause()
                await asyncio.sleep(0.01)
    rel = {k: round(v - t0, 3) for k, v in sorted(marks.items(), key=lambda kv: kv[1])}
    outcome = [s for s in statuses if any(o in s for o in t.WRITER_OUTCOMES)][:1]
    print(("profile " if profile else "marks   "), rel, outcome, flush=True)
    if profile:
        dump = os.environ.get("R1P1_DUMP")
        if dump:
            for key in ("main", "worker"):
                profs[key].dump_stats(f"{dump}-{key}.prof")
        for key in ("main", "worker"):
            out = io.StringIO()
            st = pstats.Stats(profs[key], stream=out)
            st.sort_stats("cumulative").print_stats(45)
            print(f"===== cProfile {key} (handler + commit on the main thread / worker step) =====")
            print(out.getvalue())
            out = io.StringIO()
            st = pstats.Stats(profs[key], stream=out)
            st.sort_stats("tottime").print_stats(25)
            print(f"===== cProfile {key} by tottime =====")
            print(out.getvalue())


mode = sys.argv[1]
root = Path(sys.argv[-1])
import s19_app
print("s19_app from", s19_app.__file__)
if mode == "marks":
    for _ in range(int(sys.argv[2])):
        asyncio.run(drive(Path(tempfile.mkdtemp(dir=root)), False))
else:
    asyncio.run(drive(Path(tempfile.mkdtemp(dir=root)), True))
