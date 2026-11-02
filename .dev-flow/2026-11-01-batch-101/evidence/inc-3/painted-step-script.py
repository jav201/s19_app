"""batch-101 Inc 3 E1: where the bimodal ``painted`` interval of the TC-B100-61 / SEC6-5 arms comes from.

Scene: tests/test_b100_project_check.py::test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second
(every capped array at 1 000 bad entries), driven the way the test drives it (Load dialog, click
``#load_ok``, then the test's own wait for ``#result_summary`` with a height). Every mark is seconds
after the click returned (``pressed``); the test's ``painted`` value is recomputed exactly as the test
does (now - max(pressed, _load_returned_at)). Marks:
  load_start      the routed load handler is entered (deferred by call_after_refresh)
  install_start / install_end   the one install callback (it pushes LoadResultScreen)
  compose_start / compose_end   LoadResultScreen.compose iterated
  layout_first    first LoadResultScreen._refresh_layout entered / left (layout_first_end)
  seen            the test's predicate first true
  signal_painted  candidate product stamp (public Textual API): the first publish of the pushed
                  LoadResultScreen's ``screen_layout_refresh_signal`` (sent after a layout and its
                  compositor refresh) at which ``#result_summary`` has a height; subscribed
                  ``immediate=True`` by the app from a wrapper of ``push_screen``
With env PAINT_PROFILE=<path>, the main thread is profiled from the click's return to ``seen``
(one run) and the stats are dumped to <path>.
Usage: python painted-step-script.py <runs> <tmp root>
"""
import asyncio, cProfile, os, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, os.getcwd())
from tests import test_b100_project_check as t
from tests.support import b100_manifests as hostile
from tests.support import b100_projects as projects
from s19_app.tui.app import S19TuiApp
from s19_app.tui import screens as screens_module

M = {}


def mark(key):
    M.setdefault(key, time.perf_counter())


_real_compose = screens_module.LoadResultScreen.compose


def _compose(self):
    mark("compose_start")
    yield from _real_compose(self)
    mark("compose_end")


screens_module.LoadResultScreen.compose = _compose
_real_layout = screens_module.LoadResultScreen._refresh_layout
LAYOUTS = []


def _layout(self, *a, **k):
    mark("layout_first")
    started = time.perf_counter()
    try:
        return _real_layout(self, *a, **k)
    finally:
        mark("layout_first_end")
        try:
            height = self.query_one("#result_summary").size.height
        except Exception:
            height = None
        LAYOUTS.append((started, time.perf_counter(), height))


screens_module.LoadResultScreen._refresh_layout = _layout
_real_comp = screens_module.LoadResultScreen._compositor_refresh
FRAMES = []


def _comp(self, *a, **k):
    started = time.perf_counter()
    try:
        return _real_comp(self, *a, **k)
    finally:
        FRAMES.append((started, time.perf_counter()))


screens_module.LoadResultScreen._compositor_refresh = _comp


async def drive(tmp: Path):
    M.clear()
    LAYOUTS.clear()
    FRAMES.clear()
    prof = cProfile.Profile() if os.environ.get("PAINT_PROFILE") else None
    base = tmp / "app"
    project_dir = projects.copy_sources(t._workarea(base) / "P", projects.CASE01_DIR, "firmware.s19")
    t._write_manifest(project_dir, hostile.dumps(hostile.every_array_at_cap_all_bad()))
    app = S19TuiApp(base_dir=base)
    real_load = app._handle_load_project

    def _timed(name, *args, **kwargs):
        mark("load_start")
        app._load_started_at = time.perf_counter()
        real_load(name, *args, **kwargs)

    real_install = app._install_prepared_project

    def _installed(prepared):
        mark("install_start")
        real_install(prepared)
        mark("install_end")
        app._load_returned_at = time.perf_counter()

    real_push = app.push_screen

    def _push(screen, *args, **kwargs):
        if isinstance(screen, screens_module.LoadResultScreen):
            def _published(published):
                try:
                    if published.query_one("#result_summary").size.height > 0:
                        mark("signal_painted")
                except Exception:
                    pass
            screen.screen_layout_refresh_signal.subscribe(app, _published, immediate=True)
        return real_push(screen, *args, **kwargs)

    app.push_screen = _push
    app._handle_load_project = _timed
    app._install_prepared_project = _installed
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        await t._open_panel_through_the_dialog(pilot, app)
        pressed = time.perf_counter()
        if prof:
            prof.enable()

        def seen():
            ok = len(app.screen.query("#result_summary")) > 0 and app.screen.query_one("#result_summary").size.height > 0
            if ok:
                mark("seen")
            return ok

        await t._wait_for(pilot, seen, "the painted Load-result panel", attempts=4000)
        painted = time.perf_counter() - t._paint_clock_start(app, pressed)
        if prof:
            prof.disable()
            prof.dump_stats(os.environ["PAINT_PROFILE"])
    rel = {k: round(v - pressed, 3) for k, v in sorted(M.items(), key=lambda kv: kv[1])}
    stamp = M["signal_painted"] - M["install_end"] if "signal_painted" in M and "install_end" in M else None
    print(f"painted={painted:.3f} stamped(install_end->signal_painted)={stamp if stamp is None else round(stamp, 3)}", rel, flush=True)
    print("   frames written for the panel (start, end):", [(round(a - pressed, 3), round(b - pressed, 3)) for a, b in FRAMES][:6], flush=True)
    print("   layouts (start, end, summary height):", [(round(a - pressed, 3), round(b - pressed, 3), h) for a, b, h in LAYOUTS], flush=True)


import s19_app
print("s19_app from", s19_app.__file__)
for _ in range(int(sys.argv[1])):
    asyncio.run(drive(Path(tempfile.mkdtemp(dir=sys.argv[2]))))
