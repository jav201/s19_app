"""Probe (fix round 3, not a test of record): timeline of AT-B100-18."""
import time
from pathlib import Path

from tests.test_b100_workers import (
    W, trio, projects, ld, sd, neutral_focus, wait, is_quit_question, running, wait_exit, run,
)


def test_probe_quit_timeline(tmp_path: Path) -> None:
    base = tmp_path / "app"
    s = trio(W(base) / "S")
    projects.bulk_files(s, "flows", 2000)
    t0 = time.monotonic()
    ev = []

    def mark(what):
        ev.append((round(time.monotonic() - t0, 3), what))

    async def scenario(app, pilot, log):
        await ld.open_project_through_dialog(pilot, app, "S", confirm="enter")
        await projects.dismiss_load_result_panel(pilot, app)
        orig_begin, orig_end = app.begin_busy, app.end_busy

        def begin(key, *a, **k):
            mark(f"begin {key}")
            return orig_begin(key, *a, **k)

        def end(key, gen, outcome):
            mark(f"end {key} {outcome[:40]!r}")
            return orig_end(key, gen, outcome)

        app.begin_busy, app.end_busy = begin, end
        orig_answer, orig_exit = app._answer_quit, app.exit

        def answer(q):
            mark(f"_answer_quit({q}) runs={list(app._busy.runs)}")
            return orig_answer(q)

        def exit_(*a, **k):
            mark("app.exit called")
            return orig_exit(*a, **k)

        app._answer_quit, app.exit = answer, exit_
        mark("save dialog start")
        await sd.save_through_dialog(pilot, app, "S9")
        mark(f"save dialog closed runs={list(app._busy.runs)}")
        neutral_focus(app)
        await pilot.press("q")
        mark("q pressed")
        await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), "the quit question", 10)
        asked = is_quit_question(app.screen)
        mark(f"asked={asked} runs={list(app._busy.runs)}")
        if asked:
            await pilot.press("y")
            mark(f"y pressed runs={list(app._busy.runs)} running={running(app)}")
            for _ in range(4):
                await pilot.pause()
        mark(f"after 4 pauses running={running(app)}")
        exited = await wait_exit(app, 300)
        mark(f"exited={exited}")
        return asked

    run(base, scenario)
    for e in ev:
        print(e)
    target = W(base) / "S9"
    print("S9 manifest ok:", projects.read_manifest(target).get("files") == projects.file_records(target),
          len(list((target / "flows").iterdir())))
