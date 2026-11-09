"""batch-101 Inc 12 E1 pilot: the driven half of reproducing F-34, F-35 and F-51 on the base tree.

Run from the worktree root with PYTHONPATH set to it; prints the package path
first. Each part runs the app headless (``run_test``) on its own temporary
base. The static half is ``i12e1-census.py``.
"""
import asyncio
import os
import sys
import tempfile
import time
from importlib.metadata import version
from pathlib import Path

sys.path.insert(0, os.getcwd())

import s19_app  # noqa: E402

print("s19_app.__file__ =", Path(s19_app.__file__).resolve().relative_to(Path.cwd().resolve()))
print("textual", version("textual"))

from textual.binding import Binding  # noqa: E402
from textual.widgets import Select, TextArea  # noqa: E402

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.command_bar import CommandBar  # noqa: E402
from s19_app.tui.flow_screens import FlowBuilderPanel  # noqa: E402
from s19_app.tui.screens import ReportViewerScreen  # noqa: E402
from tests.b97_fixtures import (  # noqa: E402
    fx_project,
    import_lanes,
    load_project,
    make_project,
    open_check_editor,
    open_flow_builder,
    run_lanes,
)
from tests.b97_probes import is_displayed, settle, settled  # noqa: E402

SIZE = (118, 54)


def ids(root):
    return {w.id for w in root.query("*") if w.id}


def shown(root):
    return {w.id for w in root.query("*") if w.id and is_displayed(w)}


def top(app) -> str:
    return type(app.screen).__name__


# --------------------------------------------------------------------- F-34
async def pilot_f34(base: Path) -> None:
    print("\n== F-34: the three view aliases and the keys 1, 2, 3")
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        bound = {b.action if isinstance(b, Binding) else b[1] for b in S19TuiApp.BINDINGS}
        palette = set(app.query_one(CommandBar).visible_palette_actions())
        for action in ("view_main", "view_alt", "view_mac"):
            print(f"{action}: in BINDINGS {action in bound} | in the palette {action in palette}"
                  f" | method on the app {hasattr(app, 'action_' + action)}")
        print("palette commands:", len(palette))
        for key in ("2", "3", "1"):
            await pilot.press(key)
            await settle(pilot)
            print(f"key {key} -> shown window {app._active_screen_key}")


# --------------------------------------------------------------------- F-35
async def pilot_f35(base: Path) -> None:
    print("\n== F-35: widgets mounted in the window that no driven state displays")
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        await fx_project(app)

        # -- Check Editor: the demo A2L loaded, then the three card tabs
        panel = await open_check_editor(app, pilot)
        mounted = ids(panel)
        at_open = sorted(i for i in mounted if not panel.query_one(f"#{i}").display)
        seen = shown(panel)
        for chip in ("check_tab_fields", "check_tab_json", "check_tab_addendum"):
            panel.query_one(f"#{chip}").press()
            await settle(pilot)
            seen |= shown(panel)
        print(f"Check Editor: {len(mounted)} ids mounted; display off when the window opens: {at_open}")
        print("  never displayed over the states [open with the demo A2L, Fields tab, JSON tab, Addendum tab]:", sorted(mounted - seen))
        print("  the Addendum tab shows the addendum preview:", is_displayed(panel.query_one("#check_addendum_preview")))

        # -- Flow Builder: every kind chip, Variables open, a notice, three blocks
        panel = await open_flow_builder(app, pilot)
        mounted = ids(panel)
        at_open = sorted(i for i in mounted if not panel.query_one(f"#{i}").display)
        seen = shown(panel)
        kinds = []
        for _label, kind in FlowBuilderPanel._KIND_OPTIONS:
            panel.query_one(f"#flow_palette_{kind}").press()
            await settle(pilot)
            kinds.append((kind, str(panel.query_one("#flow_kind", Select).value)))
            seen |= shown(panel)
        print(f"Flow Builder: {len(mounted)} ids mounted; display off when the window opens: {at_open}")
        print("  kind chip pressed -> value of the hidden kind select:", kinds)
        panel.query_one("#flow_funnel_toggle").press()
        await settle(pilot)
        seen |= shown(panel)
        panel.query_one("#flow_funnel_toggle").press()
        await settle(pilot)
        panel.query_one("#flow_palette_source").press()
        await settle(pilot)
        panel.query_one("#flow_ref").value = ""
        panel.query_one("#flow_add").press()
        await settle(pilot)
        seen |= shown(panel)
        counts = {"_canvas_text": 0, "_blocks_text": 0}
        canvas, listing = panel._canvas_text, panel._blocks_text

        def spy(name, fn):
            def wrapped():
                counts[name] += 1
                return fn()
            return wrapped

        panel._canvas_text = spy("_canvas_text", canvas)
        panel._blocks_text = spy("_blocks_text", listing)
        for _ in range(3):
            panel.query_one("#flow_ref").value = "prg.s19"
            panel.query_one("#flow_add").press()
            await settle(pilot)
        seen |= shown(panel)
        print(f"  {len(panel._blocks)} blocks added with Add: the hidden canvas painted {counts['_canvas_text']} times,"
              f" the hidden list {counts['_blocks_text']} times")
        start = time.perf_counter()
        for _ in range(50):
            canvas()
        print(f"  one paint of the hidden canvas with 3 blocks: {(time.perf_counter() - start) / 50 * 1000:.2f} ms (LAN host)")
        print("  never displayed over the states [open, 7 kind chips, Variables open, Add notice, 3 blocks]:",
              sorted(mounted - seen))

        # -- Flow Execution: no lane, a lane that waits, a saved set
        app.action_show_screen("flow_execution")
        await settle(pilot, 6)
        seen = shown(app.query_one("#fx_panel"))
        fx = await import_lanes(app, pilot, "flash_chain")
        mounted = ids(fx)
        seen |= shown(fx)
        await run_lanes(app, pilot, fx)
        await settled(pilot, lambda: fx.query_one("#fx_required").display, "the lane waits")
        seen |= shown(fx)
        fx.query_one("#fx_set_name").value = "s"
        fx.query_one("#fx_save").press()
        await settled(pilot, lambda: fx.query_one("#fx_notice").display, "the save notice")
        seen |= shown(fx)
        print(f"Flow Execution: {len(mounted)} ids mounted after one import")
        print("  never displayed over the states [no lane, one lane, the lane waits, set saved]:", sorted(mounted - seen))


# --------------------------------------------------------------------- F-51
async def pilot_f51(base: Path) -> None:
    print("\n== F-51: escape on the Reports dialog")
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        make_project(app, "proj1")
        project = await load_project(app, "proj1")
        (project / "reports").mkdir(exist_ok=True)
        (project / "reports" / "20261106T100000Z-report.md").write_text("# Report one\n\nbody\n", encoding="utf-8")
        (project / "reports" / "20261106T110000Z-report.md").write_text("# Report two\n", encoding="utf-8")
        (project / "filters").mkdir(exist_ok=True)
        (project / "filters" / "f1.json").write_text("{}", encoding="utf-8")

        async def open_reports():
            await pilot.press("t")
            await settled(pilot, lambda: isinstance(app.screen, ReportViewerScreen), "the Reports dialog opens")
            await settle(pilot)
            return app.screen

        screen = await open_reports()
        print("ReportViewerScreen.BINDINGS:", [(b.key, b.action, b.priority) for b in ReportViewerScreen.BINDINGS])
        try:
            print("escape among the open dialog's active bindings:", "escape" in app.screen.active_bindings)
        except Exception as exc:  # pragma: no cover - evidence only
            print("active bindings not readable:", type(exc).__name__)
        print("focus when the dialog opens:", getattr(app.focused, "id", None))
        print("declared-regions box tab_behavior:", screen.query_one("#report_declared_regions", TextArea).tab_behavior)
        await pilot.press("enter")
        await settle(pilot)
        print("enter on the list shows:", screen.selected_path.name if screen.selected_path else None)
        typed = {"report_declared_regions", "report_filter_path", "report_context_bytes"}
        for target in ("report_list", "report_markdown_scroll", "report_declared_regions", "report_filter_select",
                       "report_filter_path", "report_context_bytes", "report_generate", "report_close",
                       "open_folder_reports", "window_help_reports"):
            if not isinstance(app.screen, ReportViewerScreen):
                screen = await open_reports()
            widget = app.screen.query_one(f"#{target}")
            widget.focus()
            await settle(pilot)
            if target in typed:
                await pilot.press("x")
                await settle(pilot)
            await pilot.press("escape")
            await settle(pilot)
            print(f"focus {target:24s}{' + typed x' if target in typed else '':11s} escape -> top screen {top(app)};"
                  f" focus after {getattr(app.focused, 'id', None)}")
        select = app.screen.query_one("#report_filter_select", Select)
        select.focus()
        await settle(pilot)
        await pilot.press("enter")
        await settle(pilot)
        print("dropdown: enter on the filter dropdown opens it:", select.expanded)
        await pilot.press("escape")
        await settle(pilot)
        print("dropdown: escape -> open", select.expanded, "| top screen", top(app))
        await pilot.press("escape")
        await settle(pilot)
        print("dropdown: second escape -> top screen", top(app))
        app.screen.query_one("#report_list").focus()
        await settle(pilot)
        await pilot.press("question_mark")
        await settle(pilot)
        print("? on the list opens:", top(app), "| stack", [type(s).__name__ for s in app.screen_stack])
        await pilot.press("escape")
        await settle(pilot)
        print("escape in the help window -> top screen", top(app))
        app.screen.query_one("#report_close").press()
        await settle(pilot)
        print("Close button -> top screen", top(app))
        print("reports on disk after all of the above:", len(list((project / "reports").glob("*.md"))))

    print("-- a project with no report")
    app = S19TuiApp(base_dir=base / "empty")
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        make_project(app, "proj2")
        await load_project(app, "proj2")
        await pilot.press("t")
        await settled(pilot, lambda: isinstance(app.screen, ReportViewerScreen), "the Reports dialog opens")
        await settle(pilot)
        print("focus when the empty dialog opens:", getattr(app.focused, "id", None))
        await pilot.press("escape")
        await settle(pilot)
        print("escape -> top screen", top(app))


if __name__ == "__main__":
    runs = Path(os.environ.get("I12E1_RUNS", tempfile.gettempdir()))
    runs.mkdir(parents=True, exist_ok=True)
    for name, fn in (("f34", pilot_f34), ("f35", pilot_f35), ("f51", pilot_f51)):
        with tempfile.TemporaryDirectory(prefix=f"i12e1-{name}-", dir=runs) as tmp:
            asyncio.run(fn(Path(tmp)))
