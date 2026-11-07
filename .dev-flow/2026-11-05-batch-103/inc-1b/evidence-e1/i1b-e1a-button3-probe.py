"""batch-103 Inc 1b E1 addendum probe: the right mouse button (button 3) and Ctrl+C
in textual 8.2.8, on the base tree (e07fb00). Run on cachyos-rtx only.

Run from the read-only clone root (cwd = ~/work/s19_app) with PYTHONPATH set to it,
PYTHONDONTWRITEBYTECODE=1, and HOME / XDG_* / LOCALAPPDATA under /tmp/b103-e1-1b/.

NO CLIPBOARD IS TOUCHED:
- DISPLAY and WAYLAND_DISPLAY are removed from the environment;
- every ``copy_to_clipboard`` is replaced by a recorder that never calls the
  toolkit's copy (no app clipboard, no OSC 52 request);
- ``os_clipboard_input.write_os_clipboard`` / ``read_os_clipboard`` /
  ``_prime_tk_root`` are replaced by recorders / stubs (no Tk root, no OS call);
- the headless driver writes to no terminal.

Parts:
  A  toolkit source facts (file:line read by ``inspect``, printed, not typed)
  B  a minimal app: button-3 events through Pilot and through the driver's route
     (``App.post_message``), the screen selection, a DataTable, a read-only
     TextArea, focus, Ctrl+C on the default screen and inside a ModalScreen
  C  the product app (S19TuiApp subclass that only logs ``on_event``): right-click
     on a hex-view selection, on an A2L tag-table row (twice), Ctrl+C inside the
     Workspace help window
"""
import asyncio
import inspect
import os
import shutil
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path

for _var in ("DISPLAY", "WAYLAND_DISPLAY"):
    os.environ.pop(_var, None)

sys.path.insert(0, os.getcwd())

import s19_app  # noqa: E402

print("s19_app.__file__ =", Path(s19_app.__file__).resolve())
print("textual", version("textual"), "| python", sys.version.split()[0])
print("DISPLAY in env:", "DISPLAY" in os.environ, "| WAYLAND_DISPLAY in env:", "WAYLAND_DISPLAY" in os.environ)
for _var in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "LOCALAPPDATA"):
    print(f"{_var} =", os.environ.get(_var))

import textual  # noqa: E402
from textual import events  # noqa: E402
from textual.app import App, ComposeResult  # noqa: E402
from textual.screen import ModalScreen, Screen  # noqa: E402
from textual.widgets import Button, DataTable, Static, TextArea  # noqa: E402
from textual.widgets.text_area import Selection  # noqa: E402
from textual.pilot import Pilot  # noqa: E402

from s19_app.tui import os_clipboard_input as osc  # noqa: E402

OS_WRITES: list = []


def _fake_write(text, strategies=None):  # noqa: ANN001
    OS_WRITES.append(text)
    return True


osc.write_os_clipboard = _fake_write
osc.read_os_clipboard = lambda strategies=None: None
osc._prime_tk_root = lambda: None

TROOT = Path(textual.__file__).parent


def src_lines(obj, needles):
    """Print the file:line of each source line of ``obj`` that contains a needle."""
    lines, start = inspect.getsourcelines(obj)
    rel = Path(inspect.getsourcefile(obj)).relative_to(TROOT)
    print(f"  {obj.__qualname__} -> textual/{rel}:{start}-{start + len(lines) - 1}")
    for i, line in enumerate(lines):
        if any(n in line for n in needles):
            print(f"    textual/{rel}:{start + i}: {line.rstrip()}")


def part_a() -> None:
    print("\n== A toolkit source facts")
    src_lines(Screen._forward_event, ["MouseUp", "MouseDown", "clear_selection", "button", "set_focus(focusable_widget"])
    src_lines(DataTable._on_click, ["button", "cursor_coordinate = new_coordinate", "_post_selected_message", "event.stop"])
    src_lines(TextArea._on_mouse_down, ["button", "Selection.cursor"])
    src_lines(TextArea.action_copy, ["SkipAction", "copy_to_clipboard"])
    src_lines(Screen.action_copy_text, ["SkipAction", "copy_to_clipboard"])
    src_lines(App.action_help_quit, ["notify"])
    src_lines(App.on_event, ["is_forwarded", "Click.from_event", "_forward_event"])
    src_lines(Screen._modal_binding_chain.fget, ["is_modal", "return"])
    src_lines(Pilot._post_mouse_events, ["_forward_event", "Bypass"])
    print("  Pilot.click signature:", inspect.signature(Pilot.click))
    print("  Pilot.mouse_down signature:", inspect.signature(Pilot.mouse_down))
    print("  Pilot.mouse_up signature:", inspect.signature(Pilot.mouse_up))
    print("  MouseDown signature:", inspect.signature(events.MouseDown.__init__))
    from textual._xterm_parser import XTermParser
    src_lines(XTermParser.parse_mouse_code, ["button = (buttons + 1) & 3", "MouseDown if state"])
    for b in App.BINDINGS:
        if getattr(b, "key", "") in ("ctrl+c", "ctrl+q"):
            print(f"  App binding {b.key!r} -> {b.action!r} priority={b.priority} system={b.system}")
    for b in Screen.BINDINGS:
        if "ctrl+c" in getattr(b, "key", ""):
            print(f"  Screen binding {b.key!r} -> {b.action!r} priority={b.priority}")
    # windows_driver imports msvcrt (Windows only): read its text instead of importing it
    for rel in ("drivers/windows_driver.py", "drivers/win32.py"):
        for no, line in enumerate((TROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            if "\\x1b[?100" in line or "set_console_mode(terminal_in" in line:
                print(f"    textual/{rel}:{no}: {line.rstrip()}")


# ---------------------------------------------------------------- part B

LOG: list = []


class LogStatic(Static):
    def _sel(self) -> str:
        return repr(self.screen.get_selected_text())

    def on_mouse_down(self, event: events.MouseDown) -> None:
        LOG.append(f"{self.id}.on_mouse_down button={event.button} screen_sel={self._sel()}")

    def on_mouse_up(self, event: events.MouseUp) -> None:
        LOG.append(f"{self.id}.on_mouse_up button={event.button} screen_sel={self._sel()}")

    def on_click(self, event: events.Click) -> None:
        LOG.append(f"{self.id}.on_click button={event.button} screen_sel={self._sel()}")


class Modal(ModalScreen):
    def compose(self) -> ComposeResult:
        yield LogStatic("modal line one\nmodal line two", id="m1")
        yield Button("ok", id="mb")


class ProbeApp(App):
    CSS = "LogStatic, Static { height: 3; } DataTable { height: 8; } TextArea { height: 6; }"

    def __init__(self) -> None:
        super().__init__()
        self.copies: list = []
        self.help_quit_calls = 0
        self.table_msgs: list = []

    def compose(self) -> ComposeResult:
        yield LogStatic("alpha line\nbeta line\ngamma line", id="s1")
        yield Static("other view", id="s2")
        yield DataTable(id="t1", cursor_type="row")
        yield TextArea("one\ntwo\nthree\nfour", read_only=True, id="ta")
        yield Button("btn", id="b1")

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        t.add_columns("Tag", "Addr")
        for i in range(6):
            t.add_row(f"· NAME_{i}", f"0x{i:04X}", key=f"k{i}")

    async def on_event(self, event: events.Event) -> None:
        if isinstance(event, (events.MouseDown, events.MouseUp)) and not event.is_forwarded:
            ta = self.query("#ta")
            ta_sel = ta.first().selected_text if ta and self.screen is self.screen_stack[0] else "-"
            LOG.append(
                f"App.on_event {type(event).__name__} button={event.button} (not forwarded) "
                f"screen_sel={self.screen.get_selected_text()!r} ta_sel={ta_sel!r}"
            )
        await super().on_event(event)

    def on_mouse_down(self, event: events.MouseDown) -> None:
        LOG.append(f"App.on_mouse_down (bubbled) button={event.button} screen_sel={self.screen.get_selected_text()!r}")

    def copy_to_clipboard(self, text: str) -> None:  # recorder: no app clipboard, no OSC 52
        self.copies.append(text)

    def action_help_quit(self) -> None:  # recorder: the toolkit's ctrl+c fallback
        self.help_quit_calls += 1

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.table_msgs.append(f"RowHighlighted row={event.cursor_row}")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.table_msgs.append(f"RowSelected row={event.cursor_row}")


def mouse(cls, x: int, y: int, button: int):
    return cls(None, x, y, 0, 0, button, False, False, False, screen_x=x, screen_y=y)


async def drag(pilot, sel: str) -> None:
    await pilot.mouse_down(sel, offset=(0, 0))
    await pilot.hover(sel, offset=(8, 1))
    await pilot.mouse_up(sel, offset=(8, 1))
    await pilot.pause()


def dump(title: str) -> None:
    print(f"  -- {title}")
    for line in LOG:
        print("    " + line)
    LOG.clear()


async def part_b() -> None:
    print("\n== B minimal app (textual 8.2.8, headless)")
    app = ProbeApp()
    async with app.run_test(size=(80, 40)) as pilot:
        await pilot.pause()
        s1 = app.query_one("#s1")
        await drag(pilot, "#s1")
        LOG.clear()
        print("B1 selection after a left drag over #s1:", repr(app.screen.get_selected_text()))
        await pilot.click("#s1", offset=(2, 1), button=3)
        dump("B1 Pilot.click(button=3) on #s1 (Pilot posts to Screen._forward_event, bypassing App.on_event)")
        print("B1 selection after the button-3 click:", repr(app.screen.get_selected_text()))

        await drag(pilot, "#s1")
        LOG.clear()
        r = s1.region
        app.post_message(mouse(events.MouseDown, r.x + 2, r.y + 1, 3))
        app.post_message(mouse(events.MouseUp, r.x + 2, r.y + 1, 3))
        for _ in range(4):
            await pilot.pause()
        dump("B2 driver route: MouseDown+MouseUp button 3 posted back to back to the App")
        print("B2 selection after:", repr(app.screen.get_selected_text()))

        await drag(pilot, "#s1")
        LOG.clear()
        s2 = app.query_one("#s2").region
        await pilot.click("#s2", offset=(1, 0), button=3)
        dump("B3 Pilot.click(button=3) on #s2 while #s1 holds the selection")
        print("B3 selection after:", repr(app.screen.get_selected_text()))

        await drag(pilot, "#s1")
        LOG.clear()
        await pilot.mouse_down("#s1", offset=(0, 0), button=3)
        await pilot.hover("#s1", offset=(5, 2))
        print("B4 selection after a button-3 press then a move (right-drag):", repr(app.screen.get_selected_text()))
        await pilot.mouse_up("#s1", offset=(5, 2))
        LOG.clear()

        t = app.query_one(DataTable)
        app.query_one("#b1").focus()
        await pilot.pause()
        app.table_msgs.clear()
        print("B5 table cursor_row before:", t.cursor_row, "| focused:", app.focused.id if app.focused else None)
        await pilot.click("#t1", offset=(3, 4), button=3)
        print("B5 after Pilot.click(button=3) on table row 3:", "cursor_row", t.cursor_row,
              "| msgs", app.table_msgs, "| focused:", app.focused.id if app.focused else None)
        app.table_msgs.clear()
        await pilot.click("#t1", offset=(3, 4), button=3)
        print("B5 a second button-3 click on the same row:", "cursor_row", t.cursor_row, "| msgs", app.table_msgs)
        LOG.clear()

        ta = app.query_one("#ta", TextArea)
        ta.selection = Selection((0, 0), (2, 0))
        await pilot.pause()
        print("B6 TextArea selected_text before:", repr(ta.selected_text))
        tr = ta.region
        app.post_message(mouse(events.MouseDown, tr.x + 2, tr.y + 1, 3))
        app.post_message(mouse(events.MouseUp, tr.x + 2, tr.y + 1, 3))
        for _ in range(4):
            await pilot.pause()
        dump("B6 driver route: button 3 on the read-only TextArea")
        print("B6 TextArea selected_text after:", repr(ta.selected_text), "| selection", ta.selection)

        app.screen.clear_selection()
        app.query_one("#b1").focus()
        await pilot.pause()
        hq, cp = app.help_quit_calls, len(app.copies)
        await pilot.press("ctrl+c")
        print("B7 ctrl+c, focus on a Button, nothing selected: help_quit +", app.help_quit_calls - hq,
              "| copies +", len(app.copies) - cp)
        t.focus()
        await pilot.pause()
        hq, cp = app.help_quit_calls, len(app.copies)
        await pilot.press("ctrl+c")
        print("B7 ctrl+c, focus on the DataTable (a row highlighted), nothing selected: help_quit +",
              app.help_quit_calls - hq, "| copies +", len(app.copies) - cp)
        ta.selection = Selection((0, 0), (0, 0))
        ta.focus()
        await pilot.pause()
        hq, cp = app.help_quit_calls, len(app.copies)
        await pilot.press("ctrl+c")
        print("B7 ctrl+c, focus on the read-only TextArea, no selection: help_quit +",
              app.help_quit_calls - hq, "| copies +", len(app.copies) - cp)

        await app.push_screen(Modal())
        await pilot.pause()
        app.screen.query_one("#mb").focus()
        await pilot.pause()
        hq, cp = app.help_quit_calls, len(app.copies)
        await pilot.press("ctrl+c")
        print("B8 ctrl+c inside a ModalScreen, nothing selected: help_quit +", app.help_quit_calls - hq,
              "| copies +", len(app.copies) - cp, "| top screen", type(app.screen).__name__)
        await drag(pilot, "#m1")
        sel = app.screen.get_selected_text()
        hq, cp = app.help_quit_calls, len(app.copies)
        await pilot.press("ctrl+c")
        print("B8 ctrl+c inside the ModalScreen with", repr(sel), "selected: help_quit +",
              app.help_quit_calls - hq, "| copies +", len(app.copies) - cp, "| copied", app.copies[-1:] )
        await drag(pilot, "#m1")
        LOG.clear()
        m1 = app.screen.query_one("#m1").region
        app.post_message(mouse(events.MouseDown, m1.x + 2, m1.y + 0, 3))
        app.post_message(mouse(events.MouseUp, m1.x + 2, m1.y + 0, 3))
        for _ in range(4):
            await pilot.pause()
        dump("B9 driver route: button 3 on a selection inside the ModalScreen")
        print("B9 selection after:", repr(app.screen.get_selected_text()))


# ---------------------------------------------------------------- part C

async def part_c(base: Path) -> None:
    print("\n== C product app S19TuiApp (e07fb00), headless 118x54")
    from s19_app.tui.app import S19TuiApp
    from tests.b97_fixtures import EXAMPLES_DIR
    from tests.b97_probes import settle

    _css = S19TuiApp.CSS_PATH
    _css_abs = (
        [str(Path(inspect.getfile(S19TuiApp)).parent / p) for p in _css]
        if isinstance(_css, (list, tuple))
        else str(Path(inspect.getfile(S19TuiApp)).parent / _css)
    )

    class LoggedApp(S19TuiApp):
        CSS_PATH = _css_abs  # the product's stylesheet, resolved beside app.py

        async def on_event(self, event):  # logs only, then the product's own handling
            if isinstance(event, (events.MouseDown, events.MouseUp)) and not event.is_forwarded:
                LOG.append(f"App.on_event {type(event).__name__} button={event.button} "
                           f"screen_sel_len={len(self.screen.get_selected_text() or '')}")
            await super().on_event(event)

    app = LoggedApp(base_dir=base)
    copies: list = []
    notes: list = []
    jumps: list = []
    async with app.run_test(size=(118, 54)) as pilot:
        await settle(pilot)
        app.copy_to_clipboard = lambda text: copies.append(text)  # recorder only
        orig_notify = app.notify

        def notify(message, *a, **k):
            notes.append((str(message), k.get("title", "")))
            return orig_notify(message, *a, **k)

        app.notify = notify
        orig_jump = app._jump_to_tag_by_data

        def jump(tag):
            jumps.append(tag.get("name") if isinstance(tag, dict) else tag)
            return orig_jump(tag)

        app._jump_to_tag_by_data = jump
        for name in ("prg.s19", "ASAP2_Demo_V171.a2l"):
            copy = base / name
            shutil.copyfile(EXAMPLES_DIR / name, copy)
            (app.load_a2l_from_path if name.endswith(".a2l") else app.load_from_path)(copy)
            for _ in range(200):
                await pilot.pause(0.05)
                if name.endswith(".s19") and app.current_file is not None:
                    break
                if name.endswith(".a2l") and getattr(app, "current_a2l_data", None):
                    break
            await settle(pilot, 8)
        print("loaded: image", app.current_file is not None, "| a2l", bool(getattr(app, "current_a2l_data", None)))
        notes.clear()

        await pilot.press("1")
        await settle(pilot, 6)
        await pilot.mouse_down("#hex_view", offset=(2, 1))
        await pilot.hover("#hex_view", offset=(40, 3))
        await pilot.mouse_up("#hex_view", offset=(40, 3))
        await settle(pilot, 4)
        sel = app.screen.get_selected_text() or ""
        print("C1 hex-view drag: selected", len(sel), "chars,", len(sel.splitlines()), "lines")
        LOG.clear()
        hv = app.query_one("#hex_view").region
        app.post_message(mouse(events.MouseDown, hv.x + 10, hv.y + 2, 3))
        app.post_message(mouse(events.MouseUp, hv.x + 10, hv.y + 2, 3))
        await settle(pilot, 6)
        dump("C1 driver route: button 3 on the hex-view selection")
        print("C1 after: selection", repr(app.screen.get_selected_text()), "| copies", len(copies),
              "| notices", notes, "| focused", getattr(app.focused, "id", None),
              "| screens", [type(s).__name__ for s in app.screen_stack])

        await pilot.press("2")
        await settle(pilot, 6)
        table = app.query_one("#a2l_tags_list", DataTable)
        table.focus()
        await settle(pilot, 2)
        print("C2 A2L tag table: cursor_row", table.cursor_row, "| rows", table.row_count,
              "| header_height", table.header_height)
        y = table.header_height + 2  # the third row
        jumps.clear()
        await pilot.click("#a2l_tags_list", offset=(4, y), button=3)
        await settle(pilot, 4)
        cell = table.get_row_at(table.cursor_row)[0] if table.row_count else None
        print("C2 after Pilot.click(button=3) on the third row: cursor_row", table.cursor_row,
              "| Tag cell", repr(str(cell)), "| jumps", jumps, "| copies", len(copies),
              "| screens", [type(s).__name__ for s in app.screen_stack])
        await pilot.click("#a2l_tags_list", offset=(4, y), button=3)
        await settle(pilot, 4)
        print("C2 a second button-3 click on the same row: cursor_row", table.cursor_row, "| jumps", jumps)
        notes.clear()
        await pilot.press("ctrl+c")
        await settle(pilot, 2)
        print("C3 ctrl+c on the tag table, a row highlighted, nothing selected: notices", notes,
              "| copies", len(copies))

        await pilot.press("1")
        await settle(pilot, 6)
        app.screen.clear_selection()
        app.query_one("#hex_scroll").focus()
        await settle(pilot, 2)
        await pilot.press("question_mark")
        await settle(pilot, 6)
        print("C4 top screen after ?:", type(app.screen).__name__, "| modal", app.screen.is_modal)
        notes.clear()
        await pilot.press("ctrl+c")
        await settle(pilot, 2)
        print("C4 ctrl+c in the help window, nothing selected: notices", notes, "| copies", len(copies),
              "| top", type(app.screen).__name__)
        await pilot.press("escape")
        await settle(pilot, 4)
        print("C4 after escape: top", type(app.screen).__name__)
    print("total os writes recorded:", len(OS_WRITES), "| copy_to_clipboard calls recorded:", len(copies))


if __name__ == "__main__":
    part_a()
    asyncio.run(part_b())
    run_dir = Path(os.environ.get("B103_RUN", tempfile.mkdtemp()))
    run_dir.mkdir(parents=True, exist_ok=True)
    asyncio.run(part_c(Path(tempfile.mkdtemp(dir=run_dir))))
