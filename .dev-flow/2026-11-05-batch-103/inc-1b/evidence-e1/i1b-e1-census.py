"""batch-103 Inc 1b E1 census: copy out of the non-input views on the base tree (e07fb00).

Run from the read-only clone root (cwd = ~/work/s19_app) with PYTHONPATH set to
it and PYTHONDONTWRITEBYTECODE=1; prints the package path first.

NO CLIPBOARD IS TOUCHED. Before the app starts:
- DISPLAY and WAYLAND_DISPLAY are removed from the environment;
- ``os_clipboard_input.write_os_clipboard`` is replaced by a recorder that
  returns True and writes nothing; ``read_os_clipboard`` by a stub returning
  None; ``_prime_tk_root`` by a no-op (no Tk root is created);
- the app's driver ``write`` is wrapped to COUNT OSC 52 sequences (the headless
  driver writes to no terminal); ``copy_to_clipboard`` and ``notify`` are
  wrapped to record their calls.

Parts:
  1  per-view census: id, class, MRO, allow_select, can_focus, focusable owner
  2  owner of ctrl+c (and y, c, f7, ctrl+a) with each view's owner focused
  3  ctrl+c after a full text selection of each view (what reaches what)
  4  ctrl+c with no selection on each focusable owner
  5  a mouse drag over the main hex view (does a drag select text?)
  6  population: every widget with an id on the main screen, by family
"""
import asyncio
import base64
import os
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path

for _var in ("DISPLAY", "WAYLAND_DISPLAY"):
    os.environ.pop(_var, None)

sys.path.insert(0, os.getcwd())

import s19_app  # noqa: E402

print("s19_app.__file__ =", Path(s19_app.__file__).resolve())
print("textual", version("textual"))
print("DISPLAY in env:", "DISPLAY" in os.environ, "| WAYLAND_DISPLAY in env:", "WAYLAND_DISPLAY" in os.environ)
for _var in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "LOCALAPPDATA"):
    print(f"{_var} =", os.environ.get(_var))

import shutil  # noqa: E402

from textual.binding import Binding  # noqa: E402
from textual.widget import Widget  # noqa: E402
from textual.widgets import DataTable, Input, Label, Static, TextArea, Tree, ListView  # noqa: E402

from s19_app.tui import os_clipboard_input as osc  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests.b97_fixtures import EXAMPLES_DIR  # noqa: E402
from tests.b97_probes import is_displayed, settle  # noqa: E402

SIZE = (118, 54)
OS_WRITES: list = []


def _fake_write(text, strategies=None):  # noqa: ANN001
    OS_WRITES.append(text)
    return True


osc.write_os_clipboard = _fake_write
osc.read_os_clipboard = lambda strategies=None: None
osc._prime_tk_root = lambda: None


class Recorder:
    def __init__(self, app):
        self.copies: list = []
        self.osc52: list = []
        self.notes: list = []
        orig_copy = app.copy_to_clipboard

        def copy(text):
            self.copies.append(text)
            orig_copy(text)

        app.copy_to_clipboard = copy
        orig_notify = app.notify

        def notify(message, *a, **k):
            self.notes.append((str(message), k.get("severity", "information"), k.get("title", "")))
            return orig_notify(message, *a, **k)

        app.notify = notify
        drv = app._driver
        orig_write = drv.write

        def write(data):
            if "\x1b]52;" in data:
                payload = data.split("\x1b]52;c;", 1)[1].rstrip("\a")
                self.osc52.append(len(base64.b64decode(payload).decode("utf-8")))
            return orig_write(data)

        drv.write = write

    def mark(self):
        return (len(self.copies), len(self.osc52), len(OS_WRITES), len(self.notes))

    def since(self, m):
        c, o, w, n = m
        return {
            "copy_to_clipboard": [len(t) for t in self.copies[c:]],
            "osc52_chars": self.osc52[o:],
            "os_write": [len(t) for t in OS_WRITES[w:]],
            "notify": self.notes[n:],
        }


def mro(w) -> str:
    names = []
    for cls in type(w).__mro__:
        names.append(cls.__name__)
        if cls.__module__.startswith("textual.widgets") or cls is Widget:
            break
    return " > ".join(names)


def owner(w):
    node = w
    while node is not None and isinstance(node, Widget):
        if node.can_focus:
            return node
        node = node.parent
    return None


def text_of(w) -> str:
    if isinstance(w, TextArea):
        return w.text
    if isinstance(w, Input):
        return w.value
    if isinstance(w, DataTable):
        return f"<table rows={w.row_count} cols={len(w.columns)} cursor={w.cursor_type}>"
    try:
        return str(w.render())
    except Exception as exc:  # pragma: no cover
        return f"<render failed {type(exc).__name__}>"


def chain_for(app, key: str) -> list:
    out = []
    for namespace, bindings in app.screen._modal_binding_chain:
        for k, b in bindings:
            if k == key:
                out.append(f"{type(namespace).__name__}#{getattr(namespace, 'id', None)}:{b.action}{' [priority]' if b.priority else ''}")
    return out


VIEWS = [
    ("workspace", "hex_view"),
    ("workspace", "ws_stats"),
    ("workspace", "a2l_view"),
    ("a2l", "a2l_tags_list"),
    ("a2l", "a2l_tags_summary"),
    ("a2l", "a2l_detail_card"),
    ("a2l", "alt_hex_view"),
    ("mac", "mac_records_list"),
    ("mac", "mac_hex_view"),
    ("patch", "patch_json_view"),
    ("patch", "patch_paste_text"),
    ("workspace", "search_input"),
]


async def main(base: Path) -> None:
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        rec = Recorder(app)
        for name in ("prg.s19", "synthetic_update_test1.mac", "ASAP2_Demo_V171.a2l"):
            copy = base / name
            shutil.copyfile(EXAMPLES_DIR / name, copy)
            if name.endswith(".a2l"):
                app.load_a2l_from_path(copy)
            else:
                app.load_from_path(copy)
            for _ in range(200):
                await pilot.pause(0.05)
                if name.endswith(".s19") and app.current_file is not None:
                    break
                if name.endswith(".a2l") and getattr(app, "current_a2l_data", None):
                    break
                if name.endswith(".mac") and getattr(app.current_file, "mac_path", None):
                    break
            await settle(pilot, 8)
        print("loaded: current_file", app.current_file is not None, "| a2l", bool(getattr(app, "current_a2l_data", None)),
              "| mac", getattr(app.current_file, "mac_path", None) is not None)
        print("notes during load:", len(rec.notes))

        print("\n== 1 per-view census")
        for screen_key, wid in VIEWS:
            app.action_show_screen(screen_key)
            await settle(pilot, 6)
            w = app.query_one(f"#{wid}")
            own = owner(w)
            txt = text_of(w)
            print(f"#{wid} [{screen_key}] class={type(w).__name__} mro=({mro(w)})")
            print(f"    allow_select={w.allow_select} can_focus={w.can_focus} displayed={is_displayed(w)}"
                  f" focus_owner={'#' + str(own.id) if own is not None else None}"
                  f" owner_class={type(own).__name__ if own is not None else None}")
            print(f"    text: {len(txt)} chars, {len(txt.splitlines())} lines; first line {txt.splitlines()[0][:96] if txt else ''!r}")

        print("\n== 2 binding chain for keys, with each view's focus owner focused")
        for screen_key, wid in VIEWS:
            app.action_show_screen(screen_key)
            await settle(pilot, 6)
            w = app.query_one(f"#{wid}")
            own = owner(w)
            if own is None:
                app.screen.set_focus(None)
            else:
                own.focus()
            await settle(pilot, 4)
            foc = app.focused
            print(f"#{wid}: focused={'#' + str(foc.id) if foc is not None else None}")
            for key in ("ctrl+c", "y", "c", "f7", "ctrl+a", "ctrl+v"):
                active = app.screen.active_bindings.get(key)
                first = f"{type(active.node).__name__}:{active.binding.action}" if active else None
                print(f"    {key:6} active={first} chain={chain_for(app, key)}")

        print("\n== 3 ctrl+c after a full text selection")
        for screen_key, wid in VIEWS:
            app.action_show_screen(screen_key)
            await settle(pilot, 6)
            w = app.query_one(f"#{wid}")
            own = owner(w)
            if own is not None:
                own.focus()
            else:
                app.screen.set_focus(None)
            await settle(pilot, 2)
            if isinstance(w, (TextArea,)):
                w.select_all()
            elif isinstance(w, Input):
                w.value = "abc def"
                w.select_all()
            else:
                w.text_select_all()
            await settle(pilot, 4)
            sel = app.screen.get_selected_text()
            wsel = w.selected_text if isinstance(w, (TextArea, Input)) else None
            m = rec.mark()
            await pilot.press("ctrl+c")
            await settle(pilot, 8)
            print(f"#{wid}: screen selection={None if sel is None else len(sel)} chars;"
                  f" widget selection={None if wsel is None else len(wsel)} chars -> {rec.since(m)}")
            app.screen.clear_selection()
            if isinstance(w, TextArea):
                w.selection = type(w.selection)(w.selection.end, w.selection.end)
            await settle(pilot, 2)

        print("\n== 4 ctrl+c with no selection on each focus owner")
        for screen_key, wid in VIEWS:
            app.action_show_screen(screen_key)
            await settle(pilot, 6)
            w = app.query_one(f"#{wid}")
            own = owner(w)
            app.screen.clear_selection()
            if own is not None:
                own.focus()
            else:
                app.screen.set_focus(None)
            if isinstance(w, Input):
                w.value = "abc def"
                w.cursor_position = len(w.value)
            await settle(pilot, 4)
            m = rec.mark()
            await pilot.press("ctrl+c")
            await settle(pilot, 8)
            foc = app.focused
            print(f"#{wid} (focused {'#' + str(foc.id) if foc is not None else None}) -> {rec.since(m)}")

        print("\n== 5 mouse drag over the main hex view")
        app.action_show_screen("workspace")
        await settle(pilot, 6)
        app.screen.clear_selection()
        await settle(pilot, 2)
        try:
            await pilot.mouse_down("#hex_view", offset=(2, 1))
            await pilot.hover("#hex_view", offset=(40, 3))
            await pilot.mouse_up("#hex_view", offset=(40, 3))
            await settle(pilot, 4)
            sel = app.screen.get_selected_text()
            print("selected after drag:", None if sel is None else repr(sel[:200]))
            m = rec.mark()
            await pilot.press("ctrl+c")
            await settle(pilot, 8)
            print("ctrl+c after drag ->", rec.since(m))
        except Exception as exc:
            print("drag failed:", type(exc).__name__, exc)
        app.screen.clear_selection()

        print("\n== 5b table rows as shown (cursor row 2), and the views' text")
        for screen_key, wid in (("a2l", "a2l_tags_list"), ("mac", "mac_records_list")):
            app.action_show_screen(screen_key)
            await settle(pilot, 6)
            t = app.query_one(f"#{wid}", DataTable)
            t.focus()
            if t.row_count > 2:
                t.move_cursor(row=2)
            await settle(pilot, 4)
            labels = [str(getattr(c.label, "plain", c.label)) for c in t.ordered_columns]
            print(f"#{wid}: rows={t.row_count} columns={labels}")
            if t.row_count:
                cells = t.get_row_at(t.cursor_row)
                print("    cursor row cells:", [str(getattr(c, "plain", c)) for c in cells])
            else:
                print("    no rows")
        app.action_show_screen("a2l")
        await settle(pilot, 6)
        for wid in ("a2l_tags_summary", "a2l_detail_card"):
            print(f"#{wid} text:", repr(text_of(app.query_one(f"#{wid}"))[:400]))
        app.action_show_screen("workspace")
        await settle(pilot, 6)
        for wid in ("ws_stats", "a2l_view", "hex_view"):
            txt = text_of(app.query_one(f"#{wid}"))
            print(f"#{wid} first 4 lines:", txt.splitlines()[:4], "| lines", len(txt.splitlines()),
                  "| max line len", max((len(x) for x in txt.splitlines()), default=0))

        print("\n== 6 population: widgets with an id on the main screen, by family")
        fams = {"DataTable": DataTable, "TextArea": TextArea, "Input": Input, "Tree": Tree,
                "ListView": ListView, "Label": Label, "Static": Static}
        counts: dict = {}
        tables = []
        for w in app.screen.query("*"):
            if not w.id:
                continue
            fam = next((n for n, c in fams.items() if isinstance(w, c)), None)
            if fam is None:
                continue
            key = (fam, w.allow_select)
            counts[key] = counts.get(key, 0) + 1
            if fam == "DataTable":
                tables.append(f"#{w.id}(cursor={w.cursor_type})")
            if fam == "TextArea":
                tables.append(f"#{w.id}(TextArea {type(w).__name__} read_only={w.read_only})")
        for (fam, sel), n in sorted(counts.items()):
            print(f"{fam:10} allow_select={sel}: {n}")
        print("tables and text areas:", ", ".join(tables))
        print("App ALLOW_SELECT", S19TuiApp.ALLOW_SELECT, "| screen class", type(app.screen).__name__,
              "| screen allow_select", app.screen.allow_select)
        bound = {b.key if isinstance(b, Binding) else b[0] for b in S19TuiApp.BINDINGS}
        print("S19TuiApp.BINDINGS keys:", sorted(bound))
        print("total os writes recorded:", len(OS_WRITES))


if __name__ == "__main__":
    run_dir = Path(os.environ.get("B103_RUN", tempfile.mkdtemp()))
    base = Path(tempfile.mkdtemp(dir=run_dir))
    asyncio.run(main(base))
