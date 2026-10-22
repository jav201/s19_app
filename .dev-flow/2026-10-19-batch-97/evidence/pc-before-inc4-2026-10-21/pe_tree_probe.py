"""Throwaway: the batch-97 Patch Editor tree's CSS on a panel of the measured size
(112x40 / 112x39 / 196x46 / 196x45 = #patch_editor_panel region at 118x54 / 118x53 /
220x60 / 220x59 on HEAD 98f3c84). Reads regions of every region of the §3 tree."""
import asyncio, sys
from textual.app import App
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Static, Label, Button, DataTable, TextArea, ContentSwitcher, Input
CSS = """
Screen { layout: vertical; }
#panel { padding: 0; height: 1fr; }
#ribbon, #file_row, #doc_controls, #legend { height: 1; }
#main { height: 1fr; layout: horizontal; }
#ledger { width: 3fr; height: 100%; border: round $panel; }
#table { height: 1fr; }
#inspector { width: 2fr; height: 100%; border: round $panel; padding: 0 1; }
#tabs { height: 1; }
#tabs Button { height: 1; min-width: 6; border: none; }
#switch { height: 1fr; }
#pane_insp { height: 100%; scrollbar-gutter: stable; scrollbar-size-vertical: 1; }
#card { height: auto; padding: 0 1; border-top: solid $panel; }
.field { height: 1; }
.field Label { width: 9; }
.field Input { width: 1fr; height: 1; border: none; padding: 0; }
#chips { height: 1; } #chips Button { height: 1; border: none; min-width: 4; }
#gap { height: 1; }
#tally { height: auto; }
#json { height: 100%; }
#json_head, #stamp, #paste_head_row, #paste_controls, #hist_strip, #hist_controls { height: 1; }
#view { height: 1fr; border: none; padding: 0; }
#json_body { height: 1fr; }
#paste_row { height: 100%; }
#paste { height: 1fr; border: none; padding: 0; }
#exec { height: 3; }
#saveback { height: 3; display: none; } #ba { height: 2; display: none; }
.offered #saveback, .offered #ba { display: block; }
"""
class P(App):
    CSS = CSS
    def compose(self):
        with Vertical(id="panel"):
            yield Static("ribbon", id="ribbon")
            with Horizontal(id="main"):
                with Container(id="ledger"):
                    yield DataTable(id="table")
                with Vertical(id="inspector"):
                    with Horizontal(id="tabs"):
                        yield Button("Inspector"); yield Button("JSON"); yield Button("Checks")
                    with ContentSwitcher(initial="pane_insp", id="switch"):
                        with VerticalScroll(id="pane_insp"):
                            yield Static("x", id="card")
                            yield Static("", id="gap")
                            for n in ("Address", "String", "Bytes"):
                                with Horizontal(classes="field"):
                                    yield Label(n); yield Input()
                            with Horizontal(id="chips"):
                                yield Button("Add"); yield Button("Edit")
                            yield Static("DOCUMENT\nbar\n6 entries\n0 outside", id="tally")
                        with Vertical(id="json"):
                            yield Label("Loaded document · read-only", id="json_head")
                            yield Static("6 entries · 12:00:00 · saved", id="stamp")
                            yield TextArea("{}", id="view", read_only=True)
                            with VerticalScroll(id="json_body"):
                                with Vertical(id="paste_row"):
                                    yield Static("Paste buffer · editable   0.3K / 64.0K", id="paste_head_row")
                                    yield TextArea("{}", id="paste")
                            yield Static("p", id="paste_controls")
                            yield Static("h", id="hist_strip"); yield Static("u", id="hist_controls")
                            yield Static("e", id="exec")
                            yield Static("s", id="saveback"); yield Static("b", id="ba")
            yield Static("file", id="file_row"); yield Static("doc", id="doc_controls"); yield Static("legend", id="legend")
async def run(w, h, offered=False):
    app = P()
    async with app.run_test(size=(w, h)) as pilot:
        await pilot.pause()
        q = app.query_one
        tbl = q("#table"); ins = q("#inspector"); pane = q("#pane_insp"); card = q("#card")
        out = dict(main=q("#main").region.height, ledger_w=q("#ledger").region.width, table_h=tbl.region.height,
                   insp_w=ins.region.width, insp_content_w=ins.content_region.width, switch_h=q("#switch").region.height,
                   card_content_w=card.content_region.width)
        q("#switch").current = "json"
        if offered: q("#json").add_class("offered")
        await pilot.pause()
        out.update(view_h=q("#view").region.height, paste_h=q("#paste").region.height)
        k = max([k for k in (4, 8, 16, 32) if 3 * k + 8 <= out["card_content_w"]] or [4])
        out["k"] = k
        print((w, h, "offered" if offered else ""), out)
for w, h in ((112, 40), (112, 39), (196, 46), (196, 45)):
    asyncio.run(run(w, h))
asyncio.run(run(112, 40, True)); asyncio.run(run(112, 39, True))
