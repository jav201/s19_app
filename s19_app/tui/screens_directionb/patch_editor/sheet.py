"""s19_app.tui.screens_directionb.patch_editor.sheet - the StagingSheet widget (batch-103 Inc 8, interface I-8.4).

The widget paints the rows of the model in ``definition_sheet`` (pure, no toolkit) and owns the
selection, the row window, the pending formula text and the formula bar. Inc 9 subclasses it and
overrides only the methods named in I-8.4; every repaint goes through ``_paint``.
"""
from __future__ import annotations

from collections import deque
from typing import Mapping, Optional, Sequence

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.widgets import Input, Label, Static

from ...definition_sheet import (
    GRID_WIDTH,
    StagedOverlay,
    build_row,
    detail_lines,
    formula_fill,
    formula_tail,
    header_line,
    header_rule,
    name_echo,
    ops_for,
    plain,
    row_line,
    row_window,
    sheet_widths,
)
from ...os_clipboard_input import OsClipboardInput

#: The longest formula text (R-PE-DEF.42); the input refuses an insert that would pass it.
FORMULA_MAX = 4096

_NO_A2L = "Load an A2L file to edit parameters by definition."
_NO_ROWS = "No parameters on this page: type a filter above."

_FALLBACK_WIDTH = 118
_FALLBACK_HEIGHT = 20


class _SheetBody(Static, can_focus=True):
    """The focusable body: the header line, the row window and the detail under the selected row."""

    def on_resize(self, event: events.Resize) -> None:
        for ancestor in self.ancestors:
            if isinstance(ancestor, StagingSheet):
                ancestor._paint()
                return


class StagingSheet(Vertical):
    """One sheet row per picker-page parameter, a detail under the selected row and a formula bar.

    Summary:
        ``show_page`` and ``set_document`` rebuild the rows (never an A2L describe: the picker's
        population describe is passed in); up/down move the selection, Enter focuses the formula
        input, left/right choose an enum entry, Enter in the input posts ``StageRequested``.
    """

    DEFAULT_CSS = """
    StagingSheet { height: 1fr; }
    StagingSheet > #patch_sheet_grid {
        height: 1fr; overflow-x: auto; overflow-y: hidden; scrollbar-size-horizontal: 1;
    }
    #patch_sheet_grid > #patch_sheet_body { height: 1fr; width: auto; }
    StagingSheet > #patch_sheet_bar { height: 1; }
    StagingSheet #patch_sheet_name { width: auto; max-width: 28; }
    StagingSheet #patch_sheet_label { width: auto; padding: 0 1; }
    StagingSheet #patch_sheet_input { width: 18; height: 1; border: none; padding: 0 1; }
    StagingSheet #patch_sheet_tail { width: 1fr; height: 1; }
    """

    BINDINGS = [
        Binding("up", "move(-1)", "Row up", show=False),
        Binding("down", "move(1)", "Row down", show=False),
        Binding("enter", "edit", "Edit", show=False),
        Binding("left", "choose(-1)", "Previous entry", show=False),
        Binding("right", "choose(1)", "Next entry", show=False),
        Binding("home", "scroll_grid('home')", "Grid start", show=False),
        Binding("end", "scroll_grid('end')", "Grid end", show=False),
    ]

    class StageRequested(Message):
        """Enter in the formula input: stage ``text`` for the row ``name``."""

        def __init__(self, name: str, text: str) -> None:
            super().__init__()
            self.name = name
            self.text = text

    class SelectionChanged(Message):
        """The selected row is now the one named ``name``."""

        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.rows: list = []
        self.selected = 0
        self.top = 0
        self.pending: dict[str, str] = {}
        self.a2l_data: Optional[dict] = None
        self.states: dict[str, object] = {}
        self._image: Optional[Mapping[int, int]] = None
        self._entries: list = []
        self._overlay = StagedOverlay(None, ())
        self._previews: dict = {}
        self._programmatic: deque = deque()
        self._body: Optional[_SheetBody] = None
        self._grid: Optional[Container] = None
        self._input: Optional[OsClipboardInput] = None
        self._name_label: Optional[Label] = None
        self._label_label: Optional[Label] = None
        self._tail: Optional[Static] = None

    # ------------------------------------------------------------------
    # Composition and lifecycle
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        self._body = _SheetBody(Text(""), id="patch_sheet_body")
        self._name_label = Label(Text(""), id="patch_sheet_name")
        self._label_label = Label(Text(""), id="patch_sheet_label")
        self._input = OsClipboardInput(max_length=FORMULA_MAX, id="patch_sheet_input")
        self._tail = Static(Text(""), id="patch_sheet_tail")
        self._grid = Container(self._body, id="patch_sheet_grid")
        yield self._grid
        with Horizontal(id="patch_sheet_bar"):
            yield self._name_label
            yield self._label_label
            yield self._input
            yield self._tail

    def on_mount(self) -> None:
        self._fill_input()
        self._paint()

    @property
    def selected_name(self) -> Optional[str]:
        row = self._row()
        return row.name if row is not None else None

    # ------------------------------------------------------------------
    # Page and document
    # ------------------------------------------------------------------

    def show_page(
        self,
        names: Sequence[str],
        definitions: Mapping[str, object],
        a2l_data: Optional[dict],
        image: Optional[Mapping[int, int]],
    ) -> None:
        """Rebuild the rows of one picker page from the picker's own describe (0 describes)."""
        before = self.selected_name
        self.a2l_data = a2l_data
        self._image = image
        self._overlay = StagedOverlay(image, self._entries)
        self._previews = {}
        rows = []
        if a2l_data is not None:
            for name in names:
                definition = definitions.get(name)
                if definition is not None:
                    rows.append(build_row(definition, a2l_data, image, self._overlay))
        self.rows = rows
        shown = {row.name for row in rows}
        self.pending = {k: v for k, v in self.pending.items() if k in shown}
        index = next((i for i, row in enumerate(rows) if row.name == before), 0)
        self.selected = index
        self.top = 0
        self._fit_window()
        self._fill_input()
        self._paint()
        self._announce()

    def set_document(
        self,
        entries: Sequence[tuple[int, Sequence[int]]],
        image: Optional[Mapping[int, int]],
    ) -> None:
        """Rebuild every row's current and staged state over the new document, same definitions."""
        self._entries = [(address, tuple(data)) for address, data in entries]
        self._image = image
        self._overlay = StagedOverlay(image, self._entries)
        self._previews = {}
        if self.rows:
            self.rows = [
                build_row(row.definition, self.a2l_data, image, self._overlay)
                for row in self.rows
            ]
        self._fit_window()
        self._fill_input()
        self._paint()

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def action_move(self, delta: int) -> None:
        """Select the row ``delta`` below (negative: above); no wrap."""
        if self._input_has_focus() or not self.rows:
            return
        self._select(min(len(self.rows) - 1, max(0, self.selected + int(delta))))

    def select_after(self, name: str) -> None:
        """Drop ``name``'s pending text; select the row after it (or keep it on the last row)."""
        self.pending.pop(name, None)
        self._previews.pop(name, None)
        index = next((i for i, row in enumerate(self.rows) if row.name == name), None)
        if index is None:
            self._fill_input()
            self._paint()
            return
        self._select(min(len(self.rows) - 1, index + 1))

    def _select(self, index: int) -> None:
        before = self.selected_name
        self.selected = index
        self._fit_window()
        self._fill_input()
        self._paint()
        if self.selected_name != before:
            self._announce()

    def _announce(self) -> None:
        name = self.selected_name
        if name is not None and self.is_mounted:
            self.post_message(self.SelectionChanged(name))

    # ------------------------------------------------------------------
    # Editing
    # ------------------------------------------------------------------

    def action_edit(self) -> None:
        """Enter on the body: focus the formula input (a row with an editor only)."""
        row = self._row()
        if self._input_has_focus() or row is None or self._input is None:
            return
        if ops_for(row.kind).editable(row.definition):
            self._input.disabled = False
            self._input.focus()

    def action_choose(self, delta: int) -> None:
        """Enum rows: the previous or next table entry as the formula text (no wrap)."""
        row = self._row()
        if self._input_has_focus() or row is None or row.kind != "enum":
            return
        texts = [entry.text for entry in row.definition.enum_entries]
        if not texts:
            return
        here = formula_fill(row, self.pending.get(row.name))
        if here in texts:
            index = texts.index(here)
        else:
            value = getattr(row.current, "value", None)
            index = texts.index(value) if value in texts else -1
        target = texts[min(len(texts) - 1, max(0, index + int(delta)))]
        self._set_formula_text(row, target[:FORMULA_MAX])
        self._set_input_value(formula_fill(row, self.pending.get(row.name)))
        self._paint()

    def on_resize(self, event: events.Resize) -> None:
        """A width-only resize leaves the body at 143 x h and sends it no event: repaint here."""
        self._paint()

    def action_scroll_grid(self, where: str) -> None:
        """Home / End: scroll the grid to its first or last view position, with no animation."""
        if self._grid is None:
            return
        x = 0 if where == "home" else max(0, GRID_WIDTH - self._view_width())
        self._grid.scroll_to(x=x, animate=False, immediate=True)

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        if self._programmatic and self._programmatic[0] == event.value:
            self._programmatic.popleft()
            return
        row = self._row()
        if row is None:
            return
        self._set_formula_text(row, event.value)
        self._paint()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        row = self._row()
        if row is None or self._input is None:
            return
        ops = ops_for(row.kind)
        if ops.editable(row.definition):
            self.post_message(ops.submit(row.name, self._input.value))

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape" and self._input_has_focus():
            event.stop()
            event.prevent_default()
            self._on_formula_escape()

    def _on_formula_escape(self) -> None:
        """Escape in the input: clear the row's pending text and give the focus to the body."""
        row = self._row()
        if row is not None:
            self.pending.pop(row.name, None)
            self._previews.pop(row.name, None)
        self._fill_input()
        if self._body is not None:
            self._body.focus()
        self._paint()

    def _set_formula_text(self, row, text: str) -> None:
        """The formula text becomes the row's pending text while it differs from the base text."""
        base = formula_fill(row, None)
        self._previews.pop(row.name, None)
        if text != base:
            self.pending[row.name] = text
        else:
            self.pending.pop(row.name, None)

    # ------------------------------------------------------------------
    # Painting
    # ------------------------------------------------------------------

    def _paint(self) -> None:
        """The one repaint entry: the body (row window) and the formula bar."""
        if self._body is None or not self.is_mounted:
            return
        width = self._view_width()
        row = self._row()
        if row is None:
            self._body.update(Text(_NO_A2L if self.a2l_data is None else _NO_ROWS, no_wrap=True))
            self._paint_bar(None, width)
            return
        _, room = self._detail_geometry()
        visible = room + 1
        widths = sheet_widths(width)
        preview = self._preview_of(row)
        detail = detail_lines(row, preview, width, self.states.get(row.name), room)
        self.top, painted = row_window(self.selected, self.top, visible, len(detail))
        detail = detail[:painted]
        need = 1 + painted
        lines = [header_line(widths), header_rule(widths)]
        last = min(len(self.rows) - 1, self.top + visible - need)
        for position in range(self.top, last + 1):
            item = self.rows[position]
            shown = position == self.selected
            lines.append(
                row_line(
                    item,
                    widths,
                    shown,
                    self.pending.get(item.name),
                    self._preview_of(item),
                    self.states.get(item.name),
                    odd=bool(position % 2),
                )
            )
            if shown:
                lines.extend(detail)
        body = Text("\n").join(lines)
        body.no_wrap = True
        body.overflow = "crop"
        self._body.update(body)
        self._paint_bar(row, width, preview)

    def _paint_bar(self, row, width: int, preview=None) -> None:
        if self._name_label is None or self._label_label is None or self._tail is None:
            return
        if row is None:
            self._name_label.update(Text(""))
            self._label_label.update(Text(""))
            self._tail.update(Text(""))
            if self._input is not None:
                self._set_input_value("")
                self._disable_input()
            return
        ops = ops_for(row.kind)
        tail_width = self._tail.content_size.width or max(10, width // 3)
        if ops.bar is not None:
            name_text, tail = ops.bar(row, self.states.get(row.name), tail_width)
        else:
            name_text, tail = name_echo(row.name), formula_tail(row, preview, tail_width)
        self._name_label.update(Text(plain(name_text), no_wrap=True, overflow="ellipsis"))
        self._label_label.update(Text(ops.label, no_wrap=True))
        self._tail.update(tail)

    def _preview_of(self, row):
        """The preview of a pending row's formula text (cached until the document or text changes)."""
        text = self.pending.get(row.name)
        if text is None:
            return None
        cached = self._previews.get(row.name)
        if cached is not None and cached[0] == text:
            return cached[1]
        ops = ops_for(row.kind)
        if not ops.editable(row.definition):
            return None
        preview = ops.preview(row.definition, self.a2l_data, text, self._overlay)
        self._previews[row.name] = (text, preview)
        return preview

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _view_width(self) -> int:
        """The grid scroller's visible content width (111 before the first layout)."""
        if self._grid is not None and self._grid.content_size.width > 0:
            return self._grid.content_size.width
        return _FALLBACK_WIDTH - 7

    def _detail_geometry(self) -> tuple[int, int]:
        """The (width, room) the selected row's detail is laid out for; one source for the paint,
        the window fit and the bench canvas (R-PE-BENCH.36)."""
        height = _FALLBACK_HEIGHT
        if self._body is not None and self._body.content_size.height > 0:
            height = self._body.content_size.height
        visible = max(1, height - 2)
        return self._view_width() - 4, visible - 1

    def _row(self):
        if 0 <= self.selected < len(self.rows):
            return self.rows[self.selected]
        return None

    def _input_has_focus(self) -> bool:
        return self._input is not None and self.is_attached and self.app.focused is self._input

    def _fit_window(self) -> None:
        """Keep ``top`` inside the rows and the selected row painted (needs the body size)."""
        self.selected = min(max(0, self.selected), max(0, len(self.rows) - 1))
        if not self.rows:
            self.top = 0
            return
        _, room = self._detail_geometry()
        visible = room + 1
        row = self.rows[self.selected]
        detail = detail_lines(
            row, self._preview_of(row), self._view_width(), self.states.get(row.name), room
        )
        self.top, _ = row_window(self.selected, self.top, visible, len(detail))

    def _fill_input(self) -> None:
        """The input takes the selected row's fill; it is disabled for a row with no editor."""
        if self._input is None or not self.is_mounted:
            return
        row = self._row()
        if row is None:
            self._set_input_value("")
            self._disable_input()
            return
        self._set_input_value(formula_fill(row, self.pending.get(row.name)))
        if ops_for(row.kind).editable(row.definition):
            self._input.disabled = False
        else:
            self._disable_input()

    def _disable_input(self) -> None:
        """Disable the formula input; a focus held by it falls to the body, never to nothing, so the
        arrow keys still reach the sheet (R-PE-DEF.45; e.g. a stage that advances onto a row with no
        editor, R-PE-DEF.36/.60)."""
        if self._input is None:
            return
        if self._input_has_focus() and self._body is not None:
            self._body.focus()
        self._input.disabled = True

    def _set_input_value(self, value: str) -> None:
        """A programmatic value: its queued Changed event is not a typed edit."""
        if self._input is None or self._input.value == value:
            return
        if self._input.is_mounted:
            self._programmatic.append(value)
        self._input.value = value
