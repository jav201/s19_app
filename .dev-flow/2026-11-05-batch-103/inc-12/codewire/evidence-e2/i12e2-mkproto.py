"""Inc 12 E2 (batch-103), runner only: write the MEASUREMENT prototype of graph-inc12.md into a THROWAWAY copy.

    python -I i12e2-mkproto.py <copy root> <variant>

<copy root> is a fresh `git archive e07fb00 s19_app tests` copy under /tmp/b103-e2-12/ (never the clone, never a
worktree). The edit is the graph's prototype, written once so the examples can be measured on the real app; it is
not the implementation (E4 writes that from the graph). Every replacement must match exactly once, or the script
exits 2 and the copy is unusable.

variant (the triggers of the fit; everything else is the same in every variant):
  full         show trigger + fit after every page build + App.on_resize trigger (the first draft)
  noshow       full minus the show trigger (action_show_screen's a2l branch)
  nopostfit    full minus the fit scheduled at the end of update_a2l_tags_view
  noresize     full minus the App.on_resize trigger
  widget       show trigger + fit after every page build + the table's own resize (A2LTagTable.Measured, the
               BandBar.Measured idiom of screens_directionb.py:1645); no App.on_resize trigger
  widgetonly   the table's own resize only (no show trigger, no fit after a build)
  widgetnoshow widget minus the show trigger
  widgetnopost widget minus the fit after a build
  design       the graph's design = widgetnoshow: the fit after every page build + the table's own resize; no show
               trigger, no App.on_resize change (both measured redundant or ineffective, graph-inc12.md E2-2, E2-3)
"""
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
variant = sys.argv[2]
FLAGS = {
    "full": {"show", "postfit", "appresize"},
    "noshow": {"postfit", "appresize"},
    "nopostfit": {"show", "appresize"},
    "noresize": {"show", "postfit"},
    "widget": {"show", "postfit", "widget"},
    "widgetonly": {"widget"},
    "widgetnoshow": {"postfit", "widget"},
    "widgetnopost": {"show", "widget"},
    "design": {"postfit", "widget"},
}[variant]
path = root / "s19_app" / "tui" / "app.py"
src = path.read_text(encoding="utf-8")


def sub(old: str, new: str, label: str) -> None:
    global src
    count = src.count(old)
    if count != 1:
        print(f"PATCH ERROR {label}: anchor found {count} times")
        sys.exit(2)
    src = src.replace(old, new)
    print(f"patched {label}")


# 1. _compose_screen_a2l: padding and the two fixed columns (R-TUI-042a.2, .4)
sub('''                cursor_type="row",
                cell_padding=0,
            ),
            Label("", id="a2l_tags_summary"),''',
    '''                cursor_type="row",
                cell_padding=1,
                fixed_columns=2,
            ),
            Label("", id="a2l_tags_summary"),''', "compose: cell_padding=1, fixed_columns=2")

# 2. _setup_datatable_columns: the new column order (R-TUI-042a.4, CTX-A2L-SCREEN)
sub('''                a2l_table.add_columns(
                    "Tag",
                    "Address",
                    "Length",
                    "Source",''',
    '''                a2l_table.add_columns(
                    "Address",
                    "Length",
                    "Tag",
                    "Source",''', "columns: Address, Length, Tag, ...")

# 3. new module-level helper _shorten_tag_name (R-TUI-042a.3, .5), placed before _a2l_detail_card_text
sub('''def _a2l_detail_card_text(tag: Optional[dict]) -> Text:''',
    '''def _shorten_tag_name(name: str, width: int) -> str:
    """E2 measurement prototype (Inc 12): the name whole when it fits in ``width`` cells; else its first
    (width - 1) // 2 cells, an ellipsis and its last width - 1 - (width - 1) // 2 cells (a pad space where a
    double-width character straddles a cut). ``width`` below 1 is taken as 1."""
    if cell_len(name) <= width:
        return name
    width = max(1, width)
    head = (width - 1) // 2
    tail = width - 1 - head
    suffix = ""
    for char in reversed(name):
        if cell_len(char + suffix) > tail:
            break
        suffix = char + suffix
    return set_cell_size(name, head) + "\\u2026" + " " * (tail - cell_len(suffix)) + suffix


def _a2l_detail_card_text(tag: Optional[dict]) -> Text:''', "helper: _shorten_tag_name")

# 4. _build_a2l_table_cells: name_width parameter, the cut, the new cell order
sub('''    def _build_a2l_table_cells(self, tag: dict) -> tuple[Text, ...]:''',
    '''    def _build_a2l_table_cells(
        self, tag: dict, name_width: Optional[int] = None
    ) -> tuple[Text, ...]:''', "cells: signature")
sub('''        return (
            safe_text(f"{glyph} {name_text}", style=VALUE),
            safe_text(addr_text, style=CYAN),
            safe_text(len_text),
            safe_text(source_text, style=DGRAY),''',
    '''        shown_name = _shorten_tag_name(
            name_text, 34 if name_width is None else min(34, name_width)
        )
        return (
            safe_text(addr_text, style=CYAN),
            safe_text(len_text),
            safe_text(f"{glyph} {shown_name}", style=VALUE),
            safe_text(source_text, style=DGRAY),''', "cells: order and the cut")

# 5. update_a2l_tags_view: w measured once per page, given to every row; the fit scheduled after the refresh
sub('''        issue_severity_map = _a2l_issue_severity_map(self._validation_issues)
        for i, tag in enumerate(visible_tags):
            absolute_index = start + i
            row_key = f"a2l:{absolute_index}"
            self._a2l_row_key_to_tag[row_key] = tag
            cells = self._build_a2l_table_cells(tag)''',
    '''        issue_severity_map = _a2l_issue_severity_map(self._validation_issues)
        name_width = self._a2l_tag_name_width(a2l_table)
        for i, tag in enumerate(visible_tags):
            absolute_index = start + i
            row_key = f"a2l:{absolute_index}"
            self._a2l_row_key_to_tag[row_key] = tag
            cells = self._build_a2l_table_cells(tag, name_width)''', "page: name width")
post_fit = "        self.call_after_refresh(self._fit_a2l_tag_cells)\n" if "postfit" in FLAGS else ""
measured_handler = '''
    def on_a2l_tag_table_measured(self, event: "A2LTagTable.Measured") -> None:
        """E2 measurement prototype (Inc 12): the tag table was laid out at a new size; fit its Tag cells."""
        event.stop()
        self._fit_a2l_tag_cells()
''' if "widget" in FLAGS else ""
sub('''            len(visible_tags),
            total_tags,
            time.perf_counter() - populate_started,
        )
        self._flush_logger()

    def _build_a2l_table_cells(''',
    '''            len(visible_tags),
            total_tags,
            time.perf_counter() - populate_started,
        )
        self._flush_logger()
''' + post_fit + '''
    def _a2l_tag_name_width(self, a2l_table: DataTable) -> Optional[int]:
        """E2 measurement prototype (Inc 12): the name width w = the table's visible width minus the rendered
        widths of its first two (fixed) columns minus the Tag column's padding, glyph and blank; None while the
        table has no laid-out region (the A2L Explorer hidden)."""
        visible = a2l_table.scrollable_content_region.width
        if visible <= 0:
            return None
        fixed = sum(column.get_render_width(a2l_table) for column in a2l_table.ordered_columns[:2])
        return visible - fixed - (2 * a2l_table.cell_padding + 2)

    def _fit_a2l_tag_cells(self) -> None:
        """E2 measurement prototype (Inc 12): after a refresh, rebuild the current page when a painted Tag cell
        differs from the form for the measured name width; keep the cursor row and the scroll offsets."""
        try:
            a2l_table = self.query_one("#a2l_tags_list", DataTable)
        except Exception:
            return
        name_width = self._a2l_tag_name_width(a2l_table)
        tags = list(self._a2l_row_key_to_tag.values())
        if name_width is None or not tags or a2l_table.row_count != len(tags):
            return
        for row_index, tag in enumerate(tags):
            painted = a2l_table.get_row_at(row_index)[2]
            if getattr(painted, "plain", painted) != self._build_a2l_table_cells(tag, name_width)[2].plain:
                break
        else:
            return
        cursor_row = a2l_table.cursor_row
        scroll_x, scroll_y = a2l_table.scroll_x, a2l_table.scroll_y
        self.update_a2l_tags_view(self._a2l_filtered_tags)
        if a2l_table.row_count:
            a2l_table.move_cursor(row=min(cursor_row, a2l_table.row_count - 1), scroll=False)
        a2l_table.call_after_refresh(a2l_table.scroll_to, x=scroll_x, y=scroll_y, animate=False)
''' + measured_handler + '''
    def _build_a2l_table_cells(''', "page: fit scheduled; new methods _a2l_tag_name_width, _fit_a2l_tag_cells")

# 6. on_resize: the fit after the refresh while the A2L Explorer is shown (R-TUI-042a.5/6)
if "appresize" in FLAGS:
    sub('''        self._apply_diff_regime(event.size.width, event.size.height)
        self.call_after_refresh(self.update_project_labels)
''',
        '''        self._apply_diff_regime(event.size.width, event.size.height)
        self.call_after_refresh(self.update_project_labels)
        if self._active_screen_key == "a2l":
            self.call_after_refresh(self._fit_a2l_tag_cells)
''', "on_resize: fit while the A2L Explorer is shown")

# 7. action_show_screen: the fit after the refresh when the A2L Explorer is shown (E2-2)
if "show" in FLAGS:
    sub('''        self._apply_empty_state()
        if screen_key == "diff":''',
        '''        self._apply_empty_state()
        if screen_key == "a2l":
            self.call_after_refresh(self._fit_a2l_tag_cells)
        if screen_key == "diff":''', "action_show_screen: fit when the A2L Explorer is shown")

# 8. the table's own resize: A2LTagTable(DataTable) posts a bubbling Measured message from on_resize
if "widget" in FLAGS:
    sub('''from textual import events, work
''', '''from textual import events, work
from textual.message import Message
''', "import Message")
    sub('''class S19TuiApp(App):''', '''class A2LTagTable(DataTable):
    """E2 measurement prototype (Inc 12): the A2L Explorer tag table. ``events.Resize`` does not bubble, so the
    table re-emits its own resize as a bubbling message (the ``BandBar.Measured`` idiom)."""

    class Measured(Message, namespace="a2l_tag_table"):
        """The tag table has been laid out at a new size."""

    def on_resize(self, event: events.Resize) -> None:
        self.post_message(self.Measured())


class S19TuiApp(App):''', "class A2LTagTable")
    sub('''            DataTable(
                id="a2l_tags_list",''', '''            A2LTagTable(
                id="a2l_tags_list",''', "compose: A2LTagTable")

path.write_text(src, encoding="utf-8")
print(f"variant {variant}: wrote {path}")
