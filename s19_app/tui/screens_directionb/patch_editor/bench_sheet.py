"""The bench widget of the Patch Editor (batch-103 Inc 9, interface I-9.1): the StagingSheet subclass that paints and edits the array, curve and map benches over the pure model in definition_bench and the pure render in definition_bench_view, keeping each bench row's BenchState and running its decode, preview, summary, staged and record jobs off the UI thread."""
from __future__ import annotations

import time
from dataclasses import replace

from textual import work
from textual.binding import Binding
from textual.message import Message

from ...a2l_definition import Definition, Refusal, decode_values, encode_values
from ...definition_bench import (
    BenchState,
    BenchValues,
    apply_tool,
    bench_cells,
    bench_grid,
    bench_mark,
    bench_preview,
    finite_range,
    move_cursor,
    page_cursor,
    staged_delta,
    summary_strip,
    undo,
    window_for,
)
from ...definition_bench_view import (
    BUSY_COLOR,
    axis_labels,
    bench_detail,
    busy_title,
    canvas_shape,
    op_line,
)
from ...definition_sheet import (
    KindOps,
    StagedOverlay,
    _FALLBACK_OPS,
    _KIND_OPS,
    name_echo,
    sheet_widths,
)
from .sheet import StagingSheet

BENCH_KINDS = ("curve", "map", "array")
BENCH_LARGE = 4096
BUSY_GRACE_S = 0.2
BUSY_TICK_S = 0.1


def busy_job(name, state, stage_name):
    """The busy job of the cue: a record stage, else the selected bench row's decode or preview, else None."""
    if stage_name is not None:
        return ("stage", stage_name)
    if state is not None and state.job in ("decode", "preview"):
        return (state.job, name)
    return None


class ArrayBenchSheet(StagingSheet):
    """The staging sheet with the array, curve and map benches (Inc 9)."""

    BINDINGS = [
        Binding("shift+left", "cursor(-1, 0)", "Cursor left", show=False),
        Binding("shift+right", "cursor(1, 0)", "Cursor right", show=False),
        Binding("shift+up", "cursor(0, -1)", "Cursor up", show=False),
        Binding("shift+down", "cursor(0, 1)", "Cursor down", show=False),
        Binding("pageup", "page(-1)", "Page up", show=False),
        Binding("pagedown", "page(1)", "Page down", show=False),
        Binding("s", "tool('s')", "Set", show=False),
        Binding("d", "tool('d')", "Δ", show=False),
        Binding("p", "tool('p')", "×%", show=False),
        Binding("i", "tool('i')", "Interpolate", show=False),
        Binding("m", "tool('m')", "Smooth", show=False),
        Binding("u", "tool('u')", "Undo", show=False),
        Binding("escape", "leave_bench", "Leave bench", show=False),
        Binding("alt+s", "stage_record", "Stage record", show=False),
    ]

    class BenchApplyRequested(Message):
        """Enter in a bench row's op input: apply ``name``'s tool with operand ``text``."""

        def __init__(self, name: str, text: str) -> None:
            super().__init__()
            self.name = name
            self.text = text

    class RecordStageRequested(Message):
        """alt+s on a bench row: stage the encoded record of ``name``."""

        def __init__(self, name, definition, count, outcome, generation, edit) -> None:
            super().__init__()
            self.name = name
            self.definition = definition
            self.count = count
            self.outcome = outcome
            self.generation = generation
            self.edit = edit

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.generation: int = 0
        self._view: int = 0
        self._pages: int = 0
        self._last_selected: str | None = None
        self._strip_width: int = 12
        self._records: dict[str, tuple] = {}
        self._slot: list[tuple[str, str]] = []
        self._page: list[tuple[str, str]] = []
        self._active_job: tuple | None = None
        self._held: bool = False
        self._busy_asked: dict[tuple[str, str], float] = {}
        self._stage_name: str | None = None
        self._busy_timer = None
        self._busy_frame: int = 0
        self._busy_idle_title = None

    def on_mount(self) -> None:
        self._busy_timer = self.set_interval(BUSY_TICK_S, self._busy_tick, pause=True)

    def _paint(self) -> None:
        row = self._bench_row()
        if row is not None:
            self._state_for(row.name)
        super()._paint()

    def _status(self, text: str) -> None:
        if self.is_attached:
            set_status = getattr(self.app, "set_status", None)
            if set_status is not None:
                set_status(text)

    def _state_for(self, name: str) -> BenchState:
        state = self.states.get(name)
        if state is None:
            state = BenchState()
            self.states[name] = state
        return state

    def _bench_row(self):
        row = self._row()
        return row if row is not None and row.kind in BENCH_KINDS else None

    def _enqueue(self, kind: str, name: str, edit: tuple | None = None) -> None:
        if kind == "record":
            self._records[name] = edit
        elif kind in ("decode", "preview"):
            self._slot = [(k, n) for k, n in self._slot if k != kind]
            self._slot.append((kind, name))
        elif kind in ("summary", "staged"):
            if (kind, name) not in self._page:
                self._page.append((kind, name))
        if kind in ("record", "decode", "preview"):
            word = "stage" if kind == "record" else kind
            self._busy_asked.setdefault((word, name), time.monotonic())
            if self._busy_timer is not None:
                self._busy_timer.resume()
        self._start_next()

    def _start_next(self) -> None:
        if self._active_job is not None or self._held:
            return
        if self._body is not None:
            self._strip_width = sheet_widths(self._body.content_size.width or 118).current
        while True:
            if self._records:
                name = next(iter(self._records))
                edit = self._records.pop(name)
                kind = "record"
            elif self._slot:
                kind, name = self._slot.pop(0)
                edit = None
            elif self._page:
                kind, name = self._page.pop(0)
                edit = None
            else:
                return
            row = next((r for r in self.rows if r.name == name), None)
            if row is None:
                continue
            definition = row.definition
            token = self._pages if kind in ("summary", "staged") else self._view
            if kind == "preview":
                edit = tuple(self.states[name].edit.items())
            snapshot = tuple((address, tuple(data)) for address, data in self._entries)
            self._active_job = (kind, name, token, definition, edit)
            generation = self.generation
            self._run_job(kind, name, generation, definition, snapshot, edit)
            return

    @work(thread=True, group="bench", exit_on_error=False)
    def _run_job(self, kind, name, generation, definition, snapshot, edit):
        try:
            overlay = StagedOverlay(self._image, snapshot)
            derived = {}
            if kind == "summary":
                decoded = decode_values(definition, self.a2l_data, self._image)
                if isinstance(decoded, Refusal):
                    result = decoded
                else:
                    result = BenchValues.from_decoded(decoded)
                    derived = self._derive(definition, decoded, result)
            elif kind == "staged":
                decoded = decode_values(definition, self.a2l_data, overlay)
                result = decoded if isinstance(decoded, Refusal) else BenchValues.from_decoded(decoded)
                values = getattr(self.states.get(name), "values", None)
                if values is not None and isinstance(result, BenchValues):
                    derived = {"staged_delta": staged_delta(values, result)}
            elif kind == "decode":
                current = decode_values(definition, self.a2l_data, self._image)
                cur = current if isinstance(current, Refusal) else BenchValues.from_decoded(current)
                result = (cur, self._staged_pair(definition, overlay, snapshot, cur))
                if not isinstance(current, Refusal):
                    derived = self._derive(definition, current, cur)
                    if isinstance(result[1], BenchValues):
                        derived["staged_delta"] = staged_delta(cur, result[1])
            else:
                result = encode_values(definition, self.a2l_data, dict(edit), overlay)
                if kind == "preview" and not isinstance(result, Refusal):
                    old = tuple(overlay.get(definition.address + i, 0) for i in range(definition.byte_length))
                    runs = []
                    for i, (o, n) in enumerate(zip(old, result.data)):
                        if o != n:
                            if runs and runs[-1][0] + len(runs[-1][1]) == i:
                                off, po, pn = runs[-1]
                                runs[-1] = (off, po + bytes((o,)), pn + bytes((n,)))
                            else:
                                runs.append((i, bytes((o,)), bytes((n,))))
                    derived = {"runs": tuple(runs)}
        except Exception:
            result, derived = None, {}
        self.app.call_from_thread(self._job_done, kind, name, generation, result, derived)

    def _staged_pair(self, definition, overlay, snapshot, current):
        """The staged values of a decode job: a second I-2 decode only when an entry of the snapshot falls
        inside the record; otherwise the staged values are the current ones."""
        start = definition.address
        end = (start or 0) + (definition.byte_length or 0)
        if start is None or not any(a < end and a + len(d) > start for a, d in snapshot):
            return current
        staged = decode_values(definition, self.a2l_data, overlay)
        return staged if isinstance(staged, Refusal) else BenchValues.from_decoded(staged)

    def _job_done(self, kind, name, generation, result, derived):
        running = self._active_job
        self._active_job = None
        if running is None or running[0] != kind or running[1] != name:
            self._start_next()
            return
        token = running[2]
        current = self._pages if kind in ("summary", "staged") else self._view
        stale = generation != self.generation or (kind != "record" and token != current)
        if stale:
            if kind == "record":
                self._status(
                    f"Patch Editor: the change document or the image changed while "
                    f"{name_echo(name)} was encoding — stage it again."
                )
            elif kind == "summary" and token == self._pages:
                self._page.insert(0, ("summary", name))
            elif kind == "decode" and name == self.selected_name:
                if not any(k == "decode" for k, _ in self._slot):
                    self._slot.insert(0, ("decode", name))
            self._start_next()
            return
        if kind == "record":
            edit = running[4]
            self._held = True
            self._stage_name = name
            self.post_message(
                self.RecordStageRequested(name, running[3], len(edit), result, generation, edit)
            )
            return
        state = self._state_for(name)
        self.states[name] = self._assign_result(kind, state, result, derived)
        self._paint()
        self._start_next()

    def _assign_result(self, kind, state, result, derived) -> BenchState:
        if result is None:
            return replace(state, job=None) if state.job == kind else state
        if kind in ("summary", "decode"):
            current = result[0] if kind == "decode" else result
            staged = result[1] if kind == "decode" else None
            if isinstance(current, BenchValues):
                new = replace(
                    state,
                    values=current,
                    axes=derived["axes"],
                    lo=derived["lo"],
                    hi=derived["hi"],
                    strip=derived["strip"],
                    labels=derived["labels"],
                    refusal=None,
                )
            else:
                new = replace(state, values=None, refusal=current)
            if kind == "decode":
                staged = staged if isinstance(staged, BenchValues) else None
                new = replace(new, staged=staged, staged_delta=derived.get("staged_delta"))
            return replace(new, job=None) if state.job == kind else new
        if kind == "staged":
            staged = result if isinstance(result, BenchValues) else None
            return replace(state, staged=staged, staged_delta=derived.get("staged_delta"))
        return replace(
            state,
            preview=result,
            runs=derived.get("runs", ()),
            job=None if state.job == "preview" else state.job,
        )

    def _derive(self, definition, decoded, values) -> dict:
        grid = bench_grid(definition)
        lo, hi = finite_range(values.numbers, values.missing)
        strip = summary_strip(values, grid, self._strip_width - len(str(grid.count)) - 2)
        axes = decoded.axes
        labels = axis_labels(definition, axes, grid)
        return {"axes": axes, "lo": lo, "hi": hi, "strip": strip, "labels": labels}

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        row = self._bench_row()
        state = self.states.get(row.name) if row is not None else None
        if action in ("cursor", "page", "tool", "leave_bench"):
            return bool(state is not None and state.focus)
        if action == "stage_record":
            return bool(
                row is not None
                and ((state is not None and state.focus) or self._input_has_focus())
            )
        return True

    def _bench_geometry(self, state, grid) -> tuple[int, int]:
        """The (rows shown, columns shown) of the bench canvas, as bench_detail computes them."""
        width, room = self._detail_geometry()
        _, rows_shown, cols_shown = canvas_shape(width, grid, state.origin, room)
        return rows_shown, cols_shown

    def _reveal(self, name, state, grid) -> None:
        """Move the window so the cursor shows, store the state and repaint."""
        rows_shown, cols_shown = self._bench_geometry(state, grid)
        origin = window_for(state, grid, rows_shown, cols_shown)
        self.states[name] = replace(state, origin=origin)
        self._paint()

    def action_edit(self) -> None:
        """Enter on the body: turn bench focus on, then focus the op input."""
        row = self._bench_row()
        if row is None:
            super().action_edit()
            return
        if self._input_has_focus():
            return
        state = self._state_for(row.name)
        if not state.focus:
            self.states[row.name] = replace(state, focus=True)
            self._paint()
            return
        self._input.disabled = False
        self._input.focus()

    def action_move(self, delta: int) -> None:
        """In bench focus move the cursor down (up: negative); else select the row below."""
        row = self._bench_row()
        if row is not None:
            state = self._state_for(row.name)
            if state.focus and not self._input_has_focus():
                grid = bench_grid(row.definition)
                self._reveal(row.name, move_cursor(state, grid, 0, int(delta), False), grid)
                return
        super().action_move(delta)

    def action_choose(self, delta: int) -> None:
        """In bench focus move the cursor right (left: negative); else choose an entry."""
        row = self._bench_row()
        if row is not None:
            state = self._state_for(row.name)
            if state.focus and not self._input_has_focus():
                grid = bench_grid(row.definition)
                self._reveal(row.name, move_cursor(state, grid, int(delta), 0, False), grid)
                return
        super().action_choose(delta)

    def action_cursor(self, dx: int, dy: int) -> None:
        """Shift+arrows in bench focus: extend the selection (no wrap)."""
        row = self._bench_row()
        if row is None:
            return
        state = self._state_for(row.name)
        if state.focus and not self._input_has_focus():
            grid = bench_grid(row.definition)
            self._reveal(row.name, move_cursor(state, grid, int(dx), int(dy), True), grid)

    def action_page(self, direction) -> None:
        """PgUp/PgDn in bench focus: page the cursor by the window's rows."""
        row = self._bench_row()
        if row is None:
            return
        state = self._state_for(row.name)
        if not state.focus or self._input_has_focus():
            return
        grid = bench_grid(row.definition)
        rows_shown, _ = self._bench_geometry(state, grid)
        new = page_cursor(state, grid, rows_shown, int(direction))
        self._reveal(row.name, new, grid)

    def action_leave_bench(self) -> None:
        """Escape in bench focus: turn bench focus off, the focus stays on the body."""
        row = self._bench_row()
        if row is None:
            return
        state = self._state_for(row.name)
        if not state.focus:
            return
        self.states[row.name] = replace(state, focus=False)
        self._paint()

    def _on_formula_escape(self) -> None:
        """Escape in a bench row's op input: back to the body with bench focus on."""
        row = self._bench_row()
        if row is None:
            super()._on_formula_escape()
            return
        if self._body is not None:
            self._body.focus()
        state = self._state_for(row.name)
        self.states[row.name] = replace(state, focus=True)
        self._paint()

    def action_tool(self, key) -> None:
        """s/d/p/i/m: pick the tool; u: undo; a refusal shows in the status line."""
        row = self._bench_row()
        if row is None:
            return
        state = self._state_for(row.name)
        if not state.focus:
            return
        new = undo(state) if key == "u" else replace(state, tool=key, status=None)
        if new.status is not None:
            self._status(new.status)
        self._edit_changed(row.name, state, new)

    def _edit_changed(self, name, old, new) -> None:
        """After a state change: queue or clear the preview, then repaint."""
        if new.edit != old.edit:
            if new.edit:
                new = replace(new, job="preview", preview="encoding")
                self.states[name] = new
                self._enqueue("preview", name)
            else:
                self.states[name] = replace(new, preview=None, runs=())
        else:
            self.states[name] = new
        self._paint()

    def on_array_bench_sheet_bench_apply_requested(self, event) -> None:
        """Enter in the op input: apply the tool, or say the row is still decoding."""
        event.stop()
        row = next((r for r in self.rows if r.name == event.name), None)
        if row is None or row.kind not in BENCH_KINDS:
            return
        state = self._state_for(event.name)
        if state.values is None or state.job == "decode":
            self._status(
                f"Patch Editor: {name_echo(event.name)} is still decoding — "
                "try again when its values show."
            )
            return
        new = apply_tool(row.definition, state, bench_grid(row.definition), state.values, event.text)
        if new.status:
            self._status(new.status)
        self._edit_changed(event.name, state, new)

    def action_stage_record(self) -> None:
        """alt+s on a bench row: stage the encoded record of its edit."""
        row = self._bench_row()
        if row is None:
            return
        state = self._state_for(row.name)
        if state.values is None:
            self._status(
                f"Patch Editor: {name_echo(row.name)} is still decoding — "
                "try again when its values show."
            )
            return
        if not state.edit:
            self._status(f"Patch Editor: {name_echo(row.name)} has no bench edit to stage.")
            return
        self._enqueue("record", row.name, tuple(state.edit.items()))

    def record_staged(self, name, edit) -> None:
        """The record of ``name`` is staged: drop its edit when it still matches."""
        state = self.states.get(name)
        if state is None:
            return
        if tuple(state.edit.items()) == tuple(edit):
            self.states[name] = replace(state, edit={}, undo=(), preview=None, runs=(), status=None)
        self._paint()

    def record_done(self, name) -> None:
        """The record of ``name`` finished: release the hold and resume the queue."""
        self._held = False
        self._stage_name = None
        self._start_next()
        self._busy_tick()

    def _busy_window(self):
        for ancestor in self.ancestors:
            if getattr(ancestor, "id", None) == "patch_sheet_win":
                return ancestor
        return None

    def _busy_stage_name(self):
        if self._stage_name is not None:
            return self._stage_name
        if self._active_job is not None and self._active_job[0] == "record":
            return self._active_job[1]
        return next(iter(self._records), None)

    def _busy_tick(self) -> None:
        """The cue tick: show the busy border and title of the window while a busy job has waited past the grace."""
        win = self._busy_window()
        if win is None:
            return
        name = self.selected_name
        job = busy_job(name, self.states.get(name), self._busy_stage_name())
        self._busy_asked = {k: v for k, v in self._busy_asked.items() if k == job}
        if job is not None:
            pending = time.monotonic() - self._busy_asked.setdefault(job, time.monotonic())
        if job is None or pending < BUSY_GRACE_S:
            self._busy_idle_look(win)
            if not self._busy_asked and self._busy_timer is not None:
                self._busy_timer.pause()
            return
        if self._busy_idle_title is None:
            self._busy_idle_title = win.border_title or ""
        win.styles.border = ("round", BUSY_COLOR)
        win.border_title = busy_title(
            str(self._busy_idle_title), job[0], job[1], pending, self._busy_frame, win.size.width - 4
        )
        self._busy_frame += 1

    def _busy_idle_look(self, win) -> None:
        if self._busy_idle_title is None:
            return
        for edge in ("border_top", "border_right", "border_bottom", "border_left"):
            win.styles.clear_rule(edge)
        win.border_title = self._busy_idle_title
        self._busy_idle_title = None
        win.refresh()

    def on_staging_sheet_selection_changed(self, event) -> None:
        """A bench row selected: keep its state and decode; a large row dropped: forget its values and everything derived from them."""
        name = event.name
        row = self._row()
        if row is None or row.name != name:
            return
        is_bench = row.kind in BENCH_KINDS
        for ancestor in self.ancestors:
            if getattr(ancestor, "id", None) == "patch_editor_panel":
                ancestor.set_class(is_bench, "-bench")
                break
        if name == self._last_selected and (not is_bench or name in self.states):
            return
        before = self._last_selected
        self._last_selected = name
        self._view += 1
        self._slot = []
        if before in self.states:
            before_row = next((r for r in self.rows if r.name == before), None)
            if before_row is not None and before_row.definition.element_count > BENCH_LARGE:
                self.states[before] = replace(
                    self.states[before], values=None, staged=None, axes=(),
                    lo=0.0, hi=0.0, strip=None, labels=None, staged_delta=None,
                )
        if is_bench:
            state = self._state_for(name)
            self.states[name] = replace(state, job="decode")
            self._enqueue("decode", name)
            if state.edit:
                self._enqueue("preview", name)
        self._paint()

    def show_page(self, names, definitions, a2l_data, image) -> None:
        """Rebuild the page rows and queue the bench rows' summary decodes."""
        super().show_page(names, definitions, a2l_data, image)
        self._view += 1
        self._pages += 1
        shown = {row.name for row in self.rows}
        for name in list(self.states):
            if name not in shown:
                del self.states[name]
        self._page = []
        for row in self.rows:
            if row.kind in BENCH_KINDS and row.definition.element_count <= BENCH_LARGE:
                self.states[row.name] = replace(self._state_for(row.name), job="summary")
                self._page.append(("summary", row.name))
        self._start_next()

    def set_document(self, entries, image) -> None:
        """Rebuild the rows over the new document and requeue the changed bench work."""
        image_changed = image is not self._image
        super().set_document(entries, image)
        self.generation += 1
        selected_name = self.selected_name
        self._page = [p for p in self._page if p[0] == "summary"] + [
            ("staged", r.name)
            for r in self.rows
            if r.kind in BENCH_KINDS
            and r.name != selected_name
            and r.definition.element_count <= BENCH_LARGE
            and (
                self._holds_entry(r.definition)
                or self._staged_differs(r.name)
            )
        ]
        row = self._bench_row()
        if row is not None:
            state = self._state_for(row.name)
            if image_changed or state.job == "decode":
                self._enqueue("decode", row.name)
            elif self._holds_entry(row.definition) or self._staged_differs(row.name):
                self._enqueue("staged", row.name)
            if state.edit:
                self._enqueue("preview", row.name)
        self._start_next()

    def _staged_differs(self, name) -> bool:
        state = self.states.get(name)
        return state is not None and state.staged is not None and state.staged != state.values

    def _holds_entry(self, definition) -> bool:
        """True when a document entry's bytes fall inside the definition's span."""
        if definition.address is None:
            return False
        end = definition.address + (definition.byte_length or 0)
        return any(
            address < end and address + len(data) > definition.address
            for address, data in self._entries
        )


def bench_submit(name: str, text: str) -> ArrayBenchSheet.BenchApplyRequested:
    """The apply request of a bench row's op input."""
    return ArrayBenchSheet.BenchApplyRequested(name, text)


def _editable(definition: Definition) -> bool:
    return True


def register_bench_kinds() -> None:
    """Register the bench kinds' KindOps (assignment only, idempotent)."""
    for kind in BENCH_KINDS:
        _KIND_OPS[kind] = KindOps(
            label="op =",
            editable=_editable,
            decode=_FALLBACK_OPS.decode,
            value_text=_FALLBACK_OPS.value_text,
            staged=_FALLBACK_OPS.staged,
            preview=bench_preview,
            detail=bench_detail,
            submit=bench_submit,
            cells=bench_cells,
            bar=op_line,
            mark=bench_mark,
        )


register_bench_kinds()
