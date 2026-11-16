"""s19_app.tui.app.shell — S19TuiApp mixin: shell (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

import time
from typing import Mapping, Optional, Sequence
from textual.widgets import ProgressBar, TextArea
from rich.text import Text
from ...utils import safe_text
from ..os_clipboard_input import OsClipboardInput
from ..capped_text_area import CappedTextArea
from ..services.project_gather_service import painted_names
from ..a2l import A2LProgress
from . import deps
from .shared import (
    BusyKey,
    _BusyAction,
    _BusyRun,
    _MAC_GLYPH_PARSE_ERROR,
    _MAC_GLYPH_OUT_OF_IMAGE,
    _MAC_GLYPH_IN_IMAGE,
    _MAC_GLYPH_UNCHECKED,
)


_BUSY_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_BUSY_TICK_SECONDS = 0.1

_BUSY_ACTIONS: Mapping[BusyKey, _BusyAction] = {
    "file_load": _BusyAction(
        "Loading {name}",
        ("Copy into the work area", "Parse", "Install"),
    ),
    "a2l_load": _BusyAction(
        "Loading {name}",
        ("Copy into the work area", "Parse", "Build the tag table"),
    ),
    "project_load": _BusyAction(
        "Loading project {name}",
        ("Check the files", "Parse the A2L", "Parse the image", "Install"),
    ),
    "save_project": _BusyAction(
        "Saving project {name}",
        (
            "Create the folder",
            "Place the files",
            "Gather the project files",
            "Write project.json",
        ),
    ),
    "report": _BusyAction(
        "Generating the project report",
        ("Prepare the results", "Write the report"),
    ),
    "diff_report": _BusyAction(
        "Writing the diff report",
        ("Write Markdown", "Write HTML"),
    ),
    "before_after": _BusyAction(
        "Writing the before/after report",
        ("Compose the report",),
    ),
}


#: Inc 12b (S-a, ruling Q2): the four session actions — the keys whose run
#: refuses a second session writer and asks before quitting. Reports,
#: diff-reports and before/after runs are NOT session actions (they overlap).
SESSION_ACTION_KEYS: frozenset[BusyKey] = frozenset(
    {"file_load", "a2l_load", "project_load", "save_project"}
)

#: Inc 12b (S-a, LLR-177.3f): the one busy-refusal status line.
_BUSY_LINE = "busy: {label} is running — wait for it to finish."


#: Inc 1b (S7): the four status glyphs the MAC producer prepends to a record
#: name (``_populate_mac_datatable``); ``S19TuiApp._right_click_text`` removes
#: exactly one of these glyph-plus-space prefixes from a stored Rich cell.
_MAC_COPY_GLYPHS: tuple[str, ...] = (
    _MAC_GLYPH_PARSE_ERROR[0],
    _MAC_GLYPH_OUT_OF_IMAGE[0],
    _MAC_GLYPH_IN_IMAGE[0],
    _MAC_GLYPH_UNCHECKED[0],
)


class ShellMixin:

    def _flush_logger(self) -> None:
        """
        Summary:
            Flush every handler on ``self.logger`` so phase-boundary lines are persisted
            to disk even if the next step hangs the thread.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Iterate ``self.logger.handlers`` and call ``flush`` guarded by ``try/except``.
            - Silently ignore handlers that cannot flush (e.g., after shutdown).

        Dependencies:
            Used by:
                - ``_handle_load_dialog`` / ``load_from_path`` / ``_parse_loaded_file``
                - ``_load_mac_file`` / ``_prepare_load_payload`` / ``_start_load_worker``
                - ``_apply_prepared_load`` phase chain steps
        """
        for handler in getattr(self.logger, "handlers", []):
            try:
                handler.flush()
            except Exception:
                pass

    def set_status(self, message: str) -> None:
        self._append_log_line(message)

    def set_file_status(self, message: str) -> None:
        """Store the one file-state line; paint it only when no run is shown.

        Summary:
            Inc 12a S-d (A12a-06): the one stored file-state line is
            ``self._busy.file_state``, always written, and painted only when
            ``self._busy.runs`` is empty — while a progress line is shown it
            owns ``#status_text`` (HLR-176d). The last ``end_busy`` paints
            the stored line.

        Args:
            message (str): The file-state line (file-derived; scrubbed here).

        Returns:
            None

        Data Flow:
            - ``safe_text(str(message)).plain`` is the one scrub choke point
              shared with the seam's ``_paint_status_text`` (S12a-02).
        """
        text = str(message)
        text = painted_names([text], limit=1, clip=max(1, len(text)))
        self._busy.file_state = safe_text(text).plain
        if not self._busy.runs:
            self._paint_status_text(self._busy.file_state)

    def _append_log_line(self, message: str) -> None:
        # SE5-12a-1: the status log is the one control-byte choke point, so a
        # direct caller (the file-load coexistence line) cannot paint ESC/C0/C1.
        trimmed = safe_text(message).plain.strip()
        if not trimmed:
            return
        # N2: cap width-aware so long `.s19tool/workarea/…` paths are readable at
        # fullscreen (was a fixed 50 that clipped every path). Floor of 50 keeps
        # the narrow-viewport minimum; `self.size.width` is 0 before mount ->
        # max() falls back to the floor. markup stays off at construction, so a
        # wider cap reintroduces no markup sink.
        cap = max(50, getattr(self.size, "width", 0))
        line = trimmed[:cap]
        self.log_lines.append(line)
        self._render_log_lines()

    def _render_log_lines(self) -> None:
        lines = list(self.log_lines)
        while len(lines) < 4:
            lines.insert(0, "")
        self.query_one("#log_line_1", deps.Label).update(lines[-4])
        self.query_one("#log_line_2", deps.Label).update(lines[-3])
        self.query_one("#log_line_3", deps.Label).update(lines[-2])
        self.query_one("#log_line_4", deps.Label).update(lines[-1])

    def set_progress(self, value: int, message: Optional[str] = None) -> None:
        bar = self.query_one("#progress_bar", ProgressBar)
        bar.update(total=100, progress=max(0, min(100, value)))
        if message:
            self.set_status(message)

    def _paint_status_text(self, text: str) -> None:
        """The seam's one painter of ``#status_text`` (P-1, S12a-02).

        Summary:
            Scrub ``text`` through ``safe_text(...).plain`` and update
            ``#status_text`` — the single choke point so ESC and C0 control
            bytes never reach the terminal (LLR-176.1r, S12a-02).

        Args:
            text (str): The line to paint (file-derived names included).

        Returns:
            None

        Dependencies:
            Used by:
                - begin_busy / step_busy / end_busy / _busy_tick
                - set_file_status
        """
        self.query_one("#status_text", deps.Label).update(safe_text(text).plain)

    def begin_busy(self, key: BusyKey, label: str, steps: Sequence[str]) -> int:
        """S-a: start (or restart) one busy run and paint its first frame.

        Summary:
            Inc 12a progress seam (LLR-176.1): bump the generation, replace
            any run under ``key`` (a restart moves it last, so it is the
            shown run), paint step 1 at ``00:00``, set the bar to 0, add the
            ``-busy`` class and start the one 0.1 s timer (LLR-176.1e).

        Args:
            key (BusyKey): The action key.
            label (str): The already-painted label (no ``{name}`` left).
            steps (Sequence[str]): The step names, at least one, in order.

        Returns:
            int: The new generation, unique per begin.

        Dependencies:
            Uses: _paint_status_text / _busy_line / set_progress
            Used by: _busy_begin_action (and synthetic test begins)
        """
        b = self._busy
        b.last_gen += 1
        gen = b.last_gen
        if not b.runs:
            b.frame = 0
        b.runs.pop(key, None)
        run = _BusyRun(gen, label, tuple(steps), 1, 0.0, time.monotonic())
        b.runs[key] = run
        self._paint_status_text(self._busy_line(run))
        self.set_progress(0)
        self.query_one("#status_text", deps.Label).add_class("-busy")
        if b.timer is None:
            b.timer = self.set_interval(_BUSY_TICK_SECONDS, self._busy_tick)
        return gen

    def step_busy(
        self,
        key: BusyKey,
        gen: int,
        n: int,
        done: Optional[int] = None,
        total: Optional[int] = None,
    ) -> None:
        """S-a: advance one busy run to step ``n`` (and a within-step fraction).

        Summary:
            Inc 12a progress seam (LLR-176.1b/.1c/.1d/.1m): a stale or
            replaced generation is ignored. ``n`` is clamped to
            ``1 .. len(steps)``; with ``done`` / ``total`` the fraction is
            ``done / total`` clamped to ``0.0 .. 1.0`` and never falls within
            the same step; the bar is ``floor(100 * (n - 1 + fraction) / m)``
            only for the shown (last) run.

        Args:
            key (BusyKey): The action key.
            gen (int): The run's generation from ``begin_busy``.
            n (int): The step number (1-based).
            done (Optional[int]): Bytes/units done within the step.
            total (Optional[int]): The step's total; ignored without ``done``.

        Returns:
            None

        Dependencies:
            Uses: _paint_status_text / _busy_line / set_progress
            Used by: the 7 action bodies (main thread and via call_from_thread)
        """
        run = self._busy.runs.get(key)
        if run is None or run.gen != gen:
            return
        m = len(run.steps)
        n = min(max(n, 1), m)
        if done is not None and total is not None:
            fraction = 0.0 if total <= 0 else min(max(done / total, 0.0), 1.0)
        else:
            fraction = 0.0
        if n == run.n:
            fraction = max(run.fraction, fraction)
        run.n = n
        run.fraction = fraction
        shown = next(reversed(self._busy.runs.values()))
        if shown is run:
            self._paint_status_text(self._busy_line(run))
            self.set_progress(int(100 * (n - 1 + fraction) / m))

    def end_busy(self, key: BusyKey, gen: int, outcome: str) -> bool:
        """S-a: end one busy run; the last end hands the bar and text back.

        Summary:
            Inc 12a progress seam (LLR-176.1f/.1i/.1j/.1k/.1m/.1o, A12a-04):
            a non-empty outcome is one status-log line, written even for a
            replaced generation (the log is history). A stale generation is
            then a no-op returning ``False``. On the last end the timer is
            stopped, ``-busy`` removed, the bar set to 0 and the stored
            ``file_state`` painted.

        Args:
            key (BusyKey): The action key.
            gen (int): The run's generation.
            outcome (str): The action's final status line.

        Returns:
            bool: ``True`` only for an effective end.

        Dependencies:
            Uses: set_status / _paint_status_text / _busy_line / set_progress
            Used by: the 7 action bodies and _busy_fail
        """
        if outcome.strip():
            self.set_status(safe_text(outcome).plain)
        run = self._busy.runs.get(key)
        if run is None or run.gen != gen:
            return False
        del self._busy.runs[key]
        # E3 S12b-04 / R2-02: whenever a project_load run is removed (the
        # hand-back), the Patch Editor's paste buffer becomes editable again
        # — whether or not other runs remain.
        if key == "project_load":
            try:
                text_area = self.query_one("#patch_paste_text", TextArea)
            except Exception:  # noqa: BLE001 - not mounted (headless tests)
                text_area = None
            if text_area is not None:
                text_area.read_only = False
        if self._busy.runs:
            shown = next(reversed(self._busy.runs.values()))
            self._paint_status_text(self._busy_line(shown))
            self.set_progress(
                int(100 * (shown.n - 1 + shown.fraction) / len(shown.steps))
            )
        else:
            b = self._busy
            b.timer.stop()
            b.timer = None
            self.query_one("#status_text", deps.Label).remove_class("-busy")
            self.set_progress(0)
            self._paint_status_text(b.file_state)
        # A12a-07 / S-c: the quit-after-end check lives here, so every
        # effective end (the session handlers, _busy_fail, _handle_load_error)
        # reaches it after the hand-back; a stale end (False) does not.
        self._exit_if_quit_pending()
        return True

    def _busy_tick(self) -> None:
        """S-f: the 0.1 s interval callback — advance the spinner frame."""
        if not self._busy.runs:
            return
        # SR-12a-2: a run can still be open when the app exits (a worker
        # running at quit); the timer can tick after the status bar is
        # removed, so a tick with no ``#status_text`` paints nothing.
        if self.query_one_optional("#status_text", deps.Label) is None:
            return
        self._busy.frame = (self._busy.frame + 1) % 10
        self._paint_status_text(
            self._busy_line(next(reversed(self._busy.runs.values())))
        )

    def _busy_line(self, run: _BusyRun) -> str:
        """S-f: the pd_A line — glyph, painted label, step and mm:ss elapsed."""
        elapsed = int(time.monotonic() - run.started)
        n = run.n
        return (
            f"{_BUSY_FRAMES[self._busy.frame]} {run.label}  ·  step {n}/"
            f"{len(run.steps)} {run.steps[n - 1]}  ·  "
            f"{elapsed // 60:02d}:{elapsed % 60:02d}"
        )

    def _busy_begin_action(self, key: BusyKey, name: Optional[str] = None) -> int:
        """S-c helper: format the table row, scrub ``name`` once, begin the run.

        Summary:
            The one ``painted_names`` call site for progress labels
            (LLR-176.1r, Q-2): a row whose label holds ``{name}`` is formatted
            with the scrubbed name; a row without it is used verbatim.

        Args:
            key (BusyKey): The action key.
            name (Optional[str]): The file/project name for ``{name}`` rows.

        Returns:
            int: The generation from ``begin_busy``.

        Dependencies:
            Uses: _BUSY_ACTIONS / begin_busy
            Used by: the 7 action bodies
        """
        row = _BUSY_ACTIONS[key]
        label = (
            row.label.format(name=painted_names([name]))
            if "{name}" in row.label
            else row.label
        )
        return self.begin_busy(key, label, row.steps)

    def _busy_fail(self, key: BusyKey, gen: int) -> bool:
        """S-e failure arm: end the run with ``<label> failed`` (P-1)."""
        run = self._busy.runs.get(key)
        if run is None or run.gen != gen:
            return False
        return self.end_busy(key, gen, f"{run.label} failed")

    def _running_session_action(self) -> Optional[_BusyRun]:
        """S-a: the newest running session action, or ``None`` (HLR-177a).

        Summary:
            Read ``self._busy.runs`` only (12a S-b: ordered, newest last;
            ``_BusyRun.label`` is already painted through ``painted_names``)
            and return the newest run whose key is a session action. Writes
            nothing in ``_busy``.

        Returns:
            Optional[_BusyRun]: The newest session run, or ``None``.

        Dependencies:
            Uses: SESSION_ACTION_KEYS
            Used by: _refuse_if_busy / action_quit / _exit_if_quit_pending
        """
        return next(
            (
                run
                for key, run in reversed(self._busy.runs.items())
                if key in SESSION_ACTION_KEYS
            ),
            None,
        )

    def _refuse_if_busy(self) -> bool:
        """S-a: refuse a request while a session action runs (HLR-177a).

        Summary:
            The one busy check (LLR-177.3 … .3h): ``True`` = refused (the
            busy line is one status-log line, nothing else changes); the
            label is already painted, so no second scrub. No focus, no
            ``push_screen``, no ``notify``, no ``#status_text`` write.

        Returns:
            bool: ``True`` when a session action is running and the request
                was refused.

        Dependencies:
            Uses: _running_session_action / _BUSY_LINE / set_status
            Used by: the 17 entry points, the 4 continuations, the 4 starts
        """
        run = self._running_session_action()
        if run is None:
            return False
        self.set_status(_BUSY_LINE.format(label=run.label))
        self.logger.info("Request refused while busy: %s", run.label)
        return True

    def _right_click_text(self, x: int, y: int) -> Optional[str]:
        """
        Summary:
            Read-only resolution of the text a button-3 press on the
            top-screen cell ``(x, y)`` would copy (Inc 1b, R-COPY.4,
            R-COPY.12 … R-COPY.14). ``None`` means no clipboard action.
            The early text-box exclusion runs first, then the JSON view's
            own selection, then the A2L/MAC table row name, then the
            whole top-screen selection only for a widget that actually
            holds part of it.

        Args:
            x (int): Top-screen column of the press.
            y (int): Top-screen row of the press.

        Returns:
            Optional[str]: The text to copy, or ``None`` when the press is
            on a text box, empty space, a header, an unrelated widget, or a
            table cell with ``out_of_bounds=True``.

        Data Flow:
            - ``get_widget_at`` + ``get_style_at`` supply the widget and the
              compositor metadata (``row`` / ``column`` / ``out_of_bounds``)
              Textual assigns to the forwarded mouse event.
            - A2L resolves the clicked row key through
              ``coordinate_to_cell_key((row, 0))`` and reads the mapped
              tag's full ``name``; MAC reads column 0, normalizes with
              ``.plain``/``str`` and removes exactly one known
              glyph-plus-space prefix.

        Dependencies:
            Uses:
                - ``OsClipboardInput`` / ``CappedTextArea``
                - ``Screen.get_widget_at`` / ``Screen.get_style_at``
                - ``DataTable.coordinate_to_cell_key`` / ``get_row_at``
                - ``_a2l_row_key_to_tag`` / ``_MAC_COPY_GLYPHS``
            Used by:
                - ``S19TuiApp.on_event``
        """
        try:
            widget, _ = self.screen.get_widget_at(x, y)
        except Exception:
            return None
        if any(
            isinstance(node, (OsClipboardInput, CappedTextArea))
            for node in widget.ancestors_with_self
        ):
            return None
        meta = self.screen.get_style_at(x, y).meta
        widget_id = widget.id
        if widget_id == "patch_json_view":
            return widget.selected_text or None
        if widget_id in ("a2l_tags_list", "mac_records_list"):
            row = meta.get("row")
            column = meta.get("column")
            if not (isinstance(row, int) and isinstance(column, int)):
                return None
            if meta.get("out_of_bounds", False):
                return None
            if not (0 <= row < widget.row_count and column >= 0):
                return None
            if widget_id == "a2l_tags_list":
                try:
                    row_key, _ = widget.coordinate_to_cell_key((row, 0))
                except Exception:
                    return None
                key_value = getattr(row_key, "value", row_key)
                key_str = str(key_value) if isinstance(key_value, str) else None
                tag = (
                    self._a2l_row_key_to_tag.get(key_str)
                    if key_str is not None
                    else None
                )
                if isinstance(tag, dict):
                    name = tag.get("name")
                    if name:
                        return str(name)
                return None
            try:
                cell = widget.get_row_at(row)[0]
            except Exception:
                return None
            painted = cell.plain if isinstance(cell, Text) else str(cell)
            for glyph in _MAC_COPY_GLYPHS:
                prefix = f"{glyph} "
                if painted.startswith(prefix):
                    name = painted[len(prefix):]
                    return name or None
            return None
        selected = self.screen.get_selected_text()
        if selected and widget in self.screen.selections:
            return selected
        return None

    def _answer_quit(self, quit: Optional[bool]) -> None:
        """S-c: the quit question's answer (LLR-177.4b / .4c)."""
        self._quit_pending = bool(quit)
        self._exit_if_quit_pending()

    def _exit_if_quit_pending(self) -> None:
        """S-c: exit when a quit is confirmed and no session action runs."""
        if self._quit_pending and self._running_session_action() is None:
            self.exit()

    def _progress_forwarder(self, key: BusyKey, gen: int, n: int) -> A2LProgress:
        """S-f: the worker-side progress closure (LLR-177.5 / .5a / LLR-176.1q).

        Summary:
            Returns a callable for the worker thread that forwards
            ``step_busy`` through ``call_from_thread`` at most once per
            percent change, plus every report at or past ``total`` — so at
            most about 101 blocking round trips per step. It closes over
            ``key`` / ``gen`` / ``n`` only and reads no session attribute.

        Args:
            key (BusyKey): The action key.
            gen (int): The run's generation.
            n (int): The step number.

        Returns:
            A2LProgress: ``forward(done, total)``.

        Dependencies:
            Uses: step_busy / call_from_thread
            Used by: the A2L, project and Save workers (step 2)
        """
        last: list[Optional[int]] = [None]

        def forward(done: int, total: int) -> None:
            pct = (100 * done) // total if total > 0 else 0
            if pct != last[0] or done >= total:
                last[0] = pct
                self.call_from_thread(self.step_busy, key, gen, n, done, total)

        return forward
