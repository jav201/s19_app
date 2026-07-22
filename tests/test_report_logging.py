"""N3 — report-generation observability (fail-loud logging).

Covers the spec ACs for `.fast-dev-flow/spec.md` batch `n3-report-logging`:

- AC-1..3: each report kind (project / before-after / diff) logs a structured
  metadata line (kind · source · output · outcome).
- AC-4: a failure/refusal logs at WARNING — never silent.
- AC-5: the logged line carries metadata only — no report body / byte values.
- AC-6: the line reaches the ``s19tui.log`` file (the ``"s19tui"`` logger),
  not a ``getLogger(__name__)`` that never propagates to the file handler.

The driven AT (`test_before_after_report_generation_logs_to_file`) exercises the
REAL app surface (`action_before_after_report`) and reads the produced log file
back — a black-box output-then-consume assertion (C-12/C-31/C-32), not a
mock-was-called check.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from s19_app.tui.app import S19TuiApp, format_report_log_line
from s19_app.tui.workspace import LOG_FILENAME, LOGS_SUBDIR, setup_logging

# Reuse the proven app-driving scaffold from the before/after AT suite.
from test_before_after_report import (
    _drive_apply,
    _load_image,
    _make_s19_image,
    _statuses,
)


def _log_path(base_dir: Path) -> Path:
    return base_dir / ".s19tool" / LOGS_SUBDIR / LOG_FILENAME


class _CaptureLogger:
    """Minimal stand-in exposing a ``.logger`` for the unbound method call."""

    def __init__(self) -> None:
        self.logger = logging.getLogger("s19tui.test.report_logging")
        self.logger.handlers.clear()
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self.records: list[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = self.records.append  # type: ignore[assignment]
        self.logger.addHandler(handler)


# ---------------------------------------------------------------------------
# AC-1/2/3, AC-5 — the pure formatter
# ---------------------------------------------------------------------------

def test_format_report_log_line_names_all_four_fields() -> None:
    """AC-1/2/3: kind, source, output and outcome all appear, labelled."""
    line = format_report_log_line(
        "before-after", "prg.s19", "a.md|a.html", "ok"
    )
    assert line == (
        "report kind=before-after source=prg.s19 "
        "output=a.md|a.html outcome=ok"
    )
    for token in ("kind=before-after", "source=prg.s19", "output=a.md|a.html", "outcome=ok"):
        assert token in line


def test_format_report_log_line_is_metadata_only() -> None:
    """AC-5: the formatter emits ONLY the four metadata fields it is given —
    it cannot smuggle body/byte content because it interpolates nothing else."""
    line = format_report_log_line("diff", "a.s19|b.s19", "d.md|d.html", "ok")
    # Structurally: exactly the four labelled fields, nothing else.
    assert line.startswith("report kind=")
    assert line.count("=") == 4
    # A representative image-byte token never appears unless a caller passes it
    # as metadata (callers pass names/paths only).
    assert "AA BB" not in line


# ---------------------------------------------------------------------------
# AC-1..4 — level routing on the real method
# ---------------------------------------------------------------------------

def test_log_report_event_success_is_info() -> None:
    """AC-1..3: a successful report logs at INFO with the formatted line."""
    fake = _CaptureLogger()
    S19TuiApp._log_report_event(
        fake, "project", "proj", "reports/x.md", "ok", ok=True
    )
    assert len(fake.records) == 1
    rec = fake.records[0]
    assert rec.levelno == logging.INFO
    assert rec.getMessage() == (
        "report kind=project source=proj output=reports/x.md outcome=ok"
    )


def test_log_report_event_failure_is_warning() -> None:
    """AC-4: a failed/refused report logs at WARNING — never silent."""
    fake = _CaptureLogger()
    S19TuiApp._log_report_event(
        fake, "before-after", "prg.s19", "-", "refused", ok=False
    )
    assert len(fake.records) == 1
    rec = fake.records[0]
    assert rec.levelno == logging.WARNING
    assert "outcome=refused" in rec.getMessage()
    assert "output=-" in rec.getMessage()


# ---------------------------------------------------------------------------
# AC-6 — the "s19tui" logger reaches the log FILE
# ---------------------------------------------------------------------------

def test_report_line_reaches_s19tui_log_file(tmp_path: Path) -> None:
    """AC-6: a line logged on the ``setup_logging`` logger lands in
    ``.s19tool/logs/s19tui.log`` (readable back from disk)."""
    logger = setup_logging(tmp_path)
    logger.info(
        format_report_log_line("project", "proj", "reports/r.md", "ok")
    )
    for handler in logger.handlers:
        handler.flush()
    content = _log_path(tmp_path).read_text(encoding="utf-8")
    assert "report kind=project source=proj output=reports/r.md outcome=ok" in content


# ---------------------------------------------------------------------------
# Driven AT (gold standard) — real before/after action → real log file
# ---------------------------------------------------------------------------

def test_before_after_report_generation_logs_to_file(tmp_path: Path) -> None:
    """AC-2 + AC-5 + AC-6 through the shipped surface: driving the real
    ``b`` before/after action writes a ``report kind=before-after ... ok``
    line to ``s19tui.log``, and the log carries NO entry-byte content.

    Counterfactual: before this batch, ``action_before_after_report`` made
    ZERO logger calls, so the log file would contain no ``report kind=``
    line at all — this assert fails on the pre-fix code.
    """
    from textual.widgets import Button

    image_path = _make_s19_image(tmp_path)

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            project_dir.mkdir(parents=True, exist_ok=True)
            app.current_project = "proj"
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            await _drive_apply(app, pilot)
            app.query_one("#patch_saveback_confirm_button", Button).press()
            await pilot.pause()
            _statuses(app).clear()
            app.set_focus(None)
            await pilot.press("b")
            await pilot.pause()
            app._flush_logger()

    asyncio.run(_drive())

    content = _log_path(tmp_path).read_text(encoding="utf-8")
    report_lines = [
        ln for ln in content.splitlines() if "report kind=before-after" in ln
    ]
    assert report_lines, (
        "AC-2: driving the before/after report produced no "
        "'report kind=before-after' log line; full log:\n" + content
    )
    assert any("outcome=ok" in ln for ln in report_lines), report_lines
    # AC-5: no entry-byte content leaked into the log.
    assert "AA BB" not in content, (
        "AC-5: entry byte content leaked into the report log line"
    )
