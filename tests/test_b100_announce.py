"""Batch-100 increment 6 — the Load-result panel (HLR-178).

Covers HLR-178 / LLR-178.1–LLR-178.3 (P-E verdict B, D2, D3):

  - TC-B100-55 — LLR-178.1: ``compose_load_announcement`` — the five
    reasons (recorded active; first by name with none recorded, a damaged
    manifest, no ``project.json``; the next valid when the recorded one is
    missing), the variant count and position, the problems in precedence
    order, and "latest" only for the recorded variant, never from file
    times. The "first variant by name" mutation arm and the ``derived_from``
    lines land at Inc 7 (ARCH-PDR-3).
  - TC-B100-56 — LLR-178.2: a project load paints one summary line in
    ``#log_line_4`` (opened file, ``variant k of n``, problem count, then
    ``details: p``) inside 118 columns, and ``#status_text`` ends on the
    project and the opened file; a hostile variant name paints 0 spans; a
    recorded ``active_variant`` holding ESC / BEL paints 0 control bytes
    (corrective pass 1, SEC6-6).
  - TC-B100-67 — LLR-178.3: the panel opened by the Load project dialog —
    the focus starts on the list; an immediate ``enter`` keeps it open; the
    shown key ``esc`` closes it; ``tab`` reaches ``#result_ok`` and
    ``enter`` closes it; ``v`` opens the variant selector; 30 problems at
    118x54 are all rows, each naming its own recorded entry (30 distinct
    rows), and ``end`` brings the last into view; 0 exception class names
    and 0 internal ids are painted. Corrective pass 1 (UX-1..UX-3, the P-E
    verdict B prototype): the fallback reason, the problem heading and
    each problem's mark and label paint in the warning colour, the recorded
    reason in the OK colour; a wrapped value hangs under the value column
    and a wrapped problem under its label, never at column 0 or under the
    ``!`` (99x54). Corrective pass 2 (SEC6-7): a 40 000-character entry in
    each of ``batch``, ``assignments`` and ``gathered`` opens the project
    through the Load project dialog with one skipped-entry row each, the
    painted entry clipped. Corrective pass 3: a ``gathered`` entry through a
    junction that points to itself (SEC6-7) is one skipped-entry row, and a
    manifest holding a 5 000-digit integer (SEC6-8) reads as damaged.
  - AT-B100-19 — HLR-178 black-box: after a default save-back into P,
    reopening P opens the panel naming ``firmware-patched.s19``, recorded as
    active, and P's 2 variants; with that file deleted, reopening names
    ``firmware.s19`` as the next valid variant and lists the missing one;
    ``end`` reaches the last problem; ``tab`` then ``enter`` closes.

The pure composer is imported inside its own nodes, so the integration
nodes of this module still run (and fail behaviourally) at the base.
Inc 6 scope notes (declared in the packet): the Load dialog's preview of
the open project arrives with the Load dialog (Inc 9b); the "patched, N
bytes differ" line arrives with ``derived_from`` (Inc 7).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from pathlib import Path

import pytest
from textual.widgets import Label

from s19_app.tui.app import S19TuiApp
from s19_app.tui.insight_style import GREEN
from s19_app.tui.insight_style import YELLOW
from s19_app.tui.screens import LoadProjectScreen
from s19_app.tui.screens import SelectVariantScreen
from s19_app.tui.services.variant_execution_service import MANIFEST_BAD_STRUCTURE
from s19_app.tui.services.variant_execution_service import MANIFEST_JSON_PARSE
from s19_app.tui.services.variant_execution_service import MANIFEST_PATH_ESCAPE
from s19_app.tui.services.variant_execution_service import ProjectManifest
from s19_app.tui.workspace import WORKAREA_DIRNAME
from s19_app.tui.workspace import WORKAREA_SUBDIR
from s19_app.tui.workspace import build_variant_set
from s19_app.validation.model import ValidationIssue
from s19_app.validation.model import ValidationSeverity

from tests.support import b100_links
from tests.support import b100_projects as projects
from tests.test_b100_active_variant import _add_and_apply_through_the_panel
from tests.test_b100_active_variant import _load_file_through_dialog
from tests.test_b100_active_variant import _save_back_through_the_prompt
from tests.test_b100_active_variant import _save_project_through_dialog

SIZES = [(118, 54), (220, 60)]
EXCEPTION_NAME = re.compile(r"\b[A-Z][A-Za-z]*(Error|Exception)\b")
INTERNAL_ID = re.compile(r"MANIFEST-[A-Z-]+|\b(none-recorded|manifest-damaged|no-manifest|next-valid)\b")


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


async def _wait_for(pilot, predicate, description: str, attempts: int = 200) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {description}")


async def _flush(pilot, count: int = 12) -> None:
    for _ in range(count):
        await pilot.pause()


def _status_text(app: S19TuiApp) -> str:
    return str(app.query_one("#log_line_4", Label).render())


def _panel_open(app: S19TuiApp) -> bool:
    return len(app.screen.query("#result_ok")) > 0


def _panel_text(app: S19TuiApp) -> str:
    """Every painted line of the open panel (title, summary, rows)."""
    return projects.load_result_panel_text(app)


def _colour_of(widget, needle: str) -> str:
    """The foreground colour of the first painted segment of ``widget``
    whose text holds ``needle``."""
    for y in range(widget.size.height):
        for segment in widget.render_line(y):
            if needle in segment.text and segment.style is not None:
                color = segment.style.color
                return color.name if color is not None else "default"
    raise AssertionError(f"{needle!r} is not painted: {projects.painted_lines(widget)}")


def _issue(code: str, message: str = "x") -> ValidationIssue:
    return ValidationIssue(
        code=code, severity=ValidationSeverity.ERROR, message=message, artifact="manifest"
    )


def _variants(*names: str, active: str):
    variant_set = build_variant_set("P", [Path(name) for name in names])
    variant_set.active_id = active
    return variant_set


# ---------------------------------------------------------------------------
# TC-B100-55 — LLR-178.1: the announcement composer (pure)
# ---------------------------------------------------------------------------


def _compose(*args, **kwargs):
    from s19_app.tui.services.variant_execution_service import compose_load_announcement

    return compose_load_announcement(*args, **kwargs)


def _reasons():
    from s19_app.tui.services import variant_execution_service as service

    return service


def test_tc_b100_55_recorded_active(tmp_path: Path) -> None:
    service = _reasons()
    vs = _variants("firmware.s19", "firmware_1.s19", active="firmware_1")
    announcement = _compose(
        "P", vs, ProjectManifest(schema_version=1, active_variant="firmware_1")
    )
    assert announcement.reason == service.LOAD_REASON_RECORDED
    assert announcement.latest is True
    assert (announcement.opened, announcement.position, announcement.count) == (
        "firmware_1.s19", 2, 2,
    )
    assert announcement.others == ("firmware.s19",)
    assert announcement.problems == ()


def test_tc_b100_55_first_by_name_none_recorded() -> None:
    service = _reasons()
    vs = _variants("firmware.s19", "firmware_1.s19", active="firmware")
    announcement = _compose("P", vs, ProjectManifest(schema_version=1, active_variant=None))
    assert announcement.reason == service.LOAD_REASON_NONE_RECORDED
    assert announcement.latest is False
    assert announcement.problems == ()


def test_tc_b100_55_first_by_name_manifest_damaged() -> None:
    service = _reasons()
    vs = _variants("firmware.s19", "firmware_1.s19", active="firmware")
    manifest = ProjectManifest(
        schema_version=None,
        active_variant=None,
        issues=[_issue(MANIFEST_JSON_PARSE, "not JSON - ignored: JSONDecodeError")],
    )
    announcement = _compose("P", vs, manifest)
    assert announcement.reason == service.LOAD_REASON_MANIFEST_DAMAGED
    assert [p.label for p in announcement.problems] == ["Manifest damaged"]
    assert announcement.latest is False


def test_tc_b100_55_first_by_name_no_project_json() -> None:
    service = _reasons()
    vs = _variants("firmware.s19", "firmware_1.s19", active="firmware")
    announcement = _compose("P", vs, None)
    assert announcement.reason == service.LOAD_REASON_NO_MANIFEST
    assert [(p.label, p.file) for p in announcement.problems] == [
        ("No manifest", "project.json")
    ]
    assert announcement.latest is False


def test_tc_b100_55_next_valid_when_the_recorded_one_is_missing() -> None:
    """The recorded ``firmware-patched`` is gone: the app opened
    ``firmware``; the announcement says why and is never "recorded"."""
    service = _reasons()
    vs = _variants("firmware.s19", "firmware_1.s19", active="firmware")
    announcement = _compose(
        "P", vs, ProjectManifest(schema_version=1, active_variant="firmware-patched")
    )
    assert announcement.reason == service.LOAD_REASON_NEXT_VALID
    assert announcement.latest is False
    assert [(p.label, p.file) for p in announcement.problems] == [
        ("Missing variant", "firmware-patched")
    ]


def test_tc_b100_55_five_reasons_have_distinct_user_text() -> None:
    service = _reasons()
    ids = [
        service.LOAD_REASON_RECORDED,
        service.LOAD_REASON_NONE_RECORDED,
        service.LOAD_REASON_MANIFEST_DAMAGED,
        service.LOAD_REASON_NO_MANIFEST,
        service.LOAD_REASON_NEXT_VALID,
    ]
    texts = [service.LOAD_REASON_TEXT[reason] for reason in ids]
    assert len(set(texts)) == 5
    assert ["latest" in text for text in texts] == [True, False, False, False, False]
    assert not any("identical" in text for text in texts)


def test_tc_b100_55_three_problems_in_precedence_order() -> None:
    """Two skipped manifest entries rank before the missing variant."""
    vs = _variants("firmware.s19", active="firmware")
    manifest = ProjectManifest(
        schema_version=1,
        active_variant="gone",
        issues=[_issue(MANIFEST_PATH_ESCAPE), _issue(MANIFEST_BAD_STRUCTURE)],
    )
    announcement = _compose("P", vs, manifest)
    assert [p.label for p in announcement.problems] == [
        "Manifest entry skipped",
        "Manifest entry skipped",
        "Missing variant",
    ]


def test_tc_b100_55_latest_never_comes_from_file_times(tmp_path: Path) -> None:
    """A touched (newer) file is never called latest: only the variant the
    manifest records is; a fallback open is not latest either."""
    service = _reasons()
    folder = tmp_path / "P"
    folder.mkdir()
    for name in ("firmware.s19", "firmware_1.s19"):
        (folder / name).write_text("S0030000FC\n", encoding="ascii")
    future = time.time() + 3600
    os.utime(folder / "firmware.s19", (future, future))
    recorded = build_variant_set("P", sorted(folder.iterdir()))
    recorded.active_id = "firmware_1"
    first = _compose("P", recorded, ProjectManifest(schema_version=1, active_variant="firmware_1"))
    assert (first.opened, first.latest) == ("firmware_1.s19", True)
    touched = build_variant_set("P", sorted(folder.iterdir()))
    touched.active_id = "firmware"
    second = _compose("P", touched, ProjectManifest(schema_version=1, active_variant="gone"))
    assert (second.opened, second.latest) == ("firmware.s19", False)
    assert "latest" not in second.reason_text
    assert second.reason == service.LOAD_REASON_NEXT_VALID


def test_tc_b100_55_boundaries_one_variant_and_no_image() -> None:
    one = _compose(
        "P", _variants("firmware.s19", active="firmware"),
        ProjectManifest(schema_version=1, active_variant="firmware"),
    )
    assert (one.count, one.position, one.others) == (1, 1, ())
    nothing = _compose(
        "P", build_variant_set("P", []), ProjectManifest(schema_version=1, active_variant=None),
        mac_name="firmware.mac",
    )
    assert (nothing.opened, nothing.count, nothing.position) == (None, 0, 0)
    assert nothing.target == "firmware.mac"
    for announcement in (one, nothing):
        for text in (announcement.summary_line(), announcement.reason_text):
            assert "identical" not in text


# ---------------------------------------------------------------------------
# TC-B100-56 — LLR-178.2: the summary line and the final #status_text
# ---------------------------------------------------------------------------


def _seed_two_variants(workarea: Path, second: str = "firmware_1.s19") -> Path:
    project_dir = workarea / "P"
    projects.copy_sources(project_dir, projects.CASE01_DIR, "firmware.s19")
    shutil.copy2(projects.CASE02_DIR / "firmware.s19", project_dir / second)
    (project_dir / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": Path(second).stem}),
        encoding="utf-8",
    )
    return project_dir


def _load_directly(base: Path) -> tuple:
    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            app._handle_load_project("P")
            await _flush(pilot)
            log4 = app.query_one("#log_line_4", Label).render()
            status = app.query_one("#status_text", Label).render()
            return list(app.log_lines), log4, status, _panel_open(app)

    return asyncio.run(_drive())


def test_tc_b100_56_one_summary_line_and_the_final_status_text(tmp_path: Path) -> None:
    base = tmp_path / "app"
    _seed_two_variants(_workarea(base))
    lines, log4, status, panel = _load_directly(base)
    summaries = [line for line in lines if line.endswith("details: p")]
    assert len(summaries) == 1, lines
    assert str(log4) == summaries[0]
    assert str(log4) == (
        "Loaded project 'P' -> firmware_1.s19 - variant 2 of 2, 0 problems - details: p"
    )
    assert len(str(log4)) <= 118
    assert str(status) == "Loaded project 'P' -> firmware_1.s19"
    assert panel is False, "a direct _handle_load_project call opens no modal"


def test_tc_b100_56_hostile_variant_name_paints_no_markup(tmp_path: Path) -> None:
    base = tmp_path / "app"
    _seed_two_variants(_workarea(base), second="[b]x.s19")
    lines, log4, status, _panel = _load_directly(base)
    assert str(log4).endswith("details: p"), str(log4)
    assert "[b]x.s19" in str(log4) and "[b]x.s19" in str(status), (str(log4), str(status))
    assert list(log4.spans) == [] and list(status.spans) == [], (log4.spans, status.spans)


def test_tc_b100_56_recorded_variant_with_control_bytes_paints_none(tmp_path: Path) -> None:
    """A recorded ``active_variant`` is any JSON string: one holding an ESC
    sequence and a BEL reaches the status log scrubbed — the line naming it
    is painted, with 0 control bytes in any log line.

    RED (executed on the reviewed Inc 6 tree, d37ee857): the raw ESC and
    BEL reached ``app.log_lines`` and ``#log_line_*`` (SEC6-6)."""
    base = tmp_path / "app"
    project_dir = _seed_two_variants(_workarea(base))
    (project_dir / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": "\x1b[31mZ[red]q\x07"}),
        encoding="utf-8",
    )

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            app._handle_load_project("P")
            await _flush(pilot)
            painted = [
                str(app.query_one(f"#log_line_{i}", Label).render()) for i in (1, 2, 3, 4)
            ]
            return list(app.log_lines), painted

    lines, painted = asyncio.run(_drive())
    named = [line for line in lines if "not found - activating the first variant" in line]
    assert named == [
        "Manifest active_variant '[31mZ[red]q' not found - activating the first variant."
    ], lines
    control = re.compile(r"[\x00-\x1f\x7f-\x9f]")
    assert not [line for line in lines + painted if control.search(line)], lines + painted


def test_tc_b100_56_long_names_keep_the_details_key_inside_118_columns() -> None:
    long_set = _variants("f" * 90 + ".s19", active="f" * 90)
    from s19_app.tui.services.variant_execution_service import compose_load_announcement

    line = compose_load_announcement(
        "P" * 64, long_set, ProjectManifest(schema_version=1, active_variant="f" * 90)
    ).summary_line()
    assert len(line) <= 118 and line.endswith("variant 1 of 1, 0 problems - details: p"), line


# ---------------------------------------------------------------------------
# TC-B100-67 — LLR-178.3: the panel, reachable by keyboard
# ---------------------------------------------------------------------------


def _seed_problem_project(workarea: Path, problems: int) -> Path:
    """P with 2 variants and ``problems`` escaping batch entries, each one
    skipped and reported."""
    project_dir = _seed_two_variants(workarea)
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "firmware_1",
                "batch": [f"../escape_{i:02d}.json" for i in range(problems)],
            }
        ),
        encoding="utf-8",
    )
    return project_dir


async def _open_panel(pilot, app: S19TuiApp, name: str = "P") -> None:
    await pilot.press("p")
    await _wait_for(
        pilot, lambda: isinstance(app.screen, LoadProjectScreen), "the Load project dialog"
    )
    row = next(
        item
        for item in app.screen.query("#project_list ListItem")
        if str(item.query_one(Label).render()) == name
    )
    await pilot.click(row)
    await pilot.pause()
    assert await pilot.click("#project_ok"), "click missed #project_ok"
    await _wait_for(
        pilot,
        lambda: _panel_open(app) and app.focused is not None,
        "the Load-result panel holding a focus",
    )
    await _flush(pilot)


def _run_panel(tmp_path: Path, scenario, size=(118, 54), problems: int = 0):
    base = tmp_path / "app"
    _seed_problem_project(_workarea(base), problems)

    async def _drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _open_panel(pilot, app)
            return await scenario(pilot, app)

    return asyncio.run(_drive())


def test_tc_b100_67_focus_starts_on_the_list_and_enter_keeps_it_open(tmp_path: Path) -> None:
    async def _scenario(pilot, app):
        focused = app.focused.id if app.focused else None
        await pilot.press("enter")
        await _flush(pilot)
        return focused, _panel_open(app)

    focused, still_open = _run_panel(tmp_path, _scenario, problems=3)
    assert focused == "result_body"
    assert still_open, "an immediate enter must not close the panel unread"


def test_tc_b100_67_the_shown_esc_key_closes_it(tmp_path: Path) -> None:
    async def _scenario(pilot, app):
        label = str(app.screen.query_one("#result_ok").label)
        await pilot.press("escape")
        await _wait_for(pilot, lambda: not _panel_open(app), "the panel closed by esc")
        return label

    label = _run_panel(tmp_path, _scenario)
    assert label == "Close (esc)"


def test_tc_b100_67_tab_reaches_close_and_enter_closes(tmp_path: Path) -> None:
    async def _scenario(pilot, app):
        await pilot.press("tab")
        await _flush(pilot, 4)
        after_tab = app.focused.id if app.focused else None
        await pilot.press("enter")
        await _wait_for(pilot, lambda: not _panel_open(app), "the panel closed by enter")
        return after_tab

    assert _run_panel(tmp_path, _scenario, problems=2) == "result_ok"


def test_tc_b100_67_v_opens_the_variant_selector(tmp_path: Path) -> None:
    async def _scenario(pilot, app):
        await pilot.press("v")
        await _wait_for(
            pilot,
            lambda: isinstance(app.screen, SelectVariantScreen),
            "the variant selector",
        )
        return _panel_open(app)

    assert _run_panel(tmp_path, _scenario) is False


def test_tc_b100_67_thirty_problems_all_rows_and_end_reaches_the_last(tmp_path: Path) -> None:
    async def _scenario(pilot, app):
        rows = list(app.screen.query("#result_body .result-problem"))
        body = app.screen.query_one("#result_body")
        before = body.region.contains_region(rows[-1].region)
        await pilot.press("end")
        await _flush(pilot)
        after = body.region.contains_region(rows[-1].region)
        painted = [projects.flat("\n".join(projects.painted_lines(row))) for row in rows]
        return len(rows), before, after, _panel_text(app), painted

    count, before, after, text, painted = _run_panel(tmp_path, _scenario, problems=30)
    assert count == 30, f"{30 - count} problems missing from the panel"
    assert len(set(painted)) == 30, "the 30 problem rows are not distinct"
    for index, row in enumerate(painted):
        assert row.startswith(f"! Manifest entry skipped: ../escape_{index:02d}.json "), row
    assert before is False, "the 30th row must start outside the list's view at 118x54"
    assert after is True, "end must bring the last problem row into the list's view"
    assert not EXCEPTION_NAME.search(text), text
    assert not INTERNAL_ID.search(text), text


def test_tc_b100_67_damaged_manifest_paints_user_terms_only(tmp_path: Path) -> None:
    base = tmp_path / "app"
    project_dir = _seed_two_variants(_workarea(base))
    (project_dir / "project.json").write_text("{not json", encoding="utf-8")

    async def _drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54), notifications=True) as pilot:
            await pilot.pause()
            await _open_panel(pilot, app)
            return _panel_text(app)

    text = asyncio.run(_drive())
    assert "Manifest damaged: project.json" in text, text
    assert "the first variant by name (the manifest could not be read)" in projects.flat(text), text
    assert not EXCEPTION_NAME.search(text), text
    assert not INTERNAL_ID.search(text), text


def _run_damaged_panel(tmp_path: Path, size: tuple, scenario):
    base = tmp_path / "app"
    project_dir = _seed_two_variants(_workarea(base))
    (project_dir / "project.json").write_text("{not json", encoding="utf-8")

    async def _drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _open_panel(pilot, app)
            return scenario(app)

    return asyncio.run(_drive())


def test_tc_b100_67_fallback_and_problems_paint_in_the_warning_colour(tmp_path: Path) -> None:
    """UX-1 (the P-E verdict B prototype): with a damaged manifest the
    fallback reason, the "Problems found" heading and the problem's mark and
    label paint in the warning colour; the file the problem names does not.

    RED (executed on the reviewed Inc 6 tree, d37ee857): every row painted
    in the default colour."""

    def _scenario(app):
        summary = app.screen.query_one("#result_summary")
        heading = app.screen.query_one(".result-heading")
        row = app.screen.query("#result_body .result-problem").first()
        return (
            _colour_of(summary, "the first variant by name"),
            _colour_of(heading, "Problems found"),
            _colour_of(row, "! "),
            _colour_of(row, "Manifest damaged: "),
            _colour_of(row, "project.json"),
        )

    reason, heading, mark, label, file_name = _run_damaged_panel(tmp_path, (118, 54), _scenario)
    assert (reason, heading, mark, label) == (YELLOW, YELLOW, YELLOW, YELLOW)
    assert file_name != YELLOW


def test_tc_b100_67_recorded_reason_paints_in_the_ok_colour(tmp_path: Path) -> None:
    """UX-1: the recorded active variant's reason paints in the OK colour,
    and "No problems found." too.

    RED (executed on the reviewed Inc 6 tree, d37ee857): default colour."""

    async def _scenario(pilot, app):
        summary = app.screen.query_one("#result_summary")
        heading = app.screen.query_one(".result-heading")
        return (
            _colour_of(summary, "recorded as the active variant"),
            _colour_of(heading, "No problems found."),
        )

    assert _run_panel(tmp_path, _scenario) == (GREEN, GREEN)


def test_tc_b100_67_wrapped_lines_hang_under_their_column(tmp_path: Path) -> None:
    """UX-2 / UX-3 at 99x54: the fallback reason wraps and its continuation
    starts under the value column (10 cells), and the damaged-manifest
    problem wraps and its continuation starts under the label (4 cells),
    never at column 0 nor under the ``!``.

    RED (executed on the reviewed Inc 6 tree, d37ee857): both continuations
    started at column 0."""

    def _scenario(app):
        summary = projects.painted_lines(app.screen.query_one("#result_summary"))
        row = projects.painted_lines(app.screen.query("#result_body .result-problem").first())
        return summary, row

    summary, row = _run_damaged_panel(tmp_path, (99, 54), _scenario)
    start = next(i for i, line in enumerate(summary) if "the first variant by name" in line)
    reason = summary[start : summary.index(next(l for l in summary if l.startswith("Variants")))]
    assert len(reason) >= 2, f"the reason did not wrap at 99x54: {summary}"
    for line in reason:
        assert line.startswith(" " * 10) and line[10] != " ", summary
    assert len(row) >= 2, f"the problem did not wrap at 99x54: {row}"
    assert row[0].startswith("  ! Manifest damaged: project.json"), row
    for line in row[1:]:
        assert line.startswith(" " * 4) and line[4] != " ", row


#: Longer than Windows' ~32 760-character path limit, so ``Path.resolve()``
#: raises on the base and the reviewed trees (SEC6-7).
OVERLONG_ENTRY = "q" * 40_000


def test_tc_b100_67_overlong_entries_are_skipped_rows_not_a_crash(tmp_path: Path) -> None:
    """SEC6-7: a recorded 40 000-character entry in ``batch``,
    ``assignments`` and ``gathered`` — the project opens through the Load
    project dialog, the panel shows exactly one skipped-entry row per key,
    and each row paints the entry clipped (at most 119 of its characters
    plus an ellipsis), so the panel stays readable.

    RED (executed on the corrective-pass-1 tree, 395dcbde): the load
    raised ``ValueError`` out of ``Path.resolve()`` and the app exited."""
    base = tmp_path / "app"
    project_dir = _seed_two_variants(_workarea(base))
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "firmware_1",
                "batch": [OVERLONG_ENTRY],
                "assignments": {"firmware": [OVERLONG_ENTRY]},
                "gathered": {"patches": [OVERLONG_ENTRY]},
            }
        ),
        encoding="utf-8",
    )

    async def _drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54), notifications=True) as pilot:
            await pilot.pause()
            await _open_panel(pilot, app)
            rows = list(app.screen.query("#result_body .result-problem"))
            return [projects.flat("\n".join(projects.painted_lines(row))) for row in rows]

    rows = asyncio.run(_drive())
    assert len(rows) == 3, rows
    for row in rows:
        assert row.startswith("! Manifest entry skipped: q"), row
        assert 0 < row.count("q") <= 119 and "…" in row, (row.count("q"), row)


def test_tc_b100_67_junction_loop_entry_is_a_skipped_row_not_a_crash(tmp_path: Path) -> None:
    """SEC6-7 remainder: ``gathered`` records ``loop/x.json`` where ``loop``
    is a junction to itself — the project opens through the Load project
    dialog and the panel shows exactly one skipped-entry row naming it.

    RED (executed on the corrective-pass-2 tree, e494c50c): ``RuntimeError:
    Symlink loop`` out of ``Path.resolve()``; the app exited."""
    b100_links.require_junctions()
    base = tmp_path / "app"
    project_dir = _seed_two_variants(_workarea(base))
    loop = projects.create_junction_loop(project_dir / "loop")
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "firmware_1",
                "gathered": {"patches": ["loop/x.json"]},
            }
        ),
        encoding="utf-8",
    )

    async def _drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54), notifications=True) as pilot:
            await pilot.pause()
            await _open_panel(pilot, app)
            rows = list(app.screen.query("#result_body .result-problem"))
            return [projects.flat("\n".join(projects.painted_lines(row))) for row in rows]

    try:
        rows = asyncio.run(_drive())
    finally:
        os.rmdir(loop)
    assert len(rows) == 1, rows
    assert rows[0].startswith("! Manifest entry skipped: loop/x.json "), rows


def test_tc_b100_67_integer_over_the_digit_limit_reads_as_damaged(tmp_path: Path) -> None:
    """SEC6-8: ``project.json`` holds a 5 000-digit integer (``json.load``
    raises a plain ``ValueError``) — the project opens through the Load
    project dialog and the panel says the manifest is damaged.

    RED (executed on the corrective-pass-2 tree, e494c50c): ``ValueError``
    out of ``json.load``; the app exited."""
    base = tmp_path / "app"
    project_dir = _seed_two_variants(_workarea(base))
    (project_dir / "project.json").write_text(projects.OVERLONG_INT_MANIFEST, encoding="utf-8")

    async def _drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54), notifications=True) as pilot:
            await pilot.pause()
            await _open_panel(pilot, app)
            return _panel_text(app)

    text = asyncio.run(_drive())
    assert "Manifest damaged: project.json" in text, text
    assert "the first variant by name (the manifest could not be read)" in projects.flat(text), text
    assert not EXCEPTION_NAME.search(text), text


# ---------------------------------------------------------------------------
# AT-B100-19 — HLR-178 black-box
# ---------------------------------------------------------------------------


async def _open_project_and_read_the_panel(pilot, app: S19TuiApp) -> str:
    await pilot.press("1")
    await _flush(pilot, 4)
    await _open_panel(pilot, app)
    return _panel_text(app)


@pytest.mark.parametrize("size", SIZES)
def test_at_b100_19_the_panel_names_the_opened_variant_and_why(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-178's acceptance scene by keys and clicks: Load file, Save
    project P, apply a patch and save back with the default name; reopen P
    in a fresh app through the Load project dialog — the panel names
    ``firmware-patched.s19`` as opened, recorded as active, among P's 2
    variants; ``tab`` then ``enter`` closes it. Delete that file and reopen:
    the panel names ``firmware.s19`` as the next valid variant and lists the
    missing one; ``end`` reaches the last problem; the shown ``esc`` closes.

    RED (executed on 1d677ba, P-3): the reload status is ``Loaded project
    'P' -> firmware.s19`` with no panel, no count and no reason."""
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    base = tmp_path / "app"

    async def _save_scene() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _load_file_through_dialog(pilot, app, src / "firmware.s19")
            await _save_project_through_dialog(pilot, app, "P")
            await _add_and_apply_through_the_panel(pilot, app)
            await _save_back_through_the_prompt(pilot, app, None)

    async def _reopen(close_with: str) -> str:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            text = await _open_project_and_read_the_panel(pilot, app)
            if close_with == "tab-enter":
                await pilot.press("tab")
                await _wait_for(
                    pilot,
                    lambda: app.focused is not None and app.focused.id == "result_ok",
                    "tab on Close",
                )
                await pilot.press("enter")
            else:
                await pilot.press("end")
                await _flush(pilot, 4)
                rows = list(app.screen.query("#result_body .result-problem"))
                body = app.screen.query_one("#result_body")
                assert rows and body.region.contains_region(rows[-1].region), (
                    "end must show the last problem"
                )
                await pilot.press("escape")
            await _wait_for(pilot, lambda: not _panel_open(app), "the panel closed")
            return text

    asyncio.run(_save_scene())
    first = asyncio.run(_reopen("tab-enter"))
    assert "Opened    firmware-patched.s19" in first, first
    assert "recorded as the active variant (the latest saved)" in projects.flat(first), first
    assert "Variants  2 in the project" in first, first
    assert "Others    firmware.s19" in first, first
    (_workarea(base) / "P" / "firmware-patched.s19").unlink()
    second = asyncio.run(_reopen("end-esc"))
    assert "Opened    firmware.s19" in second, second
    assert (
        "the next valid variant (the recorded one is missing or not readable)"
        in projects.flat(second)
    ), second
    assert "Missing variant: firmware-patched" in second, second
    assert "latest" not in second, second
