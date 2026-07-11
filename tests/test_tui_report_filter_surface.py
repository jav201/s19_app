"""Report-filter selection UX + before/after arm — batch-35 Inc-4 surface ATs.

Layer B (black-box, Textual Pilot over the shipped surfaces — key ``b``,
the ``ReportViewerScreen`` selector row + Generate button, the A2B diff
Report button), one on-disk node per AT (C-18):

- **AT-056a** — a non-default dropdown selection changes the next report's
  bytes on BOTH triggers, each under an audit header carrying the REAL
  filter filename (C-10 + LLR-056.2/056.3).
- **AT-056a2** — selector-row + Generate-button geometry at 80x24 AND
  120x30 (LLR-056.5, the TC-024.6 per-width idiom).
- **AT-056a3** — project switch resets the sticky selection; the next
  report is unfiltered (LLR-056.3 / F-09).
- **AT-056b** — a markup-hostile filter filename populates the dropdown,
  renders literally in the overlay and in the confirmation status, and
  raises no ``MarkupError`` (LLR-053.6 / LLR-056.2, C-17 + C-15 probe).
- **AT-056c** — fresh app, nothing selected: the dropdown shows blank and
  the generated report is byte-identical (canonical form) to the AT-055b
  golden (LLR-055.3 arm of HLR-056).
- **AT-056d** — typed free path: a valid out-of-project filter filters the
  next report; a missing path refuses with a named diagnostic
  (LLR-056.4).
- **AT-056e** — with a filter SELECTED, the A2B diff report is
  byte-identical to a no-filter A2B run (LLR-054.5 — the selection does
  not leak into the always-complete diff).
- **AT-053a** — JOINED node: an invalid selected filter refuses BOTH
  report triggers with the kind-prefixed named fault; ``reports/`` stays
  unchanged on both (LLR-053.5/053.6).
- **AT-053b** — hostile-but-VALID filter (markup filename, pipe /
  ``<b>`` / ctl / header-forging patterns): generation PROCEEDS on both
  kinds, the confirmation renders the name literally, and every written
  file is re-read asserting sanitation (LLR-053.6/055.4, Q-3; Inc-6).
- **AT-054a** — ``b``-key with a filter: the written MD+HTML pair keeps
  the matching linkage row, omits the unmatched one, and carries the
  audit header (LLR-054.2/054.3).
- **AT-054c** — ``b``-key zero-match: the pair is still written with the
  loud ``filter matched 0 of N items`` notice, wording disjoint from the
  refusal wording (LLR-054.3, Q-12).

Layer A (white-box units):

- **TC-316** — filters/ scan: sorted, symlink skipped, absent dir -> [];
  ``validate_project_files`` regression with a ``filters/`` subdir
  (LLR-056.1).
- **TC-317** — typed-path resolution: relative resolve, missing refuse,
  symlink refuse, and the S-F2 swap cases (selected file deleted /
  replaced by a symlink before generation -> read-time refusal)
  (LLR-056.4 / LLR-053.2).
- **TC-F1** — cross-module consistency pin for the filter helpers
  duplicated between ``report_service`` and ``diff_report_service``
  (LLR-054.3; Inc-3 review F1).

Environment pin (byte-compare tests only): the LLR-054.4/055.3 fixed-clock
monkeypatches on SERVICE module attributes — never a shipped-path change.
Fixture data is synthetic / public-only under ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

import pytest
from textual.widgets import Button, Input, Label, Select

from conftest import canonical_report_bytes
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ReportViewerScreen
from s19_app.tui.screens_directionb import PatchEditorPanel

# Two minimal valid S19 images (the test_tui_report_seam.py pair): 4 bytes
# at 0x1000 / 4 bytes at 0x2000 — a real 2-variant project.
S19_A = "S107100001020304DE\nS9030000FC\n"
S19_B = "S10720000A0B0C0DAA\nS9030000FC\n"

#: The LLR-054.4/055.3 fixed-clock environment-pin instant (UTC).
_FIXED_INSTANT = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)

_GOLDEN_DIR = Path(__file__).parent / "goldens" / "batch35"
_AT055B_GOLDEN = _GOLDEN_DIR / "at055b-project-report.md"

_BA_MD_NAME = "20260710T120000Z-before-after-report.md"
_BA_HTML_NAME = "20260710T120000Z-before-after-report.html"
_PR_NAME = "20260710T120000Z-report.md"
_DIFF_MD_NAME = "20260710T120000Z-diff-report.md"
_DIFF_HTML_NAME = "20260710T120000Z-diff-report.html"


class _FixedApplyDatetime(datetime):
    """``datetime`` stand-in pinning the ``changes.apply`` stamp clock
    (the AT-054b idiom — ``apply.py`` has no ``_default_now`` seam)."""

    @classmethod
    def now(cls, tz=None):  # noqa: ANN001 - datetime.now signature
        """Return the pinned instant (tz-aware when ``tz`` is given)."""
        if tz is None:
            return cls(2026, 7, 10, 12, 0, 0)
        return cls(2026, 7, 10, 12, 0, 0, tzinfo=tz)


def _pin_report_clocks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Apply the declared environment pin on every report clock seam."""
    import s19_app.tui.changes.apply as apply_module
    from s19_app.tui.services import diff_report_service, report_service

    monkeypatch.setattr(
        diff_report_service, "_default_now", lambda: _FIXED_INSTANT
    )
    monkeypatch.setattr(
        report_service, "_default_now", lambda: _FIXED_INSTANT
    )
    monkeypatch.setattr(apply_module, "datetime", _FixedApplyDatetime)


def _valid_filter_body(
    addresses: Sequence[Tuple[str, str]] = (("0x1000", "0x1001"),),
    symbols: Sequence[str] = (),
) -> str:
    """A valid ``s19app-report-filter`` v1.0 document."""
    return json.dumps(
        {
            "format": "s19app-report-filter",
            "version": "1.0",
            "include": {
                "symbols": list(symbols),
                "addresses": [
                    {"start": start, "end": end} for start, end in addresses
                ],
            },
        }
    )


def _make_project(
    base_dir: Path,
    name: str,
    *,
    filters: Optional[Dict[str, str]] = None,
    two_entries: bool = False,
) -> Path:
    """Build the loadable, reportable 2-variant project on disk.

    Mirrors ``test_tui_report_seam.py::_make_report_project`` exactly (the
    AT-055b golden shape) plus an optional ``filters/`` directory.
    """
    project_dir = base_dir / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "a.s19").write_text(S19_A, encoding="utf-8")
    (project_dir / "b.s19").write_text(S19_B, encoding="utf-8")
    entries = [{"type": "bytes", "address": "0x1000", "bytes": "AA"}]
    if two_entries:
        entries.append({"type": "bytes", "address": "0x1002", "bytes": "BB"})
    (project_dir / "chg.json").write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "a",
                "batch": ["chg.json"],
                "assignments": {},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    for filter_name, body in (filters or {}).items():
        filter_path = project_dir / "filters" / filter_name
        filter_path.parent.mkdir(parents=True, exist_ok=True)
        filter_path.write_text(body, encoding="utf-8")
    return project_dir


def _reports(project_dir: Path) -> Dict[str, bytes]:
    """``{filename: raw bytes}`` under ``<project>/reports/`` (may be {})."""
    reports_dir = project_dir / "reports"
    if not reports_dir.is_dir():
        return {}
    return {
        p.name: p.read_bytes() for p in reports_dir.iterdir() if p.is_file()
    }


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so deferred screen/message/apply work runs."""
    for _ in range(count):
        await pilot.pause()


async def _load_project(app: S19TuiApp, pilot, name: str) -> None:
    """Load a project through the shipped handler and drain the workers."""
    app._handle_load_project(name)
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)


async def _open_reports(app: S19TuiApp, pilot) -> ReportViewerScreen:
    """Open the Reports modal and return the pushed screen."""
    app.action_view_reports()
    await _flush(pilot)
    screen = app.screen_stack[-1]
    assert isinstance(screen, ReportViewerScreen), (
        "action_view_reports must push the real ReportViewerScreen"
    )
    return screen


async def _close_reports(screen: ReportViewerScreen, pilot) -> None:
    """Dismiss the Reports modal via its Close button."""
    screen.query_one("#report_close", Button).press()
    await _flush(pilot)


async def _select_filter_via_dropdown(
    app: S19TuiApp, pilot, name: str
) -> None:
    """Pick a filter by name on the REAL dropdown, then close the modal."""
    screen = await _open_reports(app, pilot)
    select = screen.query_one("#report_filter_select", Select)
    select.value = name
    await _flush(pilot)
    await _close_reports(screen, pilot)


async def _press_generate(app: S19TuiApp, pilot) -> None:
    """Open Reports and trigger generation through the real screen control."""
    screen = await _open_reports(app, pilot)
    screen.query_one("#report_generate", Button).press()
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)


async def _apply_and_saveback(
    app: S19TuiApp,
    pilot,
    entries: Sequence[Tuple[str, str]] = (("0x1000", "AA BB"),),
) -> None:
    """Apply entries through the shipped patch panel and confirm save-back."""
    app.action_show_screen("patch")
    await pilot.pause()
    panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
    for address, bytes_text in entries:
        app.query_one("#patch_entry_address_input", Input).value = address
        app.query_one("#patch_entry_value_input", Input).value = ""
        app.query_one("#patch_entry_bytes_input", Input).value = bytes_text
        panel.request_action("add_entry")
        await pilot.pause()
    panel.request_action("apply_doc")
    await pilot.pause()
    app.query_one("#patch_saveback_confirm_button", Button).press()
    await _flush(pilot)


async def _press_bkey(app: S19TuiApp, pilot) -> None:
    """Trigger the before/after report through the shipped ``b`` binding."""
    app.set_focus(None)
    await pilot.press("b")
    await _flush(pilot)


def _symlink_or_skip(target: Path, link: Path) -> None:
    """Create a symlink or skip the test where the OS refuses (Windows)."""
    try:
        os.symlink(str(target), str(link))
    except OSError:
        pytest.skip("symlink creation not permitted on this platform")


def _assert_md_table_rows_intact(md_text: str, label: str) -> None:
    """Every contiguous MD table block keeps ONE unescaped-pipe count
    across all its rows (the batch-34 split-on-unescaped-pipes idiom): a
    hostile ``|`` surviving ``_md_table_cell`` unescaped would change one
    row's structural cell count and fail here (LLR-055.4)."""
    block: list = []
    for line in md_text.splitlines() + [""]:
        if line.startswith("|"):
            block.append(line)
            continue
        if block:
            counts = {
                row: len(re.findall(r"(?<!\\)\|", row)) for row in block
            }
            assert len(set(counts.values())) == 1, (
                f"AT-053b: {label} MD table structurally broken — "
                f"unescaped-pipe counts differ across rows: {counts}"
            )
            block = []


# ===========================================================================
# AT-056a — non-default dropdown selection changes BOTH triggers' outputs
# ===========================================================================


def test_at_056a_dropdown_selection_filters_both_triggers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-056a / LLR-056.2 + LLR-056.3 (HLR-056, C-10).

    Intent: selecting a real filter on the REAL dropdown changes the next
    report's bytes on BOTH shipped triggers — key ``b`` (MD+HTML pair) and
    the Generate button (project report) — versus an unfiltered baseline
    session, and every filtered output's audit header carries the REAL
    filter filename. Both sessions run under the identical environment pin
    so the byte comparison is the C-10 non-default-selection proof.
    """
    _pin_report_clocks(monkeypatch)
    filter_body = _valid_filter_body(addresses=(("0x1000", "0x1001"),))

    def _session(root: Path, select_filter: bool) -> Dict[str, bytes]:
        project_dir = _make_project(
            root,
            "proj",
            filters={"only-first.json": filter_body},
            two_entries=True,
        )

        async def _drive() -> Dict[str, bytes]:
            app = S19TuiApp(base_dir=root)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                await _load_project(app, pilot, "proj")
                if select_filter:
                    await _select_filter_via_dropdown(
                        app, pilot, "only-first.json"
                    )
                await _apply_and_saveback(app, pilot)
                await _press_bkey(app, pilot)
                await _press_generate(app, pilot)
            return _reports(project_dir)

        return asyncio.run(_drive())

    base_root = tmp_path / "base"
    sel_root = tmp_path / "sel"
    base_root.mkdir()
    sel_root.mkdir()
    baseline = _session(base_root, select_filter=False)
    filtered = _session(sel_root, select_filter=True)

    expected = {_BA_MD_NAME, _BA_HTML_NAME, _PR_NAME}
    assert set(baseline) == expected, f"baseline wrote {sorted(baseline)}"
    assert set(filtered) == expected, f"filtered wrote {sorted(filtered)}"

    for name in sorted(expected):
        canon_base = canonical_report_bytes(baseline[name], base_root)
        canon_sel = canonical_report_bytes(filtered[name], sel_root)
        assert canon_sel != canon_base, (
            f"AT-056a: the selection must change {name} (C-10 non-default "
            "selection observably changes output)"
        )
        filtered_text = filtered[name].decode("utf-8")
        assert "Report filter applied" in filtered_text, (
            f"AT-056a: {name} must carry the audit header"
        )
        assert "only-first.json" in filtered_text, (
            f"AT-056a: {name} audit header must carry the REAL filename"
        )
        baseline_text = baseline[name].decode("utf-8")
        assert "Report filter applied" not in baseline_text, (
            f"AT-056a: unfiltered {name} must carry no audit header"
        )


# ===========================================================================
# AT-056a2 — selector-row geometry at 80x24 and 120x30 (LLR-056.5, C-13)
# ===========================================================================


def test_at_056a2_selector_row_and_generate_visible_at_both_regimes(
    tmp_path: Path,
) -> None:
    """AT-056a2 / LLR-056.5 (HLR-056, C-13 geometry budget).

    Intent: the new selector row AND the Generate button are fully inside
    the ``#report_dialog`` region at BOTH size regimes (80x24 floor and
    120x30) — realized via RUNG 3 of the C-13.1 ladder (a second
    docked-bottom line stacked above the buttons row; rung 1's ``1fr``
    absorber was already exhausted pre-batch, styles.tcss record), so
    this node ALSO guards the dock-offset contract: the selector row and
    the buttons row must stay vertically disjoint (Inc-4 review F1 — the
    ``margin-bottom`` offset is hand-measured from the buttons row's
    realized height and would silently overlap if that height changes).
    The TC-024.6 per-width idiom: both widths asserted in this single
    node.
    """

    async def _regions(size: Tuple[int, int]) -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(tmp_path, "proj", filters={"f.json": _valid_filter_body()})
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj")
            screen = await _open_reports(app, pilot)
            dialog = screen.query_one("#report_dialog")
            row = screen.query_one("#report_filter_row")
            generate = screen.query_one("#report_generate", Button)
            buttons = screen.query_one(".modal-buttons")
            return {
                "dialog": dialog.region,
                "row": row.region,
                "generate": generate.region,
                "buttons": buttons.region,
            }

    for size in ((80, 24), (120, 30)):
        regions = asyncio.run(_regions(size))
        dialog = regions["dialog"]
        for label in ("row", "generate"):
            region = regions[label]
            assert region.width > 0 and region.height > 0, (
                f"AT-056a2 @{size}: {label} must be visible, got {region}"
            )
            assert region.x >= dialog.x and region.right <= dialog.right, (
                f"AT-056a2 @{size}: {label} exceeds the dialog horizontally "
                f"({region} vs {dialog})"
            )
            assert region.y >= dialog.y and region.bottom <= dialog.bottom, (
                f"AT-056a2 @{size}: {label} exceeds the dialog vertically "
                f"({region} vs {dialog})"
            )
        # Inc-4 review F1: the rung-3 dock offset is a magic constant —
        # guard the contract it encodes: no vertical overlap between the
        # selector row and the buttons row.
        assert regions["row"].bottom <= regions["buttons"].y, (
            f"AT-056a2 @{size}: the selector row overlaps the buttons row "
            f"(row {regions['row']} vs buttons {regions['buttons']}) — the "
            "styles.tcss dock offset no longer matches the buttons row's "
            "realized height"
        )


# ===========================================================================
# AT-056a3 — project switch resets the selection (LLR-056.3 / F-09)
# ===========================================================================


def test_at_056a3_project_switch_resets_selection_next_report_unfiltered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-056a3 / LLR-056.3 (HLR-056, F-09 reset funnel).

    Intent: a selection made on project 1 does NOT survive a project
    switch — after loading project 2 the reopened dropdown shows blank and
    the next generated report is unfiltered (no audit header). Closes the
    batch-24 cross-project survivor class.
    """
    _pin_report_clocks(monkeypatch)

    async def _drive() -> Tuple[object, Dict[str, bytes], list]:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(
            tmp_path, "proj1", filters={"f.json": _valid_filter_body()}
        )
        proj2 = _make_project(tmp_path, "proj2")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj1")
            await _select_filter_via_dropdown(app, pilot, "f.json")
            await _load_project(app, pilot, "proj2")
            screen = await _open_reports(app, pilot)
            select_value = screen.query_one(
                "#report_filter_select", Select
            ).value
            screen.query_one("#report_generate", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return select_value, _reports(proj2), list(app.log_lines)

    select_value, written, log_lines = asyncio.run(_drive())
    assert select_value is Select.NULL, (
        "AT-056a3: after the project switch the reopened dropdown must "
        f"show blank, got {select_value!r}"
    )
    assert len(written) == 1, (
        f"AT-056a3: exactly one report expected, got {sorted(written)}"
    )
    text = next(iter(written.values())).decode("utf-8")
    assert "Report filter applied" not in text, (
        "AT-056a3: the post-switch report must be unfiltered (no audit "
        f"header); status was {log_lines!r}"
    )


# ===========================================================================
# AT-056b — hostile filename: populate, literal render, no MarkupError
# ===========================================================================


def test_at_056b_hostile_filename_populates_and_renders_literally(
    tmp_path: Path,
) -> None:
    """AT-056b / LLR-053.6 + LLR-056.2 (HLR-056, C-17 + C-15).

    Intent: a filter file named ``[boom].json`` (markup-hostile, legal on
    Windows) POPULATES the dropdown, the options overlay opens and renders
    the name LITERALLY (C-15 probe 2026-07-10: textual 8.2.8 parses raw
    option labels as markup — ``[red]x[/red]`` renders styled — so
    unescaped labels would silently corrupt; ``rich.markup.escape`` at
    construction renders literal), selecting it surfaces a confirmation
    status carrying the literal name through the markup-inert log funnel,
    and no ``MarkupError`` is raised anywhere.
    """
    hostile = "[boom].json"

    async def _drive() -> dict:
        from textual.widgets._select import SelectOverlay

        app = S19TuiApp(base_dir=tmp_path)
        _make_project(
            tmp_path, "proj", filters={hostile: _valid_filter_body()}
        )
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj")
            screen = await _open_reports(app, pilot)
            select = screen.query_one("#report_filter_select", Select)
            overlay = select.query_one(SelectOverlay)
            # allow_blank adds the blank option at index 0.
            outcomes["option_count"] = overlay.option_count
            select.expanded = True
            await _flush(pilot)
            outcomes["expanded"] = select.expanded
            prompt = overlay.get_option_at_index(1).prompt
            if hasattr(prompt, "plain"):
                prompt_plain = prompt.plain
            else:
                from rich.text import Text

                prompt_plain = Text.from_markup(str(prompt)).plain
            outcomes["prompt_plain"] = prompt_plain
            select.expanded = False
            await _flush(pilot)
            select.value = hostile
            await _flush(pilot)
            outcomes["log_renders"] = [
                str(app.query_one(f"#log_line_{i}", Label).render())
                for i in range(1, 5)
            ]
            outcomes["log_lines"] = list(app.log_lines)
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["option_count"] == 2, (
        "AT-056b: the dropdown must populate with the hostile name "
        f"(blank + 1), got {outcomes['option_count']}"
    )
    assert outcomes["expanded"] is True, (
        "AT-056b: the options overlay must open with the hostile option"
    )
    assert outcomes["prompt_plain"] == hostile, (
        "AT-056b: the overlay must render the hostile name LITERALLY, got "
        f"{outcomes['prompt_plain']!r}"
    )
    assert any(hostile in text for text in outcomes["log_renders"]), (
        "AT-056b: the confirmation status must render the literal hostile "
        f"filename; rendered {outcomes['log_renders']!r} "
        f"(raw {outcomes['log_lines']!r})"
    )


# ===========================================================================
# AT-056c — fresh default: blank dropdown, byte-identical full report
# ===========================================================================


def test_at_056c_fresh_default_blank_dropdown_full_report_golden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-056c / LLR-056.2 + LLR-055.3 (HLR-056).

    Intent: on a fresh app with NOTHING selected the dropdown shows blank
    and the generated report is byte-identical (canonical form) to the
    AT-055b golden captured at the batch base revision — the selector's
    presence alone must not perturb a single byte of the default path.
    """
    _pin_report_clocks(monkeypatch)

    async def _drive() -> Tuple[object, Dict[str, bytes]]:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(tmp_path, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj")
            screen = await _open_reports(app, pilot)
            select_value = screen.query_one(
                "#report_filter_select", Select
            ).value
            screen.query_one("#report_generate", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return select_value, _reports(project_dir)

    select_value, written = asyncio.run(_drive())
    assert select_value is Select.NULL, (
        f"AT-056c: the fresh dropdown must show blank, got {select_value!r}"
    )
    assert sorted(written) == [_PR_NAME], (
        f"AT-056c: expected exactly the pinned-clock report, got "
        f"{sorted(written)}"
    )
    assert _AT055B_GOLDEN.is_file(), (
        f"AT-056c: golden fixture missing: {_AT055B_GOLDEN}"
    )
    observed = canonical_report_bytes(written[_PR_NAME], tmp_path)
    golden = canonical_report_bytes(_AT055B_GOLDEN.read_bytes())
    assert observed == golden, (
        "AT-056c: the fresh-default report drifted from the AT-055b golden "
        "(LLR-055.3 byte-identity, canonical form)"
    )


# ===========================================================================
# AT-056d — typed free path: valid out-of-project filters; missing refuses
# ===========================================================================


def test_at_056d_typed_path_valid_filters_missing_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-056d / LLR-056.4 (HLR-056, Q-4 black-box arm).

    Intent: typing a path to a VALID out-of-project filter file into the
    free-path input selects it (confirmation status carries the filename)
    and the next Generate writes a FILTERED report naming that file; then
    typing a path to a MISSING file surfaces a named refusal diagnostic
    and writes nothing new.
    """
    _pin_report_clocks(monkeypatch)
    external = tmp_path / "elsewhere" / "ext-filter.json"
    external.parent.mkdir(parents=True)
    external.write_text(
        _valid_filter_body(addresses=(("0x1000", "0x1001"),)),
        encoding="utf-8",
    )

    async def _type_path(app: S19TuiApp, pilot, raw: str) -> None:
        screen = await _open_reports(app, pilot)
        path_input = screen.query_one("#report_filter_path", Input)
        path_input.value = raw
        path_input.focus()
        await pilot.pause()
        await pilot.press("enter")
        await _flush(pilot)
        await _close_reports(screen, pilot)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(tmp_path, "proj", two_entries=True)
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj")
            await _type_path(app, pilot, str(external))
            outcomes["confirm_lines"] = list(app.log_lines)
            await _press_generate(app, pilot)
            outcomes["after_valid"] = _reports(project_dir)
            await _type_path(app, pilot, str(tmp_path / "no-such.json"))
            outcomes["refusal_lines"] = list(app.log_lines)
            outcomes["after_missing"] = _reports(project_dir)
        return outcomes

    outcomes = asyncio.run(_drive())
    assert any(
        "ext-filter.json" in line for line in outcomes["confirm_lines"]
    ), (
        "AT-056d: the typed-path confirmation must carry the filename; "
        f"status was {outcomes['confirm_lines']!r}"
    )
    assert sorted(outcomes["after_valid"]) == [_PR_NAME], (
        f"AT-056d: one filtered report expected, got "
        f"{sorted(outcomes['after_valid'])}"
    )
    text = outcomes["after_valid"][_PR_NAME].decode("utf-8")
    assert "Report filter applied" in text and "ext-filter.json" in text, (
        "AT-056d: the next report must be filtered by the typed "
        "out-of-project file"
    )
    assert any(
        "not found" in line for line in outcomes["refusal_lines"]
    ), (
        "AT-056d: the missing typed path must refuse with a named "
        f"diagnostic; status was {outcomes['refusal_lines']!r}"
    )
    assert outcomes["after_missing"].keys() == outcomes["after_valid"].keys(), (
        "AT-056d: the refused typed path must write nothing new"
    )


# ===========================================================================
# AT-056e — the A2B diff report ignores the selection (LLR-054.5)
# ===========================================================================


def test_at_056e_a2b_diff_report_byte_identical_despite_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-056e / LLR-054.5 (HLR-054 scope guard, Q-5 black-box arm).

    Intent: with a filter SELECTED on the report selector, the A2B diff
    report driven through ITS shipped surface (Compare then Report on the
    diff screen) is byte-identical (canonical form) to a no-filter A2B
    run under the same environment pin — the sticky selection observably
    does NOT leak into the always-complete diff report.
    """
    _pin_report_clocks(monkeypatch)

    def _session(root: Path, select_filter: bool) -> Dict[str, bytes]:
        project_dir = _make_project(
            root, "proj", filters={"f.json": _valid_filter_body()}
        )

        async def _drive() -> Dict[str, bytes]:
            app = S19TuiApp(base_dir=root)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                await _load_project(app, pilot, "proj")
                if select_filter:
                    await _select_filter_via_dropdown(app, pilot, "f.json")
                app.action_show_screen("diff")
                await pilot.pause()
                app.query_one("#diff_path_a", Input).value = str(
                    project_dir / "a.s19"
                )
                app.query_one("#diff_path_b", Input).value = str(
                    project_dir / "b.s19"
                )
                app.query_one("#diff_compare_button", Button).press()
                await _flush(pilot)
                app.query_one("#diff_report_button", Button).press()
                await _flush(pilot)
            return _reports(project_dir)

        return asyncio.run(_drive())

    base_root = tmp_path / "base"
    sel_root = tmp_path / "sel"
    base_root.mkdir()
    sel_root.mkdir()
    baseline = _session(base_root, select_filter=False)
    selected = _session(sel_root, select_filter=True)

    expected = {_DIFF_MD_NAME, _DIFF_HTML_NAME}
    assert set(baseline) == expected, f"baseline wrote {sorted(baseline)}"
    assert set(selected) == expected, f"selected wrote {sorted(selected)}"
    for name in sorted(expected):
        canon_base = canonical_report_bytes(baseline[name], base_root)
        canon_sel = canonical_report_bytes(selected[name], sel_root)
        assert canon_sel == canon_base, (
            f"AT-056e: the A2B {name} must be byte-identical regardless of "
            "the selection (the filter must NOT leak into the diff report)"
        )
        assert "Report filter applied" not in selected[name].decode("utf-8")


# ===========================================================================
# AT-053a — JOINED node: invalid filter refuses BOTH surfaces, zero files
# ===========================================================================


def test_at_053a_invalid_filter_refuses_both_surfaces_zero_files(
    tmp_path: Path,
) -> None:
    """AT-053a / LLR-053.5 + LLR-053.6 (HLR-053) — ONE node, BOTH surfaces.

    Intent: with an INVALID filter selected through the real dropdown, a
    run that would otherwise succeed on each surface (save-back completed
    for ``b``; manifest project for Generate) is REFUSED: each status line
    leads with its report-kind prefix and carries the parser's named
    fault, no generator/worker runs, and ``<project>/reports/`` is
    unchanged on both (0 files).
    """

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(
            tmp_path,
            "proj",
            filters={
                "bad-envelope.json": (
                    '{"format": "wrong-format", "version": "1.0", '
                    '"include": {}}'
                )
            },
        )
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj")
            await _select_filter_via_dropdown(app, pilot, "bad-envelope.json")
            await _apply_and_saveback(app, pilot)
            outcomes["before"] = sorted(_reports(project_dir))
            await _press_bkey(app, pilot)
            outcomes["after_bkey"] = sorted(_reports(project_dir))
            outcomes["bkey_lines"] = list(app.log_lines)
            await _press_generate(app, pilot)
            outcomes["after_generate"] = sorted(_reports(project_dir))
            outcomes["generate_lines"] = list(app.log_lines)
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["after_bkey"] == outcomes["before"], (
        "AT-053a: the refused b-key run must write ZERO report files, got "
        f"{outcomes['after_bkey']}"
    )
    assert any(
        line.startswith("Before/after report refused:")
        for line in outcomes["bkey_lines"]
    ), (
        "AT-053a: the b-key refusal must lead with the kind prefix; "
        f"status was {outcomes['bkey_lines']!r}"
    )
    assert any("'format'" in line for line in outcomes["bkey_lines"]), (
        "AT-053a: the b-key refusal must carry the parser's named fault; "
        f"status was {outcomes['bkey_lines']!r}"
    )
    assert outcomes["after_generate"] == outcomes["before"], (
        "AT-053a: the refused Generate run must write ZERO report files, "
        f"got {outcomes['after_generate']}"
    )
    assert any(
        line.startswith("Project report refused:")
        for line in outcomes["generate_lines"]
    ), (
        "AT-053a: the Generate refusal must lead with the kind prefix; "
        f"status was {outcomes['generate_lines']!r}"
    )
    assert not any(
        "running active scope" in line
        for line in outcomes["generate_lines"]
    ), "AT-053a: the worker must never start on the refused Generate run"


# ===========================================================================
# AT-053b — hostile-but-VALID filter proceeds; every written file sanitized
# ===========================================================================


def test_at_053b_hostile_valid_filter_proceeds_sanitized_everywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-053b / LLR-053.6 + LLR-055.4 (HLR-053, C-17 status + file sides).

    Q-3 redefinition rationale: the draft's AT-053b observed a
    hostile-content REFUSAL, which AT-053a already covers — the redefined
    node proves the complementary half of HLR-053's acceptance:
    hostility is NOT invalidity. A VALID filter whose FILENAME carries
    markup brackets + backticks (Windows-legal; NTFS forbids ``|``/``<``/
    ``>`` in names, so the pipe, ``<b>``, ctl-byte, and header-forging
    classes ride in the PATTERNS) must PROCEED on BOTH report kinds
    through the shipped surfaces (key ``b`` + Generate); the selection
    confirmation renders the filename literally through the markup-inert
    funnel with no ``MarkupError`` (LLR-053.6, Q-7 budget: the
    confirmation carries the filename); and EVERY written file —
    before/after MD + HTML and the project report — is re-read asserting
    the LLR-055.4 sanitation discipline: literal filter name in each
    audit header, no raw ``<b>`` in the HTML (the format carries no
    legitimate one — the TC-038.6 precedent), MD table cell counts
    intact (batch-34 unescaped-pipe idiom), the audit heading exactly
    ONCE at its pinned first-block-after-title position (S-F6 — no
    header forgery), and control bytes absent.
    """
    _pin_report_clocks(monkeypatch)
    hostile_name = "[boom]`b`.json"
    hostile_patterns = (
        "a|b",
        "`tick`",
        "<b>bold</b>",
        "\x01ctl",
        "x\n## Report filter applied",
    )
    body = _valid_filter_body(
        addresses=(("0x1000", "0x1001"),), symbols=hostile_patterns
    )

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(
            tmp_path, "proj", filters={hostile_name: body}, two_entries=True
        )
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj")
            await _select_filter_via_dropdown(app, pilot, hostile_name)
            outcomes["log_renders"] = [
                str(app.query_one(f"#log_line_{i}", Label).render())
                for i in range(1, 5)
            ]
            await _apply_and_saveback(
                app, pilot, entries=(("0x1000", "AA"), ("0x1002", "BB"))
            )
            await _press_bkey(app, pilot)
            await _press_generate(app, pilot)
            outcomes["written"] = _reports(project_dir)
            outcomes["log_lines"] = list(app.log_lines)
        return outcomes

    outcomes = asyncio.run(_drive())
    written = outcomes["written"]

    # (a) generation PROCEEDED on both report kinds (hostility != invalidity).
    assert set(written) == {_BA_MD_NAME, _BA_HTML_NAME, _PR_NAME}, (
        "AT-053b: a hostile-but-VALID filter must not refuse either "
        f"surface; wrote {sorted(written)}; status was "
        f"{outcomes['log_lines']!r}"
    )
    assert not any("refused" in line for line in outcomes["log_lines"]), (
        "AT-053b: no refusal may surface on the proceed path; status was "
        f"{outcomes['log_lines']!r}"
    )

    # (b) the confirmation rendered the filename literally (LLR-053.6).
    assert any(hostile_name in text for text in outcomes["log_renders"]), (
        "AT-053b: the selection confirmation must render the hostile "
        f"filename literally; rendered {outcomes['log_renders']!r}"
    )

    md_text = written[_BA_MD_NAME].decode("utf-8")
    html_text = written[_BA_HTML_NAME].decode("utf-8")
    pr_text = written[_PR_NAME].decode("utf-8")

    # (c) every written file re-read: LLR-055.4 sanitation.
    for label, text in (
        ("ba-md", md_text), ("ba-html", html_text), ("project", pr_text)
    ):
        assert f"Filter file: {hostile_name}" in text, (
            f"AT-053b: the {label} audit header must carry the literal "
            "hostile filename"
        )
        assert "\x01" not in text, (
            f"AT-053b: no control byte may reach the {label} file"
        )

    # Anti-forgery: the audit heading exactly ONCE, at its pinned
    # first-block-after-title position (S-F6), in each format — the
    # header-forging pattern must mint no second heading line.
    md_lines = md_text.splitlines()
    assert md_lines[0] == "# Diff report" and md_lines[2] == (
        "## Report filter applied"
    ), f"AT-053b: ba-md header block displaced: {md_lines[:4]}"
    assert sum(
        1 for ln in md_lines if ln == "## Report filter applied"
    ) == 1, "AT-053b: the ba-md audit heading must appear exactly once"
    pr_lines = pr_text.splitlines()
    assert pr_lines[0] == "# Project report: proj" and pr_lines[2] == (
        "## Report filter applied"
    ), f"AT-053b: project-report header block displaced: {pr_lines[:4]}"
    assert sum(
        1 for ln in pr_lines if ln == "## Report filter applied"
    ) == 1, "AT-053b: the project audit heading must appear exactly once"
    html_lines = html_text.splitlines()
    title_index = html_lines.index("<h1>Diff report</h1>")
    assert html_lines[title_index + 1] == (
        "<h2>Report filter applied</h2>"
    ), "AT-053b: the HTML audit heading must follow the title"
    assert html_text.count("Report filter applied") == 1, (
        "AT-053b: the HTML audit heading must appear exactly once"
    )

    # No raw file-derived tag in the HTML; MD tables structurally intact.
    assert "<b>" not in html_text, (
        "AT-053b: raw '<b>' must never reach the HTML (escaped form only, "
        "if echoed at all)"
    )
    _assert_md_table_rows_intact(md_text, "ba-md")
    _assert_md_table_rows_intact(pr_text, "project")


# ===========================================================================
# AT-054a — b-key filtered pair: match kept, unmatched omitted, header
# ===========================================================================


def test_at_054a_bkey_filtered_pair_keeps_match_omits_unmatched(
    tmp_path: Path,
) -> None:
    """AT-054a / LLR-054.2 + LLR-054.3 (HLR-054).

    Intent: with a valid filter designated (fixture-set sticky path — the
    selection SURFACE is AT-056a's concern), the shipped ``b``-key flow
    writes an MD+HTML pair that keeps the MATCHING linkage row, omits the
    unmatched one (and its window heading), and carries the audit header
    naming the real filter file.
    """

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(
            tmp_path,
            "proj",
            filters={
                "first-byte.json": _valid_filter_body(
                    addresses=(("0x1000", "0x1001"),)
                )
            },
        )
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj")
            app._report_filter_path = project_dir / "filters" / "first-byte.json"
            await _apply_and_saveback(
                app, pilot, entries=(("0x1000", "AA"), ("0x1002", "BB"))
            )
            await _press_bkey(app, pilot)
            outcomes["written"] = {
                name: raw.decode("utf-8")
                for name, raw in _reports(project_dir).items()
            }
            outcomes["log_lines"] = list(app.log_lines)
        return outcomes

    outcomes = asyncio.run(_drive())
    written = outcomes["written"]
    md_names = [n for n in written if n.endswith("-before-after-report.md")]
    html_names = [
        n for n in written if n.endswith("-before-after-report.html")
    ]
    assert len(md_names) == 1 and len(html_names) == 1, (
        f"AT-054a: expected the MD+HTML pair, got {sorted(written)}; "
        f"status was {outcomes['log_lines']!r}"
    )
    md_text = written[md_names[0]]
    html_text = written[html_names[0]]
    for label, text in (("md", md_text), ("html", html_text)):
        assert "Report filter applied" in text, (
            f"AT-054a: the {label} must carry the audit header"
        )
        assert "first-byte.json" in text, (
            f"AT-054a: the {label} header must name the real filter file"
        )
        assert "0x00001000" in text, (
            f"AT-054a: the {label} must keep the matching item"
        )
        assert "0x00001002" not in text, (
            f"AT-054a: the {label} must omit the unmatched linkage row and "
            "window heading"
        )
    assert "| 0x00001000 | 0x00001001 |" in md_text, (
        "AT-054a: the matching linkage row must survive in the MD table"
    )


# ===========================================================================
# AT-054c — b-key zero-match: loud notice, wording disjoint from refusal
# ===========================================================================


def test_at_054c_bkey_zero_match_writes_pair_with_loud_notice(
    tmp_path: Path,
) -> None:
    """AT-054c / LLR-054.3 (HLR-054, D-3 + Q-12).

    Intent: a VALID filter matching nothing still writes the MD+HTML pair
    with the loud ``filter matched 0 of N items`` notice — and the notice
    wording is disjoint from the refusal wording (no shared prefix token,
    no ``refused`` anywhere in the flow).
    """

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(
            tmp_path,
            "proj",
            filters={
                "matches-nothing.json": _valid_filter_body(
                    addresses=(("0x9000", "0x9010"),)
                )
            },
        )
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj")
            app._report_filter_path = (
                project_dir / "filters" / "matches-nothing.json"
            )
            await _apply_and_saveback(app, pilot)
            await _press_bkey(app, pilot)
            outcomes["written"] = {
                name: raw.decode("utf-8")
                for name, raw in _reports(project_dir).items()
            }
            outcomes["log_lines"] = list(app.log_lines)
        return outcomes

    outcomes = asyncio.run(_drive())
    written = outcomes["written"]
    md_names = [n for n in written if n.endswith("-before-after-report.md")]
    assert len(md_names) == 1, (
        f"AT-054c: the zero-match pair must still be written, got "
        f"{sorted(written)}; status was {outcomes['log_lines']!r}"
    )
    md_text = written[md_names[0]]
    assert "filter matched 0 of 1 items" in md_text, (
        "AT-054c: the loud zero-match notice must replace the filtered "
        "section bodies"
    )
    assert "refused" not in md_text, (
        "AT-054c/Q-12: the zero-match wording must be disjoint from the "
        "refusal wording"
    )
    assert not any("refused" in line for line in outcomes["log_lines"]), (
        "AT-054c/Q-12: zero-match is NOT a refusal; status was "
        f"{outcomes['log_lines']!r}"
    )


# ===========================================================================
# TC-316 — filters/ scan unit (LLR-056.1)
# ===========================================================================


def test_tc316_scan_sorted_symlink_skipped_absent_dir_and_validate(
    tmp_path: Path,
) -> None:
    """TC-316 / LLR-056.1: the filters/ scan globs ``*.json`` under the
    active project's ``filters/`` dir, SKIPS symlink entries, returns bare
    names sorted deterministically, and yields ``[]`` for an absent dir;
    plus the ``validate_project_files`` regression — a project WITH a
    ``filters/`` subdirectory still validates (subdir skip,
    ``workspace.py:360-362``).
    """
    from s19_app.tui.workspace import validate_project_files

    app = S19TuiApp(base_dir=tmp_path)
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    filters_dir = project_dir / "filters"
    filters_dir.mkdir(parents=True)
    (project_dir / "a.s19").write_text(S19_A, encoding="utf-8")
    (filters_dir / "b.json").write_text("{}", encoding="utf-8")
    (filters_dir / "a.json").write_text("{}", encoding="utf-8")
    (filters_dir / "note.txt").write_text("x", encoding="utf-8")
    app.current_project = "proj"

    symlinked = True
    try:
        os.symlink(str(filters_dir / "a.json"), str(filters_dir / "c.json"))
    except OSError:
        symlinked = False

    names = app._scan_report_filter_files()
    assert names == ["a.json", "b.json"], (
        f"TC-316: sorted bare names, symlink skipped (created={symlinked}), "
        f"non-json ignored; got {names}"
    )

    app.current_project = "noproj"
    (tmp_path / ".s19tool" / "workarea" / "noproj").mkdir(parents=True)
    assert app._scan_report_filter_files() == [], (
        "TC-316: an absent filters/ dir must yield []"
    )
    app.current_project = None
    assert app._scan_report_filter_files() == [], (
        "TC-316: no active project must yield []"
    )

    data_files, _a2l_files, error = validate_project_files(project_dir)
    assert error is None, (
        f"TC-316: a project with a filters/ subdir must still validate, "
        f"got {error!r}"
    )
    assert [p.name for p in data_files] == ["a.s19"]


# ===========================================================================
# TC-317 — typed-path resolution + the S-F2 swap cases (LLR-056.4)
# ===========================================================================


def test_tc317_typed_path_resolution_and_swap_refusals(
    tmp_path: Path,
) -> None:
    """TC-317 / LLR-056.4 + LLR-053.2 (S-F2).

    Intent: the typed-path arm resolves a RELATIVE path against the app
    base dir, refuses a missing path and a symlinked path with named
    diagnostics at selection time; and the read-time check catches BOTH
    swap classes — the dropdown-selected file DELETED before generation
    (unresolvable) and REPLACED BY A SYMLINK before generation (Inc-1's
    read-time refusal exercised through the surface path).
    """
    can_symlink = True
    probe_target = tmp_path / "probe-target.txt"
    probe_target.write_text("x", encoding="utf-8")
    try:
        os.symlink(str(probe_target), str(tmp_path / "probe-link"))
    except OSError:
        can_symlink = False

    relative_filter = tmp_path / "rel-filter.json"
    relative_filter.write_text(_valid_filter_body(), encoding="utf-8")
    if can_symlink:
        os.symlink(
            str(relative_filter), str(tmp_path / "link-filter.json")
        )

    async def _type_path(app: S19TuiApp, pilot, raw: str) -> list:
        screen = await _open_reports(app, pilot)
        path_input = screen.query_one("#report_filter_path", Input)
        path_input.value = raw
        path_input.focus()
        await pilot.pause()
        await pilot.press("enter")
        await _flush(pilot)
        await _close_reports(screen, pilot)
        return list(app.log_lines)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(
            tmp_path,
            "proj",
            filters={
                "swap-delete.json": _valid_filter_body(),
                "swap-symlink.json": _valid_filter_body(),
            },
        )
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_project(app, pilot, "proj")

            outcomes["relative_lines"] = await _type_path(
                app, pilot, "rel-filter.json"
            )
            resolved = app._report_filter_path
            outcomes["relative_resolved"] = (
                resolved is not None
                and resolved.resolve() == relative_filter.resolve()
            )

            outcomes["missing_lines"] = await _type_path(
                app, pilot, "no-such-filter.json"
            )
            if can_symlink:
                outcomes["symlink_lines"] = await _type_path(
                    app, pilot, str(tmp_path / "link-filter.json")
                )

            # Swap class 1: selected file DELETED before generation.
            await _select_filter_via_dropdown(app, pilot, "swap-delete.json")
            (project_dir / "filters" / "swap-delete.json").unlink()
            await _press_generate(app, pilot)
            outcomes["deleted_lines"] = list(app.log_lines)
            outcomes["after_deleted"] = sorted(_reports(project_dir))

            # Swap class 2: selected file replaced by a SYMLINK.
            if can_symlink:
                await _select_filter_via_dropdown(
                    app, pilot, "swap-symlink.json"
                )
                swap_path = project_dir / "filters" / "swap-symlink.json"
                swap_path.unlink()
                os.symlink(str(relative_filter), str(swap_path))
                await _press_generate(app, pilot)
                outcomes["swap_symlink_lines"] = list(app.log_lines)
                outcomes["after_swap_symlink"] = sorted(
                    _reports(project_dir)
                )
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["relative_resolved"], (
        "TC-317: a relative typed path must resolve against the app base "
        f"dir; status was {outcomes['relative_lines']!r}"
    )
    assert any(
        "not found" in line for line in outcomes["missing_lines"]
    ), (
        "TC-317: a missing typed path must refuse with a named diagnostic; "
        f"status was {outcomes['missing_lines']!r}"
    )
    if can_symlink:
        assert any(
            "symlink" in line for line in outcomes["symlink_lines"]
        ), (
            "TC-317: a symlinked typed path must refuse; status was "
            f"{outcomes['symlink_lines']!r}"
        )
    assert outcomes["after_deleted"] == [], (
        "TC-317: the deleted-after-selection swap must refuse at read "
        f"time and write nothing, got {outcomes['after_deleted']}"
    )
    assert any(
        line.startswith("Project report refused:")
        for line in outcomes["deleted_lines"]
    ), (
        "TC-317: the deleted-swap refusal must lead with the kind prefix; "
        f"status was {outcomes['deleted_lines']!r}"
    )
    if can_symlink:
        assert outcomes["after_swap_symlink"] == [], (
            "TC-317: the symlink swap must refuse at read time (S-F2) and "
            f"write nothing, got {outcomes['after_swap_symlink']}"
        )
        assert any(
            "symlink" in line for line in outcomes["swap_symlink_lines"]
        ), (
            "TC-317: the symlink-swap refusal must name the symlink fault; "
            f"status was {outcomes['swap_symlink_lines']!r}"
        )


# ===========================================================================
# TC-F1 — cross-module filter-helper consistency pin (Inc-3 review F1)
# ===========================================================================


def test_tc_f1_filter_helper_wording_identical_across_report_modules() -> None:
    """TC-F1 / LLR-054.3 (Inc-3 code-review finding F1).

    Intent: ``_zero_match_notice``, the ctl-strip twins, and
    ``_filter_display_name`` are DUPLICATED between ``report_service`` and
    ``diff_report_service``, and LLR-054.3 requires the zero-match notice
    wording to be IDENTICAL across both report kinds — this pin makes a
    future one-sided edit fail loudly instead of silently breaking the
    cross-report contract. (Consolidation is a later hygiene item; this
    node is the contract guard only.)
    """
    from s19_app.tui.services import diff_report_service as drs
    from s19_app.tui.services import report_service as rs
    from s19_app.tui.services.report_filter import (
        parse_report_filter,
        resolve_report_filter,
    )

    for total in (1, 3):
        assert rs._zero_match_notice(total) == drs._zero_match_notice(total), (
            "TC-F1: the zero-match notice wording must be identical across "
            f"both report modules (total={total})"
        )

    hostile = "a\x01b\r\nc"
    assert rs._strip_ctl_local(hostile) == drs._strip_ctl(hostile), (
        "TC-F1: the ctl-strip twins must sanitize identically"
    )

    parsed, errors = parse_report_filter(_valid_filter_body())
    assert errors == []
    named = resolve_report_filter(
        parsed, [], [], source_name="pin-check.json"
    )
    unnamed = resolve_report_filter(parsed, [], [])
    for matcher in (named, unnamed):
        assert rs._filter_display_name(matcher) == drs._filter_display_name(
            matcher
        ), (
            "TC-F1: the display-name helpers must agree "
            f"(source_name={matcher.source_name!r})"
        )
