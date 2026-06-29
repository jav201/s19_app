"""Batch-18 — shared classification legend (US-022 / US-023, LLR-022.1).

- ``test_legend_table_*`` (TC-S1) — anti-drift: every severity in
  ``color_policy.SEVERITY_CLASS_MAP`` is reachable through a ``LEGEND_TABLE``
  colour, and every legend colour maps to a known severity (or is the default
  ``"White"`` foreground). A new engine severity added without a legend colour
  fails here. Plus structural coverage of the documented REQUIREMENTS.md §3
  classifications and the colour→MEANING pairing (m2 fold: no blank meanings).
- ``test_legend_data_not_in_frozen_color_policy`` (TC-frozen-diff) — the
  LLR-022.1 frozen constraint: the legend data lives in the NEW non-frozen
  ``legend.py``; ``color_policy.py`` (engine-frozen) is unchanged vs ``main``.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

from textual.widgets import Button

from s19_app.tui.app import S19TuiApp
from s19_app.tui.color_policy import SEVERITY_CLASS_MAP
from s19_app.tui.legend import COLOUR_SEVERITY, LEGEND_TABLE
from s19_app.tui.screens import LegendScreen
from s19_app.tui.services.report_service import _legend_lines

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PRG_S19 = _REPO_ROOT / "examples" / "case_00_public" / "prg.s19"

_TOTAL_ROWS = sum(len(rows) for rows in LEGEND_TABLE.values())


def _install_prg(app: S19TuiApp) -> None:
    """Install the public ``prg.s19`` fixture as ``current_file`` so the rail
    screens lay out (the empty state otherwise hides their content)."""
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19

    s19 = S19File(str(_PRG_S19))
    app.current_file = build_loaded_s19(_PRG_S19, s19, a2l_path=None, a2l_data=None)
    app._apply_empty_state()


def _modal_meanings(screen: LegendScreen) -> list[str]:
    """The per-row meanings rendered in the legend modal body (artifact
    header Labels carry no ``' — '`` separator and are skipped)."""
    out: list[str] = []
    for label in screen.query("#legend_body Label"):
        text = str(label.render())
        if " — " in text:
            out.append(text.split(" — ", 1)[1])
    return out


def test_legend_table_covers_all_severities() -> None:  # TC-S1
    """Every policy severity is reachable via a legend colour, and no legend
    colour is an orphan (must map to a severity, or be the default White)."""
    assert set(SEVERITY_CLASS_MAP) <= set(COLOUR_SEVERITY.values()), (
        "a ValidationSeverity in SEVERITY_CLASS_MAP has no legend colour "
        "(anti-drift): add it to legend.COLOUR_SEVERITY + LEGEND_TABLE"
    )
    used_colours = {
        colour
        for rows in LEGEND_TABLE.values()
        for (colour, _meaning) in rows.values()
    }
    assert used_colours <= set(COLOUR_SEVERITY) | {"White"}, (
        f"orphan legend colour(s): {used_colours - set(COLOUR_SEVERITY) - {'White'}}"
    )


def test_legend_table_has_documented_artifacts_and_rows() -> None:  # TC-S1 structure
    """The three artifacts and their REQUIREMENTS.md §3 classifications, each
    with a non-blank colour and meaning (a blank-meaning legend must fail)."""
    assert set(LEGEND_TABLE) == {"A2L", "MAC", "Issues"}
    assert set(LEGEND_TABLE["A2L"]) == {"Red", "Green", "White", "Grey"}
    assert set(LEGEND_TABLE["MAC"]) == {"Red", "Orange", "Green", "White", "Grey"}
    assert set(LEGEND_TABLE["Issues"]) == {"Errors", "Warnings", "Optional info"}
    for artifact, rows in LEGEND_TABLE.items():
        for classification, (colour, meaning) in rows.items():
            assert colour.strip(), f"blank colour: {artifact}/{classification}"
            assert meaning.strip(), f"blank meaning: {artifact}/{classification}"


def test_legend_data_not_in_frozen_color_policy() -> None:  # TC-frozen-diff
    """``color_policy.py`` (engine-frozen) is unchanged vs ``main``; the shared
    legend table lives in the new non-frozen ``legend`` module instead."""
    diff = subprocess.run(
        ["git", "diff", "--stat", "main", "--", "s19_app/tui/color_policy.py"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert diff.returncode == 0, diff.stderr
    assert diff.stdout.strip() == "", (
        "color_policy.py is engine-frozen (LLR-022.1); legend data must live "
        f"in legend.py — unexpected diff vs main:\n{diff.stdout}"
    )
    import s19_app.tui.legend as legend_mod

    assert hasattr(legend_mod, "LEGEND_TABLE")


# ---------------------------------------------------------------------------
# US-023 — in-app Legend (modal + per-view affordances). Black-box Pilot.
#
# C-13 outcome (measured, §6.5 amendment A1): the A2L filter row already
# overflows its half-width pane, so a 10th button is off-screen at 80 AND 120
# cols. Operator-ratified resolution = the ``k`` key for A2L (no button there);
# full "Legend" buttons on MAC + Issues (both measured on-screen).
# ---------------------------------------------------------------------------


def test_at023a_a2l_legend_opens_via_key(tmp_path: Path) -> None:
    """AT-023a — on the A2L view the ``k`` key opens the legend modal.

    A2L has no Legend button (C-13: it would be off-screen); the keybinding
    is the ratified affordance. Observed black-box: drive the key on the
    shown A2L screen, assert the modal carries the A2L rows.
    """

    async def _drive() -> tuple[bool, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_prg(app)
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            app.set_focus(None)  # user not typing in a filter field
            await pilot.press("k")
            await pilot.pause()
            on_legend = isinstance(app.screen, LegendScreen)
            return on_legend, _modal_meanings(app.screen) if on_legend else []

    on_legend, meanings = asyncio.run(_drive())
    assert on_legend, "pressing 'k' on the A2L view did not open LegendScreen"
    assert LEGEND_TABLE["A2L"]["Red"][1] in meanings


def test_at023b_mac_legend_button_opens(tmp_path: Path) -> None:
    """AT-023b — the MAC view's Legend button opens the modal with content."""

    async def _drive() -> tuple[bool, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_prg(app)
            await pilot.pause()
            app.action_show_screen("mac")
            await pilot.pause()
            app.query_one("#mac_legend_button", Button).press()
            await pilot.pause()
            on_legend = isinstance(app.screen, LegendScreen)
            return on_legend, _modal_meanings(app.screen) if on_legend else []

    on_legend, meanings = asyncio.run(_drive())
    assert on_legend
    assert LEGEND_TABLE["MAC"]["Orange"][1] in meanings


def test_at023c_issues_legend_button_opens(tmp_path: Path) -> None:
    """AT-023c — the Issues view's Legend button opens the modal with content."""

    async def _drive() -> tuple[bool, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_prg(app)
            await pilot.pause()
            app.action_show_screen("issues")
            await pilot.pause()
            app.query_one("#issues_legend_button", Button).press()
            await pilot.pause()
            on_legend = isinstance(app.screen, LegendScreen)
            return on_legend, _modal_meanings(app.screen) if on_legend else []

    on_legend, meanings = asyncio.run(_drive())
    assert on_legend
    assert LEGEND_TABLE["Issues"]["Errors"][1] in meanings


def test_at023d_close_dismisses_modal(tmp_path: Path) -> None:
    """AT-023d — the Close button dismisses the modal back to the view."""

    async def _drive() -> tuple[bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_prg(app)
            await pilot.pause()
            app.action_show_screen("issues")
            await pilot.pause()
            app.query_one("#issues_legend_button", Button).press()
            await pilot.pause()
            opened = isinstance(app.screen, LegendScreen)
            app.screen.query_one("#legend_close", Button).press()
            await pilot.pause()
            closed = not isinstance(app.screen, LegendScreen)
            return opened, closed

    opened, closed = asyncio.run(_drive())
    assert opened and closed


def test_at023e_c13_geometry_at_80_cols(tmp_path: Path) -> None:
    """AT-023e — C-13: at 80 cols the MAC/Issues buttons are fully on-screen,
    A2L exposes no (clippable) button, and the opened modal fits the terminal.
    """

    async def _btn_right(key: str, btn_id: str, width: int) -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(width, 30)) as pilot:
            await pilot.pause()
            _install_prg(app)
            await pilot.pause()
            app.action_show_screen(key)
            await pilot.pause()
            btn = app.query_one(f"#{btn_id}", Button)
            return btn.region.right, app.size.width

    for key, btn_id in (
        ("mac", "mac_legend_button"),
        ("issues", "issues_legend_button"),
    ):
        right, screen_w = asyncio.run(_btn_right(key, btn_id, 80))
        assert 0 < right <= screen_w, (
            f"{btn_id} clipped at 80 cols: right={right}, screen={screen_w}"
        )

    async def _a2l_has_no_button() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 30)) as pilot:
            await pilot.pause()
            _install_prg(app)
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            return len(app.query("#a2l_legend_button"))

    assert asyncio.run(_a2l_has_no_button()) == 0

    async def _modal_within_terminal() -> tuple[int, int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 30)) as pilot:
            await pilot.pause()
            _install_prg(app)
            await pilot.pause()
            app.action_show_screen("mac")
            await pilot.pause()
            app.query_one("#mac_legend_button", Button).press()
            await pilot.pause()
            dlg = app.screen.query_one("#legend_dialog")
            return dlg.region.right, dlg.region.bottom, app.size.width, app.size.height

    right, bottom, sw, sh = asyncio.run(_modal_within_terminal())
    assert right <= sw and bottom <= sh, (
        f"legend modal clipped at 80x30: right={right}/{sw}, bottom={bottom}/{sh}"
    )


def test_at023f_legend_shows_without_file_loaded(tmp_path: Path) -> None:
    """AT-023f — empty boundary: with NO file loaded the static legend still
    opens with every documented row (the legend is static, not data-driven)."""

    async def _drive() -> tuple[bool, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("k")
            await pilot.pause()
            on_legend = isinstance(app.screen, LegendScreen)
            return on_legend, len(_modal_meanings(app.screen)) if on_legend else 0

    on_legend, n_rows = asyncio.run(_drive())
    assert on_legend
    assert n_rows == _TOTAL_ROWS


def test_tc023_1_modal_renders_all_table_rows(tmp_path: Path) -> None:
    """TC-023.1 — white-box: the modal renders every artifact header and the
    full row set read from ``LEGEND_TABLE`` (no filtered/duplicated content)."""

    async def _drive() -> tuple[list[str], list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("k")
            await pilot.pause()
            headers = [
                str(label.render())
                for label in app.screen.query("#legend_body Label")
                if "legend-artifact" in label.classes
            ]
            return headers, _modal_meanings(app.screen)

    headers, meanings = asyncio.run(_drive())
    assert headers == list(LEGEND_TABLE)  # A2L, MAC, Issues in order
    assert len(meanings) == _TOTAL_ROWS


def test_tc023_2_mac_issues_buttons_present_a2l_absent(tmp_path: Path) -> None:
    """TC-023.2 — the Legend button exists on MAC + Issues and is absent on
    A2L (the C-13 resolution); the modal opens from each button id."""

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_prg(app)
            await pilot.pause()
            counts: dict[str, int] = {}
            for key, btn_id in (
                ("mac", "mac_legend_button"),
                ("issues", "issues_legend_button"),
                ("a2l", "a2l_legend_button"),
            ):
                app.action_show_screen(key)
                await pilot.pause()
                counts[btn_id] = len(app.query(f"#{btn_id}"))
            return counts

    counts = asyncio.run(_drive())
    assert counts["mac_legend_button"] == 1
    assert counts["issues_legend_button"] == 1
    assert counts["a2l_legend_button"] == 0


def test_tc_s2_report_and_modal_render_same_rows(tmp_path: Path) -> None:
    """TC-S2 — single-source anti-drift: the report legend surface
    (``_legend_lines``) and the modal surface render the SAME documented
    meaning set; neither drops nor invents a row (m3 fold — rendered rows,
    not just a shared constant)."""
    report_text = "\n".join(_legend_lines())

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("k")
            await pilot.pause()
            return _modal_meanings(app.screen)

    modal_meanings = asyncio.run(_drive())
    all_meanings = [
        meaning for rows in LEGEND_TABLE.values() for (_c, meaning) in rows.values()
    ]
    for meaning in all_meanings:
        assert meaning in report_text, f"report surface missing row: {meaning}"
        assert meaning in modal_meanings, f"modal surface missing row: {meaning}"
    assert len(modal_meanings) == len(all_meanings)
