"""Batch-103 Inc 8, group P (panel wiring) - shared drivers for the ``test_b103_inc8_p*`` files.

Everything here drives the shipped chain: the real ``S19TuiApp`` under Textual Pilot,
the app's own A2L / image loaders, and the Patch Editor screen as the operator opens
it.  Expected colours are read from ``styles.tcss`` (never typed); expected values for
DEFC come from the generator's own files (seed 20260001, ``--case definitions``).
Fixtures are synthetic and public.
"""
from __future__ import annotations

import asyncio
import re
import subprocess
import sys
from pathlib import Path

from tests.b97_probes import painted_rows
from tests.support.b100_workers import settle_workers
from tests.support.b103_a2l_arrays import BASE_LAYOUTS, meas
from s19_app.tui.app import S19TuiApp

REPO_ROOT = Path(__file__).resolve().parents[2]
TCSS = REPO_ROOT / "s19_app" / "tui" / "styles.tcss"
SYNTH_TOOL = REPO_ROOT / "tools" / "synth" / "make_release_case.py"
SEED = 20260001

SIZE = (118, 54)
WIDE = (220, 60)
MIN_SIZE = (80, 24)

#: The seven regions of R-TUI-063.1, top to bottom (ids of ``codewire/graph-inc8.md``
#: ``LayoutMixin.compose``).
REGION_IDS = (
    "patch_identity_ribbon",
    "patch_filter_row",
    "patch_sheet_win",
    "patch_inspector",
    "patch_doc_file_row",
    "patch_doc_controls",
    "patch_legend",
)
STANDIN_DOCK_ID = "inc10_dock_standin"
STANDIN_DOCK_ROWS = 4


def tcss_colour(variable: str) -> str:
    """The hex of a ``$variable`` declared in ``styles.tcss``, lower case."""
    found = re.search(rf"^\${re.escape(variable)}:\s*(#[0-9a-fA-F]{{6}})", TCSS.read_text(encoding="utf-8"), re.M)
    assert found, f"${variable} is not declared in styles.tcss"
    return found.group(1).lower()


def need(root, selector: str, kind=None):
    """The one widget ``selector`` names, or a named assertion failure."""
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    widget = found[0]
    if kind is not None:
        assert isinstance(widget, kind), f"{selector}: expected {kind.__name__}, got {type(widget).__name__}"
    return widget


async def settle(pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


def build_defc(folder: Path) -> Path:
    """The definitions case (DEFC) through the shipped generator CLI; returns the folder."""
    result = subprocess.run(
        [sys.executable, str(SYNTH_TOOL), "--out", str(folder), "--seed", str(SEED), "--case", "definitions"],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, result.stderr
    return folder


def build_defc_variant(defc_dir: Path, out: Path, old: str, new: str) -> Path:
    """DEFC's A2L with the one occurrence of ``old`` replaced by ``new`` (a second payload)."""
    text = (defc_dir / "definitions.a2l").read_text(encoding="utf-8")
    assert text.count(old) == 1, f"{old!r} is not where the example expects it"
    out.write_text(text.replace(old, new), encoding="utf-8")
    return out


#: EX-R12: CM_DEF_LIN's factor 0.5 becomes 1.0 (DISPLAY_0001 raw 287 shows 143.5, then 287).
FACTOR_ONE = ("COEFFS_LINEAR 0.5 0", "COEFFS_LINEAR 1.0 0")
#: EX-R2: ENUM_0001's raw 1 changes its text.
ENUM_RENAMED = ('1 "IDLE"', '1 "SLEEPING"')


def build_many_names_a2l(path: Path, count: int) -> list[str]:
    """An A2L of ``count`` addressed UWORD measurements ``PNAME_0000`` ...; returns the names."""
    names = [f"PNAME_{i:04d}" for i in range(count)]
    lines = ["ASAP2_VERSION 1 71", '/begin PROJECT P ""', '  /begin MODULE M ""',
             '    /begin MOD_COMMON ""', "      BYTE_ORDER MSB_FIRST", "    /end MOD_COMMON"]
    for layout, datatype in BASE_LAYOUTS:
        lines += [f"    /begin RECORD_LAYOUT {layout}", f"      FNC_VALUES 1 {datatype} ROW_DIR DIRECT",
                  "    /end RECORD_LAYOUT"]
    for i, name in enumerate(names):
        lines.append(meas(name, "UWORD", addr=f"0x{0x1000 + 2 * i:X}"))
    lines += ["  /end MODULE", "/end PROJECT", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return names


def drive(tmp_path: Path, size, body, *, a2l: Path | None = None, image: Path | None = None, patch=None):
    """Open the Patch Editor at ``size`` (A2L / image preloaded through the app's own
    loaders) and return ``await body(app, pilot, panel)``.  ``patch`` is applied before
    the app starts (a stand-in registered by the test)."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            if a2l is not None:
                app.load_a2l_from_path(Path(a2l))
                await settle_workers(pilot)
                assert app._compute_a2l_enriched_tags(), f"the A2L did not load: {list(app.log_lines)[-3:]}"
            if image is not None:
                app.load_from_path(Path(image))
                for _ in range(100):
                    if app.current_file is not None:
                        break
                    await pilot.pause(0.05)
                assert app.current_file is not None, "the image did not load"
            app.action_show_screen("patch")
            await settle(pilot, 6)
            return await body(app, pilot, app.query_one("#patch_editor_panel"))

    if patch is not None:
        patch()
    return asyncio.run(_drive())


async def click_visible(pilot, selector: str) -> bool:
    """The operator's click: scroll the widget into view first (at 80×24 the panel scrolls, R-TUI-064.3;
    the 9-row landing pane scrolls its own tab content, R-PE-DEF.1.1), then click it. E4 integration:
    a bare ``pilot.click`` misses a widget that the layout places below the visible rows."""
    pilot.app.screen.query_one(selector).scroll_visible(animate=False)
    await settle(pilot)
    return await pilot.click(selector)


async def show_tab(pilot, chip_id: str) -> None:
    assert await click_visible(pilot, f"#{chip_id}"), f"click missed #{chip_id}"
    await settle(pilot)


def names_of(visible) -> list[str]:
    """The names of a picker page (entries are names or records with a ``name``)."""
    return [row["name"] if isinstance(row, dict) else str(row) for row in visible]


def body_rows(app) -> list[str]:
    """The text painted inside the sheet body, one string per terminal row."""
    return painted_rows(app, need(app.screen, "#patch_sheet_body"))


def row_of(app, name: str) -> str:
    """The painted sheet row that holds ``name`` (first match), or a named failure."""
    rows = [line for line in body_rows(app) if name in line]
    assert rows, f"{name} is not painted in the sheet body: {body_rows(app)}"
    return rows[0]


def selected_name(sheet) -> str:
    """The sheet's selected row's name (``selected_name`` is a method per I-8.4; a property is tolerated)."""
    value = sheet.selected_name
    return value() if callable(value) else value
