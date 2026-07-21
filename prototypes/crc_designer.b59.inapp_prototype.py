#!/usr/bin/env python
"""THROWAWAY in-APP prototype — batch-59 CRC Designer bench, mounted INSIDE the real
S19TuiApp so it inherits the real chrome, rail, footer, theme and styles.tcss.

Reuses the shipped CrcDesignerPanel widgets VERBATIM (same #crc_* ids → the real KAT /
coverage / JSON / Load-Save handlers stay live); only the LAYOUT is re-composed into a
two-column bench with a wide rendered coverage window on top (the honest terminal hero).

Run live:   python prototypes/crc_designer.b59.inapp_prototype.py     (press 0 → CRC)
Screenshot: python prototypes/crc_designer.b59.inapp_prototype.py shot
"""
from __future__ import annotations
import sys
from pathlib import Path

from rich.text import Text
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Label, Select, Static

from s19_app.tui import app as app_mod
from s19_app.tui.crc_designer_view import (
    CrcDesignerPanel, PRESETS, SEED_ALGORITHM, _VECTOR_MODES, _format_hex,
)
from s19_app.tui.operations.crc_designer_model import (
    ENDIANNESS_VALUES, INTRA_GAP_VALUES, JOIN_VALUES, ON_GAP_CONFLICT_VALUES,
)
from s19_app.tui.models import LoadedFile

AC, OKC, WA, GP = "#91abec", "#8ff6a0", "#f6ff8f", "#495259"


def _coverage_window() -> Text:
    """SIGNATURE — the multi-range coverage window in real block glyphs."""
    t = Text()
    t.append("  window  ", style=GP)
    t.append("█" * 16, style=AC); t.append("░" * 8, style=GP); t.append("█" * 16, style=AC)
    t.append("   0x8000‥0x8008  gap  0x8010‥0x8018\n", style=GP)
    t.append("  fill    ", style=GP)
    t.append("█" * 16, style=AC); t.append("█" * 8, style=WA); t.append("█" * 16, style=AC)
    t.append("   pad 0xFF over the gap  ← active\n", style=WA)
    t.append("  concat→16B ", style=GP); t.append("0x9C5BCBBD", style=AC)
    t.append("    fill→24B ", style=GP); t.append("0x2A8A3950", style=WA)
    t.append("    store_word ", style=GP); t.append("50 39 8A 2A", style=AC)
    return t


class BenchCrcPanel(CrcDesignerPanel):
    """Same widgets, re-composed as a two-column bench inside the real app."""

    DEFAULT_CSS = """
    BenchCrcPanel { padding: 1 1; }
    BenchCrcPanel #crc_designer_help { color: #7f8ba3; margin-bottom: 1; }
    BenchCrcPanel #crc_bench { height: auto; }
    BenchCrcPanel #crc_bench_c1 { width: 1fr; height: auto; padding-right: 1; }
    BenchCrcPanel #crc_bench_c2 { width: 1fr; height: auto; padding: 0 1; }
    BenchCrcPanel #crc_bench_c3 { width: 1fr; height: auto; padding-left: 1; }
    BenchCrcPanel .crc-field-group {
        border: round #2b3a5e; background: #161d31; padding: 0 1; margin-bottom: 1;
    }
    BenchCrcPanel .crc-group-title { color: #91abec; text-style: bold; }
    BenchCrcPanel #crc_hero_row { height: auto; margin-bottom: 1; }
    BenchCrcPanel #crc_coverage_window {
        width: 2fr; height: auto; padding: 1 2;
        border: round #91abec; background: #141b2e; color: #c5c8c6;
    }
    BenchCrcPanel #crc_top_right { width: 1fr; height: auto; padding-left: 1; }
    BenchCrcPanel #crc_live_verify {
        height: 5; border: round #8ff6a0; background: #10201a;
    }
    BenchCrcPanel #crc_warnings_group { height: 4; }
    BenchCrcPanel #crc_json_preview_group { min-height: 11; }
    BenchCrcPanel #crc_json_preview { min-height: 8; }
    """

    def _sel_row(self, label, sel_id, values):
        return Horizontal(
            Label(label, classes="crc-field-label"),
            Select([(v, v) for v in values], value=values[0], allow_blank=False, id=sel_id),
            classes="crc-field-row",
        )

    def compose(self):
        algo = SEED_ALGORITHM
        bw = algo.store_bytes()
        yield Static("CRC Designer — job (preview-only): pick a preset or edit; presets are read-only.",
                     id="crc_designer_help", markup=False)
        yield Horizontal(
            Label("algorithm_ref", classes="crc-field-label"),
            Select([(p.name, p.name) for p in PRESETS], value=algo.name,
                   allow_blank=False, id="crc_preset_select"),
            classes="crc-field-row",
        )
        # ---- left column: algorithm + coverage controls + serialization ----
        algo_grp = Vertical(
            Label("Algorithm", classes="crc-group-title"),
            self._text_row("Width (bits)", "crc_field_width", str(algo.width)),
            self._text_row("Polynomial", "crc_field_poly", _format_hex(algo.poly, bw)),
            self._text_row("Init", "crc_field_init", _format_hex(algo.init, bw)),
            self._switch_row("Reflect in", "crc_field_refin", algo.refin),
            self._switch_row("Reflect out", "crc_field_refout", algo.refout),
            self._text_row("XOR out", "crc_field_xorout", _format_hex(algo.xorout, bw)),
            self._text_row("Check", "crc_field_check",
                           "" if algo.check is None else _format_hex(algo.check, bw)),
            id="crc_algorithm_fields", classes="crc-field-group",
        )
        cov_grp = Vertical(
            Label("Coverage (preview-only)", classes="crc-group-title"),
            self._text_row("Ranges (start-end, comma-separated)", "crc_coverage_ranges",
                           "0x00008000-0x00008008, 0x00008010-0x00008018"),
            self._sel_row("Intra-range gap", "crc_coverage_intra_gap", INTRA_GAP_VALUES),
            self._sel_row("Join (between ranges)", "crc_coverage_join", JOIN_VALUES),
            self._text_row("Pad byte", "crc_coverage_pad_byte", "0xFF"),
            self._sel_row("On gap conflict", "crc_coverage_on_gap_conflict", ON_GAP_CONFLICT_VALUES),
            Static("", id="crc_coverage_preview", markup=False, classes="crc-verdict"),
            id="crc_coverage_group", classes="crc-field-group",
        )
        serial_grp = Vertical(
            Label("Serialization", classes="crc-group-title"),
            self._text_row("Output address", "crc_field_output_address", "0x00000000"),
            self._text_row("Store width (bytes)", "crc_field_store_width", str(bw)),
            self._sel_row("Store endianness", "crc_field_store_endianness", ENDIANNESS_VALUES),
            id="crc_serialization_fields", classes="crc-field-group",
        )

        # ---- right column: hero verdict + vector + json + warnings + template + load/save ----
        verify_grp = Vertical(
            Label("Known-answer verdict (123456789)", classes="crc-group-title"),
            Static("", id="crc_kat_verdict", markup=False, classes="crc-verdict"),
            id="crc_live_verify", classes="crc-field-group",
        )
        vector_grp = Vertical(
            Label("Custom test vector", classes="crc-group-title"),
            self._sel_row("Mode", "crc_custom_vector_mode", _VECTOR_MODES),
            self._text_row("Vector", "crc_custom_vector", "123456789"),
            Horizontal(Label("CRC of vector", classes="crc-field-label"),
                       Static("", id="crc_custom_vector_result", markup=False, classes="crc-verdict"),
                       classes="crc-field-row"),
            id="crc_custom_vector_group", classes="crc-field-group",
        )
        json_grp = Vertical(
            Label("Job JSON preview", classes="crc-group-title"),
            Static("", id="crc_json_preview", markup=False, classes="crc-json-preview"),
            id="crc_json_preview_group", classes="crc-field-group",
        )
        warn_grp = Vertical(
            Label("Warnings", classes="crc-group-title"),
            Static("", id="crc_warnings", markup=False, classes="crc-warnings"),
            id="crc_warnings_group", classes="crc-field-group",
        )
        template_grp = Vertical(
            Label("Template", classes="crc-group-title"),
            self._text_row("Name", "crc_field_name", algo.name),
            self._text_row("Aliases (comma-separated)", "crc_field_aliases", ""),
            id="crc_template_fields", classes="crc-field-group",
        )
        loadsave_grp = Vertical(
            Label("Load / Save", classes="crc-group-title"),
            self._text_row("Template path (load)", "crc_load_path", ""),
            Horizontal(Button("Save template", id="crc_save_btn"),
                       Button("Load template", id="crc_load_btn"), classes="crc-field-row"),
            Static("", id="crc_loadsave_status", markup=False, classes="crc-status"),
            id="crc_loadsave_group", classes="crc-field-group",
        )

        # Variant B — coverage-first. Hero ROW: the wide coverage window + the
        # verdict and warnings tiles at the SAME top level.
        yield Horizontal(
            Static(_coverage_window(), id="crc_coverage_window", markup=False),
            Vertical(verify_grp, warn_grp, id="crc_top_right"),
            id="crc_hero_row",
        )
        # params in a 3-column grid below; JSON gets its own roomy column.
        yield Horizontal(
            Vertical(algo_grp, serial_grp, id="crc_bench_c1"),
            Vertical(cov_grp, vector_grp, id="crc_bench_c2"),
            Vertical(json_grp, template_grp, loadsave_grp, id="crc_bench_c3"),
            id="crc_bench",
        )


app_mod.CrcDesignerPanel = BenchCrcPanel  # patch so the real screen mounts the bench


def _fixture():
    mem = {0x8000 + i: i for i in range(8)}
    mem.update({0x8010 + i: 0x10 + i for i in range(8)})
    return LoadedFile(path=Path("firmware_v2.s19"), file_type="s19", mem_map=mem,
                      row_bases=[], ranges=[], range_validity=[], errors=[],
                      a2l_path=None, a2l_data=None)


def _shot():
    import asyncio
    here = Path(__file__).resolve().parent

    async def run():
        app = app_mod.S19TuiApp()
        async with app.run_test(size=(150, 55)) as pilot:
            await pilot.pause()
            app.current_file = _fixture()
            await pilot.press("0")
            await pilot.pause(); await pilot.pause()
            app.save_screenshot(str(here / "b59_inapp.svg"))
    asyncio.run(run())
    print("wrote b59_inapp.svg")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "shot":
        _shot()
    else:
        app_mod.S19TuiApp().run()
