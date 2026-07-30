#!/usr/bin/env python
"""THROWAWAY in-APP prototype — P1 design-defect pass on the CRC Designer (2026-07-30).

Three variants mounted INSIDE the real S19TuiApp (sub-shape A): every shipped ``#crc_*``
id stays mounted so the real KAT / coverage / JSON / Load-Save handlers stay live. Each
variant fixes the switch-fusion defect (backlog 2026-07-28) by a DIFFERENT structure and
takes a different position on the KAT field (see p1_design_defects.NOTES.md §4):

  A — Guard rails:  shipped bench + separable switch rows (track tile, on/off word, gap).
  B — Paired reflection: one ``Reflection in/out`` row; KAT DEMOTED under Check.
  C — Vocabulary:   reflection as a Select (none/in/out/both); KAT hidden ("removed").

Run live:   python prototypes/crc_designer.p1.inapp_prototype.py A|B|C   (press 0 -> CRC)
Screenshot: python prototypes/crc_designer.p1.inapp_prototype.py shot
"""
from __future__ import annotations

import sys
from pathlib import Path

from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, Select, Static, Switch

from s19_app.tui import app as app_mod
from s19_app.tui.crc_designer_view import (
    PRESETS,
    SEED_ALGORITHM,
    _VECTOR_MODES,
    CrcDesignerPanel,
    _format_hex,
)
from s19_app.tui.models import LoadedFile
from s19_app.tui.operations.crc_designer_model import (
    ENDIANNESS_VALUES,
    INTRA_GAP_VALUES,
    JOIN_VALUES,
    ON_GAP_CONFLICT_VALUES,
)

# ---------------------------------------------------------------------------
# Variant A — "Guard rails": the surgical separability fix on the shipped bench.
# Only _switch_row changes: a visible track tile behind the slider, an on/off
# state word (G-2: state as word, not slider position alone), and a 1-row gap
# below each switch row (G-1: adjacent focusables never abut without a boundary).
# ---------------------------------------------------------------------------


class VariantA(CrcDesignerPanel):
    DEFAULT_CSS = """
    VariantA .proto-switch-row { margin-bottom: 1; }
    VariantA .crc-field-switch { border: none; height: 1; background: #1b233a; }
    VariantA .crc-field-switch:focus { background: #2b3a5e; }
    VariantA .proto-switch-state { color: #969aad; padding-left: 2; }
    /* polish: stop narrow Selects wrapping their value over 4-6 rows */
    VariantA Select { height: 3; }
    """

    def _switch_row(self, label: str, field_id: str, value: bool) -> Horizontal:  # type: ignore[override]
        return Horizontal(
            Label(label, classes="crc-field-label"),
            Switch(value=value, id=field_id, classes="crc-field-switch"),
            Static(
                "on" if value else "off",
                id=f"proto_{field_id}_state",
                classes="proto-switch-state",
                markup=False,
            ),
            classes="crc-field-row proto-switch-row",
        )

    def on_switch_changed(self, event: Switch.Changed) -> None:
        super().on_switch_changed(event)
        state = self.query_one(f"#proto_{event.switch.id}_state", Static)
        state.update("on" if event.value else "off")


# ---------------------------------------------------------------------------
# Variant B — "Paired reflection, demoted KAT": the two reflect switches are a
# semantic pair, so they share ONE row (adjacency killed horizontally by the
# interleaved labels); the KAT verdict is a property of the Check field, so it
# lives directly under it as a `Self-test` annotation row (id preserved), and
# the freed hero right column belongs to Warnings alone.
# ---------------------------------------------------------------------------


class VariantB(CrcDesignerPanel):
    DEFAULT_CSS = """
    VariantB .proto-pair-label { color: #969aad; padding: 0 1; }
    VariantB .crc-field-switch { border: none; height: 1; background: #1b233a; }
    VariantB .crc-field-switch:focus { background: #2b3a5e; }
    VariantB #crc_top_right { width: 1fr; height: auto; padding-left: 1; }
    VariantB Select { height: 3; }
    """

    def compose(self):
        algo = SEED_ALGORITHM
        byte_width = algo.store_bytes()
        yield Static(
            "CRC Designer (preview-only): pick a preset or edit the "
            "parameters; presets are read-only starting points.",
            id="crc_designer_help",
            markup=False,
        )
        algorithm_group = Vertical(
            Label("Algorithm", classes="crc-group-title"),
            Horizontal(
                Label("Preset", classes="crc-field-label"),
                Select(
                    [(preset.name, preset.name) for preset in PRESETS],
                    value=algo.name,
                    allow_blank=False,
                    id="crc_preset_select",
                ),
                classes="crc-field-row",
            ),
            self._text_row("Width (bits)", "crc_field_width", str(algo.width)),
            self._text_row(
                "Polynomial", "crc_field_poly", _format_hex(algo.poly, byte_width)
            ),
            self._text_row("Init", "crc_field_init", _format_hex(algo.init, byte_width)),
            # The pair: one row, labels interleaved between the two sliders.
            Horizontal(
                Label("Reflection", classes="crc-field-label"),
                Label("in", classes="proto-pair-label"),
                Switch(value=algo.refin, id="crc_field_refin", classes="crc-field-switch"),
                Label("out", classes="proto-pair-label"),
                Switch(value=algo.refout, id="crc_field_refout", classes="crc-field-switch"),
                classes="crc-field-row",
            ),
            self._text_row(
                "XOR out", "crc_field_xorout", _format_hex(algo.xorout, byte_width)
            ),
            self._text_row(
                "Check",
                "crc_field_check",
                "" if algo.check is None else _format_hex(algo.check, byte_width),
            ),
            # KAT demoted: the verdict annotates the Check field it validates.
            Horizontal(
                Label("Self-test", classes="crc-field-label"),
                Static("", id="crc_kat_verdict", markup=False, classes="crc-verdict"),
                classes="crc-field-row",
            ),
            id="crc_algorithm_fields",
            classes="crc-field-group",
        )
        serialization_group = Vertical(
            Label("Store placement", classes="crc-group-title"),
            self._text_row("Address", "crc_field_output_address", "0x00000000"),
            self._text_row(
                "Bytes", "crc_field_store_width", str(byte_width),
                placeholder="ceil(width/8)",
            ),
            self._select_row(
                "Store endianness", "crc_field_store_endianness", ENDIANNESS_VALUES
            ),
            id="crc_serialization_fields",
            classes="crc-field-group",
        )
        coverage_group = Vertical(
            Label("Coverage · preview-only", classes="crc-group-title"),
            self._text_row(
                "Ranges",
                "crc_coverage_ranges",
                "0x00008000-0x00008008, 0x00008010-0x00008018",
                placeholder="start-end, start-end, …",
            ),
            self._select_row("Intra gap", "crc_coverage_intra_gap", INTRA_GAP_VALUES),
            self._select_row("Join gaps", "crc_coverage_join", JOIN_VALUES),
            self._text_row("Pad byte", "crc_coverage_pad_byte", "0xFF"),
            self._select_row(
                "On conflict", "crc_coverage_on_gap_conflict", ON_GAP_CONFLICT_VALUES
            ),
            Static("", id="crc_coverage_preview", markup=False, classes="crc-verdict"),
            id="crc_coverage_group",
            classes="crc-field-group",
        )
        custom_vector_group = Vertical(
            Label("Custom test vector", classes="crc-group-title"),
            self._select_row("Mode", "crc_custom_vector_mode", _VECTOR_MODES),
            self._text_row("Vector", "crc_custom_vector", "123456789"),
            Horizontal(
                Label("CRC", classes="crc-field-label"),
                Static(
                    "",
                    id="crc_custom_vector_result",
                    markup=False,
                    classes="crc-verdict",
                ),
                classes="crc-field-row",
            ),
            id="crc_custom_vector_group",
            classes="crc-field-group",
        )
        json_preview_group = Vertical(
            Label(
                "Template JSON · round-trips through parse_template",
                classes="crc-group-title",
            ),
            Static("", id="crc_json_preview", markup=False, classes="crc-json-preview"),
            id="crc_json_preview_group",
            classes="crc-field-group",
        )
        template_group = Vertical(
            Label("Template", classes="crc-group-title"),
            self._text_row("Name", "crc_field_name", algo.name),
            self._text_row(
                "Aliases", "crc_field_aliases", "", placeholder="comma-separated"
            ),
            id="crc_template_fields",
            classes="crc-field-group",
        )
        loadsave_group = Vertical(
            Label("Load / Save", classes="crc-group-title"),
            self._text_row(
                "Load path", "crc_load_path", "",
                placeholder="path/to/name.crc.json",
            ),
            Horizontal(
                Button("Save", id="crc_save_btn"),
                Button("Load", id="crc_load_btn"),
                classes="crc-field-row",
            ),
            Static("", id="crc_loadsave_status", markup=False, classes="crc-status"),
            id="crc_loadsave_group",
            classes="crc-field-group",
        )
        warnings_group = Vertical(
            Label("Warnings", classes="crc-group-title"),
            Static("", id="crc_warnings", markup=False, classes="crc-warnings"),
            id="crc_warnings_group",
            classes="crc-field-group",
        )
        # Hero row: coverage window (2fr) beside Warnings ALONE (1fr) — the
        # verdict tile is gone, demoted into the Algorithm group above.
        yield Horizontal(
            Static("", id="crc_coverage_window", markup=False),
            Vertical(warnings_group, id="crc_top_right"),
            id="crc_hero_row",
        )
        yield Horizontal(
            Vertical(algorithm_group, id="crc_bench_c1"),
            Vertical(coverage_group, serialization_group, id="crc_bench_c2"),
            Vertical(custom_vector_group, template_group, loadsave_group, id="crc_bench_c3"),
            id="crc_bench",
        )
        yield json_preview_group


# ---------------------------------------------------------------------------
# Variant C — "Vocabulary + diagnostics strip": reflection collapses to ONE
# Select (none/in/out/both — 4 combos, 1 control, 0 visible switches; the real
# Switch widgets stay mounted hidden and are synced from the Select so
# _current_algorithm keeps reading them). The KAT verdict is hidden — the
# "remove" position — with a dim note pointing at the save-time KAT warning
# _save_template already emits. Warnings become a full-width strip under the
# hero (no right column: the coverage window owns the whole hero row).
# ---------------------------------------------------------------------------

_REFLECTION_VOCAB: tuple[str, ...] = ("none", "in", "out", "both")
_REFLECTION_VALUES: dict[str, tuple[bool, bool]] = {
    "none": (False, False),
    "in": (True, False),
    "out": (False, True),
    "both": (True, True),
}


def _reflection_token(refin: bool, refout: bool) -> str:
    for token, pair in _REFLECTION_VALUES.items():
        if pair == (refin, refout):
            return token
    return "none"


class VariantC(CrcDesignerPanel):
    DEFAULT_CSS = """
    VariantC #proto_hidden { display: none; }
    VariantC #crc_coverage_window { width: 100%; }
    VariantC #proto_diag_strip { height: auto; margin-bottom: 1; }
    VariantC #proto_diag_strip #crc_warnings_group { width: 2fr; margin-bottom: 0; }
    VariantC .proto-removed-note { width: 1fr; color: #969aad; padding: 1 2; }
    VariantC Select { height: 3; }
    """

    def compose(self):
        algo = SEED_ALGORITHM
        byte_width = algo.store_bytes()
        yield Static(
            "CRC Designer (preview-only): pick a preset or edit the "
            "parameters; presets are read-only starting points.",
            id="crc_designer_help",
            markup=False,
        )
        algorithm_group = Vertical(
            Label("Algorithm", classes="crc-group-title"),
            Horizontal(
                Label("Preset", classes="crc-field-label"),
                Select(
                    [(preset.name, preset.name) for preset in PRESETS],
                    value=algo.name,
                    allow_blank=False,
                    id="crc_preset_select",
                ),
                classes="crc-field-row",
            ),
            self._text_row("Width (bits)", "crc_field_width", str(algo.width)),
            self._text_row(
                "Polynomial", "crc_field_poly", _format_hex(algo.poly, byte_width)
            ),
            self._text_row("Init", "crc_field_init", _format_hex(algo.init, byte_width)),
            # Reflection as vocabulary: one Select, four combos.
            self._select_row_value(
                "Reflection", "proto_reflection", _REFLECTION_VOCAB,
                _reflection_token(algo.refin, algo.refout),
            ),
            self._text_row(
                "XOR out", "crc_field_xorout", _format_hex(algo.xorout, byte_width)
            ),
            self._text_row(
                "Check",
                "crc_field_check",
                "" if algo.check is None else _format_hex(algo.check, byte_width),
            ),
            id="crc_algorithm_fields",
            classes="crc-field-group",
        )
        serialization_group = Vertical(
            Label("Store placement", classes="crc-group-title"),
            self._text_row("Address", "crc_field_output_address", "0x00000000"),
            self._text_row(
                "Bytes", "crc_field_store_width", str(byte_width),
                placeholder="ceil(width/8)",
            ),
            self._select_row(
                "Store endianness", "crc_field_store_endianness", ENDIANNESS_VALUES
            ),
            id="crc_serialization_fields",
            classes="crc-field-group",
        )
        coverage_group = Vertical(
            Label("Coverage · preview-only", classes="crc-group-title"),
            self._text_row(
                "Ranges",
                "crc_coverage_ranges",
                "0x00008000-0x00008008, 0x00008010-0x00008018",
                placeholder="start-end, start-end, …",
            ),
            self._select_row("Intra gap", "crc_coverage_intra_gap", INTRA_GAP_VALUES),
            self._select_row("Join gaps", "crc_coverage_join", JOIN_VALUES),
            self._text_row("Pad byte", "crc_coverage_pad_byte", "0xFF"),
            self._select_row(
                "On conflict", "crc_coverage_on_gap_conflict", ON_GAP_CONFLICT_VALUES
            ),
            Static("", id="crc_coverage_preview", markup=False, classes="crc-verdict"),
            id="crc_coverage_group",
            classes="crc-field-group",
        )
        custom_vector_group = Vertical(
            Label("Custom test vector", classes="crc-group-title"),
            self._select_row("Mode", "crc_custom_vector_mode", _VECTOR_MODES),
            self._text_row("Vector", "crc_custom_vector", "123456789"),
            Horizontal(
                Label("CRC", classes="crc-field-label"),
                Static(
                    "",
                    id="crc_custom_vector_result",
                    markup=False,
                    classes="crc-verdict",
                ),
                classes="crc-field-row",
            ),
            id="crc_custom_vector_group",
            classes="crc-field-group",
        )
        json_preview_group = Vertical(
            Label(
                "Template JSON · round-trips through parse_template",
                classes="crc-group-title",
            ),
            Static("", id="crc_json_preview", markup=False, classes="crc-json-preview"),
            id="crc_json_preview_group",
            classes="crc-field-group",
        )
        template_group = Vertical(
            Label("Template", classes="crc-group-title"),
            self._text_row("Name", "crc_field_name", algo.name),
            self._text_row(
                "Aliases", "crc_field_aliases", "", placeholder="comma-separated"
            ),
            id="crc_template_fields",
            classes="crc-field-group",
        )
        loadsave_group = Vertical(
            Label("Load / Save", classes="crc-group-title"),
            self._text_row(
                "Load path", "crc_load_path", "",
                placeholder="path/to/name.crc.json",
            ),
            Horizontal(
                Button("Save", id="crc_save_btn"),
                Button("Load", id="crc_load_btn"),
                classes="crc-field-row",
            ),
            Static("", id="crc_loadsave_status", markup=False, classes="crc-status"),
            id="crc_loadsave_group",
            classes="crc-field-group",
        )
        warnings_group = Vertical(
            Label("Warnings", classes="crc-group-title"),
            Static("", id="crc_warnings", markup=False, classes="crc-warnings"),
            id="crc_warnings_group",
            classes="crc-field-group",
        )
        # Hidden but MOUNTED: _recompute queries all six surface ids and the
        # algorithm reader queries both switches — a real removal batch must
        # edit _recompute; a prototype must not fork it (NOTES §2).
        yield Horizontal(
            Switch(value=algo.refin, id="crc_field_refin"),
            Switch(value=algo.refout, id="crc_field_refout"),
            Static("", id="crc_kat_verdict", markup=False),
            id="proto_hidden",
        )
        # Hero row: the coverage window owns the full width.
        yield Horizontal(
            Static("", id="crc_coverage_window", markup=False),
            id="crc_hero_row",
        )
        # Diagnostics strip: warnings + the "removed" note, full width.
        yield Horizontal(
            warnings_group,
            Static(
                "Self-test removed — the 123456789 known-answer is validated "
                "on Save (a mismatch warns in the status line).",
                classes="proto-removed-note",
                markup=False,
            ),
            id="proto_diag_strip",
        )
        yield Horizontal(
            Vertical(algorithm_group, id="crc_bench_c1"),
            Vertical(coverage_group, serialization_group, id="crc_bench_c2"),
            Vertical(custom_vector_group, template_group, loadsave_group, id="crc_bench_c3"),
            id="crc_bench",
        )
        yield json_preview_group

    @staticmethod
    def _select_row_value(
        label: str, field_id: str, values: tuple[str, ...], value: str
    ) -> Horizontal:
        return Horizontal(
            Label(label, classes="crc-field-label"),
            Select(
                [(v, v) for v in values],
                value=value,
                allow_blank=False,
                id=field_id,
            ),
            classes="crc-field-row",
        )

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "proto_reflection":
            token = str(event.value)
            refin, refout = _REFLECTION_VALUES.get(token, (False, False))
            self.query_one("#crc_field_refin", Switch).value = refin
            self.query_one("#crc_field_refout", Switch).value = refout
            self._recompute()
            return
        super().on_select_changed(event)


_VARIANTS: dict[str, type[CrcDesignerPanel]] = {
    "A": VariantA,
    "B": VariantB,
    "C": VariantC,
}


#: The widget the "bench" frame scrolls to — the variant's reflection control
#: (C's real switches are hidden; its visible control is the Select).
_SCROLL_TARGET: dict[str, str] = {
    "A": "#crc_field_refout",
    "B": "#crc_field_refout",
    "C": "#proto_reflection",
}


def _fixture() -> LoadedFile:
    mem = {0x8000 + i: i for i in range(8)}
    mem.update({0x8010 + i: 0x10 + i for i in range(8)})
    return LoadedFile(
        path=Path("firmware_v2.s19"), file_type="s19", mem_map=mem,
        row_bases=[], ranges=[], range_validity=[], errors=[],
        a2l_path=None, a2l_data=None,
    )


def _shot() -> None:
    import asyncio

    here = Path(__file__).resolve().parent

    async def run(variant: str) -> None:
        app_mod.CrcDesignerPanel = _VARIANTS[variant]

        # 120x30 pass: empty -> loaded -> bench (scrolled to the switches; the
        # separability frame) -> invalid, one run.
        app = app_mod.S19TuiApp()
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause(); await pilot.pause()
            app.save_screenshot(str(here / f"crc_p1.variant_{variant}.120x30.empty.svg"))
            app.current_file = _fixture()
            app.query_one(_VARIANTS[variant])._recompute()
            await pilot.pause()
            app.save_screenshot(str(here / f"crc_p1.variant_{variant}.120x30.loaded.svg"))
            app.query_one(_SCROLL_TARGET[variant]).scroll_visible(animate=False)
            await pilot.pause(); await pilot.pause()
            app.save_screenshot(str(here / f"crc_p1.variant_{variant}.120x30.bench.svg"))
            app.query_one("#crc_field_width", Input).value = "999"
            await pilot.pause(); await pilot.pause()
            app.save_screenshot(str(here / f"crc_p1.variant_{variant}.120x30.invalid.svg"))

        # 80x24 floor pass: loaded, top + bench scroll.
        app = app_mod.S19TuiApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.current_file = _fixture()
            await pilot.press("0")
            await pilot.pause(); await pilot.pause()
            app.query_one(_VARIANTS[variant])._recompute()
            await pilot.pause()
            app.save_screenshot(str(here / f"crc_p1.variant_{variant}.80x24.loaded.svg"))
            app.query_one(_SCROLL_TARGET[variant]).scroll_visible(animate=False)
            await pilot.pause(); await pilot.pause()
            app.save_screenshot(str(here / f"crc_p1.variant_{variant}.80x24.bench.svg"))

        # 160x44 high-density pass: hero + full bench in ONE frame (no fold).
        app = app_mod.S19TuiApp()
        async with app.run_test(size=(160, 44)) as pilot:
            await pilot.pause()
            app.current_file = _fixture()
            await pilot.press("0")
            await pilot.pause(); await pilot.pause()
            app.query_one(_VARIANTS[variant])._recompute()
            await pilot.pause()
            app.save_screenshot(str(here / f"crc_p1.variant_{variant}.160x44.loaded.svg"))

    for variant in _VARIANTS:
        asyncio.run(run(variant))
        print(f"variant {variant}: wrote 6 SVGs")


if __name__ == "__main__":
    arg = sys.argv[1].upper() if len(sys.argv) > 1 else "A"
    if arg == "SHOT":
        _shot()
    else:
        app_mod.CrcDesignerPanel = _VARIANTS.get(arg, VariantA)
        app_mod.S19TuiApp().run()
