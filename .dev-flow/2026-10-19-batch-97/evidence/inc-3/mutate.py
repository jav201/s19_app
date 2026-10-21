"""Inc-3 mutation battery (the Inc-1/Inc-2 runner, one edit per mutant).

One edit per mutant, one node per run, restore proven by SHA-256 after every arm.
Anchors are written with ``\\n`` and matched in the file's own line endings.
Run from the repo root: python .dev-flow/2026-10-19-batch-97/evidence/inc-3/mutate.py [M1 M2 ...]

Gate fold (2026-10-21): M24 is retargeted to the status-line node (code-reviewer
F5); M29 / M30 name the ``[size0]`` id of their now-parametrized nodes; M31-M46
are the fold's new arms. ``mutations-fold.txt`` is the run of M24, M29-M46.
"""
import hashlib
import os
import pathlib
import subprocess
import sys

SDB = pathlib.Path("s19_app/tui/screens_directionb.py")
APP = pathlib.Path("s19_app/tui/app.py")
CSS = pathlib.Path("s19_app/tui/styles.tcss")
WH = pathlib.Path("s19_app/tui/window_help.py")
PROBES = pathlib.Path("tests/b97_probes.py")
TCE = pathlib.Path("tests/test_b97_check_editor.py")
C = "tests/test_b97_check_editor.py::"
W = "tests/test_b97_width.py::"
H = "tests/test_b97_chips_help.py::"

MUTANTS = [
    ("M1-head-keeping-clip", SDB,
     'return first + "…" + _tail_cells(name, width - cell_len(first) - 1)',
     'return set_cell_size(name, width - 1) + "…"',
     [C + "test_tc_b97_10_layout_and_clip_units",
      C + "test_tc_b97_10_painted_names_distinct_and_full_name_line[size0]",
      W + "test_tc_b97_37_no_wrapped_row_and_tail_kept_clips[size0]",
      C + "test_at_b97_04_engineer_reads_every_address_and_includes_one[size0]"]),
    ("M2-tail-only-clip", SDB,
     'return first + "…" + _tail_cells(name, width - cell_len(first) - 1)',
     'return "…" + _tail_cells(name, width - 1)',
     [C + "test_tc_b97_10_layout_and_clip_units",
      C + "test_tc_b97_10_painted_names_distinct_and_full_name_line[size0]"]),
    ("M3-param-floor-40", SDB, "usable - 19 - 42))", "usable - 19 - 40))",
     [C + "test_tc_b97_10_layout_and_clip_units",
      C + "test_tc_b97_10_painted_names_distinct_and_full_name_line[size0]"]),
    ("M4-vacuous-repaint", SDB,
     "            table.update_cell(name, keys[1], cells[1], update_width=(index == 0))\n"
     "            table.update_cell(name, keys[3], cells[3])",
     "            table.refresh(layout=True)",
     [W + "test_tc_b97_34_painted_widths_follow_four_resizes",
      W + "test_tc_b97_34_resize_while_hidden_rederives_on_show"]),
    ("M5-no-show-trigger", SDB,
     "    def on_show(self, event: events.Show) -> None:\n        self.call_after_refresh(self._apply_layout)",
     "    def on_show(self, event: events.Show) -> None:\n        pass",
     [W + "test_tc_b97_34_resize_while_hidden_rederives_on_show"]),
    ("M6-card-from-unfiltered", SDB, "        for name in self._picked_params:\n            address, size, _fmt",
     "        for name in self._param_rows:\n            address, size, _fmt",
     [C + "test_tc_b97_43_fields_hold_exactly_the_included"]),
    ("M7-ledger-from-markup", SDB,
     "safe_text(clip_param(plain, layout.param), VALUE),",
     "Text.from_markup(clip_param(name, layout.param)),",
     [C + "test_tc_b97_12_hostile_names_render_literally",
      C + "test_at_b97_05_hostile_parameter_reads_literally"]),
    ("M8-second-primary", SDB,
     '"Validate", id="check_validate_button", classes="patch-chip"',
     '"Validate", id="check_validate_button", classes="patch-chip fill-accent"',
     [C + "test_tc_b97_46_one_filled_element"]),
    ("M9-tabchip-no-space", SDB, 'BINDINGS = [Binding("space", "press", "Press", show=False)]',
     "BINDINGS = []",
     [C + "test_tc_b97_08_tab_chips_nine_activations"]),
    ("M10-ledger-no-space", SDB, '        Binding("space", "toggle_include", "Include", show=False),\n', "",
     [C + "test_tc_b97_45_keyboard_order_enter_space_and_chip_states",
      C + "test_at_b97_18_first_task_from_the_keyboard"]),
    ("M11-tabchip-cannot-focus", SDB,
     'BINDINGS = [Binding("space", "press", "Press", show=False)]',
     'BINDINGS = [Binding("space", "press", "Press", show=False)]\n    can_focus = False',
     [C + "test_tc_b97_45_keyboard_order_enter_space_and_chip_states"]),
    ("M12-toggle-displayed", SDB, "toggle.display = False", "toggle.display = True",
     [C + "test_tc_b97_61_every_control_displayed_in_its_home[size0]"]),
    ("M13-test-control-dropped-from-table", TCE,
     '"check_mem_size_input", "check_mem_add_button", "check_mem_remove_button"),\n        ("check_fields_lines"',
     '"check_mem_size_input", "check_mem_add_button"),\n        ("check_fields_lines"',
     [C + "test_tc_b97_61_every_control_displayed_in_its_home[size0]"]),
    ("M14-chip-without-suffix", APP, 'OpenFolderChip("checks", id_suffix="editor")', 'OpenFolderChip("checks")',
     [H + "test_tc_b97_30_check_editor_chip_unique_and_opens_checks_home"]),
    ("M15-help-without-effect", WH, '"Filter — narrows the A2L', '"Filter narrows the A2L',
     [H + "test_tc_b97_32_check_editor_help_names_every_label"]),
    ("M16-glyph-outside-vocabulary", SDB, 'Text("✓", style=GREEN) if picked else Text(" ")',
     'Text("✔", style=GREEN) if picked else Text(" ")',
     [H + "test_tc_b97_33_check_glyphs_closed_and_in_the_legend"]),
    ("M17-write-refusal-not-painted", APP,
     "                panel.show_status_line(\n                    f\"Write refused: {codes or 'not written'}.\"\n                )",
     "                pass",
     [H + "test_tc_b97_58_check_editor_region_states[write_dir]",
      H + "test_tc_b97_58_check_editor_region_states[write_readonly]"]),
    ("M18-no-ledger-empty-line", SDB,
     '_EMPTY_LEDGER = "No A2L parameters — load an A2L (^L) to list them."', '_EMPTY_LEDGER = ""',
     [H + "test_tc_b97_58_check_editor_region_states[no_a2l]",
      C + "test_at_b97_04_empty_ledger_line_and_dock_inside[size0]"]),
    ("M19-no-fields-empty-line", SDB, '_EMPTY_FIELDS = "No fields included yet."', '_EMPTY_FIELDS = ""',
     [H + "test_tc_b97_58_check_editor_region_states[nothing_included]"]),
    ("M20-spec-row-margin", CSS, "#check_spec_file_select {\n    width: 30;",
     "#check_spec_file_row {\n    margin-top: 1;\n}\n\n#check_spec_file_select {\n    width: 30;",
     [W + "test_tc_b97_38_no_blank_row_outside_the_ledger[size0]",
      W + "test_tc_b97_38_no_blank_row_outside_the_ledger[size1]"]),
    ("M21-columns-fixed-past-panel", CSS, "#check_columns {\n    height: 1fr;",
     "#check_columns {\n    height: 60;",
     [W + "test_tc_b97_36_validate_and_write_inside_at_scroll_zero[size0]",
      W + "test_tc_b97_36_validate_and_write_inside_at_scroll_zero[size1]"]),
    ("M22-panel-overflow-hidden", CSS, "    padding: 0;\n    overflow-x: hidden;\n    overflow-y: auto;",
     "    padding: 0;\n    overflow-x: hidden;\n    overflow-y: hidden;",
     [W + "test_tc_b97_59_below_the_range_actions_reachable[size0]"]),
    ("M23-fields-name-too-wide", SDB, "max(8, card_w - 14)", "max(8, card_w - 4)",
     [C + "test_tc_b97_10_painted_names_distinct_and_full_name_line[size0]"]),
    ("M24-nowrap-css-removed", CSS,
     "#check_editor_panel .ce-hint {\n    text-wrap: nowrap;", "#check_editor_panel .ce-hint {\n    text-wrap: wrap;",
     [W + "test_tc_b97_37_status_line_stays_one_row_with_a_long_typed_address[size0]"]),
    ("M25-predicate-region-not-clipped", PROBES,
     "                region = region.intersection(node.content_region)", "                pass",
     [W + "test_tc_b97_35_predicate_self_check"]),
    ("M26-address-pushed-out", SDB, "zip(columns, (1, layout.param, 10, layout.fmt))",
     "zip(columns, (1, layout.param + 25, 10, layout.fmt))",
     [C + "test_tc_b97_09_address_column_never_truncated[size0]"]),
    ("M27-json-cap-removed", SDB, "    if len(lines) <= cap:\n        return text", "    if True:\n        return text",
     [C + "test_tc_b97_43_empty_state_and_json_cap"]),
    ("M28-dock-two-rows", CSS, "#check_legend {\n    height: 1;",
     "#check_dock {\n    layout: vertical;\n    height: 3;\n}\n\n#check_legend {\n    height: 1;",
     [C + "test_tc_b97_08_census_rows_and_one_docked_row[size0]"]),
    ("M29-size-label-fmt", SDB, 'yield Label("Size (bytes)", classes="ce-label")',
     'yield Label("Fmt", classes="ce-label")',
     [C + "test_tc_b97_44_memory_inputs_labelled_inside_the_fields_tab[size0]",
      H + "test_tc_b97_32_check_editor_help_names_every_label"]),
    ("M30-buttons-three-rows", CSS, "#check_editor_panel Button {\n    width: auto;\n    height: 1;",
     "#check_editor_panel Button {\n    width: auto;\n    height: 3;",
     [C + "test_tc_b97_11_every_button_is_a_one_row_chip[size0]"]),
    # ---- Inc-3 gate fold (2026-10-21) ----
    ("M31-glyph-back-to-ballot", SDB, '    "◆": "parameter field",', '    "☑": "parameter field",',
     [H + "test_tc_b97_33_check_glyphs_are_narrow_in_windows_terminal",
      H + "test_tc_b97_33_check_glyphs_closed_and_in_the_legend"]),
    ("M32-full-name-name-first", SDB,
     "        text.append(safe_text(clip_param(safe_text(name).plain, room), VALUE))\n        line.update(text)",
     "        text = safe_text(safe_text(name).plain, VALUE) + Text(\"  \") + text\n        line.update(text)",
     [C + "test_tc_b97_10_full_name_line_keeps_address_and_name_tail",
      C + "test_tc_b97_10_parameter_floor_at_the_wide_breakpoint[size1]"]),
    ("M33-full-name-head-clip", SDB,
     "        text.append(safe_text(clip_param(safe_text(name).plain, room), VALUE))",
     "        text.append(safe_text(_clip_to_cells(safe_text(name).plain, room), VALUE))",
     [C + "test_tc_b97_10_full_name_line_keeps_address_and_name_tail"]),
    ("M34-full-name-not-recomposed", SDB,
     "        self._rebuild_memory_table()\n        self._refresh_full_name()\n        self._refresh_preview()\n\n    def on_resize",
     "        self._rebuild_memory_table()\n        self._refresh_preview()\n\n    def on_resize",
     [C + "test_tc_b97_10_full_name_line_keeps_address_and_name_tail"]),
    ("M35-form-spacers-removed", CSS, "#check_pane_fields .ce-title,\n#check_status {\n    margin-top: 1;",
     "#check_pane_fields .ce-title,\n#check_status {\n    margin-top: 0;",
     [C + "test_tc_b97_44_memory_inputs_labelled_inside_the_fields_tab[size0]",
      C + "test_tc_b97_44_memory_inputs_labelled_inside_the_fields_tab[size1]"]),
    ("M36-label-column-auto", CSS, "    width: 13;\n    padding: 0 1 0 0;", "    width: auto;\n    padding: 0 1 0 0;",
     [C + "test_tc_b97_44_memory_inputs_labelled_inside_the_fields_tab[size0]"]),
    ("M37-default-label-painted", SDB, '            if item["name"] == self._default_label(address):',
     "            if False:",
     [C + "test_tc_b97_43_memory_lines_name_the_address_once"]),
    ("M38-memory-label-tail-clip", SDB,
     "                text.append(safe_text(_clip_to_cells(name, label_w), VALUE))",
     "                text.append(safe_text(clip_tail(name, label_w), VALUE))",
     [C + "test_tc_b97_43_memory_lines_name_the_address_once"]),
    ("M39-mem-table-default-shown", SDB, "                if label == self._default_label(address)",
     "                if False",
     [C + "test_tc_b97_43_memory_lines_name_the_address_once"]),
    ("M40-ledger-no-enter", SDB, '        Binding("enter", "toggle_include", "Include", show=False),\n', "",
     [C + "test_tc_b97_45_enter_on_the_ledger_toggles_inclusion"]),
    ("M41-plural-always", SDB, '    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"', '    return f"{n} {noun}s"',
     [C + "test_tc_b97_43_counts_agree_in_number_and_the_hint_reads_whole"]),
    ("M42-selected-focus-like-focus", CSS, "    text-style: bold underline;", "    text-style: bold;",
     [C + "test_tc_b97_45_keyboard_order_enter_space_and_chip_states"]),
    ("M43-tail-counts-code-points", SDB, "        used += cell_len(text[index])", "        used += 1",
     [C + "test_tc_b97_10_clips_measure_terminal_cells"]),
    ("M44-address-cell-blank", SDB,
     '            safe_text(f"0x{address:08X}" if address is not None else "-", CYAN),\n            safe_text(_clip_fmt_unit',
     '            safe_text("0x????????", CYAN),\n            safe_text(_clip_fmt_unit',
     [C + "test_tc_b97_10_parameter_floor_at_the_wide_breakpoint[size1]"]),
    ("M45-hint-back-to-vs", SDB, '    _STATUS_HINT = "Validate compares fields to the image"',
     '    _STATUS_HINT = "Validate checks fields vs the image."',
     [C + "test_tc_b97_43_counts_agree_in_number_and_the_hint_reads_whole"]),
    ("M46-fmt-unit-off-the-full-name-line", SDB, '        text.append(f"  {fmt_unit}  ", style=DGRAY)',
     '        text.append("  ", style=DGRAY)',
     [C + "test_tc_b97_10_full_name_line_keeps_address_and_name_tail"]),
]

if len(sys.argv) > 1:
    MUTANTS = [m for m in MUTANTS if m[0].split("-")[0] in sys.argv[1:]]

env = dict(os.environ, PY_COLORS="0", PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
env.pop("NO_COLOR", None)
print("mutants:", len(MUTANTS), "arms:", sum(len(m[4]) for m in MUTANTS), flush=True)
bad = 0
for mid, f, old_s, new_s, nodes in MUTANTS:
    src = f.read_bytes()
    eol = b"\r\n" if b"\r\n" in src else b"\n"
    old = old_s.encode("utf-8").replace(b"\n", eol)
    new = new_s.encode("utf-8").replace(b"\n", eol)
    h0 = hashlib.sha256(src).hexdigest()
    if src.count(old) != 1:
        print(f"{mid}: BAD (anchor found {src.count(old)} times)")
        bad += 1
        continue
    for node in nodes:
        try:
            f.write_bytes(src.replace(old, new, 1))
            if hashlib.sha256(f.read_bytes()).hexdigest() == h0:
                print(f"{mid} {node}: BAD (the edit did not apply)")
                sys.exit(1)
            r = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--color=no", "--tb=line", node],
                env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
        finally:
            f.write_bytes(src)
        h1 = hashlib.sha256(f.read_bytes()).hexdigest()
        assert h1 == h0, "the restore is not proven"
        verdict = {1: "RED (KILLED)", 0: "GREEN (SURVIVED)"}.get(r.returncode)
        bad += verdict is None
        tail = [ln for ln in r.stdout.splitlines() if "Error" in ln or "passed" in ln or "failed" in ln][-2:]
        print(f"{mid} [{f.name}] {node.split('::')[1]}: {verdict or 'CRASH/BAD (exit %d)' % r.returncode}")
        print(f"    restore sha256 {h1} == before {h0}")
        for ln in tail:
            print("    | " + ln.strip()[:300])
        sys.stdout.flush()
sys.exit(1 if bad else 0)
