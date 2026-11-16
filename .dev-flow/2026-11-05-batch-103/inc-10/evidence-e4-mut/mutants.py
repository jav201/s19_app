# -*- coding: utf-8 -*-
"""Inc 10 mutants (MU10). Each: id, rows, file, old, new, primary pytest args."""
T = "tests/test_b103_inc10_"
G1P, G1C, G2A, G2W, G3, S0 = (T + n + ".py" for n in
    ("g1_panel", "g1_controls", "g2_arms", "g2_write", "g3_engine", "s0_written_name"))
PATCH = "s19_app/tui/app/patch.py"
ACT = "s19_app/tui/screens_directionb/patch_editor/actions.py"
TCSS = "s19_app/tui/styles.tcss"
APPLY = "s19_app/tui/changes/apply.py"
IO = "s19_app/tui/changes/io.py"
CS = "s19_app/tui/services/change_service.py"

DOCK = "#patch_editor_panel #patch_export_dock {\n    width: 100%;"
VIS_OLD = '''.styles.visibility = (
            "visible" if output_format == "s19" else "hidden"
        )'''

M = []
def m(id, rows, file, old, new, tests):
    M.append(dict(id=id, rows=rows, file=file, old=old, new=new, tests=tests))

m("MU01", "R-CHG-003.1", PATCH, 'if counts["applied"] > 0 and loaded is not None:',
  'if counts["applied"] > 1 and loaded is not None:', [G1P, "-k", "r_chg_003_1"])
m("MU02", "R-PE-EXPORT.1", TCSS, DOCK, "#patch_editor_panel #patch_export_dock {\n    width: 60%;",
  [G1P, "-k", "pe_export_1_"])
m("MU03", "R-TUI-063.1", TCSS, DOCK, "#patch_editor_panel #patch_export_dock {\n    dock: bottom;\n    width: 100%;",
  [G1P, "-k", "tui_063"])
m("MU04", "R-PE-EXPORT.2", TCSS,
  "#patch_editor_panel #patch_saveback_buttons {\n    layout: horizontal;\n    height: 1;",
  "#patch_editor_panel #patch_saveback_buttons {\n    layout: grid;\n    grid-size: 2;\n    grid-columns: auto 1fr;\n    height: auto;",
  [G1P, "-k", "pe_export_2"])
m("MU05", "R-TUI-049.1", TCSS,
  "#patch_editor_panel #patch_before_after_row {\n    layout: horizontal;\n    height: 1;",
  "#patch_editor_panel #patch_before_after_row {\n    layout: horizontal;\n    height: 0;",
  [G2A, "-k", "tui_049"])
m("MU06", "R-PE-EXPORT.3", PATCH,
  "                else:\n                    panel.hide_save_prompt()\n                    self.notify(",
  "                else:\n                    self.notify(", [G2A, "-k", "export_3"])
m("MU07a", "R-PE-EXPORT.17/1 (Add)", PATCH,
  '                panel.hide_save_prompt()\n                self.set_status("Patch Editor: entry added.")',
  '                self.set_status("Patch Editor: entry added.")', [G2A, "-k", "export_17_1"])
m("MU07b", "R-PE-EXPORT.17/2 (Edit)", PATCH,
  '                panel.hide_save_prompt()\n                self.set_status("Patch Editor: entry updated.")',
  '                self.set_status("Patch Editor: entry updated.")', [G2A, "-k", "export_17_2"])
m("MU07c", "R-PE-EXPORT.17/3 (Remove)", PATCH,
  '                panel.hide_save_prompt()\n                self.set_status("Patch Editor: entry removed.")',
  '                self.set_status("Patch Editor: entry removed.")', [G2A, "-k", "export_17_3"])
m("MU07d", "R-PE-EXPORT.17/4 (JSON edit)", PATCH,
  '        if result.ok:\n            self.query_one(\n                "#patch_editor_panel", PatchEditorPanel\n            ).hide_save_prompt()',
  '        if result.ok:\n            pass', [G2A, "-k", "export_17_4"])
m("MU07e", "R-PE-EXPORT.17/5 (stage)", PATCH,
  "            panel.note_staged(event.name)\n            panel.hide_save_prompt()",
  "            panel.note_staged(event.name)", [G2A, "-k", "export_17_5"])
m("MU08a", "R-PE-EXPORT.4 (line text)", PATCH,
  '''                            apply_line=(
                                f"{apply_text} · changed in memory only — "
                                "Write file saves it"
                            ),''',
  "                            apply_line=apply_text,", [G2A, "-k", "export_4"])
m("MU08b", "R-PE-EXPORT.4/3 (line refresh)", ACT,
  '''        self.query_one("#patch_saveback_apply_line", Static).update(
            Text(apply_line)
        )''', "        pass", [G2A, "-k", "export_4"])
m("MU09a", "R-PE-EXPORT.5 (title)", PATCH, 'title="Nothing applied"', 'title="Applied nothing"',
  [G2A, "-k", "export_5"])
m("MU09b", "R-PE-EXPORT.5 (severity)", PATCH,
  'apply_text, title="Nothing applied", severity="warning"',
  'apply_text, title="Nothing applied", severity="information"', [G2A, "-k", "export_5"])
m("MU09c", "R-PE-EXPORT.5 (notice dropped)", PATCH,
  '''                    self.notify(
                        apply_text, title="Nothing applied", severity="warning"
                    )''', "                    pass", [G2A, "-k", "export_5"])
m("MU10", "R-PE-EXPORT.6", PATCH,
  '                self.set_status(apply_text)\n                if counts["applied"] > 0 and loaded is not None:',
  '                self.set_status(apply_text)\n                if counts["applied"] > 0:\n                    self.notify(apply_text)\n                if counts["applied"] > 0 and loaded is not None:',
  [G2A, "-k", "export_6"])
m("MU11a", "R-PE-EXPORT.7/3 (format kept)", ACT,
  "self._set_saveback_format(output_format, rename=False)",
  "self._set_saveback_format(self._saveback_format, rename=False)", [G1C, "-k", "export_7"])
m("MU11b", "R-PE-EXPORT.7/2 (always s19)", PATCH, "output_format=loaded.file_type,",
  'output_format="s19",', [G1C, "-k", "export_7"])
m("MU12a", "R-PE-EXPORT.8 (no change)", ACT,
  '"hex" if self._saveback_format == "s19" else "s19", rename=True',
  "self._saveback_format, rename=True", [G2W, "-k", "export_8"])
m("MU12b", "R-PE-EXPORT.8/2 (only to hex)", ACT,
  '"hex" if self._saveback_format == "s19" else "s19", rename=True',
  '"hex", rename=True', [G2W, "-k", "export_8"])
m("MU13a", "R-PE-EXPORT.9 (label constant)", ACT, 'f"Format: {name}"', '"Format: S19"',
  [G1C, "-k", "export_7_2 or export_9"])
m("MU13b", "R-PE-EXPORT.9 (chip width 17)", TCSS,
  "#patch_editor_panel #patch_saveback_format_button {\n    width: 19;",
  "#patch_editor_panel #patch_saveback_format_button {\n    width: 17;",
  [G1C, "-k", "export_7_2 or export_9"])
m("MU14a", "R-PE-EXPORT.10 (width always shown)", ACT, VIS_OLD, '.styles.visibility = "visible"',
  [G1C, "-k", "export_10"])
m("MU14b", "R-PE-EXPORT.10 (opacity not visibility)", ACT, VIS_OLD,
  '.styles.opacity = (\n            1.0 if output_format == "s19" else 0.0\n        )', [G1C, "-k", "export_10"])
m("MU15", "R-PE-EXPORT.11 (width always hidden)", ACT, VIS_OLD, '.styles.visibility = "hidden"',
  [G1C, "-k", "export_11"])
m("MU16", "R-PE-EXPORT.12 (width collapsed)", ACT, VIS_OLD,
  '.styles.display = (\n            "block" if output_format == "s19" else "none"\n        )',
  [G1C, "-k", "export_12"])
m("MU17", "R-PE-EXPORT.13 (width reset on switch)", ACT,
  "        self._saveback_format = output_format\n        name = suffix = None",
  "        self._saveback_format = output_format\n        if rename:\n            self._saveback_width = self.SAVEBACK_WIDTHS[0]\n        name = suffix = None",
  [G2W, "-k", "export_13"])
m("MU18a", "R-PE-EXPORT.14 (case)", ACT, 'r"\\.(s19|hex)\\s*\\Z", re.IGNORECASE', 'r"\\.(s19|hex)\\s*\\Z"',
  [G1C, "-k", "export_14"])
m("MU18b", "R-PE-EXPORT.14 (whitespace)", ACT, 'r"\\.(s19|hex)\\s*\\Z"', 'r"\\.(s19|hex)\\Z"',
  [G2W, "-k", "export_14"])
m("MU18c", "R-PE-EXPORT.14/3 (only .s19)", ACT, 'r"\\.(s19|hex)\\s*\\Z"', 'r"\\.(s19)\\s*\\Z"',
  [G1C, "-k", "export_14"])
m("MU19", "R-PE-EXPORT.15", ACT,
  "name_input.value = _SUFFIX_RE.sub(suffix, name_input.value)",
  "name_input.value = _SUFFIX_RE.sub(suffix, name_input.value) if _SUFFIX_RE.search(name_input.value) else name_input.value + suffix",
  [G2W, "-k", "export_15"])
m("MU20", "R-HEX-SAVE-001.1", PATCH, "source_kind=kind,", "source_kind=loaded.file_type,",
  [G2W, "-k", "chosen_format"])
m("MU21a", "R-HEX-SAVE-001.2 (any suffix kept)", APPLY,
  "if not bare.lower().endswith(suffix.lower()):",
  'if not (bare.lower().endswith(".s19") or bare.lower().endswith(".hex")):', [G3, "-k", "hex_save_001_2"])
m("MU21b", "R-HEX-SAVE-001.2 (case sensitive)", APPLY,
  "if not bare.lower().endswith(suffix.lower()):", "if not bare.endswith(suffix):", [G3, "-k", "hex_save_001_2"])
m("MU22", "R-S19-SAVE-REUSE-001.1", IO, "row_start + HEX_DATA_BYTES_PER_RECORD,", "row_start + 32,",
  [G2W, "-k", "reuse"])
m("MU23", "R-PE-EXPORT.16 (type 04 -> 02)", IO,
  "_intel_hex_record(0x04, 0, [upper >> 8, upper & 0xFF])", "_intel_hex_record(0x02, 0, [upper >> 8, upper & 0xFF])",
  [G3, "-k", "export_16"])
m("MU24a", "R-HEX-EMIT-001.11 (boundary dropped)", IO,
  "                end,\n                (row_start | 0xFFFF) + 1,\n", "                end,\n", [G3, "-k", "emit_001_11"])
m("MU24b", "R-HEX-EMIT-001.11 (+2)", IO, "(row_start | 0xFFFF) + 1,", "(row_start | 0xFFFF) + 2,",
  [G3, "-k", "emit_001_11"])
m("MU24c", "R-HEX-EMIT-001.11 (-0)", IO, "(row_start | 0xFFFF) + 1,", "(row_start | 0xFFFF),",
  [G3, "-k", "emit_001_11"])
m("MU25", "R-S19-S0HEADER-001.1", PATCH, "s0_header = loaded.source_s0_header or None", "s0_header = None",
  [G2W, "-k", "s0header_001_1_2"])
m("MU26a", "R-S19-S0HEADER-001.2 (first render)", APPLY,
  "        if name == header_name:\n            break", "        break", [S0])
m("MU26b", "R-S19-S0HEADER-001.2 (typed name)", PATCH,
  "                s0_from_name = _synth_s0_header_from_filename",
  "                s0_from_name = lambda _written, _typed=event.filename: _synth_s0_header_from_filename(_typed)", [S0])
m("MU26c", "R-S19-S0HEADER-001.2 (non-ASCII kept as ?)", PATCH,
  'errors="ignore"', 'errors="replace"', [G2W, S0, "-k", "s0header"])
m("MU26d", "R-S19-S0HEADER-001.2 (cap 253)", PATCH,
  "ascii_bytes[:_SAVEBACK_S0_MAX_BYTES]", "ascii_bytes[:_SAVEBACK_S0_MAX_BYTES + 1]", [G2W, S0, "-k", "s0header"])
m("MU26e", "R-S19-S0HEADER-001.2 (rounds 1)", APPLY, "_S0_NAME_ROUNDS = 3", "_S0_NAME_ROUNDS = 1", [S0])
m("MU26f", "R-S19-S0HEADER-001.2 (rounds 2)", APPLY, "_S0_NAME_ROUNDS = 3", "_S0_NAME_ROUNDS = 2", [S0])
m("MU26g", "R-S19-S0HEADER-001.2 (no re-render)", APPLY,
  'if s0_header_from_name is not None and source_kind == "s19":',
  'if False and s0_header_from_name is not None and source_kind == "s19":', [S0])
m("MU26h", "R-S19-S0HEADER-001.2 (never stops early)", APPLY,
  "        if name == header_name:\n            break", "        if False:\n            break", [S0])
m("MU27", "R-S19-S0HEADER-001.3", PATCH, 'if bytes_per_line == 32 and kind == "s19":', 'if kind == "s19":',
  [G2W, "-k", "s0header or at_i10_2"])
m("MU29", "R-HEX-VERIFY-001.1", CS, "verify = verify_written_image(path, image, source_kind)",
  'verify = verify_written_image(path, image, "s19")', [G2W, "-k", "chosen_format"])
m("MU30", "R-HEX-VERIFY-002.3", PATCH, 'suffix = ".hex" if loaded.file_type == "hex" else ".s19"',
  'suffix = ".s19"', [G1C, "-k", "verify_002_3"])
m("MU31", "R-S19-WIDTH-001.1", ACT,
  '        self._saveback_width = self.SAVEBACK_WIDTHS[0]\n        self.query_one("#patch_saveback_width_button", Button).label = (',
  '        self.query_one("#patch_saveback_width_button", Button).label = (', [G1C, "-k", "width_001_1"])
m("MU32", "R-S19-WIDTH-001.2", ACT, "(index + 1) % len(self.SAVEBACK_WIDTHS)", "index",
  [G1C, "-k", "width_001_2"])
m("MU33", "R-CHG-003.2/.5", PATCH,
  "        panel.hide_save_prompt()\n        if event.filename is None:", "        if event.filename is None:",
  [G2A, "-k", "003_2 or 003_5"])
m("MU34", "R-TUI-064.1 (prompt rows padded)", TCSS,
  "#patch_editor_panel #patch_before_after_row {\n    height: auto;\n    padding: 0 1;",
  "#patch_editor_panel #patch_before_after_row {\n    height: auto;\n    padding: 4 1;", [G1C, "-k", "064_1"])
m("MU35", "R-TUI-064.2", TCSS,
  "#patch_editor_panel #patch_saveback_format_button {\n    width: 19;",
  "#patch_editor_panel #patch_saveback_format_button {\n    width: 200;", [G1C, "-k", "064_2"])
m("MU36", "R-TUI-064.4", TCSS,
  "#patch_editor_panel #patch_saveback_buttons {\n    layout: horizontal;\n    height: 1;\n    padding: 0;",
  "#patch_editor_panel #patch_saveback_buttons {\n    layout: horizontal;\n    height: 3;\n    padding: 0;", [G1C, "-k", "064_4"])
m("MU37", "I-10.2 (confirm without format)", ACT, "                    output_format=self._saveback_format,\n", "",
  [G2W, "-k", "chosen_format"])
